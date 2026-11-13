// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::pin::Pin;
use std::task::{Context, Poll};

use openshell_ocsf::{
    ActionId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest, HttpResponse, OcsfEvent,
    SeverityId, StatusId,
};
use tokio::io::AsyncWrite;

use super::{HttpOutcome, RequestCorrelation, RequestStage, close_span};
use crate::opa::PolicyGenerationGuard;

#[derive(Debug, Clone, Copy)]
pub enum ResponseCause {
    UpstreamResponse,
    UpstreamIoError,
    UpstreamTruncated,
    UpstreamIdleTimeout,
    UpstreamProtocolError,
    MiddlewareDenied,
    MiddlewareFailed,
    PolicyReloaded,
    Cancelled,
    PlatformError,
    Unknown,
}

impl ResponseCause {
    fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamResponse => "upstream_response",
            Self::UpstreamIoError => "upstream_io_error",
            Self::UpstreamTruncated => "upstream_truncated",
            Self::UpstreamIdleTimeout => "upstream_idle_timeout",
            Self::UpstreamProtocolError => "upstream_protocol_error",
            Self::MiddlewareDenied => "middleware_denied",
            Self::MiddlewareFailed => "middleware_failed",
            Self::PolicyReloaded => "policy_reloaded",
            Self::Cancelled => "cancelled",
            Self::PlatformError => "platform_error",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Complete,
    DownstreamIoError,
    CancelledOrIncomplete,
}

impl DeliveryOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::DownstreamIoError => "downstream_io_error",
            Self::CancelledOrIncomplete => "cancelled_or_incomplete",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ResponseFailure {
    pub cause: Option<ResponseCause>,
    pub delivery: DeliveryOutcome,
    pub outcome: HttpOutcome,
    pub stage: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct Completion {
    cause: ResponseCause,
    delivery: DeliveryOutcome,
    started: bool,
    interim_bytes: u64,
    stage: Option<&'static str>,
}

#[derive(Debug)]
struct AuditContext {
    method: &'static str,
    destination: Option<Endpoint>,
    policy: String,
}

#[derive(Debug, Default)]
pub(super) struct ResponseState {
    active: bool,
    interim: bool,
    started: bool,
    interim_bytes: u64,
    cause: Option<ResponseCause>,
    failure: Option<ResponseFailure>,
    terminal: Option<Completion>,
    context: Option<AuditContext>,
}

impl ResponseState {
    pub(super) fn upstream_response(&mut self) {
        if self.active {
            self.cause.get_or_insert(ResponseCause::UpstreamResponse);
        }
    }
    pub(super) fn enrich_primary(&self, event: &mut OcsfEvent) {
        if let Some(completion) = self.terminal {
            enrich(event, completion);
        }
    }
}

impl RequestCorrelation {
    pub(crate) fn response_cause(&self, cause: ResponseCause) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.response.active {
            state.response.cause = Some(cause);
        }
    }

    pub(crate) fn interim_response(&self, interim: bool) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .response
            .interim = interim;
    }

    pub(crate) fn response_failure_cause(&self, cause: ResponseCause) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.response.active
            && matches!(
                state.response.cause,
                None | Some(ResponseCause::UpstreamResponse)
            )
        {
            state.response.cause = Some(cause);
        }
    }

    pub(crate) fn response_failure(&self, failure: ResponseFailure) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.response.active {
            if let Some(cause) = failure.cause {
                state.response.cause = Some(cause);
            }
            state.response.failure = Some(failure);
        }
    }

    fn accepted_response_bytes(&self, accepted: usize) {
        if accepted == 0 {
            return;
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let response = &mut state.response;
        if !response.active {
            return;
        }
        if response.interim {
            response.interim_bytes = response
                .interim_bytes
                .saturating_add(u64::try_from(accepted).unwrap_or(u64::MAX));
        } else {
            response.started = true;
        }
    }
}

#[must_use]
pub struct ResponseDelivery<'a> {
    correlation: Option<&'a RequestCorrelation>,
    span: tracing::Span,
    active: bool,
}

impl<'a> ResponseDelivery<'a> {
    pub(crate) fn new(correlation: Option<&'a RequestCorrelation>) -> Self {
        let correlation = correlation.filter(|correlation| correlation.inspected);
        let span = correlation.map_or_else(tracing::Span::none, |correlation| {
            correlation.stage(RequestStage::Response)
        });
        if let Some(correlation) = correlation {
            let mut state = correlation
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let context = state.primary.as_ref().and_then(|event| match event {
                OcsfEvent::HttpActivity(http) => Some(AuditContext {
                    method: http.http_request.as_ref().map_or("OTHER", |request| {
                        match request.http_method.as_str() {
                            "GET" => "GET",
                            "HEAD" => "HEAD",
                            "POST" => "POST",
                            "PUT" => "PUT",
                            "DELETE" => "DELETE",
                            "CONNECT" => "CONNECT",
                            "OPTIONS" => "OPTIONS",
                            "TRACE" => "TRACE",
                            "PATCH" => "PATCH",
                            _ => "OTHER",
                        }
                    }),
                    destination: http.dst_endpoint.clone(),
                    policy: http
                        .firewall_rule
                        .as_ref()
                        .map_or_else(String::new, |rule| rule.name.clone()),
                }),
                _ => None,
            });
            state.response.active = true;
            state.response.context = context;
        }
        Self {
            correlation,
            span,
            active: true,
        }
    }

    pub(crate) fn span(&self) -> &tracing::Span {
        &self.span
    }

    pub(crate) fn finish(&mut self, fallback: Option<ResponseFailure>) {
        if !self.active {
            return;
        }
        self.active = false;
        let Some(correlation) = self.correlation else {
            return;
        };
        let (completion, upstream, effective, context, late, failed) = {
            let mut state = correlation
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let failure = state.response.failure.or(fallback).map(|mut failure| {
                if failure.stage == "response_unknown" && state.outcome == Some(HttpOutcome::Denied)
                {
                    failure.outcome = HttpOutcome::Denied;
                }
                failure
            });
            let completion = Completion {
                cause: failure
                    .and_then(|failure| failure.cause)
                    .or(state.response.cause)
                    .unwrap_or_else(|| {
                        if failure.is_some() {
                            ResponseCause::Unknown
                        } else {
                            ResponseCause::UpstreamResponse
                        }
                    }),
                delivery: failure.map_or(DeliveryOutcome::Complete, |failure| failure.delivery),
                started: state.response.started,
                interim_bytes: state.response.interim_bytes,
                stage: failure.map(|failure| {
                    if failure.stage == "response_unknown" {
                        state.failure_reason.unwrap_or(failure.stage)
                    } else {
                        failure.stage
                    }
                }),
            };
            if let Some(failure) = failure {
                state.record_outcome(failure.outcome);
                state.record_failure_reason(completion.stage.unwrap_or(failure.stage));
            }
            state.response.active = false;
            state.response.terminal = Some(completion);
            let context = state.response.context.take();
            (
                completion,
                state.upstream_status,
                state.status,
                context,
                state.primary.is_none(),
                matches!(
                    state.outcome,
                    Some(HttpOutcome::PlatformError | HttpOutcome::UpstreamError)
                ),
            )
        };
        self.span.record(
            "openshell.response.selection_cause",
            completion.cause.as_str(),
        );
        self.span.record(
            "openshell.response.delivery_outcome",
            completion.delivery.as_str(),
        );
        self.span
            .record("openshell.response.delivery_started", completion.started);
        self.span.record(
            "openshell.response.partial_delivery",
            completion.started && completion.delivery != DeliveryOutcome::Complete,
        );
        self.span.record(
            "openshell.response.interim_delivery_started",
            completion.interim_bytes > 0,
        );
        self.span.record(
            "openshell.response.interim_bytes_forwarded",
            i64::try_from(completion.interim_bytes).unwrap_or(i64::MAX),
        );
        if let Some(status) = upstream {
            self.span.record(
                "openshell.upstream.http.response.status_code",
                i64::from(status),
            );
        }
        if let Some(status) = effective {
            self.span
                .record("http.response.status_code", i64::from(status));
        }
        if let Some(stage) = completion.stage {
            self.span.record("openshell.error.stage", stage);
        }
        if failed || completion.delivery != DeliveryOutcome::Complete {
            self.span.record("otel.status_code", "ERROR");
        }
        if late
            && completion.delivery != DeliveryOutcome::Complete
            && let Some(context) = context
        {
            let mut event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .activity(openshell_ocsf::ActivityId::for_http_method(context.method))
                .action(ActionId::Observed)
                .disposition(DispositionId::Logged)
                .severity(
                    if completion.delivery == DeliveryOutcome::DownstreamIoError {
                        SeverityId::Medium
                    } else {
                        SeverityId::Low
                    },
                )
                .status(
                    if completion.delivery == DeliveryOutcome::DownstreamIoError {
                        StatusId::Failure
                    } else {
                        StatusId::Unknown
                    },
                )
                .http_request(HttpRequest {
                    http_method: context.method.parse().expect("bounded HTTP method"),
                    url: None,
                })
                .firewall_rule(&context.policy, "response-correlation")
                .unmapped("response_event_kind", "delivery_terminal")
                .message("HTTP response delivery did not complete");
            if let Some(destination) = context.destination {
                event = event.dst_endpoint(destination);
            }
            if let Some(status) = effective {
                event = event.http_response(HttpResponse { code: status });
            }
            if let Some(status) = upstream {
                event = event.unmapped("upstream_response_code", status);
            }
            let mut event = event.build();
            enrich(&mut event, completion);
            correlation.emit_correlated(event);
        }
    }
}

impl Drop for ResponseDelivery<'_> {
    fn drop(&mut self) {
        self.finish(Some(ResponseFailure {
            cause: Some(ResponseCause::Cancelled),
            delivery: DeliveryOutcome::CancelledOrIncomplete,
            outcome: HttpOutcome::PlatformError,
            stage: "response_cancelled_or_incomplete",
        }));
        close_span(std::mem::replace(&mut self.span, tracing::Span::none()));
    }
}

fn enrich(event: &mut OcsfEvent, completion: Completion) {
    event.add_unmapped("response_selection_cause", completion.cause.as_str());
    event.add_unmapped("response_delivery_outcome", completion.delivery.as_str());
    event.add_unmapped("interim_bytes_forwarded", completion.interim_bytes);
    event.add_unmapped("interim_delivery_started", completion.interim_bytes > 0);
    event.add_unmapped("delivery_started", completion.started);
    event.add_unmapped(
        "partial_delivery",
        completion.started && completion.delivery != DeliveryOutcome::Complete,
    );
}

pub struct ResponseTransport<'a, C> {
    inner: &'a mut C,
    correlation: Option<&'a RequestCorrelation>,
    generation: Option<&'a PolicyGenerationGuard>,
}

impl<'a, C> ResponseTransport<'a, C> {
    pub(crate) fn new(
        inner: &'a mut C,
        correlation: Option<&'a RequestCorrelation>,
        generation: Option<&'a PolicyGenerationGuard>,
    ) -> Self {
        Self {
            inner,
            correlation,
            generation,
        }
    }

    fn failed(&self, stage: &'static str) {
        if let Some(correlation) = self.correlation {
            let interim = correlation
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .response
                .interim;
            let stage = if interim {
                match stage {
                    "downstream_response_write" => "downstream_interim_write",
                    "downstream_response_flush" => "downstream_interim_flush",
                    _ => stage,
                }
            } else {
                stage
            };
            correlation.response_failure(ResponseFailure {
                cause: interim.then_some(ResponseCause::PlatformError),
                delivery: DeliveryOutcome::DownstreamIoError,
                outcome: HttpOutcome::PlatformError,
                stage,
            });
        }
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for ResponseTransport<'_, C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if !bytes.is_empty()
            && let Some(guard) = this.generation
            && guard.is_stale()
        {
            if let Some(correlation) = this.correlation {
                correlation.response_failure(ResponseFailure {
                    cause: Some(ResponseCause::PolicyReloaded),
                    delivery: DeliveryOutcome::CancelledOrIncomplete,
                    outcome: HttpOutcome::PlatformError,
                    stage: "response_policy_reload",
                });
            }
            return Poll::Ready(Err(std::io::Error::other("policy generation changed")));
        }
        let result = Pin::new(&mut *this.inner).poll_write(cx, bytes);
        match &result {
            Poll::Ready(Ok(0)) if !bytes.is_empty() => this.failed("downstream_response_write"),
            Poll::Ready(Ok(accepted)) => {
                if let Some(correlation) = this.correlation {
                    correlation.accepted_response_bytes(*accepted);
                }
            }
            Poll::Ready(Err(_)) => this.failed("downstream_response_write"),
            Poll::Pending => {}
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_flush(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed("downstream_response_flush");
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            this.failed("downstream_response_shutdown");
        }
        result
    }
}
