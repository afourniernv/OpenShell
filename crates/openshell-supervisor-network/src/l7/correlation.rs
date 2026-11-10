// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-request receipts and consolidated HTTP audit records.

use std::sync::Mutex;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use openshell_ocsf::{
    ActionId, DispositionId, Endpoint, HttpActivityBuilder, HttpActivityEvent, HttpRequest,
    HttpResponse, OcsfEvent, SeverityId, StatusId,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;

#[derive(Debug)]
pub struct RequestCorrelation {
    request_id: String,
    inspected: bool,
    // Keep the audit payload off the async state machine.
    state: Box<Mutex<RequestState>>,
}

#[derive(Debug, Default)]
struct RequestState {
    primary: Option<OcsfEvent>,
    seeded: bool,
    status: Option<u16>,
    upstream_status: Option<u16>,
    outcome: Option<&'static str>,
    blocked: bool,
    failure_reason: Option<&'static str>,
    late_failure_emitted: bool,
}

impl RequestCorrelation {
    #[must_use]
    pub(crate) fn new(request: &L7Request, ctx: &L7EvalContext) -> Self {
        Self::build(request, ctx, uuid::Uuid::new_v4().to_string())
    }

    pub(crate) fn uninspected() -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            inspected: false,
            state: Box::default(),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_request_id(
        request: &L7Request,
        ctx: &L7EvalContext,
        request_id: String,
    ) -> Self {
        Self::build(request, ctx, request_id)
    }

    fn build(request: &L7Request, ctx: &L7EvalContext, request_id: String) -> Self {
        let target = request.target.split(['?', '#']).next().unwrap_or("/");
        let target = if target.starts_with('/') { target } else { "/" };
        let path = openshell_core::secrets::redact_target_for_policy(target)
            .unwrap_or_else(|_| "/".to_string());
        let fallback = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .http_request(HttpRequest::new(&request.action, ctx.ocsf_url(&path)))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .message("HTTP request ended before a response was selected")
            .build();
        Self {
            request_id,
            inspected: true,
            state: Box::new(Mutex::new(RequestState {
                primary: Some(fallback),
                ..RequestState::default()
            })),
        }
    }

    #[must_use]
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(crate) fn observe_response<'a, C>(&'a self, client: &'a mut C) -> AuditedClient<'a, C> {
        AuditedClient {
            inner: client,
            correlation: self,
            head: ResponseHead::default(),
        }
    }

    pub(crate) fn record_enforcement_action(&self, action: &str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .blocked |= action == "block";
    }

    pub(crate) fn record_final_http_outcome(&self, outcome: &'static str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outcome = Some(outcome);
    }

    pub(crate) fn record_response_status(&self, status: u16) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .status = Some(status);
    }

    pub(crate) fn record_upstream_status(&self, status: u16) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upstream_status = Some(status);
    }

    pub(crate) fn record_failure_reason(&self, reason: &'static str) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failure_reason = Some(reason);
    }

    pub(crate) fn emit(&self, event: OcsfEvent) {
        if !self.inspected {
            crate::telemetry::emit_decision([event], None);
            return;
        }
        if let OcsfEvent::HttpActivity(mut incoming) = event {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.seeded && state.primary.is_some() {
                state.primary = Some(OcsfEvent::HttpActivity(incoming));
                state.seeded = true;
                return;
            }
            if let Some(OcsfEvent::HttpActivity(primary)) = &mut state.primary {
                merge_http_outcome(primary, incoming);
                return;
            }
            let fail_open = incoming.action == Some(ActionId::Other)
                && incoming.disposition == Some(DispositionId::Allowed);
            if !is_failure(&incoming) || fail_open || state.late_failure_emitted {
                return;
            }
            state.late_failure_emitted = true;
            if let Some(code) = state.status {
                incoming.http_response = Some(HttpResponse { code });
            }
            drop(state);
            self.emit_correlated(OcsfEvent::HttpActivity(incoming));
        } else {
            if let OcsfEvent::NetworkActivity(network) = &event {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !state.seeded
                    && (network.action == Some(ActionId::Denied)
                        || network.base.status == Some(StatusId::Failure))
                    && let Some(OcsfEvent::HttpActivity(primary)) = &mut state.primary
                {
                    primary.action = network.action;
                    primary.disposition = network.disposition;
                    primary.base.status = Some(StatusId::Failure);
                    primary
                        .base
                        .status_detail
                        .clone_from(&network.base.status_detail);
                    primary.base.severity = network.base.severity;
                    primary.base.message =
                        Some("HTTP request rejected before policy evaluation".into());
                    primary.src_endpoint.clone_from(&network.src_endpoint);
                    primary.actor.clone_from(&network.actor);
                }
            }
            self.emit_correlated(event);
        }
    }

    pub(crate) fn response_selected(&self, status: u16) {
        self.record_response_status(status);
        self.emit_primary(false);
    }

    fn emit_primary(&self, incomplete: bool) {
        if !self.inspected {
            return;
        }
        let (mut event, status, upstream_status, outcome, blocked, failure_reason) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(primary) = state.primary.take() else {
                return;
            };
            (
                primary,
                state.status,
                state.upstream_status,
                state.outcome,
                state.blocked,
                state.failure_reason,
            )
        };
        if let OcsfEvent::HttpActivity(http) = &mut event {
            let has_failure_reason = is_failure(http) && http.base.status_detail.is_some();
            if let Some(code) = status {
                http.http_response = Some(HttpResponse { code });
            }
            if let Some(upstream) = upstream_status.filter(|upstream| Some(*upstream) != status)
                && let serde_json::Value::Object(unmapped) = http
                    .base
                    .unmapped
                    .get_or_insert_with(|| serde_json::json!({}))
            {
                unmapped.insert("upstream_response_code".into(), serde_json::json!(upstream));
            }
            if blocked || outcome == Some("denied") {
                if http.action != Some(ActionId::Denied) {
                    http.base.message = Some("HTTP request blocked by supervisor".into());
                }
                http.action = Some(ActionId::Denied);
                http.disposition = Some(DispositionId::Blocked);
                http.base.status = Some(StatusId::Failure);
                raise_severity(http, SeverityId::Medium);
                if !has_failure_reason {
                    http.base.status_detail = Some(
                        failure_reason
                            .or(outcome)
                            .unwrap_or("supervisor_blocked")
                            .into(),
                    );
                }
            } else if matches!(outcome, Some("platform_error" | "upstream_error")) {
                http.base.status = Some(StatusId::Failure);
                raise_severity(http, SeverityId::Low);
                if !has_failure_reason {
                    http.base.status_detail = failure_reason.or(outcome).map(str::to_string);
                }
            }
            if incomplete && outcome.is_none() {
                http.base.status = Some(StatusId::Failure);
                if !has_failure_reason {
                    http.base.status_detail = Some("request_incomplete".into());
                }
                raise_severity(http, SeverityId::Low);
            }
        }
        self.emit_correlated(event);
    }

    fn emit_correlated(&self, mut event: OcsfEvent) {
        event.set_correlation_uid(self.request_id.clone());
        crate::telemetry::emit_decision([event], None);
    }
}

fn is_failure(event: &HttpActivityEvent) -> bool {
    event.action == Some(ActionId::Denied) || event.base.status == Some(StatusId::Failure)
}

fn raise_severity(event: &mut HttpActivityEvent, severity: SeverityId) {
    if event.base.severity.as_u8() < severity.as_u8() {
        event.base.severity = severity;
    }
}

fn merge_http_outcome(primary: &mut HttpActivityEvent, incoming: HttpActivityEvent) {
    let failed = is_failure(&incoming);
    if primary.actor.is_none() {
        primary.actor = incoming.actor;
    }
    if primary.src_endpoint.is_none() {
        primary.src_endpoint = incoming.src_endpoint;
    }
    if primary.dst_endpoint.is_none() {
        primary.dst_endpoint = incoming.dst_endpoint;
    }
    if primary.firewall_rule.is_none() {
        primary.firewall_rule = incoming.firewall_rule;
    }
    if primary
        .http_request
        .as_ref()
        .and_then(|request| request.url.as_ref())
        .is_none()
        && incoming
            .http_request
            .as_ref()
            .and_then(|request| request.url.as_ref())
            .is_some()
    {
        primary.http_request = incoming.http_request;
    }
    if !failed {
        if incoming
            .base
            .unmapped
            .as_ref()
            .and_then(|fields| fields.get("transformed_body_policy"))
            .and_then(serde_json::Value::as_str)
            == Some("audit")
        {
            if let serde_json::Value::Object(fields) = primary
                .base
                .unmapped
                .get_or_insert_with(|| serde_json::json!({}))
            {
                fields.insert("transformed_body_policy".into(), "audit".into());
            }
            if !is_failure(primary) && incoming.base.status_detail.is_some() {
                primary
                    .base
                    .status_detail
                    .clone_from(&incoming.base.status_detail);
            }
        }
        if primary.action.is_none() {
            primary.action = incoming.action;
            primary.disposition = incoming.disposition;
            primary.base.status = incoming.base.status;
            primary.base.message = incoming.base.message;
            primary.base.status_detail = incoming.base.status_detail;
        }
        return;
    }
    if incoming.action == Some(ActionId::Denied) {
        primary.action = incoming.action;
        primary.disposition = incoming.disposition;
    }
    primary.base.status = Some(StatusId::Failure);
    raise_severity(primary, incoming.base.severity);
    if incoming.base.message.is_some() {
        primary.base.message = incoming.base.message;
    }
    if incoming.base.status_detail.is_some() {
        primary.base.status_detail = incoming.base.status_detail;
    }
    if incoming.http_response.is_some() {
        primary.http_response = incoming.http_response;
    }
    if let Some(serde_json::Value::Object(fields)) = incoming.base.unmapped
        && let serde_json::Value::Object(existing) = primary
            .base
            .unmapped
            .get_or_insert_with(|| serde_json::json!({}))
    {
        existing.extend(fields);
    }
}

/// Observe accepted response bytes without buffering or changing delivery.
pub struct AuditedClient<'a, C> {
    inner: &'a mut C,
    correlation: &'a RequestCorrelation,
    head: ResponseHead,
}

#[derive(Default)]
struct ResponseHead {
    prefix: [u8; 12],
    prefix_len: usize,
    delimiter: u32,
    complete: bool,
}

impl ResponseHead {
    fn accept(&mut self, bytes: &[u8], correlation: &RequestCorrelation) {
        for &byte in bytes {
            if self.complete {
                break;
            }
            if self.prefix_len < self.prefix.len() {
                self.prefix[self.prefix_len] = byte;
                self.prefix_len += 1;
            }
            self.delimiter = (self.delimiter << 8) | u32::from(byte);
            if self.delimiter != u32::from_be_bytes(*b"\r\n\r\n") {
                continue;
            }
            let status = std::str::from_utf8(&self.prefix[9..12])
                .ok()
                .and_then(|code| code.parse::<u16>().ok());
            if status.is_some_and(|code| (100..200).contains(&code) && code != 101) {
                *self = Self::default();
            } else {
                self.complete = true;
                if let Some(status) = status {
                    correlation.response_selected(status);
                }
            }
        }
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for AuditedClient<'_, C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for AuditedClient<'_, C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(accepted)) = result
            && this.correlation.inspected
        {
            this.head.accept(&bytes[..accepted], this.correlation);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}

impl Drop for RequestCorrelation {
    fn drop(&mut self) {
        self.emit_primary(true);
    }
}

#[cfg(test)]
mod tests;
