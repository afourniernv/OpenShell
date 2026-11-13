// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor-owned request traces with untrusted workload links.

use opentelemetry::propagation::{Extractor, TextMapPropagator as _};
use opentelemetry::trace::{SpanContext, TraceContextExt as _};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use super::correlation::HttpOutcome;
use openshell_ocsf::{ActionId, HttpActivityEvent, StatusId};

const MAX_TRACEPARENT_BYTES: usize = 256;

#[derive(Debug)]
pub(super) struct RequestTrace {
    span: Span,
    outcome: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub enum RequestStage {
    PolicyEvaluate,
    RequestMiddleware,
    WebsocketPreflight,
    CredentialPrepare,
    UpstreamResolve,
    UpstreamDial,
    UpstreamSend,
    Response,
    ResponseMiddleware,
    McpInspect,
}

impl RequestStage {
    fn name(self) -> &'static str {
        match self {
            Self::PolicyEvaluate => "openshell.policy.evaluate",
            Self::RequestMiddleware => "openshell.middleware.request",
            Self::WebsocketPreflight => "openshell.middleware.websocket.preflight",
            Self::CredentialPrepare => "openshell.credential.prepare",
            Self::UpstreamResolve => "openshell.upstream.resolve",
            Self::UpstreamDial => "openshell.upstream.connect",
            Self::UpstreamSend => "openshell.upstream.send",
            Self::Response => "openshell.http.response",
            Self::ResponseMiddleware => "openshell.middleware.response",
            Self::McpInspect => "openshell.mcp.inspect",
        }
    }
}

impl RequestTrace {
    pub(super) fn new(
        request_id: &str,
        method: &str,
        host: &str,
        port: u16,
        raw_request: &[u8],
    ) -> Self {
        let span = tracing::info_span!(
            parent: None,
            "openshell.http.request",
            openshell.request.id = request_id,
            http.request.method = normalized_method(method),
            server.address = host,
            server.port = i64::from(port),
            openshell.request.outcome = tracing::field::Empty,
            openshell.request.delivery_started = false,
            openshell.request.failure_reason = tracing::field::Empty,
            http.response.status_code = tracing::field::Empty,
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
        );
        if let Some(context) = workload_link(raw_request) {
            span.add_link_with_attributes(
                context,
                vec![
                    KeyValue::new("openshell.correlation.source", "http.traceparent"),
                    KeyValue::new("openshell.correlation.trust", "workload"),
                ],
            );
        }
        Self {
            span,
            outcome: "incomplete",
        }
    }

    pub(super) fn span(&self) -> Span {
        self.span.clone()
    }

    pub(super) fn stage(&self, stage: RequestStage) -> Span {
        if self.span.is_disabled() || !self.span.context().span().span_context().is_valid() {
            return Span::none();
        }
        if matches!(
            stage,
            RequestStage::RequestMiddleware | RequestStage::ResponseMiddleware
        ) {
            return tracing::info_span!(
                parent: &self.span,
                "openshell.http.stage",
                otel.name = stage.name(),
                otel.status_code = tracing::field::Empty,
                openshell.middleware.outcome = "incomplete",
                openshell.middleware.mutated = false,
                openshell.middleware.fail_open = false,
                openshell.middleware.fail_closed = false,
                openshell.middleware.admission_exhausted = false,
                openshell.middleware.diagnostics_truncated = false,
                openshell.response.delivery_started = false,
                openshell.response.partial_delivery = false,
            );
        }
        if matches!(stage, RequestStage::CredentialPrepare) {
            return tracing::info_span!(
                parent: &self.span,
                "openshell.http.stage",
                otel.name = stage.name(),
                otel.status_code = tracing::field::Empty,
                openshell.credential.outcome = tracing::field::Empty,
                openshell.credential.mechanisms = tracing::field::Empty,
                openshell.credential.surfaces = tracing::field::Empty,
                openshell.credential.static_placeholder.outcome = tracing::field::Empty,
                openshell.credential.token_grant.outcome = tracing::field::Empty,
                openshell.credential.sigv4.outcome = tracing::field::Empty,
            );
        }
        if matches!(stage, RequestStage::McpInspect) {
            return tracing::info_span!(
                parent: &self.span,
                "openshell.http.stage",
                otel.name = stage.name(),
                otel.status_code = tracing::field::Empty,
                openshell.l7.protocol = tracing::field::Empty,
                openshell.jsonrpc.effective.message_kind = tracing::field::Empty,
                openshell.jsonrpc.effective.inspection_outcome = "incomplete",
                openshell.jsonrpc.effective.call_count = tracing::field::Empty,
                openshell.jsonrpc.effective.notification_count = tracing::field::Empty,
                openshell.jsonrpc.effective.counts_truncated = tracing::field::Empty,
                openshell.jsonrpc.effective.has_response = tracing::field::Empty,
                openshell.mcp.selected_protocol_revision = tracing::field::Empty,
                openshell.mcp.effective.protocol_revision = tracing::field::Empty,
                openshell.mcp.effective.method_classification = tracing::field::Empty,
                openshell.mcp.tools_call_observed = tracing::field::Empty,
            );
        }
        tracing::info_span!(
            parent: &self.span,
            "openshell.http.stage",
            otel.name = stage.name(),
            otel.status_code = tracing::field::Empty,
        )
    }

    pub(super) fn record_status(&self, status: u16) {
        self.span
            .record("http.response.status_code", i64::from(status));
    }

    pub(super) fn record_delivery_started(&self) {
        self.span.record("openshell.request.delivery_started", true);
    }

    pub(super) fn record_outcome(&mut self, outcome: HttpOutcome) {
        let outcome = match outcome {
            HttpOutcome::Allowed if self.outcome == "denied" => "denied",
            HttpOutcome::Allowed => "allowed",
            HttpOutcome::Denied => "denied",
            HttpOutcome::PlatformError | HttpOutcome::UpstreamError => "failed",
            HttpOutcome::Upgraded => "upgraded",
        };
        self.outcome = outcome;
        self.span.record("openshell.request.outcome", outcome);
    }

    pub(super) fn record_failure_reason(&self, reason: &'static str) {
        self.span.record("openshell.request.failure_reason", reason);
    }

    pub(super) fn observe_http(&mut self, event: &HttpActivityEvent) {
        if let Some(response) = &event.http_response {
            self.record_status(response.code);
        }
        if event.action == Some(ActionId::Denied) {
            if self.outcome != "failed" {
                self.record_outcome(HttpOutcome::Denied);
            }
        } else if self.outcome == "incomplete" {
            self.record_outcome(if event.base.status == Some(StatusId::Failure) {
                HttpOutcome::PlatformError
            } else {
                HttpOutcome::Allowed
            });
        }
    }
}

impl Drop for RequestTrace {
    fn drop(&mut self) {
        // Finalize exported timing after the request's child stages.
        self.span.in_scope(|| {
            self.span.record("openshell.request.outcome", self.outcome);
            if matches!(self.outcome, "failed" | "incomplete") {
                self.span.record("otel.status_code", "ERROR");
            }
        });
    }
}

fn normalized_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "CONNECT" => "CONNECT",
        "OPTIONS" => "OPTIONS",
        "TRACE" => "TRACE",
        "PATCH" => "PATCH",
        _ => "_OTHER",
    }
}

fn workload_link(raw_request: &[u8]) -> Option<SpanContext> {
    let end = raw_request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")?;
    let mut value = None;
    for line in raw_request[..end].split(|byte| *byte == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        if !line[..colon].eq_ignore_ascii_case(b"traceparent") {
            continue;
        }
        if value.is_some() {
            return None;
        }
        let candidate = std::str::from_utf8(&line[colon + 1..]).ok()?.trim();
        if candidate.len() > MAX_TRACEPARENT_BYTES {
            return None;
        }
        value = Some(candidate);
    }
    let context = TraceContextPropagator::new()
        .extract_with_context(&Context::new(), &OnlyTraceparent(value?));
    let span_context = context.span().span_context().clone();
    span_context.is_valid().then_some(span_context)
}

struct OnlyTraceparent<'a>(&'a str);

impl Extractor for OnlyTraceparent<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        (key == "traceparent").then_some(self.0)
    }

    fn keys(&self) -> Vec<&str> {
        vec!["traceparent"]
    }
}

#[cfg(test)]
mod tests;
