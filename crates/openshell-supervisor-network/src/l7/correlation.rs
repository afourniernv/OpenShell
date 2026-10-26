// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-request correlation for HTTP enforcement events.

use std::sync::atomic::{AtomicBool, Ordering};

use http::{HeaderMap, HeaderValue};
use openshell_ocsf::{OcsfEvent, ocsf_emit};

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;

#[derive(Debug)]
pub struct RequestCorrelation {
    request_id: String,
    span: tracing::Span,
    completed: AtomicBool,
}

impl RequestCorrelation {
    #[must_use]
    pub(crate) fn new(request: &L7Request, ctx: &L7EvalContext) -> Self {
        Self::build(request, ctx, uuid::Uuid::new_v4().to_string())
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
        let method = bounded_http_method(&request.action);
        let span = tracing::info_span!(
            "openshell.http.enforcement",
            "openshell.request.id" = %request_id,
            "http.request.method" = method,
            "server.address" = %ctx.host,
            "server.port" = ctx.port,
            "openshell.target.reached" = false,
            "openshell.policy.decision" = tracing::field::Empty,
            "openshell.enforcement.action" = tracing::field::Empty,
            "openshell.http.outcome" = tracing::field::Empty,
            "http.response.status_code" = tracing::field::Empty,
            "openshell.error.stage" = tracing::field::Empty,
        );
        let headers = trace_headers(&request.raw_header);
        let _ = openshell_otel::set_parent_from_headers(&span, &headers);
        Self {
            request_id,
            span,
            completed: AtomicBool::new(false),
        }
    }

    #[must_use]
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(crate) fn record_policy_decision(&self, decision: &str) {
        self.span.record("openshell.policy.decision", decision);
    }

    pub(crate) fn record_enforcement_action(&self, action: &str) {
        self.span.record("openshell.enforcement.action", action);
    }

    pub(crate) fn record_final_http_outcome(&self, outcome: &str) {
        self.span.record("openshell.http.outcome", outcome);
        self.completed.store(true, Ordering::Release);
    }

    pub(crate) fn record_response_status(&self, status: u16) {
        self.span.record("http.response.status_code", status);
    }

    pub(crate) fn record_target_reached(&self) {
        self.span.record("openshell.target.reached", true);
    }

    pub(crate) fn record_error_stage(&self, stage: &str) {
        self.span.record("openshell.error.stage", stage);
    }

    pub(crate) fn emit(&self, mut event: OcsfEvent) {
        event.set_correlation_uid(self.request_id.clone());
        openshell_otel::with_span_context(&self.span, || {
            self.span.in_scope(|| ocsf_emit!(event));
        });
    }
}

fn bounded_http_method(method: &str) -> &'static str {
    [
        "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE",
    ]
    .into_iter()
    .find(|known| method.eq_ignore_ascii_case(known))
    .unwrap_or("OTHER")
}

impl Drop for RequestCorrelation {
    fn drop(&mut self) {
        if !self.completed.load(Ordering::Acquire) {
            self.span.record("openshell.http.outcome", "incomplete");
            self.span.record("openshell.error.stage", "unclassified");
        }
    }
}

fn trace_headers(raw_header: &[u8]) -> HeaderMap {
    let Some(header_end) = raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 2)
    else {
        return HeaderMap::new();
    };

    let mut headers = HeaderMap::new();
    for line in raw_header[..header_end]
        .split(|byte| *byte == b'\n')
        .skip(1)
    {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = trim_optional_whitespace(&line[..separator]);
        if !name.eq_ignore_ascii_case(b"traceparent") {
            continue;
        }
        let Ok(name) = http::HeaderName::from_bytes(name) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(trim_optional_whitespace(&line[separator + 1..]))
        else {
            continue;
        };
        if value.to_str().is_err() {
            continue;
        }
        headers.append(name, value);
    }
    headers
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> L7Request {
        L7Request {
            action: "GET".into(),
            target: "/data".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /data HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
            body_length: crate::l7::provider::BodyLength::None,
        }
    }

    #[test]
    fn request_ids_are_unique_canonical_uuids() {
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };
        let first = RequestCorrelation::new(&request(), &ctx);
        let second = RequestCorrelation::new(&request(), &ctx);

        assert_ne!(first.request_id(), second.request_id());
        assert!(uuid::Uuid::parse_str(first.request_id()).is_ok());
        assert!(uuid::Uuid::parse_str(second.request_id()).is_ok());
    }

    #[test]
    fn extracts_only_traceparent_and_preserves_duplicates() {
        let headers = trace_headers(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-OpenShell-Request-ID: forged\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nTraceParent: 00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01\r\ntracestate: vendor=value\r\n\r\n",
        );
        assert_eq!(headers.get_all("traceparent").iter().count(), 2);
        assert!(headers.get("tracestate").is_none());
        assert!(headers.get("x-openshell-request-id").is_none());
    }

    #[test]
    fn unrelated_obs_text_does_not_discard_valid_trace_context() {
        let headers = trace_headers(
            b"GET / HTTP/1.1\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nx-observation-note: contains traceparent: but is not a field\r\n\r\n",
        );

        assert_eq!(headers.get_all("traceparent").iter().count(), 1);
    }

    #[test]
    fn non_ascii_traceparent_is_rejected_and_tracestate_is_ignored() {
        let headers = trace_headers(
            b"GET / HTTP/1.1\r\ntraceparent: \xff\r\ntracestate: vendor=value\r\n\r\n",
        );

        assert!(headers.get("traceparent").is_none());
        assert!(headers.get("tracestate").is_none());
    }

    #[test]
    fn records_only_bounded_enforcement_outcome_fields() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };

        tracing::subscriber::with_default(subscriber, || {
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &ctx,
                "00000000-0000-4000-8000-000000000001".into(),
            );
            correlation.record_policy_decision("deny");
            correlation.record_enforcement_action("block");
            correlation.record_final_http_outcome("denied");
            correlation.record_response_status(403);
            correlation.record_error_stage("policy");
            correlation.record_target_reached();
        });

        let span = exporter
            .get_finished_spans()
            .unwrap()
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .unwrap();
        let attributes = span
            .attributes
            .into_iter()
            .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(attributes["openshell.policy.decision"], "deny");
        assert_eq!(attributes["openshell.enforcement.action"], "block");
        assert_eq!(attributes["openshell.http.outcome"], "denied");
        assert_eq!(attributes["http.response.status_code"], "403");
        assert_eq!(attributes["openshell.error.stage"], "policy");
        assert_eq!(attributes["openshell.target.reached"], "true");
    }

    #[test]
    fn custom_method_is_bounded_in_telemetry() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };
        let mut custom = request();
        custom.action = "SENTINEL-UNTRUSTED-METHOD".into();

        tracing::subscriber::with_default(subscriber, || {
            let correlation = RequestCorrelation::with_request_id(
                &custom,
                &ctx,
                "00000000-0000-4000-8000-000000000002".into(),
            );
            correlation.record_final_http_outcome("denied");
        });

        let span = exporter
            .get_finished_spans()
            .unwrap()
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .unwrap();
        let method = span
            .attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == "http.request.method")
            .expect("method attribute");
        assert_eq!(method.value.to_string(), "OTHER");
    }

    #[test]
    fn unfinished_request_is_recorded_as_incomplete() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };

        tracing::subscriber::with_default(subscriber, || {
            let _correlation = RequestCorrelation::with_request_id(
                &request(),
                &ctx,
                "00000000-0000-4000-8000-000000000002".into(),
            );
        });

        let span = exporter
            .get_finished_spans()
            .unwrap()
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .unwrap();
        let attributes = span
            .attributes
            .into_iter()
            .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(attributes["openshell.http.outcome"], "incomplete");
        assert_eq!(attributes["openshell.error.stage"], "unclassified");
    }

    #[test]
    fn malformed_or_incomplete_header_block_has_no_trace_context() {
        assert!(trace_headers(b"GET / HTTP/1.1\r\ntraceparent: value").is_empty());
        assert!(trace_headers(&[0xff, b'\r', b'\n', b'\r', b'\n']).is_empty());
    }
}
