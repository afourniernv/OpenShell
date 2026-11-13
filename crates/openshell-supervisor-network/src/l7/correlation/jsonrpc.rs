// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::RequestCorrelation;
use crate::l7::{L7Protocol, jsonrpc};

#[derive(Debug, Default)]
pub(super) struct JsonRpcObservations {
    tools_call_observed: bool,
}

impl RequestCorrelation {
    pub(crate) fn record_jsonrpc_summary(
        &self,
        span: &tracing::Span,
        protocol: L7Protocol,
        info: &jsonrpc::JsonRpcRequestInfo,
    ) {
        let calls = info
            .calls
            .iter()
            .filter(|call| !call.is_notification)
            .count();
        let notifications = info.calls.len() - calls;
        let limit = 64;
        span.record(
            "openshell.l7.protocol",
            if protocol == L7Protocol::Mcp {
                "mcp"
            } else {
                "jsonrpc"
            },
        );
        span.record(
            "openshell.jsonrpc.effective.message_kind",
            message_kind(info, calls, notifications),
        );
        span.record(
            "openshell.jsonrpc.effective.inspection_outcome",
            inspection_outcome(info),
        );
        span.record(
            "openshell.jsonrpc.effective.call_count",
            i64::try_from(calls.min(limit)).expect("bounded call count"),
        );
        span.record(
            "openshell.jsonrpc.effective.notification_count",
            i64::try_from(notifications.min(limit)).expect("bounded notification count"),
        );
        span.record(
            "openshell.jsonrpc.effective.counts_truncated",
            calls > limit || notifications > limit,
        );
        span.record(
            "openshell.jsonrpc.effective.has_response",
            info.has_response,
        );
        if info.error.as_ref().is_some_and(|error| {
            error.kind() != jsonrpc::JsonRpcInspectionErrorKind::RevisionNotSelected
        }) {
            span.record("otel.status_code", "ERROR");
        }
        if protocol == L7Protocol::Mcp {
            let observed = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.jsonrpc.tools_call_observed |=
                    info.calls.iter().any(|call| call.method == "tools/call");
                state.jsonrpc.tools_call_observed
            };
            if let Some(revision) = info.mcp_revision {
                span.record(
                    "openshell.mcp.selected_protocol_revision",
                    revision.as_str(),
                );
                span.record(
                    "openshell.mcp.effective.protocol_revision",
                    revision.as_str(),
                );
            }
            span.record(
                "openshell.mcp.effective.method_classification",
                method_classification(info),
            );
            span.record("openshell.mcp.tools_call_observed", observed);
        }
    }
}

fn message_kind(
    info: &jsonrpc::JsonRpcRequestInfo,
    calls: usize,
    notifications: usize,
) -> &'static str {
    if info.error.is_some() {
        return "invalid";
    }
    if info.receive_stream {
        return "receive_stream";
    }
    if info.is_batch {
        return match (calls > 0, notifications > 0, info.has_response) {
            (true, false, false) => "batch_calls",
            (false, true, false) => "batch_notifications",
            (false, false, true) => "batch_responses",
            _ => "batch_mixed",
        };
    }
    match (calls > 0, notifications > 0, info.has_response) {
        (true, false, false) => "call",
        (false, true, false) => "notification",
        (false, false, true) => "response",
        (false, false, false) => "empty",
        _ => "mixed",
    }
}

fn inspection_outcome(info: &jsonrpc::JsonRpcRequestInfo) -> &'static str {
    match info
        .error
        .as_ref()
        .map(jsonrpc::JsonRpcInspectionError::kind)
    {
        None => "accepted",
        Some(jsonrpc::JsonRpcInspectionErrorKind::InvalidJson) => "invalid_json",
        Some(jsonrpc::JsonRpcInspectionErrorKind::InvalidMessage) => "invalid_message",
        Some(jsonrpc::JsonRpcInspectionErrorKind::RevisionNotSelected) => "revision_not_selected",
        Some(jsonrpc::JsonRpcInspectionErrorKind::McpProfileViolation) => "mcp_profile_violation",
        Some(jsonrpc::JsonRpcInspectionErrorKind::McpLifecycleViolation) => {
            "mcp_lifecycle_violation"
        }
    }
}

fn method_classification(info: &jsonrpc::JsonRpcRequestInfo) -> &'static str {
    let mut core = false;
    let mut extension = false;
    let mut unclassified = false;
    for call in &info.calls {
        match call.mcp_classification {
            Some(jsonrpc::McpMethodClassification::Available) => core = true,
            Some(jsonrpc::McpMethodClassification::Extension) => extension = true,
            None => unclassified = true,
        }
    }
    match (core, extension, unclassified) {
        (false, false, false) => "none",
        (true, false, false) => "core",
        (false, true, false) => "extension",
        (true, true, false) => "mixed",
        _ => "unclassified",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l7::correlation::RequestStage;
    use crate::l7::provider::{BodyLength, L7Request};
    use crate::l7::relay::L7EvalContext;
    use crate::test_support::request_tracing::RequestTracing;
    use opentelemetry_sdk::trace::Sampler;

    #[test]
    fn summaries_do_not_create_or_finish_inspection_spans() {
        let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
        tracing::subscriber::with_default(capture.subscriber(), || {
            let request = L7Request {
                action: "POST".into(),
                target: "/rpc".into(),
                query_params: std::collections::HashMap::new(),
                raw_header: b"POST /rpc HTTP/1.1\r\nHost: api.test\r\n\r\n".to_vec(),
                body_length: BodyLength::None,
            };
            let correlation = RequestCorrelation::new(&request, &L7EvalContext::default());
            let body = serde_json::Value::Array((0..75).map(|id| serde_json::json!({
                "jsonrpc": "2.0", "id": id, "method": "SENTINEL", "params": {"secret": "SENTINEL"}
            })).collect()).to_string();
            let info = jsonrpc::parse_jsonrpc_body(
                body.as_bytes(),
                jsonrpc::JsonRpcInspectionMode::JsonRpc,
            );
            for _ in 0..2 {
                let span = correlation.stage(RequestStage::McpInspect);
                let before = capture.spans().len();
                correlation.record_jsonrpc_summary(&span, L7Protocol::JsonRpc, &info);
                assert_eq!(
                    capture.spans().len(),
                    before,
                    "summary must not end the owned operation"
                );
                drop(span);
                assert_eq!(capture.spans().len(), before + 1);
            }
        });
        let spans = capture.spans();
        let root = spans
            .iter()
            .find(|span| span.name == "openshell.http.request")
            .unwrap();
        let stages: Vec<_> = spans
            .iter()
            .filter(|span| span.name == "openshell.mcp.inspect")
            .collect();
        assert_eq!(stages.len(), 2);
        for stage in stages {
            assert_eq!(stage.parent_span_id, root.span_context.span_id());
            assert!(stage.end_time <= root.end_time);
            for (key, value) in [
                ("openshell.jsonrpc.effective.call_count", "64"),
                ("openshell.jsonrpc.effective.counts_truncated", "true"),
            ] {
                assert!(
                    stage
                        .attributes
                        .iter()
                        .any(|field| field.key.as_str() == key && field.value.as_str() == value)
                );
            }
        }
        assert!(!format!("{spans:?}").contains("SENTINEL"));
        capture.shutdown();
    }
}
