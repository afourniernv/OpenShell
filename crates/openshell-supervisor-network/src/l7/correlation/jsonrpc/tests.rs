// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::correlation::{HttpOutcome, RequestCorrelation, scope_connection};
use crate::l7::jsonrpc::parse_jsonrpc_body_with_options;
use crate::l7::relay::L7EvalContext;
use crate::test_support::request_tracing::{RequestTracing, span_attribute};
use opentelemetry_sdk::trace::Sampler;
use tracing::instrument::WithSubscriber as _;

#[tokio::test]
async fn inspection_metadata_is_bounded_and_does_not_expose_parser_input() {
    let _lock = openshell_otel_test_support::tracing_test_lock().await;
    let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
    let options = JsonRpcInspectionMode::JsonRpc.into();
    let mut messages = (0..70)
        .map(|id| {
            let mut message = serde_json::json!({
                "jsonrpc": "2.0", "method": "DO-NOT-RECORD-METHOD",
                "params": { "secret": "DO-NOT-RECORD-PAYLOAD" }
            });
            if id % 2 == 0 {
                message["id"] = id.into();
            }
            message
        })
        .collect::<Vec<_>>();
    messages.push(serde_json::json!({"jsonrpc":"2.0", "id":123, "result":"DO-NOT-RECORD-RESULT"}));
    let body = serde_json::to_vec(&messages).unwrap();
    scope_connection(async {
        let correlation = RequestCorrelation::new_http(
            "POST",
            b"POST /rpc HTTP/1.1\r\nHost: example.test\r\n\r\n",
            &L7EvalContext::default(),
        );
        let info = parse_jsonrpc_body_with_options(&body, options);
        assert_eq!(info.calls.len(), 70);
        assert_eq!(info.calls[0].method, "DO-NOT-RECORD-METHOD");
        assert!(info.has_response);
        let malformed = parse_jsonrpc_body_with_options(
            br#"{"DO-NOT-RECORD-KEY":1,"DO-NOT-RECORD-KEY":2}"#,
            options,
        );
        assert_eq!(
            malformed.error.as_ref().unwrap().kind(),
            JsonRpcInspectionErrorKind::InvalidJson
        );
        correlation.record_outcome(HttpOutcome::Allowed);
    })
    .with_subscriber(capture.subscriber())
    .await;

    // The public parser is also used without an inspected request.
    tracing::subscriber::with_default(capture.subscriber(), || {
        assert_eq!(
            parse_jsonrpc_body_with_options(&body, options).calls.len(),
            70
        );
    });
    let spans = capture.spans();
    let inspections = spans
        .iter()
        .filter(|span| span.name == "openshell.mcp.inspect")
        .collect::<Vec<_>>();
    assert_eq!(inspections.len(), 2);
    let batch = inspections
        .iter()
        .find(|span| {
            span_attribute(span, "openshell.mcp.inspection.shape")
                .is_some_and(|value| value.as_str() == "batch")
        })
        .unwrap();
    for (key, value) in [
        ("openshell.mcp.request_count", 32_i64),
        ("openshell.mcp.notification_count", 32_i64),
    ] {
        assert_eq!(
            span_attribute(batch, key),
            Some(&opentelemetry::Value::I64(value))
        );
    }
    assert_eq!(
        span_attribute(batch, "openshell.mcp.has_response"),
        Some(&opentelemetry::Value::Bool(true))
    );
    assert_eq!(
        span_attribute(batch, "openshell.mcp.counts_truncated"),
        Some(&opentelemetry::Value::Bool(true))
    );
    let rejected = inspections
        .iter()
        .find(|span| {
            span_attribute(span, "openshell.mcp.inspection.outcome")
                .is_some_and(|value| value.as_str() == "rejected")
        })
        .unwrap();
    assert_eq!(
        span_attribute(rejected, "openshell.mcp.inspection.failure_kind")
            .unwrap()
            .as_str(),
        "invalid_json"
    );
    assert!(matches!(
        rejected.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    assert!(!format!("{spans:?}").contains("DO-NOT-RECORD"));
    assert!(capture.events.json_events().is_empty());
    capture.shutdown();
}
