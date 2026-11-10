// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use openshell_ocsf::{ActivityId, NetworkActivityBuilder, Process};
use tokio::io::AsyncWriteExt as _;

fn request() -> L7Request {
    L7Request {
        action: "GET".into(),
        target: "/data".into(),
        query_params: std::collections::HashMap::new(),
        raw_header: b"GET /data HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
        body_length: crate::l7::provider::BodyLength::None,
    }
}

fn context() -> L7EvalContext {
    L7EvalContext {
        host: "example.test".into(),
        port: 443,
        policy_name: "protected-api".into(),
        ..Default::default()
    }
}

fn allowed() -> OcsfEvent {
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .http_request(HttpRequest::new("GET", context().ocsf_url("/data")))
        .actor_process(Process::new("curl", 42).with_cmd_line("curl /data"))
        .firewall_rule("protected-api", "l7")
        .action(ActionId::Allowed)
        .disposition(DispositionId::Allowed)
        .status(StatusId::Success)
        .message("HTTP request admitted by policy")
        .status_detail("matched_rule")
        .build()
}

fn denied() -> OcsfEvent {
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .http_request(HttpRequest {
            http_method: "GET".parse().unwrap(),
            url: None,
        })
        .http_response(HttpResponse { code: 403 })
        .firewall_rule("protected-api", "credential-binding")
        .action(ActionId::Denied)
        .disposition(DispositionId::Blocked)
        .status(StatusId::Failure)
        .severity(SeverityId::High)
        .message("Credential use denied")
        .status_detail("credential_endpoint_mismatch")
        .build()
}

fn http_events(capture: &openshell_ocsf::test_support::OcsfCapture) -> Vec<serde_json::Value> {
    capture
        .json_events()
        .into_iter()
        .filter(|event| event["class_uid"] == 4002)
        .collect()
}

#[test]
fn request_ids_are_unique_canonical_uuids() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let first = RequestCorrelation::new(&request(), &context());
    let second = RequestCorrelation::new(&request(), &context());
    assert_ne!(first.request_id(), second.request_id());
    assert!(uuid::Uuid::parse_str(first.request_id()).is_ok());
    assert!(uuid::Uuid::parse_str(second.request_id()).is_ok());
}

#[tokio::test]
async fn primary_record_waits_for_final_response_headers_and_is_emitted_once_without_otel() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(allowed());
    let mut output = Vec::new();
    {
        let mut client = correlation.observe_response(&mut output);
        client
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n")
            .await
            .unwrap();
        assert!(capture.events().is_empty());
        client.write_all(b"\r\nbody").await.unwrap();
    }
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["http_response"]["code"], 200);
    assert_eq!(events[0]["http_request"]["url"]["path"], "/data");
    assert_eq!(events[0]["action"], "Allowed");
    assert_eq!(events[0]["status"], "Success");
    assert_eq!(events[0]["actor"]["process"]["pid"], 42);
    assert_eq!(events[0]["metadata"]["correlation_uid"], id);
    assert!(events[0].get("trace").is_none());
    assert!(output.ends_with(b"\r\n\r\nbody"));
}

#[test]
fn later_credential_denial_preserves_policy_request_context() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(allowed());
    correlation.emit(denied());
    // A routine later middleware result cannot undo the denial.
    correlation.emit(allowed());
    correlation.response_selected(403);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["action"], "Denied");
    assert_eq!(event["disposition"], "Blocked");
    assert_eq!(event["status"], "Failure");
    assert_eq!(event["severity"], "High");
    assert_eq!(event["status_detail"], "credential_endpoint_mismatch");
    assert_eq!(event["http_response"]["code"], 403);
    assert_eq!(event["http_request"]["url"]["path"], "/data");
    assert_eq!(event["firewall_rule"]["type"], "l7");
    assert_eq!(event["actor"]["process"]["pid"], 42);
    assert_eq!(event["metadata"]["correlation_uid"], id);
}

#[test]
fn local_refusals_and_upstream_failures_are_distinct() {
    for (outcome, blocked, code, expected_action, expected_disposition) in [
        ("platform_error", true, 503, "Denied", "Blocked"),
        ("upstream_error", false, 502, "Allowed", "Allowed"),
        ("platform_error", false, 502, "Allowed", "Allowed"),
    ] {
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _subscriber = capture.install();
        let correlation = RequestCorrelation::new(&request(), &context());
        correlation.emit(allowed());
        correlation.record_enforcement_action(if blocked { "block" } else { "allow" });
        correlation.record_final_http_outcome(outcome);
        correlation.response_selected(code);
        drop(correlation);
        let events = http_events(&capture);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["action"], expected_action);
        assert_eq!(events[0]["disposition"], expected_disposition);
        assert_eq!(events[0]["status"], "Failure");
        assert_eq!(events[0]["http_response"]["code"], code);
    }
}

#[test]
fn remote_api_error_does_not_become_a_policy_denial() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    correlation.emit(allowed());
    correlation.record_final_http_outcome("allowed");
    correlation.response_selected(500);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "Allowed");
    assert_eq!(events[0]["status"], "Success");
    assert_eq!(events[0]["http_response"]["code"], 500);
}

#[test]
fn pre_policy_rejection_retains_reason_without_claiming_policy_admission() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(
        NetworkActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .activity(ActivityId::Other)
            .dst_endpoint(Endpoint::from_domain("example.test", 443))
            .action(ActionId::Denied)
            .disposition(DispositionId::Blocked)
            .status(StatusId::Failure)
            .severity(SeverityId::Medium)
            .status_detail("invalid_jsonrpc_request")
            .actor_process(Process::new("curl", 42))
            .build(),
    );
    correlation.record_enforcement_action("block");
    correlation.record_final_http_outcome("denied");
    correlation.response_selected(400);
    drop(correlation);
    assert_eq!(capture.events().len(), 2);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["http_request"]["url"]["path"], "/data");
    assert_eq!(events[0]["status_detail"], "invalid_jsonrpc_request");
    assert_eq!(
        events[0]["message"],
        "HTTP request rejected before policy evaluation"
    );
    assert_eq!(events[0]["action"], "Denied");
    assert_eq!(events[0]["actor"]["process"]["pid"], 42);
    assert!(events[0].get("firewall_rule").is_none());
    assert!(
        capture
            .json_events()
            .iter()
            .all(|event| event["metadata"]["correlation_uid"] == id)
    );
}

#[test]
fn late_failure_is_preserved_once_but_routine_late_records_are_not_duplicated() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(allowed());
    correlation.response_selected(200);
    correlation.emit(allowed());
    correlation.emit(denied());
    correlation.emit(denied());
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["action"], "Allowed");
    assert_eq!(events[0]["http_response"]["code"], 200);
    assert_eq!(events[1]["action"], "Denied");
    assert_eq!(events[1]["status_detail"], "credential_endpoint_mismatch");
    assert_eq!(events[1]["http_response"]["code"], 200);
    assert!(
        events
            .iter()
            .all(|event| event["metadata"]["correlation_uid"] == id)
    );
}

#[test]
fn unfinished_request_retains_safe_path_without_inventing_a_rule() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let mut request = request();
    request.target = "/data?secret=SENTINEL-QUERY".into();
    let id;
    {
        let correlation = RequestCorrelation::new(&request, &context());
        id = correlation.request_id().to_string();
        let mut head = ResponseHead::default();
        head.accept(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n", &correlation);
        assert!(capture.events().is_empty());
    }
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["metadata"]["correlation_uid"], id);
    assert_eq!(events[0]["status_detail"], "request_incomplete");
    assert_eq!(events[0]["http_request"]["url"]["path"], "/data");
    assert!(events[0].get("http_response").is_none());
    assert!(events[0].get("firewall_rule").is_none());
    assert!(!events[0].to_string().contains("SENTINEL-QUERY"));
}

#[test]
fn workload_traceparent_does_not_supply_audit_trace_identity() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let mut request = request();
    request.raw_header = b"GET /data HTTP/1.1\r\nHost: example.test\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\n".to_vec();
    let correlation = RequestCorrelation::new(&request, &context());
    correlation.emit(allowed());
    correlation.response_selected(200);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert!(events[0].get("trace").is_none());
    assert!(
        !events[0]
            .to_string()
            .contains("4bf92f3577b34da6a3ce929d0e0e4736")
    );
}

#[tokio::test]
async fn uninspected_response_and_events_preserve_legacy_behavior() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::uninspected();
    assert!(uuid::Uuid::parse_str(correlation.request_id()).is_ok());
    let mut output = Vec::new();
    {
        let mut client = correlation.observe_response(&mut output);
        client
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    }
    assert!(capture.events().is_empty());
    let expected = allowed();
    correlation.emit(expected.clone());
    drop(correlation);
    assert_eq!(capture.events(), vec![expected]);
    assert_eq!(output, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
}

#[test]
fn policy_classification_fills_an_existing_forward_request_context() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let seed = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .http_request(HttpRequest::new("GET", context().ocsf_url("/forward")))
        .actor_process(Process::new("python3", 77))
        .message("HTTP request awaiting inspection")
        .build();
    correlation.emit(seed);
    correlation.emit(allowed());
    correlation.response_selected(200);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["http_request"]["url"]["path"], "/forward");
    assert_eq!(events[0]["actor"]["process"]["pid"], 77);
    assert_eq!(events[0]["action"], "Allowed");
    assert_eq!(events[0]["status"], "Success");
    assert_eq!(events[0]["firewall_rule"]["type"], "l7");
    assert_eq!(events[0]["message"], "HTTP request admitted by policy");
}

#[test]
fn failure_reason_replaces_only_a_prior_success_reason() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    correlation.emit(allowed());
    correlation.record_enforcement_action("block");
    correlation.record_final_http_outcome("platform_error");
    correlation.record_failure_reason("middleware_admission");
    correlation.response_selected(503);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["status_detail"], "middleware_admission");
    assert_eq!(events[0]["action"], "Denied");
    assert_eq!(events[0]["status"], "Failure");
}

#[test]
fn unfinished_admitted_request_does_not_keep_a_success_reason() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(allowed());
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["action"], "Allowed");
    assert_eq!(events[0]["status"], "Failure");
    assert_eq!(events[0]["status_detail"], "request_incomplete");
    assert_eq!(events[0]["metadata"]["correlation_uid"], id);
    assert_eq!(events[0]["http_request"]["url"]["path"], "/data");
    assert_eq!(events[0]["actor"]["process"]["pid"], 42);
    assert!(events[0].get("http_response").is_none());
}

#[test]
fn late_fail_open_does_not_hide_a_later_blocking_failure() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    let id = correlation.request_id().to_string();
    correlation.emit(allowed());
    correlation.response_selected(200);
    correlation.emit(
        HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .http_request(HttpRequest::new("GET", context().ocsf_url("/data")))
            .action(ActionId::Other)
            .disposition(DispositionId::Allowed)
            .status(StatusId::Failure)
            .status_detail("middleware_fail_open")
            .build(),
    );
    correlation.emit(denied());
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["action"], "Denied");
    assert_eq!(events[1]["status_detail"], "credential_endpoint_mismatch");
    assert_eq!(events[1]["metadata"]["correlation_uid"], id);
    assert_eq!(events[1]["http_response"]["code"], 200);
}

#[test]
fn resource_revisions_keep_first_valid_identities_on_primary_and_late_records() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    correlation.record_policy_runtime_generation(u64::MAX);
    correlation.record_policy_runtime_generation(1);
    correlation.record_selected_policy_endpoint("SENTINEL-INVALID", "endpoint:v1:invalid");
    let hash = "a".repeat(64);
    let endpoint = format!("endpoint:v1:{}", "b".repeat(64));
    correlation.record_selected_policy_endpoint(&hash, &endpoint);
    let mut snapshot = openshell_core::provider_credentials::ProviderCredentialSnapshot {
        installation_id: "SENTINEL-INVALID".into(),
        revision: u64::MAX,
        child_env: std::collections::HashMap::from([("KEY".into(), "SENTINEL-SECRET".into())]),
        dynamic_credentials: std::collections::HashMap::new(),
    };
    correlation.record_provider_credential_snapshot(&snapshot);
    snapshot.installation_id = "00000000-0000-4000-8000-000000000041".into();
    correlation.record_provider_credential_snapshot(&snapshot);
    correlation.emit(allowed());
    correlation.response_selected(200);

    correlation.record_selected_policy_endpoint(&"c".repeat(64), &endpoint);
    snapshot.revision = 1;
    snapshot.installation_id = "00000000-0000-4000-8000-000000000042".into();
    correlation.record_provider_credential_snapshot(&snapshot);
    correlation.emit(denied());
    drop(correlation);

    let events = http_events(&capture);
    assert_eq!(events.len(), 2);
    for event in &events {
        assert_eq!(
            event["unmapped"]["policy_runtime_generation"],
            u64::MAX.to_string()
        );
        assert_eq!(
            event["unmapped"]["provider_environment_revision"],
            u64::MAX.to_string()
        );
        assert_eq!(event["unmapped"]["policy_hash"], hash);
        assert_eq!(event["unmapped"]["endpoint_id"], endpoint);
        assert_eq!(
            event["unmapped"]["provider_credential_installation_id"],
            "00000000-0000-4000-8000-000000000041"
        );
        assert!(event.get("trace").is_none());
    }
    assert!(!serde_json::to_string(&events).unwrap().contains("SENTINEL"));
    assert_eq!(events[0]["firewall_rule"]["type"], "l7");
}

#[test]
fn unknown_resource_identities_are_omitted() {
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let correlation = RequestCorrelation::new(&request(), &context());
    correlation.record_selected_policy_endpoint(&"A".repeat(64), &"endpoint:v1:".repeat(20));
    correlation.emit(allowed());
    correlation.response_selected(200);
    drop(correlation);
    let events = http_events(&capture);
    assert_eq!(events.len(), 1);
    assert!(events[0].get("unmapped").is_none());
}
