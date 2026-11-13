// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::l7::relay::L7EvalContext;
use crate::test_support::request_tracing::RequestTracing;
use opentelemetry_sdk::trace::Sampler;
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::instrument::WithSubscriber as _;

fn correlation() -> RequestCorrelation {
    correlation_for_method("GET")
}

fn correlation_for_method(method: &str) -> RequestCorrelation {
    let context = L7EvalContext {
        host: "api.example.test".into(),
        port: 443,
        policy_name: "protected-api".into(),
        ..Default::default()
    };
    let request = L7Request {
        action: method.into(),
        target: "/report".into(),
        query_params: HashMap::new(),
        raw_header: format!("{method} /report HTTP/1.1\r\nHost: api.example.test\r\n\r\n")
            .into_bytes(),
        body_length: BodyLength::None,
    };
    let correlation = RequestCorrelation::new(&request, &context);
    correlation.record_selected_policy_endpoint(
        &"a".repeat(64),
        &format!("endpoint:v1:{}", "b".repeat(64)),
    );
    correlation.emit(
        openshell_ocsf::HttpActivityBuilder::new(ocsf_ctx())
            .http_request(openshell_ocsf::HttpRequest::new(
                method,
                context.ocsf_url("/report"),
            ))
            .dst_endpoint(openshell_ocsf::Endpoint::from_domain(
                &context.host,
                context.port,
            ))
            .firewall_rule(&context.policy_name, "l7")
            .action(openshell_ocsf::ActionId::Allowed)
            .status(openshell_ocsf::StatusId::Success)
            .build(),
    );
    correlation
}

fn assert_records(capture: &RequestTracing, code: Option<u16>, terminal: usize, delivery: &str) {
    let events = capture.events.json_events();
    let primary: Vec<_> = events
        .iter()
        .filter(|event| event["class_uid"] == 4002 && event["firewall_rule"]["type"] == "l7")
        .collect();
    let late: Vec<_> = events
        .iter()
        .filter(|event| event["firewall_rule"]["type"] == "response-correlation")
        .collect();
    assert_eq!(primary.len(), 1, "{events:?}");
    assert_eq!(late.len(), terminal, "{events:?}");
    assert_eq!(
        primary[0]["http_response"]["code"].as_u64(),
        code.map(u64::from)
    );
    for event in &late {
        assert_eq!(event["http_response"]["code"].as_u64(), code.map(u64::from));
        assert_eq!(
            event["metadata"]["correlation_uid"],
            primary[0]["metadata"]["correlation_uid"]
        );
        assert_eq!(event["unmapped"]["policy_hash"], "a".repeat(64));
        assert_eq!(event["action"], "Observed");
        assert_eq!(event["unmapped"]["response_delivery_outcome"], delivery);
    }
    assert!(
        !capture
            .created_span_names()
            .contains(&"supervisor.egress.deny")
    );
    let spans = capture.spans();
    if !spans.is_empty() {
        let root = spans
            .iter()
            .find(|span| span.name == "openshell.http.request")
            .unwrap();
        let responses: Vec<_> = spans
            .iter()
            .filter(|span| span.name == "openshell.http.response")
            .collect();
        assert_eq!(responses.len(), 1, "{spans:?}");
        assert_eq!(responses[0].parent_span_id, root.span_context.span_id());
        assert!(
            responses[0].end_time <= root.end_time,
            "response {:?}..{:?}, root {:?}..{:?}, delivery={delivery}",
            responses[0].start_time,
            responses[0].end_time,
            root.start_time,
            root.end_time
        );
        assert!(
            responses[0]
                .attributes
                .iter()
                .any(
                    |field| field.key.as_str() == "openshell.response.delivery_outcome"
                        && field.value.as_str() == delivery
                )
        );
    }
    assert!(!format!("{events:?}{spans:?}").contains("SENTINEL_PRIVATE_ERROR"));
}

#[tokio::test]
async fn primary_headers_and_terminal_delivery_are_independent_of_export() {
    for sampler in [None, Some(Sampler::AlwaysOff), Some(Sampler::AlwaysOn)] {
        for (wire, code, terminal, delivery) in [
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".as_slice(),
                Some(200),
                0,
                "complete",
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhe".as_slice(),
                Some(200),
                1,
                "cancelled_or_incomplete",
            ),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n".as_slice(),
                Some(200),
                1,
                "cancelled_or_incomplete",
            ),
            (
                b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"
                    .as_slice(),
                Some(204),
                0,
                "complete",
            ),
            (
                b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n".as_slice(),
                None,
                0,
                "cancelled_or_incomplete",
            ),
        ] {
            let capture = RequestTracing::new(sampler.clone());
            async {
                let correlation = correlation();
                if sampler.is_none() {
                    correlation.finish_http_trace();
                }
                let mut output = Vec::new();
                let mut upstream = wire;
                let mut client = correlation.observe_response(&mut output);
                let _ = relay_response(
                    "GET",
                    &mut upstream,
                    &mut client,
                    RelayResponseOptions {
                        correlation: Some(&correlation),
                        ..Default::default()
                    },
                    None,
                )
                .await;
            }
            .with_subscriber(capture.subscriber())
            .await;
            assert_records(&capture, code, terminal, delivery);
            if wire.starts_with(b"HTTP/1.1 103") {
                let spans = capture.spans();
                if let Some(response) = spans
                    .iter()
                    .find(|span| span.name == "openshell.http.response")
                {
                    assert!(
                        response.attributes.iter().any(|field| field.key.as_str()
                            == "openshell.response.interim_bytes_forwarded"
                            && field.value.as_str() == "40"),
                        "{response:?}"
                    );
                    assert!(response.attributes.iter().any(|field| field.key.as_str()
                        == "openshell.response.delivery_started"
                        && field.value.as_str() == if code.is_some() { "true" } else { "false" }));
                }
            }
            capture.shutdown();
        }
    }
}

#[tokio::test]
async fn terminal_audit_methods_preserve_standard_and_bound_custom_values() {
    for (method, expected) in [("GET", "GET"), ("POST", "POST"), ("PROPFIND", "OTHER")] {
        let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
        async {
            let correlation = correlation_for_method(method);
            let mut upstream = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi".as_slice();
            let mut output = Vec::new();
            let mut client = correlation.observe_response(&mut output);
            relay_response(
                method,
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                None,
            )
            .await
            .expect_err("truncated body produces a terminal record");
        }
        .with_subscriber(capture.subscriber())
        .await;
        assert_records(&capture, Some(200), 1, "cancelled_or_incomplete");
        let events = capture.events.json_events();
        let terminal = events
            .iter()
            .find(|event| event["firewall_rule"]["type"] == "response-correlation")
            .unwrap();
        assert_eq!(terminal["http_request"]["http_method"], expected);
        capture.shutdown();
    }
}

#[derive(Clone, Copy)]
enum SinkFailure {
    None,
    WriteAfter(usize),
    ZeroAfter(usize),
    Flush,
    Shutdown,
}

struct Sink {
    bytes: Vec<u8>,
    failure: SinkFailure,
}

impl AsyncWrite for Sink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let limit = match this.failure {
            SinkFailure::WriteAfter(limit) | SinkFailure::ZeroAfter(limit) => limit,
            _ => usize::MAX,
        };
        if !bytes.is_empty() && this.bytes.len() >= limit {
            return Poll::Ready(if matches!(this.failure, SinkFailure::ZeroAfter(_)) {
                Ok(0)
            } else {
                Err(std::io::Error::other("SENTINEL_PRIVATE_ERROR"))
            });
        }
        let accepted = bytes
            .len()
            .min(3)
            .min(limit.saturating_sub(this.bytes.len()));
        this.bytes.extend_from_slice(&bytes[..accepted]);
        Poll::Ready(Ok(accepted))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(if matches!(self.failure, SinkFailure::Flush) {
            Err(std::io::Error::other("SENTINEL_PRIVATE_ERROR"))
        } else {
            Ok(())
        })
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(if matches!(self.failure, SinkFailure::Shutdown) {
            Err(std::io::Error::other("SENTINEL_PRIVATE_ERROR"))
        } else {
            Ok(())
        })
    }
}

#[tokio::test]
async fn partial_writes_zero_flush_and_shutdown_keep_accepted_status() {
    for failure in [
        SinkFailure::None,
        SinkFailure::WriteAfter(0),
        SinkFailure::ZeroAfter(0),
        SinkFailure::WriteAfter(8),
        SinkFailure::ZeroAfter(8),
        SinkFailure::WriteAfter(usize::MAX),
        SinkFailure::Flush,
        SinkFailure::Shutdown,
    ] {
        let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
        let (code, late, delivery) = async {
            let correlation = correlation();
            let header = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n";
            let failure = if matches!(failure, SinkFailure::WriteAfter(usize::MAX)) {
                SinkFailure::WriteAfter(final_response_head(header, Some(&correlation)).len() + 2)
            } else {
                failure
            };
            let before_head = matches!(
                failure,
                SinkFailure::WriteAfter(0 | 8) | SinkFailure::ZeroAfter(0 | 8)
            );
            let failed = !matches!(failure, SinkFailure::None);
            let mut sink = Sink {
                bytes: Vec::new(),
                failure,
            };
            let mut client = correlation.observe_response(&mut sink);
            let wire = [header.as_slice(), b"hello"].concat();
            let mut upstream = wire.as_slice();
            let result = relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                None,
            )
            .await;
            assert_eq!(result.is_err(), failed);
            (
                if before_head { None } else { Some(200) },
                usize::from(failed && !before_head),
                if failed {
                    "downstream_io_error"
                } else {
                    "complete"
                },
            )
        }
        .with_subscriber(capture.subscriber())
        .await;
        assert_records(&capture, code, late, delivery);
        capture.shutdown();
    }
}

struct PendingRead {
    prefix: &'static [u8],
    pending: std::sync::Arc<tokio::sync::Notify>,
}

impl AsyncRead for PendingRead {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.prefix.is_empty() {
            self.pending.notify_one();
            Poll::Pending
        } else {
            Pin::new(&mut self.prefix).poll_read(cx, buf)
        }
    }
}

#[tokio::test]
async fn cancelling_after_headers_closes_the_owned_stage_and_records_one_terminal() {
    let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
    async {
        let correlation = correlation();
        let pending = std::sync::Arc::new(tokio::sync::Notify::new());
        let mut upstream = PendingRead { prefix: b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi", pending: pending.clone() };
        let mut output = Vec::new();
        let mut client = correlation.observe_response(&mut output);
        let mut relay = Box::pin(relay_response("GET", &mut upstream, &mut client, RelayResponseOptions { correlation: Some(&correlation), ..Default::default() }, None));
        tokio::select! { () = pending.notified() => {}, result = &mut relay => panic!("response should be waiting for body: {result:?}") }
        drop(relay);
    }.with_subscriber(capture.subscriber()).await;
    assert_records(&capture, Some(200), 1, "cancelled_or_incomplete");
    capture.shutdown();
}

#[tokio::test(start_paused = true)]
async fn close_delimited_idle_cutoff_is_not_reported_as_complete() {
    let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
    async {
        let correlation = correlation();
        let mut upstream = PendingRead {
            prefix: b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello",
            pending: std::sync::Arc::new(tokio::sync::Notify::new()),
        };
        let mut output = Vec::new();
        let mut client = correlation.observe_response(&mut output);
        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .unwrap();
    }
    .with_subscriber(capture.subscriber())
    .await;
    assert_records(&capture, Some(200), 1, "cancelled_or_incomplete");
    assert!(
        capture
            .events
            .json_events()
            .iter()
            .any(|event| event["unmapped"]["response_selection_cause"] == "upstream_idle_timeout")
    );
    capture.shutdown();
}

#[tokio::test]
async fn reload_interrupts_fixed_and_chunk_payload_reads_without_more_delivery() {
    let policy = include_str!("../../../../data/sandbox-policy.rego");
    for prefix in [
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nhi".as_slice(),
    ] {
        let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
        async {
            let correlation = correlation();
            let engine = crate::opa::OpaEngine::from_strings(policy, "network_policies: {}\n").unwrap();
            let guard = engine.generation_guard(engine.current_generation()).unwrap();
            let runner = openshell_supervisor_middleware::ChainRunner::default();
            let middleware = HttpResponseMiddlewareRelay {
                chain: &[], runner: &runner, request_context: RequestContext::default(), target: HttpRequestTarget::default(), policy_name: "protected-api", generation_guard: Some(&guard), whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT, client_accepts_chunked: true, request_head: None,
            };
            let pending = std::sync::Arc::new(tokio::sync::Notify::new());
            let mut upstream = PendingRead { prefix, pending: pending.clone() };
            let mut output = Vec::new();
            let mut client = correlation.observe_response(&mut output);
            let mut relay = Box::pin(relay_response("GET", &mut upstream, &mut client, RelayResponseOptions { correlation: Some(&correlation), ..Default::default() }, Some(middleware)));
            tokio::select! { () = pending.notified() => {}, result = &mut relay => panic!("response should await body: {result:?}") }
            engine.reload(policy, "network_policies: {}\n").unwrap();
            assert!(tokio::time::timeout(std::time::Duration::from_secs(1), relay).await.expect("reload wakes pending read").is_err());
        }.with_subscriber(capture.subscriber()).await;
        assert_records(&capture, Some(200), 1, "cancelled_or_incomplete");
        assert!(
            capture
                .events
                .json_events()
                .iter()
                .any(|event| event["unmapped"]["response_selection_cause"] == "policy_reloaded")
        );
        capture.shutdown();
    }
}

#[test]
fn response_stage_closes_under_its_own_subscriber() {
    let capture = RequestTracing::new(Some(Sampler::AlwaysOn));
    let dispatch = tracing::Dispatch::new(capture.subscriber());
    let correlation = tracing::dispatcher::with_default(&dispatch, correlation);
    let delivery =
        tracing::dispatcher::with_default(&dispatch, || ResponseDelivery::new(Some(&correlation)));
    drop(delivery);
    drop(correlation);
    let spans = capture.spans();
    assert_eq!(
        spans
            .iter()
            .filter(|span| span.name == "openshell.http.response")
            .count(),
        1
    );
    assert_eq!(
        spans
            .iter()
            .filter(|span| span.name == "openshell.http.request")
            .count(),
        1
    );
    capture.shutdown();
}
