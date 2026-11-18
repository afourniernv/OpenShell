// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::{RelayOutcome, RelayResponseOptions, relay_response, tests::test_correlation};
use crate::l7::correlation::{HttpOutcome, RequestStage};
use crate::l7::relay::correlation_dispatch_tests::{TracedOperation, capture_request_spans};
use crate::l7::rest::tests::{
    ResponseRelayScript, response_middleware_context, response_middleware_fixture,
};
use crate::test_support::request_tracing::span_attribute;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    Write,
    WriteZero,
    Flush,
    Shutdown,
    Pending,
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
    failure: Option<Failure>,
}

impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.failure == Some(Failure::Pending) {
            return Poll::Pending;
        }
        if self.failure == Some(Failure::WriteZero) {
            return Poll::Ready(Ok(0));
        }
        let remaining = if self.failure == Some(Failure::Write) {
            8_usize.saturating_sub(self.bytes.len())
        } else {
            usize::MAX
        };
        if remaining == 0 {
            return Poll::Ready(Err(io::Error::other("write sentinel")));
        }
        let accepted = bytes.len().min(3).min(remaining);
        self.bytes.extend_from_slice(&bytes[..accepted]);
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(if self.failure == Some(Failure::Flush) {
            Err(io::Error::other("flush sentinel"))
        } else {
            Ok(())
        })
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(if self.failure == Some(Failure::Shutdown) {
            Err(io::Error::other("shutdown sentinel"))
        } else {
            Ok(())
        })
    }
}

async fn observe(
    mut upstream: &[u8],
    failure: Option<Failure>,
    requested_upgrade: bool,
) -> TracedOperation<(miette::Result<RelayOutcome>, Writer)> {
    capture_request_spans(true, async {
        let correlation = test_correlation("delivery-observation");
        let mut writer = Writer {
            failure,
            ..Default::default()
        };
        let result = Box::pin(correlation.run_stage(
            RequestStage::Response,
            HttpOutcome::UpstreamError,
            "response_failed",
            relay_response(
                "GET",
                &mut upstream,
                &mut writer,
                RelayResponseOptions {
                    client_requested_upgrade: requested_upgrade,
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                None,
            ),
        ))
        .await;
        (result, writer)
    })
    .await
}

#[tokio::test]
async fn delivery_observation_counts_partial_writes_and_requires_framing_completion() {
    for (bytes, upgrade, expected, error) in [
        (&b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..], false, "completed", false),
        (&b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"[..], false, "completed", false),
        (&b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody"[..], false, "completed", false),
        (&b"HTTP/1.1 204 No Content\r\n\r\n"[..], false, "completed", false),
        (&b"HTTP/1.1 200 OK\r\n\r\n"[..], false, "returned", false),
        (&b"HTTP/1.1 100 Continue\r\n\r\n"[..], false, "incomplete", false),
        (&b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbo"[..], false, "failed", true),
        (&b"HTTP/1.1 200"[..], false, "incomplete", false),
        (&b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: example\r\n\r\nnext"[..], false, "incomplete", false),
        (&b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: example\r\n\r\nnext"[..], true, "upgraded", false),
    ] {
        let evidence = observe(bytes, None, upgrade).await;
        assert_eq!(evidence.output.0.is_err(), error);
        if error {
            assert!(evidence.output.0.unwrap_err().to_string().contains("2 bytes remaining"));
        }
        let response = evidence.spans.iter().find(|span| span.name == "openshell.http.response").unwrap();
        assert_eq!(evidence.spans.iter().filter(|span| span.name == "openshell.http.response").count(), 1);
        assert_eq!(span_attribute(response, "openshell.response.delivery_outcome").unwrap().as_str(), expected);
        assert_eq!(span_attribute(response, "openshell.response.wire_bytes_written").unwrap().to_string(), evidence.output.1.bytes.len().to_string());
        assert!(span_attribute(response, "openshell.response.io_error_operation").is_none());
        assert!(evidence.events.is_empty(), "observation must not synthesize audit records");
    }
}

#[tokio::test]
async fn delivery_observation_middleware_replacement_does_not_claim_completion() {
    let evidence = capture_request_spans(true, async {
        let correlation = test_correlation("replacement-delivery");
        let (runner, chain) = response_middleware_fixture(ResponseRelayScript::WholeBody);
        let middleware = response_middleware_context(&runner, &chain, "GET");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nETag: stale\r\n\r\nhello"[..];
        let mut client = Vec::new();
        let outcome = Box::pin(correlation.run_stage(
            RequestStage::Response,
            HttpOutcome::UpstreamError,
            "response_failed",
            relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                Some(middleware),
            ),
        ))
        .await;
        (outcome, client)
    })
    .await;

    assert!(matches!(evidence.output.0.unwrap(), RelayOutcome::Reusable));
    let delivered = String::from_utf8(evidence.output.1).unwrap();
    assert!(delivered.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(delivered.contains("Content-Length: 11\r\n"));
    assert!(!delivered.to_ascii_lowercase().contains("etag:"));
    assert!(delivered.ends_with("\r\n\r\nwhole:hello"));
    let response = evidence
        .spans
        .iter()
        .find(|span| span.name == "openshell.http.response")
        .unwrap();
    assert_eq!(
        span_attribute(response, "openshell.response.delivery_outcome")
            .unwrap()
            .as_str(),
        "returned"
    );
    assert_eq!(
        span_attribute(response, "openshell.response.wire_bytes_written")
            .unwrap()
            .to_string(),
        delivered.len().to_string()
    );
}

#[tokio::test]
async fn delivery_observation_retains_downstream_error_operations_and_original_errors() {
    for (failure, operation, message) in [
        (Failure::Write, "write", "write sentinel"),
        (Failure::WriteZero, "write", "write"),
        (Failure::Flush, "flush", "flush sentinel"),
        (Failure::Shutdown, "shutdown", "shutdown sentinel"),
    ] {
        let evidence = observe(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody",
            Some(failure),
            false,
        )
        .await;
        assert!(evidence.output.0.unwrap_err().to_string().contains(message));
        let response = evidence
            .spans
            .iter()
            .find(|span| span.name == "openshell.http.response")
            .unwrap();
        assert_eq!(
            span_attribute(response, "openshell.response.delivery_outcome")
                .unwrap()
                .as_str(),
            "downstream_failed"
        );
        assert_eq!(
            span_attribute(response, "openshell.response.io_error_operation")
                .unwrap()
                .as_str(),
            operation
        );
        assert_eq!(
            span_attribute(response, "openshell.response.wire_bytes_written")
                .unwrap()
                .to_string(),
            evidence.output.1.bytes.len().to_string()
        );
        assert!(evidence.events.is_empty());
        assert!(!format!("{:?}", evidence.spans).contains("sentinel"));
    }
}

#[tokio::test]
async fn delivery_observation_cancellation_records_no_success_or_audit_record() {
    let evidence = capture_request_spans(true, async {
        let correlation = test_correlation("cancelled-delivery");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
        let mut writer = Writer {
            failure: Some(Failure::Pending),
            ..Default::default()
        };
        let mut response = Box::pin(correlation.run_stage(
            RequestStage::Response,
            HttpOutcome::UpstreamError,
            "response_failed",
            relay_response(
                "GET",
                &mut upstream,
                &mut writer,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                None,
            ),
        ));
        assert!(futures::poll!(&mut response).is_pending());
        drop(response);
        assert!(writer.bytes.is_empty());
    })
    .await;
    let response = evidence
        .spans
        .iter()
        .find(|span| span.name == "openshell.http.response")
        .unwrap();
    assert_eq!(
        span_attribute(response, "openshell.response.delivery_outcome")
            .unwrap()
            .as_str(),
        "cancelled"
    );
    assert!(matches!(
        response.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    assert!(evidence.events.is_empty());
}

#[tokio::test(start_paused = true)]
async fn delivery_observation_does_not_treat_close_delimited_idle_timeout_as_eof() {
    let evidence = capture_request_spans(true, async {
        let correlation = test_correlation("idle-delivery");
        let (mut upstream, mut peer) = tokio::io::duplex(1024);
        peer.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody")
            .await
            .unwrap();
        let mut client = Vec::new();
        let result = Box::pin(correlation.run_stage(
            RequestStage::Response,
            HttpOutcome::UpstreamError,
            "response_failed",
            relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                None,
            ),
        ))
        .await;
        assert!(matches!(result.unwrap(), RelayOutcome::Consumed));
        drop(peer);
    })
    .await;
    let response = evidence
        .spans
        .iter()
        .find(|span| span.name == "openshell.http.response")
        .unwrap();
    assert_eq!(
        span_attribute(response, "openshell.response.delivery_outcome")
            .unwrap()
            .as_str(),
        "incomplete"
    );
    assert!(evidence.events.is_empty());
}
