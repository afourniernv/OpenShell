// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_supervisor_middleware::{
    HttpResponseInvocation, HttpResponseInvocationOutcome as Outcome, NamespacedFinding,
};

fn invocation(outcome: Outcome, failed: bool) -> HttpResponseInvocation {
    HttpResponseInvocation {
        config_name: "guard".to_string(),
        implementation: "test/guard".to_string(),
        outcome,
        sequence: None,
        input_size: 0,
        output_size: None,
        failed,
        transformed: false,
        stage_disabled: false,
        reason_code: None,
        failure_category: None,
    }
}

fn finding() -> NamespacedFinding {
    NamespacedFinding {
        middleware: "guard".to_string(),
        finding: openshell_core::proto::Finding {
            r#type: "test.finding".to_string(),
            label: "Test finding".to_string(),
            count: 1,
            severity: "high".to_string(),
            ..Default::default()
        },
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_terminal_failure_without_diagnostics_has_no_deny_trace() {
    use crate::telemetry::tests::{assert_no_deny, exported};

    // Platform refusals can lack invocation diagnostics, but must retain
    // their terminal failure record. Without an HTTP record, no deny span.
    for committed in [false, true] {
        let (events, received) = exported("warn", || {
            super::emit_http_response_middleware_failure(
                "response-policy",
                &HttpRequestTarget::default(),
                200,
                committed,
                None,
            );
        })
        .await;

        assert_eq!(events.len(), 1, "only the terminal failure is emitted");
        assert_eq!(
            events[0]["finding_info"]["uid"],
            "openshell.middleware.http_response_failure"
        );
        assert_no_deny(&events, &received);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_diagnostic_findings_share_a_deny_span_only_when_delivery_is_denied() {
    use crate::telemetry::tests::{assert_deny_resolves, assert_no_deny, exported};

    for denied in [false, true] {
        let (events, received) = exported("warn", || {
            let outcome = if denied {
                Outcome::BlockDelivery
            } else {
                Outcome::PassThrough
            };
            let diagnostics = openshell_supervisor_middleware::HttpResponseDiagnostics {
                invocations: vec![invocation(outcome, false)],
                findings: vec![finding()],
                ..Default::default()
            };
            super::emit_http_response_diagnostics(
                "response-policy",
                &HttpRequestTarget::default(),
                200,
                &diagnostics,
                denied,
                None,
                None,
            );
        })
        .await;
        // A blocking invocation adds its own block finding.
        assert_eq!(events.len(), if denied { 3 } else { 2 });
        if denied {
            let blocked = events
                .iter()
                .find(|event| {
                    event["finding_info"]["uid"] == "openshell.middleware.http_response_blocked"
                })
                .expect("blocked delivery emits its refusal finding");
            assert_eq!(blocked["action_id"], 2);
            assert_eq!(blocked["action"], "Denied");
            assert_eq!(received.spans.len(), 1);
            assert_deny_resolves(&events, &received, true);
        } else {
            assert_no_deny(&events, &received);
        }
    }
}

#[test]
fn fail_closed_invocations_and_enforced_failures_record_the_denial() {
    let target = HttpRequestTarget::default();
    for (outcome, failed, action_id) in [
        (Outcome::BlockDelivery, false, 2),
        (Outcome::FailClosed, true, 2),
        (Outcome::FailOpen, true, 99),
        (Outcome::PassThrough, false, 1),
    ] {
        let events = super::http_response_middleware_invocation_events(
            "p",
            &target,
            200,
            &[invocation(outcome, failed)],
        );
        assert_eq!(
            events[0].to_json().unwrap()["action_id"],
            action_id,
            "{outcome:?}"
        );
    }
    for denied in [false, true] {
        let failure =
            super::http_response_middleware_failure_event("p", &target, 200, false, denied)
                .to_json()
                .unwrap();
        assert_eq!(failure["action_id"] == 2, denied);
    }
}

use super::{
    DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT, HttpResponseMiddlewareRelay, RelayResponseOptions,
    ResponseFraming, WebSocketResponseValidation, http_response_diagnostic_truncation_event,
    parse_connection_keep_alive, parse_response_head_for_middleware, relay_response,
    response_is_http_10, response_middleware_failure_denial, response_middleware_observation,
    serialize_response_head, validate_http_response_header_block,
};
use crate::l7::correlation::MiddlewareObservation;
use crate::l7::provider::{BodyLength, L7Request, RelayOutcome};
use crate::l7::relay::L7EvalContext;
use openshell_core::proto::{
    Decision, ExistingHeaderAction, HeaderMutation, HttpHeader, HttpRequestResult,
    HttpRequestTarget, HttpResponseBlockDelivery, HttpResponseBodyMode, HttpResponseBodyResult,
    HttpResponseBodySkipRemaining, HttpResponseBodyTransform, HttpResponseEvent,
    HttpResponseEventResult, HttpResponsePreflightInspect, HttpResponsePreflightResult,
    HttpResponseTrailersResult, MiddlewareBinding, MiddlewareManifest, RequestContext,
    SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, WriteHeader, header_mutation,
    http_response_body_result, http_response_body_skip_remaining, http_response_body_transform,
    http_response_body_unit, http_response_event, http_response_event_result,
    http_response_preflight_result,
};
use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};
use tokio_stream::wrappers::ReceiverStream;

struct StreamingResponseMiddleware {
    body_mode: i32,
    body_delay: Option<std::time::Duration>,
    mutate_headers: bool,
}

struct BlockingResponseMiddleware;

struct RequestOnlyMiddleware;

#[tonic::async_trait]
impl openshell_supervisor_middleware::InProcessMiddleware for RequestOnlyMiddleware {
    async fn describe(&self) -> MiddlewareManifest {
        let mut manifest = openshell_supervisor_middleware::InProcessMiddleware::describe(
            &BlockingResponseMiddleware,
        )
        .await;
        manifest.name = "test/request-only".into();
        manifest.bindings[0].operation = SupervisorMiddlewareOperation::HttpRequest as i32;
        manifest.bindings[0].phase = SupervisorMiddlewarePhase::PreCredentials as i32;
        manifest
    }

    async fn validate_config(&self, _: &str, _: &prost_types::Struct) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _: openshell_supervisor_middleware::HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        panic!("request hook must not run on a response")
    }
}

#[tokio::test]
async fn an_absent_response_binding_does_not_create_a_cancelled_phase() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber =
        tracing_subscriber::registry().with(openshell_otel::layer(&provider, "no-response-hook"));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let correlation = test_correlation("request-only");
    let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(RequestOnlyMiddleware));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "request".into(),
        implementation: "test/request-only".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
    let mut output = Vec::new();
    relay_response(
        "GET",
        &mut upstream,
        &mut output,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(test_response_middleware(&runner, &chain, "request-only")),
    )
    .await
    .unwrap();
    drop(correlation);
    assert!(output.ends_with(b"\r\n\r\nbody"));
    assert!(
        !exporter
            .get_finished_spans()
            .unwrap()
            .iter()
            .any(|span| span.name == "openshell.middleware.response")
    );
}

enum BodyTestAction {
    Block,
    ReloadAndSkipTransform(Arc<crate::opa::OpaEngine>),
}

struct BodyResponseMiddleware {
    action: BodyTestAction,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReloadThenErrorPoint {
    Describe,
    Preflight,
    Finish,
}

struct ReloadThenErrorResponseMiddleware {
    point: ReloadThenErrorPoint,
    body_mode: i32,
    engine: Arc<crate::opa::OpaEngine>,
}

struct PartialThenErrorWriter {
    remaining_success: usize,
}

struct ReloadOnBodyReader {
    head: Vec<u8>,
    head_position: usize,
    body: Vec<u8>,
    body_position: usize,
    reloaded: bool,
    engine: Arc<crate::opa::OpaEngine>,
}

struct SegmentsThenPendingReader {
    segments: VecDeque<Vec<u8>>,
    segment_position: usize,
    pending_polled: Arc<Notify>,
}

impl SegmentsThenPendingReader {
    fn new(segments: impl IntoIterator<Item = Vec<u8>>, pending_polled: Arc<Notify>) -> Self {
        Self {
            segments: segments.into_iter().collect(),
            segment_position: 0,
            pending_polled,
        }
    }
}

impl AsyncRead for SegmentsThenPendingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        while let Some(segment) = self.segments.front() {
            if self.segment_position == segment.len() {
                self.segments.pop_front();
                self.segment_position = 0;
                continue;
            }
            let remaining = &segment[self.segment_position..];
            let count = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..count]);
            self.segment_position += count;
            return Poll::Ready(Ok(()));
        }
        self.pending_polled.notify_one();
        Poll::Pending
    }
}

async fn wait_for_pending_read(pending_polled: &Notify) {
    tokio::time::timeout(std::time::Duration::from_secs(5), pending_polled.notified())
        .await
        .expect("response relay reached the pending read");
}

async fn cancel_after_pending_read(
    operation: impl Future<Output = miette::Result<RelayOutcome>>,
    pending_polled: &Notify,
) {
    let mut operation = Box::pin(operation);
    tokio::select! {
        result = &mut operation => panic!("response finished before cancellation: {result:?}"),
        () = wait_for_pending_read(pending_polled) => {}
    }
}

impl ReloadOnBodyReader {
    fn new(head: &[u8], body: &[u8], engine: Arc<crate::opa::OpaEngine>) -> Self {
        Self {
            head: head.to_vec(),
            head_position: 0,
            body: body.to_vec(),
            body_position: 0,
            reloaded: false,
            engine,
        }
    }
}

impl AsyncRead for ReloadOnBodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.head_position < self.head.len() {
            let remaining = &self.head[self.head_position..];
            let count = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..count]);
            self.head_position += count;
            return Poll::Ready(Ok(()));
        }
        if !self.reloaded {
            self.engine
                .reload(
                    include_str!("../../../../data/sandbox-policy.rego"),
                    "network_policies: {}\n",
                )
                .expect("reload test policy");
            self.reloaded = true;
        }
        if self.body_position < self.body.len() {
            let remaining = &self.body[self.body_position..];
            let count = remaining.len().min(buffer.remaining());
            buffer.put_slice(&remaining[..count]);
            self.body_position += count;
        }
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct ControlledResponseWriter {
    bytes: Vec<u8>,
    zero_first_write: bool,
    shutdown_error: bool,
}

impl AsyncWrite for ControlledResponseWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.zero_first_write {
            self.zero_first_write = false;
            return Poll::Ready(Ok(0));
        }
        self.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.shutdown_error {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test shutdown failure",
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}

impl AsyncWrite for PartialThenErrorWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.remaining_success == 0 {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "test downstream disconnect",
            )));
        }
        let written = bytes.len().min(self.remaining_success);
        self.remaining_success -= written;
        Poll::Ready(Ok(written))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tonic::async_trait]
impl openshell_supervisor_middleware::InProcessMiddleware for BlockingResponseMiddleware {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: "test/blocking-response".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: 4096,
                request_timeout: None,
            }],
            expected_audience: String::new(),
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                "openshell/test-blocking-response",
                "test",
                [],
            )),
        }
    }

    async fn validate_config(
        &self,
        _middleware_name: &str,
        _config: &prost_types::Struct,
    ) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: openshell_supervisor_middleware::HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        Ok(HttpRequestResult {
            decision: Decision::Allow as i32,
            ..Default::default()
        })
    }

    async fn open_http_response_pre_return(
        &self,
        mut requests: mpsc::Receiver<HttpResponseEvent>,
    ) -> Result<openshell_supervisor_middleware::HttpResponseResultStream, tonic::Status> {
        let first = requests
            .recv()
            .await
            .ok_or_else(|| tonic::Status::invalid_argument("missing response preflight"))?;
        if !matches!(first.event, Some(http_response_event::Event::Preflight(_))) {
            return Err(tonic::Status::invalid_argument(
                "expected response preflight",
            ));
        }
        let result = HttpResponseEventResult {
            result: Some(http_response_event_result::Result::PreflightResult(
                HttpResponsePreflightResult {
                    action: Some(http_response_preflight_result::Action::BlockDelivery(
                        HttpResponseBlockDelivery {},
                    )),
                    reason_code: "test_block".into(),
                    ..Default::default()
                },
            )),
        };
        Ok(Box::pin(futures::stream::iter([Ok(result)])))
    }
}

#[tonic::async_trait]
impl openshell_supervisor_middleware::InProcessMiddleware for StreamingResponseMiddleware {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: "test/streaming-response".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: 4096,
                request_timeout: None,
            }],
            expected_audience: String::new(),
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                "openshell/test-streaming-response",
                "test",
                [],
            )),
        }
    }

    async fn validate_config(
        &self,
        _middleware_name: &str,
        _config: &prost_types::Struct,
    ) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: openshell_supervisor_middleware::HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        Ok(HttpRequestResult {
            decision: Decision::Allow as i32,
            ..Default::default()
        })
    }

    async fn open_http_response_pre_return(
        &self,
        mut requests: mpsc::Receiver<HttpResponseEvent>,
    ) -> Result<openshell_supervisor_middleware::HttpResponseResultStream, tonic::Status> {
        let (sender, receiver) = mpsc::channel(4);
        let body_mode = self.body_mode;
        let body_delay = self.body_delay;
        let mutate_headers = self.mutate_headers;
        tokio::spawn(async move {
            while let Some(event) = requests.recv().await {
                let Some(event) = event.event else {
                    break;
                };
                let result = match event {
                    http_response_event::Event::Preflight(_) => HttpResponseEventResult {
                        result: Some(http_response_event_result::Result::PreflightResult(
                            HttpResponsePreflightResult {
                                action: Some(http_response_preflight_result::Action::Inspect(
                                    HttpResponsePreflightInspect {
                                        body_mode,
                                        header_mutations: mutate_headers
                                            .then(|| HeaderMutation {
                                                operation: Some(header_mutation::Operation::Write(
                                                    WriteHeader {
                                                        name: "x-inspected".into(),
                                                        value: "true".into(),
                                                        on_existing: ExistingHeaderAction::Overwrite
                                                            as i32,
                                                    },
                                                )),
                                            })
                                            .into_iter()
                                            .collect(),
                                    },
                                )),
                                ..Default::default()
                            },
                        )),
                    },
                    http_response_event::Event::Body(body) => {
                        if let Some(delay) = body_delay {
                            tokio::time::sleep(delay).await;
                        }
                        let Some(http_response_body_unit::Payload::Data(data)) = body.payload
                        else {
                            break;
                        };
                        HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::BodyResult(
                                HttpResponseBodyResult {
                                    sequence: body.sequence,
                                    action: Some(http_response_body_result::Action::Transform(
                                        HttpResponseBodyTransform {
                                            replacement: Some(
                                                http_response_body_transform::Replacement::Data(
                                                    data,
                                                ),
                                            ),
                                        },
                                    )),
                                    ..Default::default()
                                },
                            )),
                        }
                    }
                    http_response_event::Event::Trailers(_) => HttpResponseEventResult {
                        result: Some(http_response_event_result::Result::TrailersResult(
                            HttpResponseTrailersResult::default(),
                        )),
                    },
                    http_response_event::Event::SessionEnd(_) => break,
                };
                if sender.send(Ok(result)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}

#[tonic::async_trait]
impl openshell_supervisor_middleware::InProcessMiddleware for BodyResponseMiddleware {
    async fn describe(&self) -> MiddlewareManifest {
        MiddlewareManifest {
            name: "test/body-response".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: 4096,
                request_timeout: None,
            }],
            expected_audience: String::new(),
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                "openshell/test-body-response",
                "test",
                [],
            )),
        }
    }

    async fn validate_config(
        &self,
        _middleware_name: &str,
        _config: &prost_types::Struct,
    ) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: openshell_supervisor_middleware::HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        Ok(HttpRequestResult {
            decision: Decision::Allow as i32,
            ..Default::default()
        })
    }

    async fn open_http_response_pre_return(
        &self,
        mut requests: mpsc::Receiver<HttpResponseEvent>,
    ) -> Result<openshell_supervisor_middleware::HttpResponseResultStream, tonic::Status> {
        let (sender, receiver) = mpsc::channel(4);
        let action = match &self.action {
            BodyTestAction::Block => BodyTestAction::Block,
            BodyTestAction::ReloadAndSkipTransform(engine) => {
                BodyTestAction::ReloadAndSkipTransform(Arc::clone(engine))
            }
        };
        tokio::spawn(async move {
            while let Some(event) = requests.recv().await {
                let Some(event) = event.event else {
                    break;
                };
                let result = match event {
                    http_response_event::Event::Preflight(_) => HttpResponseEventResult {
                        result: Some(http_response_event_result::Result::PreflightResult(
                            HttpResponsePreflightResult {
                                action: Some(http_response_preflight_result::Action::Inspect(
                                    HttpResponsePreflightInspect {
                                        body_mode: HttpResponseBodyMode::StreamBytes as i32,
                                        header_mutations: Vec::new(),
                                    },
                                )),
                                ..Default::default()
                            },
                        )),
                    },
                    http_response_event::Event::Body(body) => {
                        let Some(http_response_body_unit::Payload::Data(data)) = body.payload
                        else {
                            break;
                        };
                        let action = match &action {
                            BodyTestAction::Block => {
                                http_response_body_result::Action::BlockDelivery(
                                    HttpResponseBlockDelivery {},
                                )
                            }
                            BodyTestAction::ReloadAndSkipTransform(engine) => {
                                engine
                                    .reload(
                                        include_str!("../../../../data/sandbox-policy.rego"),
                                        "network_policies: {}\n",
                                    )
                                    .expect("reload test policy");
                                http_response_body_result::Action::SkipRemaining(
                                    HttpResponseBodySkipRemaining {
                                        current: Some(
                                            http_response_body_skip_remaining::Current::Transform(
                                                HttpResponseBodyTransform {
                                                    replacement: Some(
                                                        http_response_body_transform::Replacement::Data(data),
                                                    ),
                                                },
                                            ),
                                        ),
                                    },
                                )
                            }
                        };
                        HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::BodyResult(
                                HttpResponseBodyResult {
                                    sequence: body.sequence,
                                    action: Some(action),
                                    reason_code: "test_body_action".into(),
                                    ..Default::default()
                                },
                            )),
                        }
                    }
                    http_response_event::Event::Trailers(_) => HttpResponseEventResult {
                        result: Some(http_response_event_result::Result::TrailersResult(
                            HttpResponseTrailersResult::default(),
                        )),
                    },
                    http_response_event::Event::SessionEnd(_) => break,
                };
                if sender.send(Ok(result)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}

impl ReloadThenErrorResponseMiddleware {
    fn reload_policy(&self) {
        self.engine
            .reload(
                include_str!("../../../../data/sandbox-policy.rego"),
                "network_policies: {}\n",
            )
            .expect("reload test policy");
    }
}

#[tonic::async_trait]
impl openshell_supervisor_middleware::InProcessMiddleware for ReloadThenErrorResponseMiddleware {
    async fn describe(&self) -> MiddlewareManifest {
        if self.point == ReloadThenErrorPoint::Describe {
            self.reload_policy();
        }
        MiddlewareManifest {
            name: "test/reload-then-error-response".into(),
            service_version: "test".into(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: if self.point == ReloadThenErrorPoint::Describe {
                    0
                } else {
                    4096
                },
                request_timeout: None,
            }],
            expected_audience: String::new(),
            extension: Some(openshell_core::extension_protocol::extension_metadata(
                openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                "openshell/test-reload-then-error-response",
                "test",
                [],
            )),
        }
    }

    async fn validate_config(
        &self,
        _middleware_name: &str,
        _config: &prost_types::Struct,
    ) -> miette::Result<()> {
        Ok(())
    }

    async fn evaluate_http_request(
        &self,
        _request: openshell_supervisor_middleware::HttpRequestView<'_>,
    ) -> miette::Result<HttpRequestResult> {
        Ok(HttpRequestResult {
            decision: Decision::Allow as i32,
            ..Default::default()
        })
    }

    async fn open_http_response_pre_return(
        &self,
        mut requests: mpsc::Receiver<HttpResponseEvent>,
    ) -> Result<openshell_supervisor_middleware::HttpResponseResultStream, tonic::Status> {
        let first = requests
            .recv()
            .await
            .ok_or_else(|| tonic::Status::invalid_argument("missing response preflight"))?;
        if !matches!(first.event, Some(http_response_event::Event::Preflight(_))) {
            return Err(tonic::Status::invalid_argument(
                "expected response preflight",
            ));
        }
        if self.point == ReloadThenErrorPoint::Preflight {
            self.reload_policy();
            return Err(tonic::Status::internal(
                "test preflight failure after policy reload",
            ));
        }

        let (sender, receiver) = mpsc::channel(4);
        sender
            .send(Ok(HttpResponseEventResult {
                result: Some(http_response_event_result::Result::PreflightResult(
                    HttpResponsePreflightResult {
                        action: Some(http_response_preflight_result::Action::Inspect(
                            HttpResponsePreflightInspect {
                                body_mode: self.body_mode,
                                header_mutations: Vec::new(),
                            },
                        )),
                        ..Default::default()
                    },
                )),
            }))
            .await
            .map_err(|_| tonic::Status::unavailable("test response stream closed"))?;

        let point = self.point;
        let engine = Arc::clone(&self.engine);
        tokio::spawn(async move {
            while let Some(event) = requests.recv().await {
                let Some(event) = event.event else {
                    break;
                };
                let result = match event {
                    http_response_event::Event::Body(body)
                        if point == ReloadThenErrorPoint::Finish && body.end_of_stream =>
                    {
                        engine
                            .reload(
                                include_str!("../../../../data/sandbox-policy.rego"),
                                "network_policies: {}\n",
                            )
                            .expect("reload test policy");
                        let _ = sender
                            .send(Err(tonic::Status::internal(
                                "test finish failure after policy reload",
                            )))
                            .await;
                        break;
                    }
                    http_response_event::Event::Body(body) => {
                        let Some(http_response_body_unit::Payload::Data(data)) = body.payload
                        else {
                            break;
                        };
                        HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::BodyResult(
                                HttpResponseBodyResult {
                                    sequence: body.sequence,
                                    action: Some(http_response_body_result::Action::Transform(
                                        HttpResponseBodyTransform {
                                            replacement: Some(
                                                http_response_body_transform::Replacement::Data(
                                                    data,
                                                ),
                                            ),
                                        },
                                    )),
                                    ..Default::default()
                                },
                            )),
                        }
                    }
                    http_response_event::Event::Trailers(_) => HttpResponseEventResult {
                        result: Some(http_response_event_result::Result::TrailersResult(
                            HttpResponseTrailersResult::default(),
                        )),
                    },
                    http_response_event::Event::Preflight(_)
                    | http_response_event::Event::SessionEnd(_) => break,
                };
                if sender.send(Ok(result)).await.is_err() {
                    break;
                }
            }
        });
        Ok(Box::pin(ReceiverStream::new(receiver)))
    }
}

fn test_correlation_for_method(
    request_id: &str,
    method: &str,
) -> crate::l7::correlation::RequestCorrelation {
    let request = L7Request {
        action: method.into(),
        target: "/data".into(),
        query_params: HashMap::new(),
        raw_header: b"GET /data HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
        body_length: BodyLength::None,
    };
    crate::l7::correlation::RequestCorrelation::with_request_id(
        &request,
        &L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        },
        request_id.into(),
    )
}

fn test_correlation(request_id: &str) -> crate::l7::correlation::RequestCorrelation {
    test_correlation_for_method(request_id, "GET")
}

fn test_response_middleware<'a>(
    runner: &'a openshell_supervisor_middleware::ChainRunner,
    chain: &'a [openshell_supervisor_middleware::ChainEntry],
    request_id: &str,
) -> HttpResponseMiddlewareRelay<'a> {
    HttpResponseMiddlewareRelay {
        chain,
        runner,
        request_context: RequestContext {
            request_id: request_id.into(),
            sandbox_id: "sandbox-1".into(),
            ..Default::default()
        },
        target: HttpRequestTarget {
            scheme: "https".into(),
            host: "example.test".into(),
            port: 443,
            method: "GET".into(),
            path: "/data".into(),
            query: String::new(),
        },
        policy_name: "test-policy",
        generation_guard: None,
        whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
    }
}

fn response_audit_event_for(
    capture: &openshell_ocsf::test_support::OcsfCapture,
    request_id: &str,
) -> serde_json::Value {
    let (mut terminal, mut primary): (Vec<_>, Vec<_>) = capture
        .json_events()
        .into_iter()
        .filter(|event| {
            event["class_uid"] == 4002
                && event["metadata"]["correlation_uid"] == request_id
                && event["firewall_rule"]["type"] != "supervisor-middleware"
        })
        .partition(|event| event["firewall_rule"]["type"] == "response-correlation");
    assert_eq!(primary.len(), 1, "one primary record for the request");
    if terminal.is_empty() {
        return primary.pop().unwrap();
    }
    assert_eq!(
        terminal.len(),
        1,
        "one post-header exception for the request"
    );
    terminal.pop().unwrap()
}

fn request_id_header_count(response: &[u8]) -> usize {
    String::from_utf8_lossy(response)
        .lines()
        .filter(|line| {
            line.split_once(':').is_some_and(|(name, _)| {
                name.eq_ignore_ascii_case(openshell_core::token_grant_failure::REQUEST_ID_HEADER)
            })
        })
        .count()
}

#[tokio::test]
async fn allowed_final_response_carries_platform_receipt() {
    let correlation = test_correlation("receipt-1");
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
    let mut client = Vec::new();

    let outcome = relay_response(
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
    .expect("relay response");

    assert!(matches!(outcome, RelayOutcome::Reusable));
    assert_eq!(request_id_header_count(&client), 1);
    assert!(String::from_utf8_lossy(&client).contains("x-openshell-request-id: receipt-1\r\n"));
}

#[tokio::test]
async fn cancellation_before_final_head_emits_one_incomplete_terminal_event() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation("response-cancel-before-head");
    let pending_polled = Arc::new(Notify::new());
    let mut upstream = SegmentsThenPendingReader::new([], Arc::clone(&pending_polled));
    let mut client = Vec::new();

    cancel_after_pending_read(
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
        &pending_polled,
    )
    .await;
    drop(correlation);

    let event = response_audit_event_for(&capture, "response-cancel-before-head");
    assert_eq!(
        event["unmapped"]["response_delivery_outcome"],
        "cancelled_or_incomplete"
    );
    assert_eq!(event["unmapped"]["response_selection_cause"], "cancelled");
    assert_eq!(event["unmapped"]["delivery_started"], false);
    assert_eq!(event["unmapped"]["partial_delivery"], false);
}

#[tokio::test]
async fn unsolicited_switching_protocols_is_a_protocol_failure() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation("response-unsolicited-101");
    let mut upstream =
        &b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"[..];
    let mut client = Vec::new();

    relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            client_requested_upgrade: false,
            correlation: Some(&correlation),
            ..Default::default()
        },
        None,
    )
    .await
    .expect_err("unsolicited 101 must fail");
    assert!(client.is_empty());
    drop(correlation);

    let event = response_audit_event_for(&capture, "response-unsolicited-101");
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "upstream_protocol_error"
    );
    assert_eq!(
        event["unmapped"]["response_delivery_outcome"],
        "cancelled_or_incomplete"
    );
    assert!(event.get("http_response").is_none());
    assert_eq!(event["unmapped"]["delivery_started"], false);
}

#[tokio::test]
async fn invalid_websocket_handshake_is_a_correlated_upstream_protocol_failure() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let request_id = "response-invalid-websocket-accept";
    let correlation = test_correlation(request_id);
    let validation = WebSocketResponseValidation {
        expected_accept: "expected-accept".into(),
        expected_extension: None,
        offered_subprotocols: Vec::new(),
    };
    let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: invalid\r\n\r\n"[..];
    let mut client = Vec::new();

    let error = relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            client_requested_upgrade: true,
            websocket: Some(validation),
            correlation: Some(&correlation),
            ..Default::default()
        },
        None,
    )
    .await
    .expect_err("invalid upstream WebSocket handshake must fail");
    assert!(
        error
            .downcast_ref::<super::RelayError>()
            .is_some_and(|error| matches!(
                error,
                super::RelayError::Protocol {
                    code: "invalid_websocket_handshake",
                    ..
                }
            )),
        "{error}"
    );
    assert!(client.is_empty(), "invalid 101 response reached the client");
    drop(correlation);

    let event = response_audit_event_for(&capture, request_id);
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "upstream_protocol_error"
    );
    assert_eq!(
        event["unmapped"]["response_delivery_outcome"],
        "cancelled_or_incomplete"
    );
    assert_eq!(event["unmapped"]["upstream_response_code"], 101);
    assert!(event.get("http_response").is_none());
    assert!(
        event["unmapped"]
            .get("effective_http_status_code")
            .is_none()
    );
    assert_eq!(event["unmapped"]["delivery_started"], false);
    assert_eq!(event["unmapped"]["partial_delivery"], false);
}

#[tokio::test]
async fn whole_body_cancellation_before_selection_has_no_effective_status() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation("response-whole-body-cancel");
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(StreamingResponseMiddleware {
            body_mode: HttpResponseBodyMode::WholeBodyBytes as i32,
            body_delay: None,
            mutate_headers: true,
        }));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/streaming-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let middleware = test_response_middleware(&runner, &chain, "response-whole-body-cancel");
    let pending_polled = Arc::new(Notify::new());
    let mut upstream = SegmentsThenPendingReader::new(
        [b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nbody".to_vec()],
        Arc::clone(&pending_polled),
    );
    let mut client = Vec::new();

    cancel_after_pending_read(
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
        &pending_polled,
    )
    .await;
    assert!(client.is_empty());
    drop(correlation);

    let event = response_audit_event_for(&capture, "response-whole-body-cancel");
    assert_eq!(event["unmapped"]["response_selection_cause"], "cancelled");
    assert_eq!(event["unmapped"]["upstream_response_code"], 200);
    assert!(event.get("http_response").is_none());
    assert!(
        event["unmapped"]
            .get("effective_http_status_code")
            .is_none()
    );
    assert_eq!(event["unmapped"]["delivery_started"], false);
}

#[tokio::test]
async fn whole_body_fail_open_timeout_selects_upstream_response_on_commit() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let request_id = "response-whole-body-fail-open-timeout";
    let correlation = test_correlation(request_id);
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(StreamingResponseMiddleware {
            body_mode: HttpResponseBodyMode::WholeBodyBytes as i32,
            body_delay: Some(std::time::Duration::from_millis(75)),
            mutate_headers: true,
        }));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/streaming-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailOpen,
    }];
    let mut middleware = test_response_middleware(&runner, &chain, request_id);
    middleware.whole_body_timeout = std::time::Duration::from_millis(10);
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..];
    let mut client = Vec::new();

    let outcome = relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect("whole-body timeout fails open");
    assert!(matches!(outcome, RelayOutcome::Reusable));
    assert!(client.ends_with(b"hello"));
    drop(correlation);

    let event = response_audit_event_for(&capture, request_id);
    assert!(event["unmapped"]["response_selection_cause"].is_null());
    assert_eq!(event["unmapped"]["middleware_fail_open"], true);
    assert!(
        event["unmapped"]["response_delivery_outcome"].is_null(),
        "completion is not claimed by the primary record"
    );
    assert!(
        event["unmapped"]["upstream_response_code"].is_null(),
        "unchanged upstream status is not duplicated"
    );
    assert_eq!(event["http_response"]["code"], 200);
    assert!(
        event["unmapped"]["delivery_started"].is_null(),
        "completion is not claimed by the primary record"
    );
    assert!(
        event["unmapped"]["partial_delivery"].is_null(),
        "completion is not claimed by the primary record"
    );
}

#[tokio::test]
async fn accepted_early_hints_are_separate_from_cancelled_final_delivery() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation("response-early-hints-cancel");
    let pending_polled = Arc::new(Notify::new());
    let mut upstream = SegmentsThenPendingReader::new(
        [b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n".to_vec()],
        Arc::clone(&pending_polled),
    );
    let mut client = Vec::new();

    cancel_after_pending_read(
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
        &pending_polled,
    )
    .await;
    assert!(client.starts_with(b"HTTP/1.1 103 Early Hints\r\n"));
    drop(correlation);

    let event = response_audit_event_for(&capture, "response-early-hints-cancel");
    assert_eq!(event["unmapped"]["interim_delivery_started"], true);
    assert!(
        event["unmapped"]["interim_bytes_forwarded"]
            .as_u64()
            .is_some_and(|bytes| bytes > 0)
    );
    assert_eq!(event["unmapped"]["delivery_started"], false);
    assert_eq!(event["unmapped"]["partial_delivery"], false);
}

#[tokio::test]
async fn response_head_reload_during_early_hints_is_not_forwarded() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let engine = Arc::new(
        crate::opa::OpaEngine::from_strings(
            include_str!("../../../../data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .expect("test policy"),
    );
    let generation_guard = engine
        .generation_guard(engine.current_generation())
        .expect("generation guard");
    let request_id = "response-early-hints-reload-race";
    let correlation = test_correlation(request_id);
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(StreamingResponseMiddleware {
            body_mode: HttpResponseBodyMode::HeadersOnly as i32,
            body_delay: None,
            mutate_headers: false,
        }));
    let chain = Vec::new();
    let mut middleware = test_response_middleware(&runner, &chain, request_id);
    middleware.generation_guard = Some(&generation_guard);
    let mut upstream = ReloadOnBodyReader::new(
        b"",
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n",
        Arc::clone(&engine),
    );
    let mut client = Vec::new();

    let error = relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect_err("policy reload must win before forwarding early hints");
    assert!(
        error
            .downcast_ref::<super::RelayError>()
            .is_some_and(|error| matches!(error, super::RelayError::PolicyReloaded(_))),
        "{error}"
    );
    assert!(client.is_empty(), "stale early hints reached the client");
    drop(correlation);

    let event = response_audit_event_for(&capture, request_id);
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "policy_reloaded"
    );
    assert_eq!(
        event["unmapped"]["response_delivery_outcome"],
        "cancelled_or_incomplete"
    );
    assert_eq!(event["unmapped"]["interim_delivery_started"], false);
    assert_eq!(event["unmapped"]["delivery_started"], false);
}

#[tokio::test]
async fn idle_before_final_response_head_wakes_on_policy_reload() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let engine = Arc::new(
        crate::opa::OpaEngine::from_strings(
            include_str!("../../../../data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .expect("test policy"),
    );
    let generation_guard = engine
        .generation_guard(engine.current_generation())
        .expect("generation guard");
    let request_id = "response-idle-before-head-reload";
    let correlation = test_correlation(request_id);
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(StreamingResponseMiddleware {
            body_mode: HttpResponseBodyMode::HeadersOnly as i32,
            body_delay: None,
            mutate_headers: false,
        }));
    let chain = Vec::new();
    let mut middleware = test_response_middleware(&runner, &chain, request_id);
    middleware.generation_guard = Some(&generation_guard);
    let pending_polled = Arc::new(Notify::new());
    let mut upstream =
        SegmentsThenPendingReader::new(Vec::<Vec<u8>>::new(), Arc::clone(&pending_polled));
    let mut client = Vec::new();
    let mut relay = Box::pin(relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    ));

    tokio::select! {
        result = &mut relay => panic!("idle response finished before reload: {result:?}"),
        () = wait_for_pending_read(&pending_polled) => {}
    }
    engine
        .reload(
            include_str!("../../../../data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .expect("reload test policy");
    let error = tokio::time::timeout(std::time::Duration::from_secs(5), &mut relay)
        .await
        .expect("policy reload wakes the response-head read")
        .expect_err("policy reload stops the response");
    assert!(
        error
            .downcast_ref::<super::RelayError>()
            .is_some_and(|error| matches!(error, super::RelayError::PolicyReloaded(_))),
        "{error}"
    );
    drop(relay);
    assert!(client.is_empty());
    drop(correlation);

    let event = response_audit_event_for(&capture, request_id);
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "policy_reloaded"
    );
    assert_eq!(event["unmapped"]["delivery_started"], false);
    assert_eq!(event["unmapped"]["partial_delivery"], false);
}

#[tokio::test]
async fn framed_response_reads_wake_on_policy_reload_without_stale_body_bytes() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    for (case_name, segments) in [
        (
            "fixed-payload",
            vec![b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".to_vec()],
        ),
        (
            "chunk-size",
            vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec()],
        ),
        (
            "chunk-payload",
            vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n".to_vec()],
        ),
        (
            "chunk-terminator",
            vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody".to_vec()],
        ),
        (
            "chunk-trailer",
            vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec()],
        ),
    ] {
        let engine = Arc::new(
            crate::opa::OpaEngine::from_strings(
                include_str!("../../../../data/sandbox-policy.rego"),
                "network_policies: {}\n",
            )
            .expect("test policy"),
        );
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .expect("generation guard");
        let request_id = format!("response-stalled-{case_name}-reload");
        let correlation = test_correlation(&request_id);
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                body_delay: None,
                mutate_headers: false,
            },
        ));
        let chain = Vec::new();
        let mut middleware = test_response_middleware(&runner, &chain, &request_id);
        middleware.generation_guard = Some(&generation_guard);
        let pending_polled = Arc::new(Notify::new());
        let mut upstream = SegmentsThenPendingReader::new(segments, Arc::clone(&pending_polled));
        let mut client = Vec::new();
        let mut relay = Box::pin(relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        ));

        tokio::select! {
            result = &mut relay => {
                panic!("{case_name} response finished before reload: {result:?}")
            }
            () = wait_for_pending_read(&pending_polled) => {}
        }
        engine
            .reload(
                include_str!("../../../../data/sandbox-policy.rego"),
                "network_policies: {}\n",
            )
            .expect("reload test policy");
        let error = tokio::time::timeout(std::time::Duration::from_secs(5), &mut relay)
            .await
            .expect("policy reload wakes the framed response read")
            .expect_err("policy reload stops the response");
        assert!(
            error
                .downcast_ref::<super::RelayError>()
                .is_some_and(|error| matches!(error, super::RelayError::PolicyReloaded(_))),
            "{case_name}: {error}"
        );
        drop(relay);
        let head_end = client
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
            .expect("final response head delivered before body acquisition");
        assert_eq!(
            &client[head_end..],
            b"",
            "{case_name} leaked stale body or chunk framing bytes"
        );
        drop(correlation);

        let event = response_audit_event_for(&capture, &request_id);
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "policy_reloaded"
        );
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert_eq!(event["unmapped"]["delivery_started"], true);
        assert_eq!(event["unmapped"]["partial_delivery"], true);
    }
}

#[tokio::test]
async fn shutdown_failure_overrides_delivery_but_retains_upstream_selection() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation("response-shutdown-failure");
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..];
    let mut client = ControlledResponseWriter {
        shutdown_error: true,
        ..Default::default()
    };

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
    .expect_err("shutdown failure");
    drop(correlation);

    let event = response_audit_event_for(&capture, "response-shutdown-failure");
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "upstream_response"
    );
    assert_eq!(
        event["unmapped"]["response_delivery_outcome"],
        "downstream_io_error"
    );
    assert_eq!(event["unmapped"]["upstream_response_code"], 200);
    assert_eq!(event["http_response"]["code"], 200);
    assert_eq!(event["unmapped"]["delivery_started"], true);
    assert_eq!(event["unmapped"]["partial_delivery"], true);
}

#[tokio::test]
async fn zero_byte_first_write_does_not_claim_delivery_started() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation("response-zero-write");
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
    let mut client = ControlledResponseWriter {
        zero_first_write: true,
        ..Default::default()
    };

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
    .expect_err("write zero");
    drop(correlation);

    let event = response_audit_event_for(&capture, "response-zero-write");
    assert_eq!(
        event["unmapped"]["response_delivery_outcome"],
        "downstream_io_error"
    );
    assert_eq!(event["unmapped"]["delivery_started"], false);
    assert_eq!(event["unmapped"]["partial_delivery"], false);
}

#[tokio::test]
async fn content_length_overflow_is_rejected_before_final_head() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation("response-content-length-overflow");
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbodyEXTRA"[..];
    let mut client = Vec::new();

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
    .expect_err("content-length overflow");
    assert!(client.is_empty());
    drop(correlation);

    let event = response_audit_event_for(&capture, "response-content-length-overflow");
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "upstream_protocol_error"
    );
    assert_eq!(
        event["unmapped"]["response_delivery_outcome"],
        "cancelled_or_incomplete"
    );
    assert_eq!(event["unmapped"]["upstream_response_code"], 200);
    assert!(
        event["unmapped"]
            .get("effective_http_status_code")
            .is_none()
    );
    assert_eq!(event["unmapped"]["delivery_started"], false);
}

#[tokio::test]
async fn malformed_chunk_is_typed_as_protocol_failure_after_head_delivery() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation("response-malformed-chunk");
    let mut upstream = &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\nbody\r\n"[..];
    let mut client = Vec::new();

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
    .expect_err("malformed chunk");
    assert!(client.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(!client.ends_with(b"body\r\n"));
    drop(correlation);

    let event = response_audit_event_for(&capture, "response-malformed-chunk");
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "upstream_protocol_error"
    );
    assert_eq!(
        event["unmapped"]["response_delivery_outcome"],
        "cancelled_or_incomplete"
    );
    assert_eq!(event["unmapped"]["delivery_started"], true);
    assert_eq!(event["unmapped"]["partial_delivery"], true);
}

#[tokio::test]
async fn complete_fixed_chunked_and_sse_responses_record_terminal_delivery() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry()
        .with(openshell_otel::layer(
            &provider,
            "response-correlation-test",
        ))
        .with(ocsf.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    for (request_id, response) in [
        (
            "response-fixed-complete",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody".as_slice(),
        ),
        (
            "response-chunked-complete",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"
                .as_slice(),
        ),
        (
            "response-sse-complete",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: ok\n\n".as_slice(),
        ),
    ] {
        let correlation = test_correlation(request_id);
        let mut upstream = response;
        let mut client = Vec::new();
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
        .expect("complete response relay");
        drop(correlation);
    }
    provider.force_flush().expect("flush spans");

    let spans = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .filter(|span| span.name == "openshell.response.deliver")
        .map(|span| {
            span.attributes
                .into_iter()
                .map(|attribute| {
                    (
                        attribute.key.as_str().to_string(),
                        attribute.value.to_string(),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(spans.len(), 3);
    for attributes in spans {
        assert_eq!(
            attributes["openshell.upstream.http.response.status_code"],
            "200"
        );
        assert_eq!(attributes["http.response.status_code"], "200");
        assert_eq!(attributes["openshell.response.delivery_started"], "true");
        assert_eq!(attributes["openshell.response.partial_delivery"], "false");
        assert_eq!(
            attributes["openshell.response.delivery_outcome"],
            "complete"
        );
    }
    assert!(
        !ocsf
            .json_events()
            .iter()
            .any(|event| event["firewall_rule"]["type"] == "response-correlation"),
        "routine completion remains in sampled spans"
    );
    let primary = ocsf
        .json_events()
        .into_iter()
        .filter(|event| event["class_uid"] == 4002)
        .collect::<Vec<_>>();
    assert_eq!(primary.len(), 3);
    assert!(
        primary
            .iter()
            .all(|event| event["http_response"]["code"] == 200)
    );
}

#[tokio::test]
async fn downstream_disconnect_after_partial_head_write_is_correlated() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
        &provider,
        "response-correlation-test",
    ));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let correlation = test_correlation("response-client-disconnect");
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
    let mut client = PartialThenErrorWriter {
        remaining_success: 8,
    };

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
    .expect_err("downstream disconnect");
    drop(correlation);
    provider.force_flush().expect("flush spans");

    let span = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .find(|span| span.name == "openshell.response.deliver")
        .expect("HTTP enforcement span");
    let attributes = span
        .attributes
        .into_iter()
        .map(|attribute| {
            (
                attribute.key.as_str().to_string(),
                attribute.value.to_string(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(attributes["openshell.response.delivery_started"], "true");
    assert_eq!(attributes["openshell.response.partial_delivery"], "true");
    assert_eq!(
        attributes["openshell.response.delivery_outcome"],
        "downstream_io_error"
    );
}

#[tokio::test]
async fn truncated_fixed_response_is_not_reported_complete() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
        &provider,
        "response-correlation-test",
    ));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let correlation = test_correlation("response-upstream-truncated");
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nbody"[..];
    let mut client = Vec::new();

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
    .expect_err("truncated upstream response");
    drop(correlation);
    provider.force_flush().expect("flush spans");

    let span = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .find(|span| span.name == "openshell.response.deliver")
        .expect("HTTP enforcement span");
    let attributes = span
        .attributes
        .into_iter()
        .map(|attribute| {
            (
                attribute.key.as_str().to_string(),
                attribute.value.to_string(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        attributes["openshell.response.delivery_outcome"],
        "cancelled_or_incomplete"
    );
    assert_eq!(
        attributes["openshell.response.selection_cause"],
        "upstream_truncated"
    );
    assert_eq!(attributes["openshell.response.partial_delivery"], "true");
}

#[tokio::test]
async fn middleware_truncated_fixed_and_chunked_bodies_select_complete_502() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    for (request_id, response) in [
        (
            "response-middleware-fixed-truncated",
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nbody".as_slice(),
        ),
        (
            "response-middleware-chunked-truncated",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbo".as_slice(),
        ),
    ] {
        let correlation = test_correlation(request_id);
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::WholeBodyBytes as i32,
                body_delay: None,
                mutate_headers: true,
            },
        ));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/streaming-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = test_response_middleware(&runner, &chain, request_id);
        let mut upstream = response;
        let mut client = Vec::new();

        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect("pre-commit truncation gets a bounded fallback");
        assert!(matches!(outcome, RelayOutcome::Consumed));
        assert!(client.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
        drop(correlation);

        let event = response_audit_event_for(&capture, request_id);
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "upstream_truncated"
        );
        assert!(
            event["unmapped"]["response_delivery_outcome"].is_null(),
            "completion is not claimed by the primary record"
        );
        assert_eq!(event["unmapped"]["upstream_response_code"], 200);
        assert_eq!(event["http_response"]["code"], 502);
        assert_eq!(event["http_response"]["code"], 502);
        assert!(
            event["unmapped"]["partial_delivery"].is_null(),
            "completion is not claimed by the primary record"
        );
    }
}

#[tokio::test]
async fn fallback_disconnect_preserves_the_precommit_upstream_cause() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation("response-fallback-disconnect");
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(StreamingResponseMiddleware {
            body_mode: HttpResponseBodyMode::WholeBodyBytes as i32,
            body_delay: None,
            mutate_headers: true,
        }));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/streaming-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let middleware = test_response_middleware(&runner, &chain, "response-fallback-disconnect");
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nbody"[..];
    let mut client = ControlledResponseWriter {
        zero_first_write: true,
        ..Default::default()
    };

    relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect_err("fallback head is not accepted downstream");
    drop(correlation);

    let event = response_audit_event_for(&capture, "response-fallback-disconnect");
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "upstream_truncated"
    );
    assert_eq!(
        event["unmapped"]["response_delivery_outcome"],
        "downstream_io_error"
    );
    assert_eq!(event["unmapped"]["upstream_response_code"], 200);
    assert_eq!(event["http_response"]["code"], 502);
    assert_eq!(event["unmapped"]["delivery_started"], false);
    assert_eq!(event["unmapped"]["partial_delivery"], false);
}

#[tokio::test(start_paused = true)]
async fn close_delimited_idle_timeout_is_not_reported_complete() {
    use tokio::io::AsyncWriteExt as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
        &provider,
        "response-correlation-test",
    ));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let correlation = test_correlation("response-idle-timeout");
    let (mut upstream, mut upstream_peer) = tokio::io::duplex(256);
    upstream_peer
        .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody")
        .await
        .expect("seed response");
    let mut client = Vec::new();

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
    .expect("idle timeout consumes close-delimited response");
    drop(upstream_peer);
    drop(correlation);
    provider.force_flush().expect("flush spans");

    let span = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .find(|span| span.name == "openshell.response.deliver")
        .expect("HTTP enforcement span");
    let attributes = span
        .attributes
        .into_iter()
        .map(|attribute| {
            (
                attribute.key.as_str().to_string(),
                attribute.value.to_string(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        attributes["openshell.response.delivery_outcome"],
        "cancelled_or_incomplete"
    );
    assert_eq!(
        attributes["openshell.response.selection_cause"],
        "upstream_idle_timeout"
    );
    assert_eq!(attributes["openshell.http.outcome"], "upstream_error");
    assert_eq!(attributes["openshell.response.partial_delivery"], "true");
}

#[tokio::test]
async fn branch08_response_middleware_denial_records_that_upstream_was_reached() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry()
        .with(openshell_otel::layer(
            &provider,
            "response-correlation-test",
        ))
        .with(ocsf.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation_for_method("response-denied", "POST");
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(BlockingResponseMiddleware));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/blocking-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let middleware = HttpResponseMiddlewareRelay {
        chain: &chain,
        runner: &runner,
        request_context: RequestContext {
            request_id: "response-denied".into(),
            sandbox_id: "sandbox-1".into(),
            ..Default::default()
        },
        target: HttpRequestTarget {
            scheme: "https".into(),
            host: "example.test".into(),
            port: 443,
            method: "POST".into(),
            path: "/mutate".into(),
            query: String::new(),
        },
        policy_name: "test-policy",
        generation_guard: None,
        whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
    };
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
    let mut client = Vec::new();

    let outcome = relay_response(
        "POST",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect("middleware denial response");

    assert!(matches!(outcome, RelayOutcome::Consumed));
    assert!(client.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
    assert!(
        String::from_utf8_lossy(&client).contains("x-openshell-request-id: response-denied\r\n")
    );
    drop(correlation);

    let span = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .find(|span| span.name == "openshell.http.request")
        .expect("HTTP enforcement span");
    assert!(matches!(
        span.status,
        opentelemetry::trace::Status::Error { .. }
    ));
    let attributes = span
        .attributes
        .into_iter()
        .map(|attribute| {
            (
                attribute.key.as_str().to_string(),
                attribute.value.to_string(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(attributes["openshell.target.reached"], "true");
    assert_eq!(attributes["openshell.http.outcome"], "denied");
    assert_eq!(attributes["http.response.status_code"], "403");
    assert!(!attributes.contains_key("openshell.error.stage"));
}

#[tokio::test]
async fn fully_delivered_middleware_failure_keeps_upstream_and_effective_statuses() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation("response-middleware-failure");
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(BlockingResponseMiddleware));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/unavailable-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let middleware = HttpResponseMiddlewareRelay {
        chain: &chain,
        runner: &runner,
        request_context: RequestContext {
            request_id: "response-middleware-failure".into(),
            sandbox_id: "sandbox-1".into(),
            ..Default::default()
        },
        target: HttpRequestTarget {
            scheme: "https".into(),
            host: "example.test".into(),
            port: 443,
            method: "GET".into(),
            path: "/data".into(),
            query: String::new(),
        },
        policy_name: "test-policy",
        generation_guard: None,
        whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
    };
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
    let mut client = Vec::new();

    let outcome = relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect("canonical middleware failure response");
    assert!(matches!(outcome, RelayOutcome::Consumed));
    assert!(client.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
    drop(correlation);

    let event = response_audit_event_for(&capture, "response-middleware-failure");
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "middleware_failed"
    );
    assert!(
        event["unmapped"]["response_delivery_outcome"].is_null(),
        "completion is not claimed by the primary record"
    );
    assert_eq!(event["unmapped"]["upstream_response_code"], 200);
    assert_eq!(event["http_response"]["code"], 502);
    assert!(
        event["unmapped"]["delivery_started"].is_null(),
        "completion is not claimed by the primary record"
    );
    assert!(
        event["unmapped"]["partial_delivery"].is_null(),
        "completion is not claimed by the primary record"
    );
}

#[tokio::test]
async fn bodiless_middleware_denial_and_failure_select_canonical_statuses() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    for (action_name, denied) in [("denied", true), ("failed", false)] {
        for (case_name, method, response, upstream_status) in [
            (
                "head",
                "HEAD",
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".as_slice(),
                200,
            ),
            (
                "204",
                "GET",
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".as_slice(),
                204,
            ),
            (
                "304",
                "GET",
                b"HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n".as_slice(),
                304,
            ),
        ] {
            let request_id = format!("response-bodiless-{case_name}-{action_name}");
            let correlation = test_correlation_for_method(&request_id, method);
            let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
                BlockingResponseMiddleware,
            ));
            let chain = vec![openshell_supervisor_middleware::ChainEntry {
                name: "response".into(),
                implementation: if denied {
                    "test/blocking-response".into()
                } else {
                    "test/unavailable-response".into()
                },
                order: 0,
                config: prost_types::Struct::default(),
                on_error: openshell_supervisor_middleware::OnError::FailClosed,
            }];
            let mut middleware = test_response_middleware(&runner, &chain, &request_id);
            middleware.target.method = method.into();
            let mut upstream = response;
            let mut client = Vec::new();

            let outcome = relay_response(
                method,
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                Some(middleware),
            )
            .await
            .expect("bodiless middleware result gets a canonical response");
            assert!(matches!(outcome, RelayOutcome::Consumed));
            let effective_status = if denied { 403 } else { 502 };
            let expected_head = if denied {
                b"HTTP/1.1 403 Forbidden\r\n".as_slice()
            } else {
                b"HTTP/1.1 502 Bad Gateway\r\n".as_slice()
            };
            assert!(
                client.starts_with(expected_head),
                "{case_name}/{action_name}: {}",
                String::from_utf8_lossy(&client)
            );
            drop(correlation);

            let event = response_audit_event_for(&capture, &request_id);
            assert_eq!(
                event["unmapped"]["response_selection_cause"],
                if denied {
                    "middleware_denied"
                } else {
                    "middleware_failed"
                }
            );
            assert!(
                event["unmapped"]["response_delivery_outcome"].is_null(),
                "completion is not claimed by the primary record"
            );
            assert_eq!(event["unmapped"]["upstream_response_code"], upstream_status);
            assert_eq!(event["http_response"]["code"], effective_status);
            assert!(
                !capture
                    .json_events()
                    .iter()
                    .any(
                        |event| event["firewall_rule"]["type"] == "middleware-correlation"
                            && event["metadata"]["correlation_uid"] == request_id
                    )
            );
        }
    }
}

#[tokio::test]
async fn response_finish_block_retains_an_explicit_denial() {
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(BodyResponseMiddleware {
            action: BodyTestAction::Block,
        }));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/body-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let outcome = runner
        .preflight_http_response(
            &chain,
            openshell_supervisor_middleware::HttpResponsePreflightInput {
                context: RequestContext::default(),
                target: HttpRequestTarget {
                    scheme: "https".into(),
                    host: "example.test".into(),
                    port: 443,
                    method: "GET".into(),
                    path: "/data".into(),
                    query: String::new(),
                },
                status_code: 200,
                declared_body_length: Some(0),
                headers: Vec::new(),
                connection_nominated_headers: Vec::new(),
            },
        )
        .await
        .expect("response preflight");
    let failure = outcome
        .session
        .expect("streaming response session")
        .finish(Vec::new())
        .await
        .expect_err("final body event is denied");

    let denial = response_middleware_failure_denial(&failure).expect("explicit denial");
    assert_eq!(denial.config_name, "response");
    assert_eq!(denial.reason_code.as_deref(), Some("test_body_action"));
}

#[tokio::test]
async fn chain_description_failure_is_middleware_failed_not_upstream_protocol() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let request_id = "response-describe-failure";
    let correlation = test_correlation(request_id);
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(StreamingResponseMiddleware {
            body_mode: HttpResponseBodyMode::HeadersOnly as i32,
            body_delay: None,
            mutate_headers: false,
        }));
    let chain = (0..=openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES)
        .map(|index| openshell_supervisor_middleware::ChainEntry {
            name: format!("response-{index}"),
            implementation: "test/streaming-response".into(),
            order: i32::try_from(index).expect("bounded test index"),
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        })
        .collect::<Vec<_>>();
    let middleware = test_response_middleware(&runner, &chain, request_id);
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
    let mut client = Vec::new();

    relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect("description failure gets a canonical 502");
    assert!(client.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
    drop(correlation);

    let event = response_audit_event_for(&capture, request_id);
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "middleware_failed"
    );
    assert!(
        event["unmapped"]["response_delivery_outcome"].is_null(),
        "completion is not claimed by the primary record"
    );
    assert_eq!(event["unmapped"]["upstream_response_code"], 200);
    assert_eq!(event["http_response"]["code"], 502);
    assert!(capture.json_events().iter().any(|event| {
        event["finding_info"]["uid"] == "openshell.middleware.http_response_failure"
            && event["metadata"]["correlation_uid"] == request_id
    }));
}

#[tokio::test]
async fn policy_reload_wins_over_describe_preflight_and_finish_errors() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    for (case_name, point, method, body_mode) in [
        (
            "describe",
            ReloadThenErrorPoint::Describe,
            "GET",
            HttpResponseBodyMode::HeadersOnly,
        ),
        (
            "preflight",
            ReloadThenErrorPoint::Preflight,
            "GET",
            HttpResponseBodyMode::HeadersOnly,
        ),
        (
            "bodiless-finish",
            ReloadThenErrorPoint::Finish,
            "HEAD",
            HttpResponseBodyMode::WholeBodyBytes,
        ),
        (
            "normal-finish",
            ReloadThenErrorPoint::Finish,
            "GET",
            HttpResponseBodyMode::WholeBodyBytes,
        ),
        (
            "normal-finish-streaming",
            ReloadThenErrorPoint::Finish,
            "GET",
            HttpResponseBodyMode::StreamBytes,
        ),
    ] {
        let engine = Arc::new(
            crate::opa::OpaEngine::from_strings(
                include_str!("../../../../data/sandbox-policy.rego"),
                "network_policies: {}\n",
            )
            .expect("test policy"),
        );
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .expect("generation guard");
        let request_id = format!("response-reload-then-error-{case_name}");
        let correlation = test_correlation_for_method(&request_id, method);
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            ReloadThenErrorResponseMiddleware {
                point,
                body_mode: body_mode as i32,
                engine: Arc::clone(&engine),
            },
        ));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/reload-then-error-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let mut middleware = test_response_middleware(&runner, &chain, &request_id);
        middleware.generation_guard = Some(&generation_guard);
        // Keep the middleware target body-capable in the HEAD case so the
        // test creates a session and reaches the relay's bodiless finish.
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        let error = relay_response(
            method,
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect_err("policy reload must override the middleware error");
        assert!(
            error
                .downcast_ref::<super::RelayError>()
                .is_some_and(|error| matches!(error, super::RelayError::PolicyReloaded(_))),
            "{case_name}: {error}"
        );
        let committed = case_name == "normal-finish-streaming";
        if committed {
            assert!(
                client.starts_with(b"HTTP/1.1 200 OK\r\n"),
                "{case_name}: expected the response head to be committed"
            );
            let head_end = client
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
                .expect("committed response head");
            assert_eq!(
                &client[head_end..],
                b"",
                "{case_name}: stale response body reached the client"
            );
        } else {
            assert!(
                client.is_empty(),
                "{case_name}: stale middleware result reached the client"
            );
        }
        drop(correlation);

        let event = response_audit_event_for(&capture, &request_id);
        assert_eq!(
            event["unmapped"]["response_selection_cause"], "policy_reloaded",
            "{case_name}"
        );
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"], "cancelled_or_incomplete",
            "{case_name}"
        );
        assert_eq!(
            event["unmapped"]["upstream_response_code"], 200,
            "{case_name}"
        );
        if committed {
            assert_eq!(event["http_response"]["code"], 200, "{case_name}");
            assert_eq!(event["http_response"]["code"], 200, "{case_name}");
        } else {
            assert!(event.get("http_response").is_none(), "{case_name}");
            assert!(
                event["unmapped"]
                    .get("effective_http_status_code")
                    .is_none(),
                "{case_name}"
            );
        }
        assert_eq!(
            event["unmapped"]["delivery_started"], committed,
            "{case_name}"
        );
        assert_eq!(
            event["unmapped"]["partial_delivery"], committed,
            "{case_name}"
        );
        assert!(!capture.json_events().iter().any(|event| {
            event["finding_info"]["uid"] == "openshell.middleware.http_response_failure"
                && event["metadata"]["correlation_uid"] == request_id
        }));
        if case_name == "preflight" {
            assert!(event["unmapped"]["middleware_fail_closed"].is_null());
        }
    }
}

#[tokio::test]
async fn normalized_head_parse_failure_is_upstream_protocol_not_middleware_failure() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry()
        .with(capture.clone())
        .with(openshell_otel::layer(&provider, "response-head-failure"));
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let request_id = "response-head-parse-failure";
    let correlation = test_correlation(request_id);
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(StreamingResponseMiddleware {
            body_mode: HttpResponseBodyMode::HeadersOnly as i32,
            body_delay: None,
            mutate_headers: false,
        }));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/streaming-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let middleware = test_response_middleware(&runner, &chain, request_id);
    let mut upstream = &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Content-Length\r\n\r\n0\r\n\r\n"[..];
    let mut client = Vec::new();

    relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect("malformed normalized head gets a canonical 502");
    assert!(client.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
    drop(correlation);
    assert!(
        !exporter
            .get_finished_spans()
            .unwrap()
            .iter()
            .any(|span| { span.name == "openshell.middleware.response" }),
        "invalid upstream headers must not invent a cancelled middleware phase"
    );

    let event = response_audit_event_for(&capture, request_id);
    assert_eq!(
        event["unmapped"]["response_selection_cause"],
        "upstream_protocol_error"
    );
    assert!(
        event["unmapped"]["response_delivery_outcome"].is_null(),
        "completion is not claimed by the primary record"
    );
    assert_eq!(event["unmapped"]["upstream_response_code"], 200);
    assert_eq!(event["http_response"]["code"], 502);
    assert!(!capture.json_events().iter().any(|event| {
        event["finding_info"]["uid"] == "openshell.middleware.http_response_failure"
            && event["metadata"]["correlation_uid"] == request_id
    }));
    let events = capture.json_events();
    assert!(
        !events.iter().any(|event| {
            event["firewall_rule"]["type"] == "middleware-correlation"
                && event["metadata"]["correlation_uid"] == request_id
        }),
        "{events:#?}"
    );
}

#[tokio::test]
async fn streaming_response_middleware_aggregates_header_and_body_mutations() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
        &provider,
        "response-correlation-test",
    ));
    let correlation = tracing::subscriber::with_default(subscriber, || {
        test_correlation_for_method("response-streaming", "GET")
    });
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(StreamingResponseMiddleware {
            body_mode: HttpResponseBodyMode::StreamBytes as i32,
            body_delay: None,
            mutate_headers: true,
        }));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/streaming-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let middleware = HttpResponseMiddlewareRelay {
        chain: &chain,
        runner: &runner,
        request_context: RequestContext {
            request_id: "response-streaming".into(),
            sandbox_id: "sandbox-1".into(),
            ..Default::default()
        },
        target: HttpRequestTarget {
            scheme: "https".into(),
            host: "example.test".into(),
            port: 443,
            method: "GET".into(),
            path: "/data".into(),
            query: String::new(),
        },
        policy_name: "test-policy",
        generation_guard: None,
        whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
    };
    let body = vec![b'a'; 9_000];
    let mut response =
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    response.extend_from_slice(&body);
    let mut upstream = response.as_slice();
    let mut client = Vec::new();

    let outcome = relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect("streaming middleware response");

    assert!(matches!(outcome, RelayOutcome::Reusable));
    assert!(String::from_utf8_lossy(&client).contains("x-inspected: true\r\n"));
    assert!(
        String::from_utf8_lossy(&client).contains("x-openshell-request-id: response-streaming\r\n")
    );
    drop(correlation);

    let span = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .find(|span| span.name == "openshell.middleware.response")
        .expect("HTTP enforcement span");
    let attributes = span
        .attributes
        .into_iter()
        .map(|attribute| {
            (
                attribute.key.as_str().to_string(),
                attribute.value.to_string(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(attributes["openshell.middleware.outcome"], "allowed");
    assert_eq!(attributes["openshell.middleware.mutated"], "true");
    assert_eq!(attributes["openshell.middleware.fail_open"], "false");
    assert!(!attributes.contains_key("openshell.request.id"));
}

#[tokio::test]
async fn streaming_body_denial_records_partial_delivery() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry()
        .with(openshell_otel::layer(
            &provider,
            "response-correlation-test",
        ))
        .with(ocsf.clone());
    let _subscriber = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let correlation = test_correlation_for_method("response-partial-denial", "GET");
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(BodyResponseMiddleware {
            action: BodyTestAction::Block,
        }));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/body-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let middleware = HttpResponseMiddlewareRelay {
        chain: &chain,
        runner: &runner,
        request_context: RequestContext {
            request_id: "response-partial-denial".into(),
            sandbox_id: "sandbox-1".into(),
            ..Default::default()
        },
        target: HttpRequestTarget {
            scheme: "https".into(),
            host: "example.test".into(),
            port: 443,
            method: "GET".into(),
            path: "/data".into(),
            query: String::new(),
        },
        policy_name: "test-policy",
        generation_guard: None,
        whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
    };
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
    let mut client = Vec::new();

    let error = relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect_err("streaming body denial follows response commitment");
    assert!(error.to_string().contains("stopped delivery"), "{error}");
    assert!(client.starts_with(b"HTTP/1.1 200 OK\r\n"));
    drop(correlation);
    provider.force_flush().expect("flush spans");

    let span = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .find(|span| span.name == "openshell.middleware.response")
        .expect("HTTP enforcement span");
    let attributes = span
        .attributes
        .into_iter()
        .map(|attribute| {
            (
                attribute.key.as_str().to_string(),
                attribute.value.to_string(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(attributes["openshell.middleware.outcome"], "denied");
    assert_eq!(attributes["openshell.response.delivery_started"], "true");
    assert_eq!(attributes["openshell.response.partial_delivery"], "true");
    assert!(
        !ocsf
            .json_events()
            .iter()
            .any(|event| event["firewall_rule"]["type"] == "middleware-correlation"),
        "routine middleware aggregates are not separate audit records"
    );
}

#[tokio::test]
async fn stale_generation_preserves_skip_transform_observation() {
    use tracing_subscriber::layer::SubscriberExt as _;

    let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_simple_exporter(exporter.clone())
        .build();
    let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
        &provider,
        "response-correlation-test",
    ));
    let correlation = tracing::subscriber::with_default(subscriber, || {
        test_correlation_for_method("response-stale-transform", "GET")
    });
    let engine = Arc::new(
        crate::opa::OpaEngine::from_strings(
            include_str!("../../../../data/sandbox-policy.rego"),
            "network_policies: {}\n",
        )
        .expect("test policy"),
    );
    let generation_guard = engine
        .generation_guard(engine.current_generation())
        .expect("generation guard");
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(BodyResponseMiddleware {
            action: BodyTestAction::ReloadAndSkipTransform(Arc::clone(&engine)),
        }));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/body-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let middleware = HttpResponseMiddlewareRelay {
        chain: &chain,
        runner: &runner,
        request_context: RequestContext {
            request_id: "response-stale-transform".into(),
            sandbox_id: "sandbox-1".into(),
            ..Default::default()
        },
        target: HttpRequestTarget {
            scheme: "https".into(),
            host: "example.test".into(),
            port: 443,
            method: "GET".into(),
            path: "/data".into(),
            query: String::new(),
        },
        policy_name: "test-policy",
        generation_guard: Some(&generation_guard),
        whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
    };
    let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
    let mut client = Vec::new();

    let error = relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect_err("policy reload must stop the stale response");
    assert!(
        error.to_string().contains("policy generation is stale"),
        "{error}"
    );
    drop(correlation);
    provider.force_flush().expect("flush spans");

    let span = exporter
        .get_finished_spans()
        .expect("finished spans")
        .into_iter()
        .find(|span| span.name == "openshell.middleware.response")
        .expect("HTTP enforcement span");
    let attributes = span
        .attributes
        .into_iter()
        .map(|attribute| {
            (
                attribute.key.as_str().to_string(),
                attribute.value.to_string(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(attributes["openshell.middleware.outcome"], "incomplete");
    assert_eq!(attributes["openshell.middleware.mutated"], "true");
    assert_eq!(attributes["openshell.response.delivery_started"], "true");
    assert_eq!(attributes["openshell.response.partial_delivery"], "true");
}

#[test]
fn response_middleware_observation_maps_bounded_outcomes() {
    let invocation = |outcome| HttpResponseInvocation {
        config_name: "not-exported".into(),
        implementation: "not-exported".into(),
        outcome,
        sequence: None,
        input_size: 17,
        output_size: None,
        transformed: outcome
            == openshell_supervisor_middleware::HttpResponseInvocationOutcome::Transform,
        failed: false,
        stage_disabled: false,
        reason_code: None,
        failure_category: None,
    };
    let mut invocations = vec![
        invocation(openshell_supervisor_middleware::HttpResponseInvocationOutcome::Transform),
        invocation(openshell_supervisor_middleware::HttpResponseInvocationOutcome::FailOpen),
        invocation(openshell_supervisor_middleware::HttpResponseInvocationOutcome::FailClosed),
    ];
    let mut skip_transform =
        invocation(openshell_supervisor_middleware::HttpResponseInvocationOutcome::SkipRemaining);
    skip_transform.transformed = true;
    invocations.push(skip_transform);
    let observation = response_middleware_observation(&invocations, false, true);

    assert_eq!(
        observation,
        MiddlewareObservation {
            mutated: true,
            fail_open: true,
            fail_closed: true,
            admission_exhausted: true,
            ..Default::default()
        }
    );
}

#[test]
fn response_diagnostic_truncation_event_is_bounded() {
    let event = http_response_diagnostic_truncation_event(
        "test-policy",
        &HttpRequestTarget {
            scheme: "https".into(),
            host: "example.test".into(),
            port: 443,
            method: "GET".into(),
            path: "/private".into(),
            query: "secret=value".into(),
        },
    )
    .to_json()
    .expect("serialize truncation event");

    assert_eq!(event["severity"], "Low");
    assert_eq!(
        event["finding_info"]["uid"],
        "openshell.middleware.http_response_diagnostics_truncated"
    );
    assert_eq!(event["unmapped"]["phase"], "pre_return");
    let encoded = serde_json::to_string(&event).expect("encode truncation event");
    assert!(!encoded.contains("/private"));
    assert!(!encoded.contains("secret=value"));
}

#[tokio::test]
async fn upstream_receipt_is_replaced_by_platform_receipt() {
    let correlation = test_correlation("trusted");
    let mut upstream =
        &b"HTTP/1.1 200 OK\r\nX-OpenShell-Request-ID: forged\r\nContent-Length: 0\r\n\r\n"[..];
    let mut client = Vec::new();

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
    .expect("relay response");

    assert!(!String::from_utf8_lossy(&client).contains("forged"));
    assert!(String::from_utf8_lossy(&client).contains("x-openshell-request-id: trusted\r\n"));
    assert_eq!(request_id_header_count(&client), 1);
}

#[tokio::test]
async fn ordinary_response_removes_receipt_connection_nomination() {
    let correlation = test_correlation("trusted");
    let mut upstream = &b"HTTP/1.1 200 OK\r\n\
        Connection: X-OpenShell-Request-ID\r\n\
        cOnNeCtIoN: keep-alive, x-OpEnShElL-rEqUeSt-Id\r\n\
        X-OpenShell-Request-ID: forged-head\r\n\
        Trailer: x-openshell-request-id, X-Checksum\r\n\
        Transfer-Encoding: chunked\r\n\r\n\
        4\r\nbody\r\n\
        0\r\n\
        x-OPENshell-request-ID: forged-trailer\r\n\
        X-Checksum: ok\r\n\r\n"[..];
    let mut client = Vec::new();

    let outcome = relay_response(
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
    .expect("relay response");

    assert!(matches!(outcome, RelayOutcome::Reusable));
    let delivered = String::from_utf8(client).expect("HTTP response is UTF-8");
    let head = delivered
        .split_once("\r\n\r\n")
        .expect("response head terminator")
        .0;
    let connection_headers: Vec<_> = head
        .lines()
        .filter(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("connection"))
        })
        .collect();
    assert_eq!(connection_headers, ["cOnNeCtIoN: keep-alive"]);
    assert!(!delivered.contains("forged"), "{delivered}");
    assert!(head.contains("Trailer: X-Checksum"), "{head}");
    assert!(delivered.contains("0\r\nX-Checksum: ok\r\n\r\n"));
    assert!(head.contains("x-openshell-request-id: trusted"), "{head}");
    assert_eq!(request_id_header_count(delivered.as_bytes()), 1);
}

#[tokio::test]
async fn ordinary_response_rejects_folded_receipt_connection_nomination() {
    let correlation = test_correlation("trusted");
    let mut upstream = &b"HTTP/1.1 200 OK\r\nConnection: keep-alive,\r\n X-OpenShell-Request-ID\r\nContent-Length: 0\r\n\r\n"[..];
    let mut client = Vec::new();

    let error = relay_response(
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
    .expect_err("folded response fields must fail closed");

    assert!(
        error
            .to_string()
            .contains("response header continuation lines are not supported"),
        "{error}"
    );
    assert!(client.is_empty());
}

#[tokio::test]
async fn ordinary_response_rejects_bare_lf_receipt_smuggling() {
    let correlation = test_correlation("trusted");
    let mut upstream = &b"HTTP/1.1 200 OK\r\nX-Safe: yes\nX-OpenShell-Request-ID: forged\r\nContent-Length: 0\r\n\r\n"[..];
    let mut client = Vec::new();

    let error = relay_response(
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
    .expect_err("bare LF response fields must fail closed");

    assert!(error.to_string().contains("bare LF"), "{error}");
    assert!(client.is_empty());
}

#[test]
fn response_head_validation_rejects_malformed_syntax() {
    let cases: &[(&str, &[u8])] = &[
        ("incomplete block", b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n"),
        ("bare LF", b"HTTP/1.1 200 OK\r\nX-Test: yes\n\r\n"),
        ("bare CR", b"HTTP/1.1 200 OK\r\nX-Test: yes\rX: no\r\n\r\n"),
        (
            "obsolete fold",
            b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n continued\r\n\r\n",
        ),
        ("unsupported protocol", b"HTTP/2 200 OK\r\n\r\n"),
        ("invalid status range", b"HTTP/1.1 099 Nope\r\n\r\n"),
        ("non-numeric status", b"HTTP/1.1 2O0 Nope\r\n\r\n"),
        ("four-digit status", b"HTTP/1.1 2000 Nope\r\n\r\n"),
        ("missing reason separator", b"HTTP/1.1 200\r\n\r\n"),
        ("malformed field", b"HTTP/1.1 200 OK\r\nX-Test\r\n\r\n"),
        ("empty field name", b"HTTP/1.1 200 OK\r\n: value\r\n\r\n"),
        (
            "non-token field name",
            b"HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n",
        ),
        (
            "whitespace before colon",
            b"HTTP/1.1 200 OK\r\nX-Test : value\r\n\r\n",
        ),
        (
            "field control byte",
            b"HTTP/1.1 200 OK\r\nX-Test: value\x0bmore\r\n\r\n",
        ),
        (
            "field delete byte",
            b"HTTP/1.1 200 OK\r\nX-Test: value\x7f\r\n\r\n",
        ),
        ("reason control byte", b"HTTP/1.1 200 O\x00K\r\n\r\n"),
        (
            "early empty line",
            b"HTTP/1.1 200 OK\r\n\r\nX-Smuggled: yes\r\n\r\n",
        ),
    ];

    for (name, input) in cases {
        assert!(
            validate_http_response_header_block(input).is_err(),
            "{name} unexpectedly passed validation"
        );
    }
}

#[test]
fn response_head_validation_accepts_supported_informational_and_upgrade_responses() {
    for response in [
        &b"HTTP/1.0 200 OK\r\nX-Test: yes\r\n\r\n"[..],
        &b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"[..],
        &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"[..],
    ] {
        validate_http_response_header_block(response).expect("valid HTTP/1.x response head");
    }
}

#[tokio::test]
async fn response_middleware_rejects_forged_request_id_trailer() {
    let correlation = test_correlation("trusted");
    let runner =
        openshell_supervisor_middleware::ChainRunner::new(Arc::new(StreamingResponseMiddleware {
            body_mode: HttpResponseBodyMode::StreamBytes as i32,
            body_delay: None,
            mutate_headers: true,
        }));
    let chain = vec![openshell_supervisor_middleware::ChainEntry {
        name: "response".into(),
        implementation: "test/streaming-response".into(),
        order: 0,
        config: prost_types::Struct::default(),
        on_error: openshell_supervisor_middleware::OnError::FailClosed,
    }];
    let middleware = HttpResponseMiddlewareRelay {
        chain: &chain,
        runner: &runner,
        request_context: RequestContext {
            request_id: "middleware-request".into(),
            sandbox_id: "sandbox-1".into(),
            ..Default::default()
        },
        target: HttpRequestTarget {
            scheme: "https".into(),
            host: "example.test".into(),
            port: 443,
            method: "GET".into(),
            path: "/data".into(),
            query: String::new(),
        },
        policy_name: "test-policy",
        generation_guard: None,
        whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
    };
    let mut upstream = &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\nX-OpenShell-Request-ID: forged\r\n\r\n"[..];
    let mut client = Vec::new();

    let error = relay_response(
        "GET",
        &mut upstream,
        &mut client,
        RelayResponseOptions {
            correlation: Some(&correlation),
            ..Default::default()
        },
        Some(middleware),
    )
    .await
    .expect_err("platform correlation trailers must fail closed");

    assert!(
        error.to_string().contains("protected field name"),
        "{error}"
    );
    let delivered = String::from_utf8_lossy(&client);
    assert!(!delivered.contains("forged"), "{delivered}");
    assert!(
        delivered.contains("x-openshell-request-id: trusted\r\n"),
        "{delivered}"
    );
    assert_eq!(request_id_header_count(&client), 1);
}

#[test]
fn response_middleware_rejects_declared_request_id_trailer() {
    let error = parse_response_head_for_middleware(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-OpenShell-Request-ID\r\n\r\n",
    )
    .expect_err("platform correlation trailer declarations must fail closed");

    assert!(
        error.to_string().contains("protected trailer field"),
        "{error}"
    );
}

#[tokio::test]
async fn informational_responses_are_not_decorated_but_upgrade_receives_a_receipt() {
    let correlation = test_correlation("receipt-1");
    let mut upstream =
        &b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
    let mut client = Vec::new();

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
    .expect("relay response");
    assert!(client.starts_with(b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n"));
    assert_eq!(request_id_header_count(&client), 1);

    let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-OpenShell-Request-ID: forged\r\n\r\n"[..];
    let mut client = Vec::new();
    let outcome = relay_response(
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
    .expect("relay response");
    assert!(matches!(outcome, RelayOutcome::Upgraded { .. }));
    assert_eq!(request_id_header_count(&client), 1);
    assert!(!String::from_utf8_lossy(&client).contains("forged"));
    assert!(String::from_utf8_lossy(&client).contains("x-openshell-request-id: receipt-1\r\n"));
}

#[tokio::test]
async fn switching_protocols_removes_receipt_connection_nomination() {
    let correlation = test_correlation("trusted-upgrade");
    let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\n\
        Connection: X-OpenShell-Request-ID\r\n\
        cOnNeCtIoN: keep-alive, x-OpEnShElL-rEqUeSt-Id, UpGrAdE\r\n\
        Upgrade: websocket\r\n\
        X-OpenShell-Request-ID: forged\r\n\r\n"[..];
    let mut client = Vec::new();

    let outcome = relay_response(
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
    .expect("relay response");

    assert!(matches!(outcome, RelayOutcome::Upgraded { .. }));
    let delivered = String::from_utf8(client).expect("HTTP response is UTF-8");
    let connection_headers: Vec<_> = delivered
        .lines()
        .filter(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("connection"))
        })
        .collect();
    assert_eq!(connection_headers, ["cOnNeCtIoN: keep-alive, UpGrAdE"]);
    assert!(!delivered.contains("forged"), "{delivered}");
    assert!(
        delivered.contains("x-openshell-request-id: trusted-upgrade\r\n"),
        "{delivered}"
    );
    assert_eq!(request_id_header_count(delivered.as_bytes()), 1);
}

#[tokio::test]
async fn switching_protocols_rejects_folded_receipt_connection_nomination() {
    let correlation = test_correlation("trusted-upgrade");
    let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade,\r\n\tX-OpenShell-Request-ID\r\nUpgrade: websocket\r\n\r\n"[..];
    let mut client = Vec::new();

    let error = relay_response(
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
    .expect_err("folded upgrade fields must fail closed");

    assert!(
        error
            .to_string()
            .contains("response header continuation lines are not supported"),
        "{error}"
    );
    assert!(client.is_empty());
}

#[test]
fn http_10_connection_persistence() {
    let default_close = "HTTP/1.0 200 OK\r\nServer: test\r\n\r\n";
    assert!(response_is_http_10(default_close));
    assert!(!parse_connection_keep_alive(default_close));

    let keep_alive = "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\n";
    assert!(response_is_http_10(keep_alive));
    assert!(parse_connection_keep_alive(keep_alive));
}

#[test]
fn response_middleware_preflight_keeps_read_only_content_length() {
    let parsed = parse_response_head_for_middleware(
        b"HTTP/1.1 206 Partial Content\r\n\
          Content-Length: 5\r\n\
          Content-Encoding: gzip\r\n\
          Content-Range: bytes 0-4/10\r\n\
          Connection: x-hop\r\n\
          X-Hop: omitted\r\n\r\n",
    )
    .expect("parse response head");

    assert_eq!(
        parsed.headers,
        vec![
            HttpHeader {
                name: "content-length".into(),
                value: "5".into(),
            },
            HttpHeader {
                name: "content-encoding".into(),
                value: "gzip".into(),
            },
            HttpHeader {
                name: "content-range".into(),
                value: "bytes 0-4/10".into(),
            },
        ]
    );

    let nominated = parse_response_head_for_middleware(
        b"HTTP/1.1 200 OK\r\nConnection: Content-Length\r\nContent-Length: 5\r\n\r\n",
    )
    .expect("parse nominated response head");
    assert!(nominated.headers.is_empty());
}

#[test]
fn response_middleware_serializes_only_relay_owned_framing() {
    let headers = vec![
        HttpHeader {
            name: "content-length".into(),
            value: "999".into(),
        },
        HttpHeader {
            name: "Content-Length".into(),
            value: "998".into(),
        },
        HttpHeader {
            name: "content-type".into(),
            value: "text/plain".into(),
        },
    ];

    for (framing, expected) in [
        (
            ResponseFraming::Preserve(BodyLength::ContentLength(5)),
            Some("Content-Length: 5\r\n"),
        ),
        (
            ResponseFraming::ContentLength(9),
            Some("Content-Length: 9\r\n"),
        ),
        (ResponseFraming::Chunked, None),
        (ResponseFraming::Preserve(BodyLength::None), None),
    ] {
        let serialized = String::from_utf8(serialize_response_head(
            "HTTP/1.1 200 OK",
            &headers,
            &[],
            framing,
            false,
            &[],
        ))
        .expect("serialized response head");

        assert_eq!(
            serialized
                .lines()
                .filter(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                .count(),
            usize::from(expected.is_some())
        );
        if let Some(expected) = expected {
            assert!(serialized.contains(expected));
        }
        if matches!(framing, ResponseFraming::Chunked) {
            assert!(serialized.contains("Transfer-Encoding: chunked\r\n"));
        }
    }
}
