// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::middleware::{
    HttpRequestHookResultStream, HttpRequestView, HttpResponseHookResultStream,
    HttpResponseResultStream, SupervisorMiddlewareEndpoint, WebSocketResponseStream,
};
use openshell_core::proto::middleware::v1::http_hooks_client::HttpHooksClient;
use openshell_core::proto::middleware::v1::http_response_pre_return_client::HttpResponsePreReturnClient;
use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestHookEvent, HttpRequestResult, HttpResponseEvent,
    HttpResponseHookEvent, MiddlewareDescribeRequest, MiddlewareManifest, ValidateConfigRequest,
    ValidateConfigResponse, WebSocketSessionEvent,
};
use openshell_extension_core::{
    BearerTokenInterceptor, BearerTokenSlot, ExtensionChannelConfig, ExtensionServerTrust,
    connect_channel,
};
use std::sync::Arc;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};
use tracing::{Instrument as _, Span};

use crate::MIDDLEWARE_GRPC_MESSAGE_BYTES;

type ExtensionChannel = InterceptedService<Channel, BearerTokenInterceptor>;

fn http_rpc_span(operation: &'static str) -> Span {
    tracing::info_span!(
        "middleware_rpc",
        otel.name = operation,
        otel.kind = "client",
        otel.status_code = tracing::field::Empty,
        rpc.system.name = "grpc",
        rpc.method = operation,
        rpc.response.status_code = tracing::field::Empty,
        error.type = tracing::field::Empty,
    )
}

fn traced_request<T>(request: Request<T>) -> std::result::Result<Request<T>, Status> {
    use tonic::service::Interceptor as _;

    let (metadata, extensions, message) = request.into_parts();
    let mut context = Request::from_parts(metadata, extensions, ());
    context.metadata_mut().remove("traceparent");
    context.metadata_mut().remove("tracestate");
    let context = openshell_otel::TraceContextInterceptor.call(context)?;
    let (metadata, extensions, ()) = context.into_parts();
    Ok(Request::from_parts(metadata, extensions, message))
}

fn traced_response_stream<T: Send + 'static>(
    response: std::result::Result<Response<tonic::Streaming<T>>, Status>,
    span: Span,
) -> std::result::Result<openshell_otel::BoxGrpcStream<T>, Status> {
    match response {
        Ok(response) => Ok(Box::pin(openshell_otel::TracedGrpcStream::new(
            response.into_inner(),
            span,
        ))),
        Err(status) => {
            openshell_otel::record_grpc_status(&span, status.code());
            Err(status)
        }
    }
}

/// Adapts the borrowed runtime request contract to the owned protobuf service
/// contract only when dispatch crosses a gRPC-shaped boundary.
#[derive(Clone)]
pub struct GrpcMiddlewareService {
    service: Arc<dyn SupervisorMiddlewareEndpoint>,
}

impl GrpcMiddlewareService {
    /// Connect an operator registration and wrap its generated gRPC client.
    pub async fn connect(
        registration_name: &str,
        grpc_endpoint: &str,
        tls_ca_cert_pem: &[u8],
        bearer: Option<BearerTokenSlot>,
    ) -> Result<Self> {
        Ok(Self {
            service: Arc::new(
                RemoteMiddlewareService::connect(
                    registration_name,
                    grpc_endpoint,
                    tls_ca_cert_pem,
                    bearer,
                )
                .await?,
            ),
        })
    }

    /// Wrap a protobuf-shaped service used by transport-boundary tests.
    #[cfg(test)]
    pub fn from_service(service: Arc<dyn SupervisorMiddlewareEndpoint>) -> Self {
        Self { service }
    }

    /// Forward a manifest request through the protobuf service contract.
    pub async fn describe(&self) -> std::result::Result<Response<MiddlewareManifest>, Status> {
        self.service
            .describe(Request::new(MiddlewareDescribeRequest {
                gateway: Some(openshell_core::extension_protocol::gateway_metadata(
                    openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                )),
            }))
            .await
    }

    /// Materialize the owned configuration request required by gRPC.
    pub async fn validate_config(
        &self,
        middleware_name: &str,
        config: &prost_types::Struct,
    ) -> std::result::Result<Response<ValidateConfigResponse>, Status> {
        self.service
            .validate_config(Request::new(ValidateConfigRequest {
                config: Some(config.clone()),
                middleware_name: middleware_name.to_string(),
            }))
            .await
    }

    /// Materialize an owned protobuf evaluation immediately before transport.
    pub async fn evaluate_http_request(
        &self,
        request: HttpRequestView<'_>,
    ) -> std::result::Result<Response<HttpRequestResult>, Status> {
        self.service
            .evaluate_http_request(Request::new(HttpRequestEvaluation {
                phase: request.phase() as i32,
                context: Some(request.context().clone()),
                config: Some(request.config().clone()),
                target: Some(request.target().clone()),
                headers: request.headers().to_vec(),
                body: request.body().to_vec(),
                middleware_name: request.middleware_name().to_string(),
            }))
            .await
    }

    /// Open a remote WebSocket middleware stream through the gRPC adapter.
    pub async fn open_websocket_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<WebSocketSessionEvent>,
    ) -> std::result::Result<WebSocketResponseStream, Status> {
        self.service.open_websocket_session(receiver).await
    }

    /// Open a remote HTTP response pre-return stream through the gRPC adapter.
    pub async fn open_http_response_pre_return(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseEvent>,
    ) -> std::result::Result<HttpResponseResultStream, Status> {
        self.service.open_http_response_pre_return(receiver).await
    }

    /// Open a remote HTTP hook request exchange through the gRPC
    /// adapter.
    pub async fn open_http_request_hook(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpRequestHookEvent>,
    ) -> std::result::Result<HttpRequestHookResultStream, Status> {
        self.service.open_http_request_hook(receiver).await
    }

    /// Open a remote HTTP hook response exchange through the gRPC
    /// adapter.
    pub async fn open_http_response_hook(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseHookEvent>,
    ) -> std::result::Result<HttpResponseHookResultStream, Status> {
        self.service.open_http_response_hook(receiver).await
    }
}

#[derive(Clone)]
pub struct RemoteMiddlewareService {
    client: SupervisorMiddlewareClient<ExtensionChannel>,
    response_client: HttpResponsePreReturnClient<ExtensionChannel>,
    http_hooks_client: HttpHooksClient<ExtensionChannel>,
}

impl RemoteMiddlewareService {
    pub async fn connect(
        registration_name: &str,
        grpc_endpoint: &str,
        tls_ca_cert_pem: &[u8],
        bearer: Option<BearerTokenSlot>,
    ) -> Result<Self> {
        let mut config = ExtensionChannelConfig::new(grpc_endpoint);
        if !tls_ca_cert_pem.is_empty() {
            config = config
                .with_server_trust(ExtensionServerTrust::CustomCaPem(tls_ca_cert_pem.to_vec()));
        }
        let channel = connect_channel(&config)
            .await
            .into_diagnostic()
            .wrap_err_with(|| {
                format!(
                    "middleware registration '{registration_name}' could not connect to {grpc_endpoint}"
                )
            })?;
        let interceptor =
            bearer.map_or_else(BearerTokenInterceptor::disabled, |slot| slot.interceptor());
        let channel = InterceptedService::new(channel, interceptor);

        Ok(Self {
            client: SupervisorMiddlewareClient::new(channel.clone())
                .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
            response_client: HttpResponsePreReturnClient::new(channel.clone())
                .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
            http_hooks_client: HttpHooksClient::new(channel)
                .max_decoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES)
                .max_encoding_message_size(MIDDLEWARE_GRPC_MESSAGE_BYTES),
        })
    }
}

#[tonic::async_trait]
impl SupervisorMiddlewareEndpoint for RemoteMiddlewareService {
    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> std::result::Result<Response<MiddlewareManifest>, Status> {
        let mut client = self.client.clone();
        client.describe(request).await
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> std::result::Result<Response<ValidateConfigResponse>, Status> {
        let mut client = self.client.clone();
        client.validate_config(request).await
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> std::result::Result<Response<HttpRequestResult>, Status> {
        let mut client = self.client.clone();
        let span =
            http_rpc_span("openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest");
        let result = async {
            let guard = openshell_otel::ErrorStatusGuard::current();
            let request = traced_request(request)?;
            // Legacy HTTP hooks stay callable until their removal in 0.2.0.
            #[allow(deprecated)]
            guard.finish(client.evaluate_http_request(request).await)
        }
        .instrument(span.clone())
        .await;
        openshell_otel::record_grpc_status(
            &span,
            result
                .as_ref()
                .map_or_else(Status::code, |_| tonic::Code::Ok),
        );
        result
    }

    async fn open_websocket_session(
        &self,
        receiver: tokio::sync::mpsc::Receiver<WebSocketSessionEvent>,
    ) -> std::result::Result<WebSocketResponseStream, Status> {
        let mut client = self.client.clone();
        let responses = client
            .evaluate_web_socket_session(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .await?
            .into_inner();
        Ok(Box::pin(responses))
    }

    async fn open_http_response_pre_return(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseEvent>,
    ) -> std::result::Result<HttpResponseResultStream, Status> {
        let mut client = self.response_client.clone();
        let span = http_rpc_span("openshell.middleware.v1.HttpResponsePreReturn/Evaluate");
        let response = async {
            let guard = openshell_otel::ErrorStatusGuard::current();
            let request = traced_request(Request::new(
                tokio_stream::wrappers::ReceiverStream::new(receiver),
            ))?;
            // Legacy HTTP hooks stay callable until their removal in 0.2.0.
            #[allow(deprecated)]
            guard.finish(client.evaluate(request).await)
        }
        .instrument(span.clone())
        .await;
        traced_response_stream(response, span)
    }

    async fn open_http_request_hook(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpRequestHookEvent>,
    ) -> std::result::Result<HttpRequestHookResultStream, Status> {
        let mut client = self.http_hooks_client.clone();
        let span = http_rpc_span("openshell.middleware.v1.HttpHooks/EvaluateHttpRequestHook");
        let response = async {
            let guard = openshell_otel::ErrorStatusGuard::current();
            let request = traced_request(Request::new(
                tokio_stream::wrappers::ReceiverStream::new(receiver),
            ))?;
            guard.finish(client.evaluate_http_request_hook(request).await)
        }
        .instrument(span.clone())
        .await;
        traced_response_stream(response, span)
    }

    async fn open_http_response_hook(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseHookEvent>,
    ) -> std::result::Result<HttpResponseHookResultStream, Status> {
        let mut client = self.http_hooks_client.clone();
        let span = http_rpc_span("openshell.middleware.v1.HttpHooks/EvaluateHttpResponseHook");
        let response = async {
            let guard = openshell_otel::ErrorStatusGuard::current();
            let request = traced_request(Request::new(
                tokio_stream::wrappers::ReceiverStream::new(receiver),
            ))?;
            guard.finish(client.evaluate_http_response_hook(request).await)
        }
        .instrument(span.clone())
        .await;
        traced_response_stream(response, span)
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use openshell_core::proto::middleware::v1::http_hooks_server::{HttpHooks, HttpHooksServer};
    use openshell_core::proto::{
        HttpContinue, HttpDenial, HttpPreflightResult, HttpRequestHookPreflight,
        HttpRequestHookResult, HttpResponseHookPreflight, HttpResponseHookResult,
        SupervisorMiddlewarePhase, http_preflight_result, http_request_hook_event,
        http_request_hook_result, http_response_hook_event, http_response_hook_result,
    };
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use tracing::instrument::WithSubscriber as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    struct HttpHooksService;

    fn continue_without_body() -> HttpPreflightResult {
        HttpPreflightResult {
            decision: Some(http_preflight_result::Decision::ContinueWithoutBody(
                HttpContinue::default(),
            )),
            ..Default::default()
        }
    }

    #[tonic::async_trait]
    impl HttpHooks for HttpHooksService {
        type EvaluateHttpRequestHookStream = HttpRequestHookResultStream;
        type EvaluateHttpResponseHookStream = HttpResponseHookResultStream;

        async fn evaluate_http_request_hook(
            &self,
            request: Request<tonic::Streaming<HttpRequestHookEvent>>,
        ) -> std::result::Result<Response<Self::EvaluateHttpRequestHookStream>, Status> {
            let event = request
                .into_inner()
                .message()
                .await?
                .expect("request event");
            let Some(http_request_hook_event::Event::Preflight(preflight)) = event.event else {
                panic!("expected request preflight");
            };
            assert_eq!(
                preflight.phase,
                SupervisorMiddlewarePhase::PreCredentials as i32
            );
            if preflight.middleware_name == "rpc-error" {
                return Err(Status::unavailable("private-error-sentinel"));
            }
            let result = if preflight.middleware_name == "deny" {
                http_request_hook_result::Result::Deny(HttpDenial::default())
            } else {
                http_request_hook_result::Result::PreflightResult(continue_without_body())
            };
            Ok(Response::new(Box::pin(futures::stream::iter([Ok(
                HttpRequestHookResult {
                    result: Some(result),
                },
            )]))))
        }

        async fn evaluate_http_response_hook(
            &self,
            request: Request<tonic::Streaming<HttpResponseHookEvent>>,
        ) -> std::result::Result<Response<Self::EvaluateHttpResponseHookStream>, Status> {
            let event = request
                .into_inner()
                .message()
                .await?
                .expect("response event");
            let Some(http_response_hook_event::Event::Preflight(preflight)) = event.event else {
                panic!("expected response preflight");
            };
            assert_eq!(preflight.phase, SupervisorMiddlewarePhase::PreReturn as i32);
            Ok(Response::new(Box::pin(futures::stream::iter([Ok(
                HttpResponseHookResult {
                    result: Some(http_response_hook_result::Result::PreflightResult(
                        continue_without_body(),
                    )),
                },
            )]))))
        }
    }

    #[test]
    fn requests_without_active_context_discard_stale_trace_headers_only() {
        tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
            let mut request = Request::new("unchanged body");
            request
                .metadata_mut()
                .insert("traceparent", "forged".parse().unwrap());
            request
                .metadata_mut()
                .insert("tracestate", "forged=value".parse().unwrap());
            request
                .metadata_mut()
                .insert("authorization", "Bearer unchanged".parse().unwrap());
            let request = traced_request(request).unwrap();
            assert!(request.metadata().get("traceparent").is_none());
            assert!(request.metadata().get("tracestate").is_none());
            assert_eq!(
                request.metadata().get("authorization").unwrap(),
                "Bearer unchanged"
            );
            assert_eq!(request.into_inner(), "unchanged body");
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn http_hooks_rpcs_share_channel_and_rotating_bearer() {
        let _tracing_lock = openshell_otel_test_support::tracing_test_lock().await;
        let collector = openshell_otel_test_support::OtlpTestServer::start().await;
        let provider = openshell_otel::build_provider(&openshell_otel::OtlpExportConfig {
            endpoint: collector.endpoint(),
            service_name: openshell_otel::ServiceName::Fixed("middleware-rpc-test"),
            service_version: None,
            resource_attributes: Vec::new(),
        })
        .unwrap();
        let subscriber = tracing::Dispatch::new(tracing_subscriber::registry().with(
            openshell_otel::layer_for_target_prefix(
                &provider,
                "middleware-test",
                "openshell_supervisor_middleware",
            ),
        ));
        exercise_http_hooks(&provider, collector)
            .with_subscriber(subscriber)
            .await;
    }

    async fn exercise_http_hooks(
        provider: &openshell_otel::SdkTracerProvider,
        collector: openshell_otel_test_support::OtlpTestServer,
    ) {
        let phase = tracing::info_span!("test.middleware.phase");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let (authorization_tx, mut authorization_rx) = mpsc::unbounded_channel();
        let (context_tx, mut context_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(HttpHooksServer::with_interceptor(
                    HttpHooksService,
                    move |request: Request<()>| {
                        context_tx
                            .send((
                                request
                                    .metadata()
                                    .get("traceparent")
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_owned),
                                request
                                    .metadata()
                                    .get("tracestate")
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_owned),
                            ))
                            .unwrap();
                        authorization_tx
                            .send(
                                request
                                    .metadata()
                                    .get("authorization")
                                    .expect("authorization metadata")
                                    .to_str()
                                    .expect("ASCII authorization")
                                    .to_owned(),
                            )
                            .expect("record authorization");
                        Ok(request)
                    },
                ))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve");
        });
        let bearer = BearerTokenSlot::new("request-token", i64::MAX).expect("bearer");
        let client = RemoteMiddlewareService::connect(
            "test/http-hooks",
            &format!("http://{address}"),
            &[],
            Some(bearer.clone()),
        )
        .await
        .expect("connect");

        let (request_tx, request_rx) = mpsc::channel(1);
        request_tx
            .send(HttpRequestHookEvent {
                event: Some(http_request_hook_event::Event::Preflight(
                    HttpRequestHookPreflight {
                        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                        ..Default::default()
                    },
                )),
            })
            .await
            .expect("send request");
        drop(request_tx);
        let mut requests = client
            .open_http_request_hook(request_rx)
            .instrument(phase.clone())
            .await
            .expect("request RPC");
        assert_eq!(
            requests
                .next()
                .await
                .expect("request result")
                .expect("request status")
                .result,
            Some(http_request_hook_result::Result::PreflightResult(
                continue_without_body()
            ))
        );
        assert_eq!(
            authorization_rx.recv().await.as_deref(),
            Some("Bearer request-token")
        );
        provider.force_flush().unwrap();
        assert!(
            collector.received().spans.is_empty(),
            "the RPC is not complete before stream EOS"
        );
        assert!(requests.next().await.is_none());
        let mut contexts = vec![(context_rx.recv().await.unwrap(), Some("OK"))];

        bearer
            .update("response-token", i64::MAX)
            .expect("rotate bearer");
        let (response_tx, response_rx) = mpsc::channel(1);
        response_tx
            .send(HttpResponseHookEvent {
                event: Some(http_response_hook_event::Event::Preflight(
                    HttpResponseHookPreflight {
                        phase: SupervisorMiddlewarePhase::PreReturn as i32,
                        ..Default::default()
                    },
                )),
            })
            .await
            .expect("send response");
        drop(response_tx);
        let mut responses = client
            .open_http_response_hook(response_rx)
            .instrument(phase.clone())
            .await
            .expect("response RPC");
        assert_eq!(
            responses
                .next()
                .await
                .expect("response result")
                .expect("response status")
                .result,
            Some(http_response_hook_result::Result::PreflightResult(
                continue_without_body()
            ))
        );
        assert_eq!(
            authorization_rx.recv().await.as_deref(),
            Some("Bearer response-token")
        );
        assert!(responses.next().await.is_none());
        contexts.push((context_rx.recv().await.unwrap(), Some("OK")));

        for (mode, expected_status) in [
            ("rpc-error", Some("UNAVAILABLE")),
            ("deny", Some("OK")),
            ("drop", None),
        ] {
            let (tx, rx) = mpsc::channel(1);
            tx.send(HttpRequestHookEvent {
                event: Some(http_request_hook_event::Event::Preflight(
                    HttpRequestHookPreflight {
                        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                        middleware_name: mode.into(),
                        ..Default::default()
                    },
                )),
            })
            .await
            .unwrap();
            drop(tx);
            let result = client
                .open_http_request_hook(rx)
                .instrument(phase.clone())
                .await;
            if mode == "rpc-error" {
                let error = result.err().expect("transport failure");
                assert_eq!(error.code(), tonic::Code::Unavailable);
                assert_eq!(error.message(), "private-error-sentinel");
            } else {
                let mut stream = result.unwrap();
                let result = stream.next().await.unwrap().unwrap();
                if mode == "deny" {
                    assert!(matches!(
                        result.result,
                        Some(http_request_hook_result::Result::Deny(_))
                    ));
                    assert!(stream.next().await.is_none());
                }
                // Dropping before EOS must not invent a successful terminal status.
            }
            assert_eq!(
                authorization_rx.recv().await.as_deref(),
                Some("Bearer response-token")
            );
            contexts.push((context_rx.recv().await.unwrap(), expected_status));
        }

        drop((requests, responses, client));
        drop(phase);
        shutdown_tx.send(()).expect("shutdown");
        server.await.expect("server task");
        provider.force_flush().unwrap();
        provider.shutdown().unwrap();
        let received = collector.shutdown().await;
        let phase = received
            .spans
            .iter()
            .find(|span| span.name == "test.middleware.phase")
            .unwrap();
        assert_eq!(received.spans.len(), 6);
        for ((context, state), expected_status) in contexts {
            assert!(state.as_deref().unwrap_or_default().is_empty());
            let context = context.expect("trusted RPC trace context");
            let rpc = received
                .spans
                .iter()
                .find(|span| {
                    context == format!("00-{}-{}-01", hex(&span.trace_id), hex(&span.span_id))
                })
                .expect("carrier identifies the actual RPC span");
            assert_eq!(rpc.parent_span_id, phase.span_id);
            assert!(rpc.name.starts_with("openshell.middleware.v1.HttpHooks/"));
            if let Some(status) = expected_status {
                assert!(rpc.attributes.contains(
                    &openshell_otel_test_support::relay::string_attribute(
                        "rpc.response.status_code",
                        status
                    )
                ));
            } else {
                assert!(
                    !rpc.attributes
                        .iter()
                        .any(|attribute| attribute.key == "rpc.response.status_code")
                );
            }
        }
        let spans = format!("{:?}", received.spans);
        for secret in ["request-token", "response-token", "private-error-sentinel"] {
            assert!(!spans.contains(secret));
        }
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(value, "{byte:02x}").unwrap();
        }
        value
    }
}
