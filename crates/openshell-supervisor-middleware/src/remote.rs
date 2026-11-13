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
use tracing::Instrument as _;

use crate::MIDDLEWARE_GRPC_MESSAGE_BYTES;

type ExtensionChannel = InterceptedService<Channel, MiddlewareClientInterceptor>;

fn rpc_span(method: &'static str) -> tracing::Span {
    tracing::info_span!(
        "openshell.middleware.rpc",
        otel.kind = "client",
        rpc.system.name = "grpc",
        rpc.method = method,
        rpc.response.status_code = tracing::field::Empty,
        error.type = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
    )
}

#[derive(Clone, Debug)]
struct MiddlewareClientInterceptor {
    bearer: BearerTokenInterceptor,
    trace_context: openshell_otel::TraceContextInterceptor,
}

impl MiddlewareClientInterceptor {
    fn new(bearer: BearerTokenInterceptor) -> Self {
        Self {
            bearer,
            trace_context: openshell_otel::TraceContextInterceptor,
        }
    }
}

impl tonic::service::Interceptor for MiddlewareClientInterceptor {
    fn call(&mut self, mut request: Request<()>) -> std::result::Result<Request<()>, Status> {
        request.metadata_mut().remove("traceparent");
        request.metadata_mut().remove("tracestate");
        let request = tonic::service::Interceptor::call(&mut self.bearer, request)?;
        tonic::service::Interceptor::call(&mut self.trace_context, request)
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
        let channel =
            InterceptedService::new(channel, MiddlewareClientInterceptor::new(interceptor));

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
        let span = rpc_span("EvaluateHttpRequest");
        // Legacy HTTP hooks stay callable until their removal in 0.2.0.
        #[allow(deprecated)]
        let result = client
            .evaluate_http_request(request)
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
        let span = rpc_span("EvaluateWebSocketSession");
        let responses = client
            .evaluate_web_socket_session(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .instrument(span.clone())
            .await
            .inspect_err(|status| openshell_otel::record_grpc_status(&span, status.code()))?
            .into_inner();
        Ok(Box::pin(openshell_otel::TracedGrpcStream::new(
            responses, span,
        )))
    }

    async fn open_http_response_pre_return(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseEvent>,
    ) -> std::result::Result<HttpResponseResultStream, Status> {
        let mut client = self.response_client.clone();
        let span = rpc_span("HttpResponsePreReturn");
        // Legacy HTTP hooks stay callable until their removal in 0.2.0.
        #[allow(deprecated)]
        let responses = client
            .evaluate(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .instrument(span.clone())
            .await
            .inspect_err(|status| openshell_otel::record_grpc_status(&span, status.code()))?
            .into_inner();
        Ok(Box::pin(openshell_otel::TracedGrpcStream::new(
            responses, span,
        )))
    }

    async fn open_http_request_hook(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpRequestHookEvent>,
    ) -> std::result::Result<HttpRequestHookResultStream, Status> {
        let mut client = self.http_hooks_client.clone();
        let span = rpc_span("EvaluateHttpRequestHook");
        let responses = client
            .evaluate_http_request_hook(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .instrument(span.clone())
            .await
            .inspect_err(|status| openshell_otel::record_grpc_status(&span, status.code()))?
            .into_inner();
        Ok(Box::pin(openshell_otel::TracedGrpcStream::new(
            responses, span,
        )))
    }

    async fn open_http_response_hook(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseHookEvent>,
    ) -> std::result::Result<HttpResponseHookResultStream, Status> {
        let mut client = self.http_hooks_client.clone();
        let span = rpc_span("EvaluateHttpResponseHook");
        let responses = client
            .evaluate_http_response_hook(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .instrument(span.clone())
            .await
            .inspect_err(|status| openshell_otel::record_grpc_status(&span, status.code()))?
            .into_inner();
        Ok(Box::pin(openshell_otel::TracedGrpcStream::new(
            responses, span,
        )))
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use openshell_core::proto::middleware::v1::http_hooks_server::{HttpHooks, HttpHooksServer};
    use openshell_core::proto::{
        HttpContinue, HttpPreflightResult, HttpRequestHookPreflight, HttpRequestHookResult,
        HttpResponseHookPreflight, HttpResponseHookResult, SupervisorMiddlewarePhase,
        http_preflight_result, http_request_hook_event, http_request_hook_result,
        http_response_hook_event, http_response_hook_result,
    };
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use tracing::instrument::WithSubscriber as _;

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
            let deny = preflight.middleware_name == "hold-after-deny";
            let hold = deny || preflight.middleware_name == "hold-after-continue";
            let result = HttpRequestHookResult {
                result: Some(if deny {
                    http_request_hook_result::Result::Deny(
                        openshell_core::proto::HttpDenial::default(),
                    )
                } else {
                    http_request_hook_result::Result::PreflightResult(continue_without_body())
                }),
            };
            let results = futures::stream::iter([Ok(result)]);
            if hold {
                Ok(Response::new(Box::pin(
                    results.chain(futures::stream::pending()),
                )))
            } else {
                Ok(Response::new(Box::pin(results)))
            }
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

    #[tokio::test]
    async fn http_hooks_rpcs_share_channel_bearer_and_phase_context() {
        let captured = ClosedSpans::default();
        let provider = openshell_otel::SdkTracerProvider::builder().build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(
                &provider,
                "middleware-http-hooks-test",
            ))
            .with(captured.clone());
        async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let address = listener.local_addr().expect("address");
            let (authorization_tx, mut authorization_rx) = mpsc::unbounded_channel();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let server = tokio::spawn(async move {
                Server::builder()
                    .add_service(HttpHooksServer::with_interceptor(
                        HttpHooksService,
                        move |request: Request<()>| {
                            authorization_tx
                                .send((
                                    request
                                        .metadata()
                                        .get("authorization")
                                        .expect("authorization metadata")
                                        .to_str()
                                        .expect("ASCII authorization")
                                        .to_owned(),
                                    request
                                        .metadata()
                                        .get("traceparent")
                                        .expect("trace context")
                                        .to_str()
                                        .expect("ASCII trace context")
                                        .to_owned(),
                                ))
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
            let phase = tracing::info_span!("middleware.request");
            let expected = phase
                .in_scope(openshell_otel::current_trace_context_carrier)
                .expect("phase trace context");
            let mut requests = client
                .open_http_request_hook(request_rx)
                .instrument(phase)
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
            let (authorization, traceparent) =
                authorization_rx.recv().await.expect("request metadata");
            assert_eq!(authorization, "Bearer request-token");
            assert_eq!(
                traceparent.split('-').nth(1),
                expected["traceparent"].split('-').nth(1)
            );
            assert_ne!(traceparent, expected["traceparent"]);
            assert!(captured.0.lock().unwrap().is_empty());

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
            let phase = tracing::info_span!("middleware.response");
            let expected = phase
                .in_scope(openshell_otel::current_trace_context_carrier)
                .expect("phase trace context");
            let mut responses = client
                .open_http_response_hook(response_rx)
                .instrument(phase)
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
            let (authorization, traceparent) =
                authorization_rx.recv().await.expect("response metadata");
            assert_eq!(authorization, "Bearer response-token");
            assert_eq!(
                traceparent.split('-').nth(1),
                expected["traceparent"].split('-').nth(1)
            );
            assert_ne!(traceparent, expected["traceparent"]);
            assert!(captured.0.lock().unwrap().is_empty());
            assert!(requests.next().await.is_none());
            assert!(responses.next().await.is_none());

            drop((requests, responses, client));
            shutdown_tx.send(()).expect("shutdown");
            server.await.expect("server task");
        }
        .with_subscriber(subscriber)
        .await;
        provider.shutdown().expect("shutdown provider");
        let spans = captured.0.lock().unwrap();
        assert_eq!(spans.len(), 2);
        for (span, parent) in spans
            .iter()
            .zip(["middleware.request", "middleware.response"])
        {
            assert_eq!(span.get("parent.name").map(String::as_str), Some(parent));
            assert_eq!(
                span.get("rpc.response.status_code").map(String::as_str),
                Some("\"OK\"")
            );
        }
    }
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use tonic::service::Interceptor as _;
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::registry::LookupSpan;

    #[derive(Default)]
    struct Fields(BTreeMap<String, String>);

    impl Visit for Fields {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    #[derive(Clone, Default)]
    struct ClosedSpans(Arc<Mutex<Vec<BTreeMap<String, String>>>>);

    impl<S: tracing::Subscriber + for<'a> LookupSpan<'a>> Layer<S> for ClosedSpans {
        fn on_new_span(
            &self,
            attributes: &tracing::span::Attributes<'_>,
            id: &tracing::Id,
            context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut fields = Fields::default();
            attributes.record(&mut fields);
            let span = context.span(id).unwrap();
            if let Some(parent) = span.parent() {
                fields.0.insert(
                    "parent.name".to_string(),
                    parent.metadata().name().to_string(),
                );
            }
            span.extensions_mut().insert(fields);
        }

        fn on_record(
            &self,
            id: &tracing::Id,
            values: &tracing::span::Record<'_>,
            context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            values.record(
                context
                    .span(id)
                    .unwrap()
                    .extensions_mut()
                    .get_mut::<Fields>()
                    .unwrap(),
            );
        }

        fn on_close(&self, id: tracing::Id, context: tracing_subscriber::layer::Context<'_, S>) {
            let span = context.span(&id).unwrap();
            if span.metadata().name() == "openshell.middleware.rpc" {
                self.0
                    .lock()
                    .unwrap()
                    .push(span.extensions().get::<Fields>().unwrap().0.clone());
            }
        }
    }

    #[tokio::test]
    async fn policy_denial_is_rpc_success_and_stream_span_outlives_headers() {
        use openshell_core::proto::{HttpDenial, HttpRequestHookResult, http_request_hook_result};

        let captured = ClosedSpans::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());
        async {
            let span = rpc_span("EvaluateHttpRequestHook");
            let denial = HttpRequestHookResult {
                result: Some(http_request_hook_result::Result::Deny(HttpDenial::default())),
            };
            let mut results =
                openshell_otel::TracedGrpcStream::new(futures::stream::iter([Ok(denial)]), span);
            assert!(captured.0.lock().unwrap().is_empty());
            assert!(matches!(
                results.next().await.unwrap().unwrap().result,
                Some(http_request_hook_result::Result::Deny(_))
            ));
            assert!(captured.0.lock().unwrap().is_empty());
            assert!(results.next().await.is_none());
            drop(results);
        }
        .with_subscriber(subscriber)
        .await;
        let spans = captured.0.lock().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].get("rpc.response.status_code").map(String::as_str),
            Some("\"OK\"")
        );
        assert!(!spans[0].contains_key("otel.status_code"));
    }

    #[tokio::test]
    async fn accepted_terminal_results_can_close_without_grpc_eof() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            Server::builder()
                .add_service(HttpHooksServer::new(HttpHooksService))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve");
        });
        let client = RemoteMiddlewareService::connect(
            "test/http-hooks",
            &format!("http://{address}"),
            &[],
            None,
        )
        .await
        .expect("connect");
        for (middleware_name, denied) in [("hold-after-continue", false), ("hold-after-deny", true)]
        {
            let captured = ClosedSpans::default();
            let subscriber = tracing_subscriber::registry().with(captured.clone());
            async {
                let (sender, receiver) = mpsc::channel(1);
                sender
                    .send(HttpRequestHookEvent {
                        event: Some(http_request_hook_event::Event::Preflight(
                            HttpRequestHookPreflight {
                                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                                middleware_name: middleware_name.into(),
                                ..Default::default()
                            },
                        )),
                    })
                    .await
                    .expect("send preflight");
                let mut results = client
                    .open_http_request_hook(receiver)
                    .await
                    .expect("open RPC");
                let result = results
                    .next()
                    .await
                    .expect("terminal result")
                    .expect("RPC status");
                assert_eq!(
                    matches!(
                        result.result,
                        Some(http_request_hook_result::Result::Deny(_))
                    ),
                    denied
                );
                assert!(captured.0.lock().unwrap().is_empty());
                // The protocol accepts this terminal result without requiring gRPC EOF.
                drop((results, sender));
            }
            .with_subscriber(subscriber)
            .await;
            let spans = captured.0.lock().unwrap();
            assert_eq!(spans.len(), 1);
            assert!(!spans[0].contains_key("rpc.response.status_code"));
            assert!(!spans[0].contains_key("otel.status_code"));
            assert!(!spans[0].contains_key("error.type"));
        }
        drop(client);
        shutdown_tx.send(()).expect("shutdown");
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn result_stream_errors_record_only_bounded_transport_status() {
        let captured = ClosedSpans::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());
        async {
            let span = rpc_span("EvaluateHttpResponseHook");
            let mut results = openshell_otel::TracedGrpcStream::new(
                futures::stream::iter([Err::<(), _>(Status::unavailable("service-secret"))]),
                span,
            );
            assert!(results.next().await.unwrap().is_err());
            drop(results);
        }
        .with_subscriber(subscriber)
        .await;
        let spans = captured.0.lock().unwrap();
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].get("rpc.response.status_code").map(String::as_str),
            Some("\"UNAVAILABLE\"")
        );
        assert_eq!(
            spans[0].get("otel.status_code").map(String::as_str),
            Some("\"ERROR\"")
        );
        assert!(!format!("{spans:?}").contains("service-secret"));
    }

    #[test]
    fn dropping_unfinished_stream_does_not_claim_rpc_success() {
        let captured = ClosedSpans::default();
        let subscriber = tracing_subscriber::registry().with(captured.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = rpc_span("EvaluateHttpRequestHook");
            let results = openshell_otel::TracedGrpcStream::new(
                futures::stream::pending::<std::result::Result<(), Status>>(),
                span,
            );
            assert!(captured.0.lock().unwrap().is_empty());
            drop(results);
        });
        let spans = captured.0.lock().unwrap();
        assert_eq!(spans.len(), 1);
        assert!(!spans[0].contains_key("rpc.response.status_code"));
    }

    #[test]
    fn client_interceptor_replaces_untrusted_trace_context_and_keeps_bearer() {
        let slot = BearerTokenSlot::new("middleware-secret", i64::MAX).unwrap();
        let mut interceptor = MiddlewareClientInterceptor::new(slot.interceptor());
        let forged = "00-11111111111111111111111111111111-2222222222222222-01";
        let provider = openshell_otel::SdkTracerProvider::builder().build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "middleware-client-test"));
        let (request, expected_traceparent) = tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("middleware.client");
            let _entered = span.enter();
            let expected_traceparent = openshell_otel::current_trace_context_carrier()
                .and_then(|carrier| carrier.get("traceparent").cloned())
                .expect("active host span has trace context");
            let mut request = Request::new(());
            request
                .metadata_mut()
                .insert("traceparent", forged.parse().unwrap());
            request
                .metadata_mut()
                .insert("tracestate", "vendor=untrusted".parse().unwrap());
            (interceptor.call(request).unwrap(), expected_traceparent)
        });

        assert_eq!(
            request.metadata().get("authorization").unwrap(),
            "Bearer middleware-secret"
        );
        let traceparent = request
            .metadata()
            .get("traceparent")
            .expect("active host span is propagated")
            .to_str()
            .unwrap();
        assert_ne!(traceparent, forged);
        assert_eq!(traceparent, expected_traceparent);
        assert_ne!(
            request
                .metadata()
                .get("tracestate")
                .and_then(|value| value.to_str().ok()),
            Some("vendor=untrusted")
        );
    }
}
