// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use miette::{IntoDiagnostic, Result, WrapErr};
use openshell_core::middleware::{
    HttpRequestView, HttpResponseResultStream, SupervisorMiddlewareEndpoint,
    WebSocketResponseStream,
};
use openshell_core::proto::middleware::v1::http_response_pre_return_client::HttpResponsePreReturnClient;
use openshell_core::proto::middleware::v1::supervisor_middleware_client::SupervisorMiddlewareClient;
use openshell_core::proto::{
    HttpRequestEvaluation, HttpRequestResult, HttpResponseEvent, MiddlewareDescribeRequest,
    MiddlewareManifest, ValidateConfigRequest, ValidateConfigResponse, WebSocketSessionEvent,
};
use openshell_extension_core::{
    BearerTokenInterceptor, BearerTokenSlot, ExtensionChannelConfig, ExtensionServerTrust,
    connect_channel,
};
use std::sync::Arc;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Request, Response, Status};

use crate::MIDDLEWARE_GRPC_MESSAGE_BYTES;

type ExtensionChannel = InterceptedService<Channel, MiddlewareClientInterceptor>;

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
}

#[derive(Clone)]
pub struct RemoteMiddlewareService {
    client: SupervisorMiddlewareClient<ExtensionChannel>,
    response_client: HttpResponsePreReturnClient<ExtensionChannel>,
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
            response_client: HttpResponsePreReturnClient::new(channel)
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

    #[tracing::instrument(name = "openshell.middleware.rpc", skip_all, fields(otel.kind = "client", rpc.method = "EvaluateHttpRequest"))]
    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> std::result::Result<Response<HttpRequestResult>, Status> {
        let mut client = self.client.clone();
        client.evaluate_http_request(request).await
    }

    #[tracing::instrument(name = "openshell.middleware.rpc", skip_all, fields(otel.kind = "client", rpc.method = "EvaluateWebSocketSession"))]
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

    #[tracing::instrument(name = "openshell.middleware.rpc", skip_all, fields(otel.kind = "client", rpc.method = "HttpResponsePreReturn"))]
    async fn open_http_response_pre_return(
        &self,
        receiver: tokio::sync::mpsc::Receiver<HttpResponseEvent>,
    ) -> std::result::Result<HttpResponseResultStream, Status> {
        let mut client = self.response_client.clone();
        let responses = client
            .evaluate(Request::new(tokio_stream::wrappers::ReceiverStream::new(
                receiver,
            )))
            .await?
            .into_inner();
        Ok(Box::pin(responses))
    }
}

#[cfg(test)]
mod tests {
    use tonic::service::Interceptor as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

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
