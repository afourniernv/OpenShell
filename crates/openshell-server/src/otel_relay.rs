// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated OTLP exporter for relayed telemetry from supervisors.
//!
//! Uses a separate gRPC client to forward pre-enriched trace data to the
//! configured OTLP collector, bypassing the gateway's own `SdkTracerProvider`
//! which would overwrite resource attributes.

use std::sync::Arc;

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tonic::transport::Channel;
use tracing::{debug, info};

use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;

/// Gateway-wide cap on trace batches waiting for an external collector.
/// Admission happens before spawning so an outage cannot accumulate an
/// unbounded number of tasks retaining payloads. This is availability
/// hardening; normal Hermes/Relay delivery does not depend on reaching it.
pub const MAX_IN_FLIGHT_OTEL_EXPORTS: usize = 32;

/// Agent telemetry signals enabled for one gateway deployment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelaySignals {
    traces: bool,
    logs: bool,
}

impl RelaySignals {
    pub const fn none() -> Self {
        Self {
            traces: false,
            logs: false,
        }
    }

    pub const fn traces_only() -> Self {
        Self {
            traces: true,
            logs: false,
        }
    }

    pub fn from_config(signals: &[crate::config_file::OtlpAgentSignal]) -> Self {
        let mut enabled = Self::none();
        for signal in signals {
            match signal {
                crate::config_file::OtlpAgentSignal::Traces => enabled.traces = true,
                crate::config_file::OtlpAgentSignal::Logs => enabled.logs = true,
            }
        }
        enabled
    }

    pub const fn traces(self) -> bool {
        self.traces
    }

    pub const fn logs(self) -> bool {
        self.logs
    }

    pub const fn any(self) -> bool {
        self.traces || self.logs
    }
}

impl From<bool> for RelaySignals {
    fn from(enabled: bool) -> Self {
        if enabled {
            Self::traces_only()
        } else {
            Self::none()
        }
    }
}

/// Exporter that forwards raw protobuf-encoded trace data to an OTLP collector.
#[derive(Debug, Clone)]
pub struct OtelRelayExporter {
    trace_client: TraceServiceClient<Channel>,
    logs_client: LogsServiceClient<Channel>,
    enabled_signals: RelaySignals,
    export_permits: Arc<Semaphore>,
}

impl OtelRelayExporter {
    /// Configure a lazy channel to the OTLP collector at the given gRPC endpoint.
    ///
    /// The channel connects on the first export and reconnects after collector
    /// outages, so collector availability does not determine whether the
    /// gateway enables its relay capability at startup.
    pub fn connect(endpoint: &str) -> Result<Self, ConnectError> {
        Self::connect_with_signals(endpoint, RelaySignals::traces_only())
    }

    pub fn connect_with_signals(
        endpoint: &str,
        enabled_signals: RelaySignals,
    ) -> Result<Self, ConnectError> {
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|e| ConnectError::InvalidUri(e.to_string()))?
            .connect_lazy();
        Ok(Self {
            trace_client: TraceServiceClient::new(channel.clone()),
            logs_client: LogsServiceClient::new(channel),
            enabled_signals,
            export_permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT_OTEL_EXPORTS)),
        })
    }

    pub const fn enabled_signals(&self) -> RelaySignals {
        self.enabled_signals
    }

    /// Reserve one in-flight export slot without waiting.
    pub fn try_reserve_export(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.export_permits).try_acquire_owned().ok()
    }

    /// An exporter over a lazy channel that performs no I/O until the first
    /// RPC, for tests that only need "a relay exporter is configured".
    #[cfg(test)]
    pub(crate) fn lazy_for_test() -> Self {
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        Self {
            trace_client: TraceServiceClient::new(channel.clone()),
            logs_client: LogsServiceClient::new(channel),
            enabled_signals: RelaySignals::traces_only(),
            export_permits: Arc::new(Semaphore::new(MAX_IN_FLIGHT_OTEL_EXPORTS)),
        }
    }

    /// Export raw protobuf-encoded `ExportTraceServiceRequest` bytes.
    pub async fn export_raw(&self, trace_data: Vec<u8>) -> Result<ExportOutcome, ExportError> {
        let request = ExportTraceServiceRequest::decode(trace_data.as_slice())
            .map_err(ExportError::Decode)?;

        let mut client = self.trace_client.clone();
        let response = client
            .export(tonic::Request::new(request))
            .await
            .map_err(ExportError::Grpc)?
            .into_inner();

        if let Some(partial) = response.partial_success
            && (partial.rejected_spans != 0 || !partial.error_message.is_empty())
        {
            return Ok(ExportOutcome::PartialSuccess {
                rejected_items: partial.rejected_spans,
                error_message: partial.error_message,
            });
        }

        Ok(ExportOutcome::FullSuccess)
    }

    /// Export raw protobuf-encoded `ExportLogsServiceRequest` bytes.
    pub async fn export_logs_raw(&self, logs_data: Vec<u8>) -> Result<ExportOutcome, ExportError> {
        let request =
            ExportLogsServiceRequest::decode(logs_data.as_slice()).map_err(ExportError::Decode)?;

        let mut client = self.logs_client.clone();
        let response = client
            .export(tonic::Request::new(request))
            .await
            .map_err(ExportError::Grpc)?
            .into_inner();

        if let Some(partial) = response.partial_success
            && (partial.rejected_log_records != 0 || !partial.error_message.is_empty())
        {
            return Ok(ExportOutcome::PartialSuccess {
                rejected_items: partial.rejected_log_records,
                error_message: partial.error_message,
            });
        }

        Ok(ExportOutcome::FullSuccess)
    }
}

/// Collector acknowledgement for an accepted OTLP export.
///
/// OTLP partial success is non-retryable, so it is a successful outcome with
/// diagnostics rather than an [`ExportError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportOutcome {
    FullSuccess,
    PartialSuccess {
        rejected_items: i64,
        error_message: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("failed to decode trace data: {0}")]
    Decode(prost::DecodeError),
    #[error("gRPC export failed: {0}")]
    Grpc(tonic::Status),
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("invalid OTLP endpoint URI: {0}")]
    InvalidUri(String),
}

/// Create a relay exporter from the gateway's OTLP config, if configured.
pub fn try_create_exporter(
    config_file: Option<&crate::config_file::ConfigFile>,
) -> Option<Arc<OtelRelayExporter>> {
    let Some(cf) = config_file else {
        debug!("no config file; OTEL relay disabled");
        return None;
    };
    let Some(otlp) = cf.openshell.gateway.otlp.as_ref() else {
        debug!("no [openshell.gateway.otlp] section in config; OTEL relay disabled");
        return None;
    };
    if !otlp.sandbox_relay_enabled {
        debug!("sandbox OTEL relay is not enabled; relay exporter disabled");
        return None;
    }
    // Agent traces ride their own lane: `agent_endpoint` when the operator
    // split the collectors, otherwise the shared infrastructure endpoint.
    let endpoint = otlp.agent_lane_endpoint();
    let enabled_signals = RelaySignals::from_config(&otlp.agent_signals);
    if !enabled_signals.any() {
        debug!("sandbox OTEL relay has no enabled signals; relay exporter disabled");
        return None;
    }
    match OtelRelayExporter::connect_with_signals(endpoint, enabled_signals) {
        Ok(exporter) => {
            info!(
                endpoint,
                dedicated_lane = otlp.agent_endpoint.is_some(),
                traces = enabled_signals.traces(),
                logs = enabled_signals.logs(),
                "OTEL relay exporter configured"
            );
            Some(Arc::new(exporter))
        }
        Err(e) => {
            tracing::warn!(
                endpoint,
                error = %e,
                "failed to configure OTEL relay exporter; relay disabled"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsServiceResponse,
        logs_service_server::{LogsService, LogsServiceServer},
    };
    use opentelemetry_proto::tonic::collector::trace::v1::{
        ExportTracePartialSuccess, ExportTraceServiceResponse,
        trace_service_server::{TraceService, TraceServiceServer},
    };
    use tokio_stream::wrappers::TcpListenerStream;

    #[derive(Clone, Default)]
    struct CountingCollector {
        exports: Arc<AtomicUsize>,
    }

    #[tonic::async_trait]
    impl TraceService for CountingCollector {
        async fn export(
            &self,
            _request: tonic::Request<ExportTraceServiceRequest>,
        ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
            self.exports.fetch_add(1, Ordering::Relaxed);
            Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
        }
    }

    #[derive(Clone)]
    enum CollectorReply {
        Success,
        Partial {
            rejected_spans: i64,
            error_message: &'static str,
        },
        GrpcError(tonic::Code),
    }

    #[derive(Clone)]
    struct ResultCollector {
        reply: CollectorReply,
    }

    #[derive(Clone, Default)]
    struct LogCollector;

    #[tonic::async_trait]
    impl LogsService for LogCollector {
        async fn export(
            &self,
            _request: tonic::Request<ExportLogsServiceRequest>,
        ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
            Ok(tonic::Response::new(ExportLogsServiceResponse::default()))
        }
    }

    #[tonic::async_trait]
    impl TraceService for ResultCollector {
        async fn export(
            &self,
            _request: tonic::Request<ExportTraceServiceRequest>,
        ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
            match &self.reply {
                CollectorReply::Success => {
                    Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
                }
                CollectorReply::Partial {
                    rejected_spans,
                    error_message,
                } => Ok(tonic::Response::new(ExportTraceServiceResponse {
                    partial_success: Some(ExportTracePartialSuccess {
                        rejected_spans: *rejected_spans,
                        error_message: (*error_message).to_string(),
                    }),
                })),
                CollectorReply::GrpcError(code) => {
                    Err(tonic::Status::new(*code, "collector unavailable"))
                }
            }
        }
    }

    struct TestCollector {
        endpoint: String,
        shutdown: tokio::sync::oneshot::Sender<()>,
        task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
    }

    impl TestCollector {
        async fn start(reply: CollectorReply) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                tonic::transport::Server::builder()
                    .add_service(TraceServiceServer::new(ResultCollector { reply }))
                    .add_service(LogsServiceServer::new(LogCollector))
                    .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                        let _ = shutdown_rx.await;
                    })
                    .await
            });
            Self {
                endpoint,
                shutdown,
                task,
            }
        }

        async fn shutdown(self) {
            self.shutdown.send(()).unwrap();
            self.task.await.unwrap().unwrap();
        }
    }

    fn empty_request() -> Vec<u8> {
        ExportTraceServiceRequest::default().encode_to_vec()
    }

    fn empty_logs_request() -> Vec<u8> {
        ExportLogsServiceRequest::default().encode_to_vec()
    }

    #[tokio::test]
    async fn gateway_otlp_does_not_enable_sandbox_relay_implicitly() {
        let mut config = crate::config_file::ConfigFile::default();
        config.openshell.gateway.otlp = Some(crate::config_file::OtlpConfig {
            endpoint: "http://127.0.0.1:4317".to_string(),
            service_name: None,
            agent_endpoint: None,
            sandbox_relay_enabled: false,
            agent_signals: vec![crate::config_file::OtlpAgentSignal::Traces],
        });

        assert!(try_create_exporter(Some(&config)).is_none());
    }

    #[tokio::test]
    async fn connect_rejects_invalid_endpoint_uri() {
        let err = OtelRelayExporter::connect("not a valid uri")
            .expect_err("an unparsable endpoint must not connect");
        assert!(matches!(err, ConnectError::InvalidUri(_)), "{err}");
    }

    #[tokio::test]
    async fn exporter_survives_collector_starting_after_configuration() {
        let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = reservation.local_addr().unwrap();
        drop(reservation);

        let exporter = OtelRelayExporter::connect(&format!("http://{addr}"))
            .expect("a valid collector URI should configure while the collector is down");

        let request = ExportTraceServiceRequest::default().encode_to_vec();
        let first_error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            exporter.export_raw(request.clone()),
        )
        .await
        .expect("the first connection attempt should fail promptly")
        .expect_err("an export cannot succeed before the collector starts");
        assert!(matches!(first_error, ExportError::Grpc(_)), "{first_error}");

        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let collector = CountingCollector::default();
        let exports = Arc::clone(&collector.exports);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(collector))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
        });

        let delivered = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            for _ in 0..20 {
                let attempt = tokio::time::timeout(
                    std::time::Duration::from_millis(250),
                    exporter.export_raw(request.clone()),
                )
                .await;
                if matches!(attempt, Ok(Ok(ExportOutcome::FullSuccess))) {
                    return true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            false
        })
        .await
        .expect("collector recovery probe must have a total deadline");
        assert!(
            delivered,
            "the channel should reconnect after the collector starts"
        );
        assert_eq!(exports.load(Ordering::Relaxed), 1);

        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn export_raw_rejects_undecodable_trace_bytes() {
        // A lazy channel performs no I/O, so the decode failure surfaces
        // before any RPC is attempted and no collector is needed.
        let exporter = OtelRelayExporter::lazy_for_test();
        let err = exporter
            .export_raw(vec![0xff, 0xff, 0xff])
            .await
            .expect_err("garbage bytes must not decode as ExportTraceServiceRequest");
        assert!(matches!(err, ExportError::Decode(_)), "{err}");
    }

    #[tokio::test]
    async fn risk_control_bounds_export_admission_and_recovers() {
        let exporter = OtelRelayExporter::lazy_for_test();
        let mut permits: Vec<_> = (0..MAX_IN_FLIGHT_OTEL_EXPORTS)
            .map(|index| {
                exporter
                    .try_reserve_export()
                    .unwrap_or_else(|| panic!("missing permit {index}"))
            })
            .collect();

        assert!(
            exporter.try_reserve_export().is_none(),
            "the exporter must shed work once the in-flight limit is reached"
        );
        drop(permits.pop());
        assert!(
            exporter.try_reserve_export().is_some(),
            "releasing an export restores admission"
        );
    }

    #[tokio::test]
    async fn export_raw_accepts_a_successful_collector_response() {
        let collector = TestCollector::start(CollectorReply::Success).await;
        let exporter = OtelRelayExporter::connect(&collector.endpoint).unwrap();

        assert_eq!(
            exporter.export_raw(empty_request()).await.unwrap(),
            ExportOutcome::FullSuccess
        );

        collector.shutdown().await;
    }

    #[tokio::test]
    async fn export_logs_raw_accepts_a_successful_collector_response() {
        let collector = TestCollector::start(CollectorReply::Success).await;
        let exporter = OtelRelayExporter::connect_with_signals(
            &collector.endpoint,
            RelaySignals::from_config(&[
                crate::config_file::OtlpAgentSignal::Traces,
                crate::config_file::OtlpAgentSignal::Logs,
            ]),
        )
        .unwrap();

        assert_eq!(
            exporter
                .export_logs_raw(empty_logs_request())
                .await
                .unwrap(),
            ExportOutcome::FullSuccess
        );

        collector.shutdown().await;
    }

    #[tokio::test]
    async fn export_raw_reports_rejected_spans() {
        let collector = TestCollector::start(CollectorReply::Partial {
            rejected_spans: 2,
            error_message: "span limit exceeded",
        })
        .await;
        let exporter = OtelRelayExporter::connect(&collector.endpoint).unwrap();

        let outcome = exporter
            .export_raw(empty_request())
            .await
            .expect("partial success must not request a retry");
        assert_eq!(
            outcome,
            ExportOutcome::PartialSuccess {
                rejected_items: 2,
                error_message: "span limit exceeded".to_string(),
            }
        );

        collector.shutdown().await;
    }

    #[tokio::test]
    async fn export_raw_reports_collector_warning_messages() {
        let collector = TestCollector::start(CollectorReply::Partial {
            rejected_spans: 0,
            error_message: "collector sampled the request",
        })
        .await;
        let exporter = OtelRelayExporter::connect(&collector.endpoint).unwrap();

        let outcome = exporter
            .export_raw(empty_request())
            .await
            .expect("collector warnings must not request a retry");
        assert_eq!(
            outcome,
            ExportOutcome::PartialSuccess {
                rejected_items: 0,
                error_message: "collector sampled the request".to_string(),
            }
        );

        collector.shutdown().await;
    }

    #[tokio::test]
    async fn export_raw_preserves_grpc_errors() {
        let collector =
            TestCollector::start(CollectorReply::GrpcError(tonic::Code::Unavailable)).await;
        let exporter = OtelRelayExporter::connect(&collector.endpoint).unwrap();

        let err = exporter.export_raw(empty_request()).await.unwrap_err();
        assert!(
            matches!(err, ExportError::Grpc(ref status) if status.code() == tonic::Code::Unavailable),
            "{err}"
        );

        collector.shutdown().await;
    }
}
