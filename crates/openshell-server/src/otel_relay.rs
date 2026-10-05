// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated OTLP exporter for relayed telemetry from supervisors.
//!
//! Uses separate OTLP service clients on one gRPC channel to forward
//! pre-enriched trace, log, and metric data to the
//! configured OTLP collector, bypassing the gateway's own `SdkTracerProvider`
//! which would overwrite resource attributes.

use std::collections::HashMap;
use std::mem::size_of;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest, ExportLogsServiceResponse, logs_service_client::LogsServiceClient,
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
    metrics_service_client::MetricsServiceClient,
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use prost::Message;
use tokio::sync::Semaphore;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tracing::{debug, info, warn};

use opentelemetry_proto::tonic::collector::trace::v1::trace_service_client::TraceServiceClient;

const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_EXPORTS: usize = 32;
// Keep this below the decoded-resident budget so one sandbox cannot occupy
// every request that may retain a decoded OTLP object graph while exporting.
const MAX_CONCURRENT_EXPORTS_PER_SANDBOX: usize = 2;
const MAX_RESIDENT_DECODED_REQUESTS: usize = 4;
const MAX_PARTIAL_SUCCESS_MESSAGE_CHARS: usize = 256;
const MAX_STRUCTURAL_ITEMS_PER_REQUEST: usize = 16 * 1_024;
const MAX_RELAY_PAYLOAD_BYTES: usize = openshell_core::proto::MAX_GRPC_MESSAGE_SIZE;

/// Agent OTLP signals enabled for one gateway deployment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelaySignals {
    traces: bool,
    logs: bool,
    metrics: bool,
}

impl RelaySignals {
    pub const fn all() -> Self {
        Self {
            traces: true,
            logs: true,
            metrics: true,
        }
    }

    pub const fn traces_only() -> Self {
        Self {
            traces: true,
            logs: false,
            metrics: false,
        }
    }

    pub const fn none() -> Self {
        Self::default_const()
    }

    const fn default_const() -> Self {
        Self {
            traces: false,
            logs: false,
            metrics: false,
        }
    }

    pub fn from_config(signals: &[crate::config_file::OtlpAgentSignal]) -> Self {
        let mut enabled = Self::none();
        for signal in signals {
            match signal {
                crate::config_file::OtlpAgentSignal::Traces => enabled.traces = true,
                crate::config_file::OtlpAgentSignal::Logs => enabled.logs = true,
                crate::config_file::OtlpAgentSignal::Metrics => enabled.metrics = true,
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

    pub const fn metrics(self) -> bool {
        self.metrics
    }

    pub const fn any(self) -> bool {
        self.traces || self.logs || self.metrics
    }

    fn allows(self, signal: &RelaySignal) -> bool {
        match signal {
            RelaySignal::Traces(_) => self.traces,
            RelaySignal::Logs(_) => self.logs,
            RelaySignal::Metrics(_) => self.metrics,
        }
    }
}

impl From<bool> for RelaySignals {
    fn from(enabled: bool) -> Self {
        if enabled { Self::all() } else { Self::none() }
    }
}

/// A protobuf-encoded OTLP signal forwarded by the supervisor.
#[derive(Debug)]
pub enum RelaySignal {
    Traces(Vec<u8>),
    Logs(Vec<u8>),
    Metrics(Vec<u8>),
}

impl RelaySignal {
    const fn name(&self) -> &'static str {
        self.kind().name()
    }

    const fn kind(&self) -> RelaySignalKind {
        match self {
            Self::Traces(_) => RelaySignalKind::Traces,
            Self::Logs(_) => RelaySignalKind::Logs,
            Self::Metrics(_) => RelaySignalKind::Metrics,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum RelaySignalKind {
    Traces,
    Logs,
    Metrics,
}

impl RelaySignalKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Traces => "traces",
            Self::Logs => "logs",
            Self::Metrics => "metrics",
        }
    }
}

enum DecodedRelaySignal {
    Traces(ExportTraceServiceRequest),
    Logs(ExportLogsServiceRequest),
    Metrics(ExportMetricsServiceRequest),
}

#[derive(Debug, Default)]
struct SignalCounters {
    total: AtomicU64,
    traces: AtomicU64,
    logs: AtomicU64,
    metrics: AtomicU64,
}

impl SignalCounters {
    fn record(&self, signal: RelaySignalKind) -> (u64, u64) {
        let total = self.total.fetch_add(1, Ordering::Relaxed) + 1;
        let signal_total = match signal {
            RelaySignalKind::Traces => &self.traces,
            RelaySignalKind::Logs => &self.logs,
            RelaySignalKind::Metrics => &self.metrics,
        }
        .fetch_add(1, Ordering::Relaxed)
            + 1;
        (total, signal_total)
    }

    #[cfg(test)]
    fn total(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn for_signal(&self, signal: RelaySignalKind) -> u64 {
        match signal {
            RelaySignalKind::Traces => &self.traces,
            RelaySignalKind::Logs => &self.logs,
            RelaySignalKind::Metrics => &self.metrics,
        }
        .load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct SandboxExportLimiter {
    max_per_sandbox: usize,
    in_flight: Mutex<HashMap<String, usize>>,
}

impl SandboxExportLimiter {
    fn new(max_per_sandbox: usize) -> Self {
        Self {
            max_per_sandbox,
            in_flight: Mutex::new(HashMap::new()),
        }
    }

    fn try_acquire(self: &Arc<Self>, sandbox_id: &str) -> Option<SandboxExportPermit> {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let count = in_flight.entry(sandbox_id.to_string()).or_default();
        if *count >= self.max_per_sandbox {
            return None;
        }
        *count += 1;
        Some(SandboxExportPermit {
            limiter: Arc::clone(self),
            sandbox_id: sandbox_id.to_string(),
        })
    }

    #[cfg(test)]
    fn in_flight(&self, sandbox_id: &str) -> usize {
        *self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(sandbox_id)
            .unwrap_or(&0)
    }
}

#[derive(Debug)]
struct SandboxExportPermit {
    limiter: Arc<SandboxExportLimiter>,
    sandbox_id: String,
}

impl Drop for SandboxExportPermit {
    fn drop(&mut self) {
        let mut in_flight = self
            .limiter
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(count) = in_flight.get_mut(&self.sandbox_id) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            in_flight.remove(&self.sandbox_id);
        }
    }
}

/// Exporter that forwards raw protobuf-encoded OTLP signals to a collector.
#[derive(Debug, Clone)]
pub struct OtelRelayExporter {
    trace_client: TraceServiceClient<Channel>,
    logs_client: LogsServiceClient<Channel>,
    metrics_client: MetricsServiceClient<Channel>,
    export_slots: Arc<Semaphore>,
    resident_slots: Arc<Semaphore>,
    sandbox_export_limiter: Arc<SandboxExportLimiter>,
    enabled_signals: RelaySignals,
    backpressure_drops: Arc<AtomicU64>,
    disabled_signal_drops: Arc<AtomicU64>,
    export_failures: Arc<SignalCounters>,
    collector_warnings: Arc<SignalCounters>,
}

impl OtelRelayExporter {
    /// Configure a lazy, reconnecting channel to the OTLP collector.
    ///
    /// This validates the endpoint URI but intentionally performs no startup
    /// network I/O. Tonic connects on the first export and reconnects after
    /// transient collector failures.
    pub fn connect(endpoint: &str) -> Result<Self, ConnectError> {
        Self::connect_with_signals(endpoint, RelaySignals::all())
    }

    fn connect_with_signals(
        endpoint: &str,
        enabled_signals: RelaySignals,
    ) -> Result<Self, ConnectError> {
        Self::connect_with_signals_and_tls(endpoint, enabled_signals, None)
    }

    fn connect_with_signals_and_tls(
        endpoint: &str,
        enabled_signals: RelaySignals,
        tls_override: Option<ClientTlsConfig>,
    ) -> Result<Self, ConnectError> {
        let uri = endpoint
            .parse::<http::Uri>()
            .map_err(|error| ConnectError::InvalidUri(error.to_string()))?;
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| ConnectError::InvalidUri("endpoint must include a scheme".into()))?;
        if !matches!(scheme, "http" | "https") {
            return Err(ConnectError::InvalidUri(format!(
                "unsupported endpoint scheme {scheme:?}; expected http or https"
            )));
        }
        if uri.authority().is_none() || uri.host().is_none_or(str::is_empty) {
            return Err(ConnectError::InvalidUri(
                "endpoint must include an authority".into(),
            ));
        }

        let mut transport = Endpoint::from_shared(endpoint.to_owned())
            .map_err(|error| ConnectError::InvalidUri(error.to_string()))?;
        if scheme == "https" {
            transport = match tls_override {
                Some(tls) => transport
                    .tls_config(tls)
                    .map_err(|error| ConnectError::Tls(error.to_string()))?,
                None => configure_tls_with_fallback(
                    transport,
                    ClientTlsConfig::new().with_native_roots(),
                    ClientTlsConfig::new()
                        .trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
                )?,
            };
        }
        let channel = transport.connect_lazy();
        Ok(Self::from_channel_with_signals(channel, enabled_signals))
    }

    /// An exporter over a lazy channel that performs no I/O until the first
    /// RPC, for tests that only need "a relay exporter is configured".
    #[cfg(test)]
    pub(crate) fn lazy_for_test() -> Self {
        Self::from_channel(Channel::from_static("http://127.0.0.1:1").connect_lazy())
    }

    #[cfg(test)]
    fn from_channel(channel: Channel) -> Self {
        Self::from_channel_with_signals(channel, RelaySignals::all())
    }

    fn from_channel_with_signals(channel: Channel, enabled_signals: RelaySignals) -> Self {
        Self::from_channel_with_limit(channel, enabled_signals, MAX_CONCURRENT_EXPORTS)
    }

    fn from_channel_with_limit(
        channel: Channel,
        enabled_signals: RelaySignals,
        max_concurrent_exports: usize,
    ) -> Self {
        Self::from_channel_with_limits(
            channel,
            enabled_signals,
            max_concurrent_exports,
            MAX_CONCURRENT_EXPORTS_PER_SANDBOX,
        )
    }

    fn from_channel_with_limits(
        channel: Channel,
        enabled_signals: RelaySignals,
        max_concurrent_exports: usize,
        max_concurrent_exports_per_sandbox: usize,
    ) -> Self {
        Self {
            trace_client: TraceServiceClient::new(channel.clone()),
            logs_client: LogsServiceClient::new(channel.clone()),
            metrics_client: MetricsServiceClient::new(channel),
            export_slots: Arc::new(Semaphore::new(max_concurrent_exports)),
            resident_slots: Arc::new(Semaphore::new(MAX_RESIDENT_DECODED_REQUESTS)),
            sandbox_export_limiter: Arc::new(SandboxExportLimiter::new(
                max_concurrent_exports_per_sandbox,
            )),
            enabled_signals,
            backpressure_drops: Arc::new(AtomicU64::new(0)),
            disabled_signal_drops: Arc::new(AtomicU64::new(0)),
            export_failures: Arc::new(SignalCounters::default()),
            collector_warnings: Arc::new(SignalCounters::default()),
        }
    }

    pub const fn enabled_signals(&self) -> RelaySignals {
        self.enabled_signals
    }

    /// Start a best-effort, at-most-once export when bounded gateway and
    /// per-sandbox capacity are available.
    ///
    /// Collector I/O runs off the supervisor stream task. Accepted telemetry
    /// is not persisted or retried, so the workload-facing OTLP success only
    /// acknowledges relay admission, not collector delivery.
    pub fn try_spawn_export(self: &Arc<Self>, signal: RelaySignal, sandbox_id: String) -> bool {
        if !self.enabled_signals.allows(&signal) {
            let signal_name = signal.name();
            let drops = self.disabled_signal_drops.fetch_add(1, Ordering::Relaxed) + 1;
            if drops == 1 || drops.is_power_of_two() {
                warn!(
                    sandbox_id = %sandbox_id,
                    signal = signal_name,
                    disabled_signal_drops = drops,
                    "OTEL relay: signal is not enabled; dropping telemetry"
                );
            }
            return false;
        }
        let Some(sandbox_permit) = self.sandbox_export_limiter.try_acquire(&sandbox_id) else {
            let drops = self.backpressure_drops.fetch_add(1, Ordering::Relaxed) + 1;
            if drops == 1 || drops.is_power_of_two() {
                warn!(
                    sandbox_id = %sandbox_id,
                    backpressure_drops = drops,
                    max_concurrent_exports_per_sandbox = self.sandbox_export_limiter.max_per_sandbox,
                    "OTEL relay: sandbox export capacity exhausted; dropping telemetry"
                );
            }
            return false;
        };
        let Ok(permit) = Arc::clone(&self.export_slots).try_acquire_owned() else {
            let drops = self.backpressure_drops.fetch_add(1, Ordering::Relaxed) + 1;
            if drops == 1 || drops.is_power_of_two() {
                warn!(
                    backpressure_drops = drops,
                    "OTEL relay: gateway export capacity exhausted; dropping telemetry"
                );
            }
            return false;
        };
        let Ok(resident_permit) = Arc::clone(&self.resident_slots).try_acquire_owned() else {
            let drops = self.backpressure_drops.fetch_add(1, Ordering::Relaxed) + 1;
            if drops == 1 || drops.is_power_of_two() {
                warn!(
                    backpressure_drops = drops,
                    max_resident_decoded_requests = MAX_RESIDENT_DECODED_REQUESTS,
                    "OTEL relay: decoded request capacity exhausted; dropping telemetry"
                );
            }
            return false;
        };
        let signal_kind = signal.kind();
        let exporter = Arc::clone(self);
        tokio::spawn(async move {
            let _permit = permit;
            let _sandbox_permit = sandbox_permit;
            // Keep the substantially smaller resident-data permit for the
            // entire decode-and-export lifetime. This bounds decoded OTLP
            // object graphs even when the collector stalls.
            let _resident_permit = resident_permit;
            let decoded = match exporter.decode_raw(signal).await {
                Ok(decoded) => decoded,
                Err(error) => {
                    let (total_failures, signal_failures) =
                        exporter.record_export_failure(signal_kind, error.reason());
                    if signal_failures == 1 || signal_failures.is_power_of_two() {
                        warn!(
                            sandbox_id = %sandbox_id,
                            signal = signal_kind.name(),
                            error = %error,
                            total_export_failures = total_failures,
                            signal_export_failures = signal_failures,
                            "OTEL relay: collector export failed"
                        );
                    }
                    return;
                }
            };
            match tokio::time::timeout(EXPORT_TIMEOUT, exporter.export_decoded(decoded)).await {
                Ok(Err(error)) => {
                    let (total_failures, signal_failures) =
                        exporter.record_export_failure(signal_kind, error.reason());
                    if signal_failures == 1 || signal_failures.is_power_of_two() {
                        warn!(
                            sandbox_id = %sandbox_id,
                            signal = signal_kind.name(),
                            error = %error,
                            total_export_failures = total_failures,
                            signal_export_failures = signal_failures,
                            "OTEL relay: collector export failed"
                        );
                    }
                }
                Err(_) => {
                    let (total_failures, signal_failures) =
                        exporter.record_export_failure(signal_kind, "timeout");
                    if signal_failures == 1 || signal_failures.is_power_of_two() {
                        warn!(
                            sandbox_id = %sandbox_id,
                            signal = signal_kind.name(),
                            timeout_seconds = EXPORT_TIMEOUT.as_secs(),
                            total_export_failures = total_failures,
                            signal_export_failures = signal_failures,
                            "OTEL relay: collector export timed out"
                        );
                    }
                }
                Ok(Ok(())) => {}
            }
        });
        true
    }

    #[cfg(test)]
    fn available_export_slots(&self) -> usize {
        self.export_slots.available_permits()
    }

    #[cfg(test)]
    fn available_resident_slots(&self) -> usize {
        self.resident_slots.available_permits()
    }

    #[cfg(test)]
    fn backpressure_drops(&self) -> u64 {
        self.backpressure_drops.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    fn disabled_signal_drops(&self) -> u64 {
        self.disabled_signal_drops.load(Ordering::Relaxed)
    }

    fn record_export_failure(&self, signal: RelaySignalKind, reason: &'static str) -> (u64, u64) {
        metrics::counter!(
            "openshell_otlp_relay_export_failures_total",
            "signal" => signal.name(),
            "reason" => reason
        )
        .increment(1);
        self.export_failures.record(signal)
    }

    fn record_collector_warning(&self, signal: RelaySignalKind, message: &str) {
        metrics::counter!(
            "openshell_otlp_relay_collector_warnings_total",
            "signal" => signal.name()
        )
        .increment(1);
        let (total_warnings, signal_warnings) = self.collector_warnings.record(signal);
        if signal_warnings == 1 || signal_warnings.is_power_of_two() {
            warn!(
                signal = signal.name(),
                collector_message = message,
                total_collector_warnings = total_warnings,
                signal_collector_warnings = signal_warnings,
                "OTEL relay: collector accepted export with a warning"
            );
        }
    }

    #[cfg(test)]
    fn export_failure_counts(&self, signal: RelaySignalKind) -> (u64, u64) {
        (
            self.export_failures.total(),
            self.export_failures.for_signal(signal),
        )
    }

    #[cfg(test)]
    fn collector_warning_counts(&self, signal: RelaySignalKind) -> (u64, u64) {
        (
            self.collector_warnings.total(),
            self.collector_warnings.for_signal(signal),
        )
    }

    #[cfg(test)]
    fn sandbox_exports_in_flight(&self, sandbox_id: &str) -> usize {
        self.sandbox_export_limiter.in_flight(sandbox_id)
    }

    /// Decode and export one raw protobuf-encoded OTLP service request.
    pub async fn export_raw(&self, signal: RelaySignal) -> Result<(), ExportError> {
        let signal_name = signal.name();
        let _resident_permit = Arc::clone(&self.resident_slots)
            .try_acquire_owned()
            .map_err(|_| ExportError::DecodeCapacity {
                signal: signal_name,
            })?;
        let decoded = self.decode_raw(signal).await?;
        self.export_decoded(decoded).await
    }

    async fn decode_raw(&self, signal: RelaySignal) -> Result<DecodedRelaySignal, ExportError> {
        if !self.enabled_signals.allows(&signal) {
            return Err(ExportError::SignalDisabled {
                signal: signal.name(),
            });
        }

        let signal_name = signal.name();
        tokio::task::spawn_blocking(move || decode_relay_signal(signal))
            .await
            .map_err(|source| ExportError::DecodeWorker {
                signal: signal_name,
                source,
            })?
    }

    async fn export_decoded(&self, signal: DecodedRelaySignal) -> Result<(), ExportError> {
        match signal {
            DecodedRelaySignal::Traces(request) => {
                let response = self
                    .trace_client
                    .clone()
                    .export(tonic::Request::new(request))
                    .await
                    .map_err(|source| ExportError::Grpc {
                        signal: "traces",
                        source,
                    })?
                    .into_inner();
                if let Some(message) = inspect_trace_response(response)? {
                    self.record_collector_warning(RelaySignalKind::Traces, &message);
                }
            }
            DecodedRelaySignal::Logs(request) => {
                let response = self
                    .logs_client
                    .clone()
                    .export(tonic::Request::new(request))
                    .await
                    .map_err(|source| ExportError::Grpc {
                        signal: "logs",
                        source,
                    })?
                    .into_inner();
                if let Some(message) = inspect_logs_response(response)? {
                    self.record_collector_warning(RelaySignalKind::Logs, &message);
                }
            }
            DecodedRelaySignal::Metrics(request) => {
                let response = self
                    .metrics_client
                    .clone()
                    .export(tonic::Request::new(request))
                    .await
                    .map_err(|source| ExportError::Grpc {
                        signal: "metrics",
                        source,
                    })?
                    .into_inner();
                if let Some(message) = inspect_metrics_response(response)? {
                    self.record_collector_warning(RelaySignalKind::Metrics, &message);
                }
            }
        }
        Ok(())
    }
}

/// Configure the relay's TLS trust without changing tonic's crate-wide root
/// features. Platform roots take precedence so enterprise collectors remain
/// anchored to the operator's trust store. The bundled `WebPKI` anchors are used
/// only when tonic cannot construct a connector from the platform roots (for
/// example, a minimal image with no native trust store).
fn configure_tls_with_fallback(
    transport: Endpoint,
    primary: ClientTlsConfig,
    fallback: ClientTlsConfig,
) -> Result<Endpoint, ConnectError> {
    match transport.clone().tls_config(primary) {
        Ok(transport) => Ok(transport),
        Err(primary_error) => transport.tls_config(fallback).map_err(|fallback_error| {
            ConnectError::Tls(format!(
                "native roots: {primary_error}; relay WebPKI fallback: {fallback_error}"
            ))
        }),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error("{signal} export is disabled by gateway configuration")]
    SignalDisabled { signal: &'static str },
    #[error("{signal} decode capacity is exhausted")]
    DecodeCapacity { signal: &'static str },
    #[error("{signal} decode worker failed: {source}")]
    DecodeWorker {
        signal: &'static str,
        #[source]
        source: tokio::task::JoinError,
    },
    #[error("{signal} payload has {bytes} bytes; maximum is {max}")]
    PayloadTooLarge {
        signal: &'static str,
        bytes: usize,
        max: usize,
    },
    #[error("{signal} payload has {items} structural items; maximum is {max}")]
    StructuralItemLimit {
        signal: &'static str,
        items: usize,
        max: usize,
    },
    #[error("{signal} payload exceeds protobuf nesting depth {max}")]
    NestingLimit { signal: &'static str, max: usize },
    #[error("failed to decode {signal} data: {detail}")]
    MalformedProtobuf {
        signal: &'static str,
        detail: &'static str,
    },
    #[error("failed to decode {signal} data: {source}")]
    Decode {
        signal: &'static str,
        #[source]
        source: prost::DecodeError,
    },
    #[error("{signal} gRPC export failed: {source}")]
    Grpc {
        signal: &'static str,
        #[source]
        source: tonic::Status,
    },
    #[error("collector partially accepted {signal}: rejected={rejected}, message={message}")]
    PartialSuccess {
        signal: &'static str,
        rejected: i64,
        message: String,
    },
}

impl ExportError {
    const fn reason(&self) -> &'static str {
        match self {
            Self::SignalDisabled { .. } => "disabled",
            Self::DecodeCapacity { .. } => "decode_capacity",
            Self::DecodeWorker { .. } => "decode_worker",
            Self::PayloadTooLarge { .. } => "payload_too_large",
            Self::StructuralItemLimit { .. } => "structural_item_limit",
            Self::NestingLimit { .. } => "nesting_limit",
            Self::MalformedProtobuf { .. } | Self::Decode { .. } => "decode",
            Self::Grpc { .. } => "grpc",
            Self::PartialSuccess { .. } => "partial_success",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    #[error("invalid OTLP endpoint URI: {0}")]
    InvalidUri(String),
    #[error("failed to configure TLS for OTLP endpoint: {0}")]
    Tls(String),
}

fn decode_relay_signal(signal: RelaySignal) -> Result<DecodedRelaySignal, ExportError> {
    match signal {
        RelaySignal::Traces(data) => {
            structural_preflight(RelaySignalKind::Traces, &data)?;
            ExportTraceServiceRequest::decode(data.as_slice())
                .map(DecodedRelaySignal::Traces)
                .map_err(|source| ExportError::Decode {
                    signal: "traces",
                    source,
                })
        }
        RelaySignal::Logs(data) => {
            structural_preflight(RelaySignalKind::Logs, &data)?;
            ExportLogsServiceRequest::decode(data.as_slice())
                .map(DecodedRelaySignal::Logs)
                .map_err(|source| ExportError::Decode {
                    signal: "logs",
                    source,
                })
        }
        RelaySignal::Metrics(data) => {
            structural_preflight(RelaySignalKind::Metrics, &data)?;
            ExportMetricsServiceRequest::decode(data.as_slice())
                .map(DecodedRelaySignal::Metrics)
                .map_err(|source| ExportError::Decode {
                    signal: "metrics",
                    source,
                })
        }
    }
}

/// Message shapes which may contain repeated, allocation-amplifying fields.
///
/// This intentionally describes the OTLP wire schema separately from Prost's
/// generated structs. The scan runs before typed decoding so a compact body
/// containing thousands of empty nested messages cannot make Prost allocate an
/// unbounded number of `Vec` elements at the gateway trust boundary.
#[derive(Debug, Clone, Copy)]
enum ProtoMessage {
    TraceRequest,
    ResourceSpans,
    ScopeSpans,
    Span,
    SpanEvent,
    SpanLink,
    LogsRequest,
    ResourceLogs,
    ScopeLogs,
    LogRecord,
    MetricsRequest,
    ResourceMetrics,
    ScopeMetrics,
    Metric,
    Gauge,
    Sum,
    Histogram,
    ExponentialHistogram,
    Summary,
    NumberDataPoint,
    HistogramDataPoint,
    ExponentialHistogramDataPoint,
    ExponentialHistogramBuckets,
    SummaryDataPoint,
    SummaryQuantile,
    Exemplar,
    Resource,
    EntityRef,
    InstrumentationScope,
    KeyValue,
    AnyValue,
    ArrayValue,
    KeyValueList,
}

#[derive(Debug, Clone, Copy)]
enum StructuralField {
    Message(ProtoMessage),
    RepeatedString,
    RepeatedFixed64,
    RepeatedVarint,
    Other,
}

impl ProtoMessage {
    // Keeping one explicit row per protobuf field makes this security boundary
    // auditable against the OTLP schema, even where several rows share a target.
    #[allow(clippy::match_same_arms, clippy::use_self)]
    const fn field(self, number: u32) -> StructuralField {
        use ProtoMessage as M;
        use StructuralField as F;

        match (self, number) {
            (M::TraceRequest, 1) => F::Message(M::ResourceSpans),
            (M::ResourceSpans, 1) => F::Message(M::Resource),
            (M::ResourceSpans, 2) => F::Message(M::ScopeSpans),
            (M::ScopeSpans, 1) => F::Message(M::InstrumentationScope),
            (M::ScopeSpans, 2) => F::Message(M::Span),
            (M::Span, 9) => F::Message(M::KeyValue),
            (M::Span, 11) => F::Message(M::SpanEvent),
            (M::Span, 13) => F::Message(M::SpanLink),
            (M::SpanEvent, 3) => F::Message(M::KeyValue),
            (M::SpanLink, 4) => F::Message(M::KeyValue),

            (M::LogsRequest, 1) => F::Message(M::ResourceLogs),
            (M::ResourceLogs, 1) => F::Message(M::Resource),
            (M::ResourceLogs, 2) => F::Message(M::ScopeLogs),
            (M::ScopeLogs, 1) => F::Message(M::InstrumentationScope),
            (M::ScopeLogs, 2) => F::Message(M::LogRecord),
            (M::LogRecord, 5) => F::Message(M::AnyValue),
            (M::LogRecord, 6) => F::Message(M::KeyValue),

            (M::MetricsRequest, 1) => F::Message(M::ResourceMetrics),
            (M::ResourceMetrics, 1) => F::Message(M::Resource),
            (M::ResourceMetrics, 2) => F::Message(M::ScopeMetrics),
            (M::ScopeMetrics, 1) => F::Message(M::InstrumentationScope),
            (M::ScopeMetrics, 2) => F::Message(M::Metric),
            (M::Metric, 5) => F::Message(M::Gauge),
            (M::Metric, 7) => F::Message(M::Sum),
            (M::Metric, 9) => F::Message(M::Histogram),
            (M::Metric, 10) => F::Message(M::ExponentialHistogram),
            (M::Metric, 11) => F::Message(M::Summary),
            (M::Metric, 12) => F::Message(M::KeyValue),
            (M::Gauge | M::Sum, 1) => F::Message(M::NumberDataPoint),
            (M::Histogram, 1) => F::Message(M::HistogramDataPoint),
            (M::ExponentialHistogram, 1) => F::Message(M::ExponentialHistogramDataPoint),
            (M::Summary, 1) => F::Message(M::SummaryDataPoint),
            (M::NumberDataPoint, 5) => F::Message(M::Exemplar),
            (M::NumberDataPoint, 7) => F::Message(M::KeyValue),
            (M::HistogramDataPoint, 6 | 7) => F::RepeatedFixed64,
            (M::HistogramDataPoint, 8) => F::Message(M::Exemplar),
            (M::HistogramDataPoint, 9) => F::Message(M::KeyValue),
            (M::ExponentialHistogramDataPoint, 1) => F::Message(M::KeyValue),
            (M::ExponentialHistogramDataPoint, 8 | 9) => F::Message(M::ExponentialHistogramBuckets),
            (M::ExponentialHistogramDataPoint, 11) => F::Message(M::Exemplar),
            (M::ExponentialHistogramBuckets, 2) => F::RepeatedVarint,
            (M::SummaryDataPoint, 6) => F::Message(M::SummaryQuantile),
            (M::SummaryDataPoint, 7) => F::Message(M::KeyValue),
            (M::Exemplar, 7) => F::Message(M::KeyValue),

            (M::Resource, 1) => F::Message(M::KeyValue),
            (M::Resource, 3) => F::Message(M::EntityRef),
            (M::EntityRef, 3 | 4) => F::RepeatedString,
            (M::InstrumentationScope, 3) => F::Message(M::KeyValue),
            (M::KeyValue, 2) => F::Message(M::AnyValue),
            (M::AnyValue, 5) => F::Message(M::ArrayValue),
            (M::AnyValue, 6) => F::Message(M::KeyValueList),
            (M::ArrayValue, 1) => F::Message(M::AnyValue),
            (M::KeyValueList, 1) => F::Message(M::KeyValue),
            _ => F::Other,
        }
    }
}

#[derive(Clone, Copy)]
struct ScanFrame<'a> {
    message: ProtoMessage,
    bytes: &'a [u8],
    offset: usize,
}

enum WireValue<'a> {
    Varint,
    Fixed64,
    LengthDelimited(&'a [u8]),
    Fixed32,
}

struct StructuralBudget {
    signal: &'static str,
    items: usize,
}

impl StructuralBudget {
    const fn new(signal: &'static str) -> Self {
        Self { signal, items: 0 }
    }

    fn add(&mut self, count: usize) -> Result<(), ExportError> {
        self.items = self.items.saturating_add(count);
        if self.items > MAX_STRUCTURAL_ITEMS_PER_REQUEST {
            return Err(ExportError::StructuralItemLimit {
                signal: self.signal,
                items: self.items,
                max: MAX_STRUCTURAL_ITEMS_PER_REQUEST,
            });
        }
        Ok(())
    }
}

fn structural_preflight(kind: RelaySignalKind, data: &[u8]) -> Result<(), ExportError> {
    let signal = kind.name();
    if data.len() > MAX_RELAY_PAYLOAD_BYTES {
        return Err(ExportError::PayloadTooLarge {
            signal,
            bytes: data.len(),
            max: MAX_RELAY_PAYLOAD_BYTES,
        });
    }

    let root = match kind {
        RelaySignalKind::Traces => ProtoMessage::TraceRequest,
        RelaySignalKind::Logs => ProtoMessage::LogsRequest,
        RelaySignalKind::Metrics => ProtoMessage::MetricsRequest,
    };
    let mut budget = StructuralBudget::new(signal);
    let mut frames = Vec::with_capacity(openshell_core::proto::MAX_OTLP_PROTOBUF_NESTING_DEPTH);
    frames.push(ScanFrame {
        message: root,
        bytes: data,
        offset: 0,
    });

    while let Some(mut frame) = frames.pop() {
        if frame.offset == frame.bytes.len() {
            continue;
        }

        let key = take_varint(frame.bytes, &mut frame.offset)
            .map_err(|detail| malformed_wire(signal, detail))?;
        let field_number = u32::try_from(key >> 3)
            .ok()
            .filter(|number| *number != 0 && *number <= 0x1fff_ffff)
            .ok_or_else(|| malformed_wire(signal, "invalid protobuf field number"))?;
        let value = take_wire_value(frame.bytes, &mut frame.offset, (key & 0x07) as u8)
            .map_err(|detail| malformed_wire(signal, detail))?;
        frames.push(frame);

        match (frame.message.field(field_number), value) {
            (StructuralField::Message(message), WireValue::LengthDelimited(bytes)) => {
                budget.add(1)?;
                if !openshell_core::proto::otlp_protobuf_nesting_depth_allowed(frames.len()) {
                    return Err(ExportError::NestingLimit {
                        signal,
                        max: openshell_core::proto::MAX_OTLP_PROTOBUF_NESTING_DEPTH,
                    });
                }
                frames.push(ScanFrame {
                    message,
                    bytes,
                    offset: 0,
                });
            }
            (StructuralField::RepeatedString, WireValue::LengthDelimited(_)) => {
                budget.add(1)?;
            }
            (StructuralField::RepeatedFixed64, WireValue::Fixed64)
            | (StructuralField::RepeatedVarint, WireValue::Varint) => budget.add(1)?,
            (StructuralField::RepeatedFixed64, WireValue::LengthDelimited(bytes)) => {
                if bytes.len() % size_of::<u64>() != 0 {
                    return Err(malformed_wire(
                        signal,
                        "packed fixed64 field has an invalid length",
                    ));
                }
                budget.add(bytes.len() / size_of::<u64>())?;
            }
            (StructuralField::RepeatedVarint, WireValue::LengthDelimited(bytes)) => {
                count_packed_varints(signal, bytes, &mut budget)?;
            }
            _ => {}
        }
    }

    Ok(())
}

fn count_packed_varints(
    signal: &'static str,
    bytes: &[u8],
    budget: &mut StructuralBudget,
) -> Result<(), ExportError> {
    let mut offset = 0;
    while offset < bytes.len() {
        take_varint(bytes, &mut offset).map_err(|detail| malformed_wire(signal, detail))?;
        budget.add(1)?;
    }
    Ok(())
}

fn take_wire_value<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    wire_type: u8,
) -> Result<WireValue<'a>, &'static str> {
    match wire_type {
        0 => {
            take_varint(bytes, offset)?;
            Ok(WireValue::Varint)
        }
        1 => {
            advance(bytes, offset, 8)?;
            Ok(WireValue::Fixed64)
        }
        2 => {
            let length = usize::try_from(take_varint(bytes, offset)?)
                .map_err(|_| "length-delimited protobuf field is too large")?;
            let start = *offset;
            advance(bytes, offset, length)?;
            Ok(WireValue::LengthDelimited(&bytes[start..*offset]))
        }
        5 => {
            advance(bytes, offset, 4)?;
            Ok(WireValue::Fixed32)
        }
        3 | 4 => Err("protobuf groups are not valid in OTLP relay payloads"),
        _ => Err("invalid protobuf wire type"),
    }
}

fn advance(bytes: &[u8], offset: &mut usize, count: usize) -> Result<(), &'static str> {
    let end = offset
        .checked_add(count)
        .ok_or("protobuf field length overflow")?;
    if end > bytes.len() {
        return Err("truncated protobuf field");
    }
    *offset = end;
    Ok(())
}

fn take_varint(bytes: &[u8], offset: &mut usize) -> Result<u64, &'static str> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*offset).ok_or("truncated protobuf varint")?;
        *offset += 1;
        if shift == 63 && byte > 1 {
            return Err("protobuf varint overflow");
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("protobuf varint overflow")
}

fn malformed_wire(signal: &'static str, detail: &'static str) -> ExportError {
    ExportError::MalformedProtobuf { signal, detail }
}

fn inspect_trace_response(
    response: ExportTraceServiceResponse,
) -> Result<Option<String>, ExportError> {
    inspect_partial_success(
        "traces",
        response
            .partial_success
            .map(|partial| (partial.rejected_spans, partial.error_message)),
    )
}

fn inspect_logs_response(
    response: ExportLogsServiceResponse,
) -> Result<Option<String>, ExportError> {
    inspect_partial_success(
        "logs",
        response
            .partial_success
            .map(|partial| (partial.rejected_log_records, partial.error_message)),
    )
}

fn inspect_metrics_response(
    response: ExportMetricsServiceResponse,
) -> Result<Option<String>, ExportError> {
    inspect_partial_success(
        "metrics",
        response
            .partial_success
            .map(|partial| (partial.rejected_data_points, partial.error_message)),
    )
}

fn inspect_partial_success(
    signal: &'static str,
    partial: Option<(i64, String)>,
) -> Result<Option<String>, ExportError> {
    let Some((rejected, message)) = partial else {
        return Ok(None);
    };
    if rejected == 0 && message.is_empty() {
        return Ok(None);
    }
    let message = message
        .chars()
        .take(MAX_PARTIAL_SUCCESS_MESSAGE_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    if rejected == 0 {
        Ok(Some(message))
    } else {
        Err(ExportError::PartialSuccess {
            signal,
            rejected,
            message,
        })
    }
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
    // Agent telemetry rides its own lane: `agent_endpoint` when the operator
    // split the collectors, otherwise the shared infrastructure endpoint.
    let endpoint = otlp.agent_lane_endpoint();
    let enabled_signals = RelaySignals::from_config(&otlp.agent_signals);
    if !enabled_signals.any() {
        debug!("agent_signals is empty; OTEL relay disabled");
        return None;
    }
    match OtelRelayExporter::connect_with_signals(endpoint, enabled_signals) {
        Ok(exporter) => {
            info!(
                endpoint,
                dedicated_lane = otlp.agent_endpoint.is_some(),
                traces = enabled_signals.traces(),
                logs = enabled_signals.logs(),
                metrics = enabled_signals.metrics(),
                "OTEL relay exporter configured"
            );
            Some(Arc::new(exporter))
        }
        Err(e) => {
            tracing::warn!(
                endpoint,
                error = %e,
                "invalid OTLP relay endpoint; relay disabled"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use opentelemetry_proto::tonic::collector::logs::v1::{
        ExportLogsPartialSuccess, ExportLogsServiceResponse,
        logs_service_server::{LogsService, LogsServiceServer},
    };
    use opentelemetry_proto::tonic::collector::metrics::v1::{
        ExportMetricsPartialSuccess, ExportMetricsServiceResponse,
        metrics_service_server::{MetricsService, MetricsServiceServer},
    };
    use opentelemetry_proto::tonic::collector::trace::v1::{
        ExportTracePartialSuccess, ExportTraceServiceResponse,
        trace_service_server::{TraceService, TraceServiceServer},
    };
    use opentelemetry_proto::tonic::common::v1::{AnyValue, EntityRef, KeyValue};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::metrics::v1::{
        Gauge, Metric, ResourceMetrics, ScopeMetrics, metric,
    };
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use tonic::transport::{Certificate, Identity, ServerTlsConfig};

    use super::*;
    use crate::tls_test_utils::generate_test_certs_with_ca;

    #[derive(Clone, Default)]
    struct Collector {
        traces: Arc<AtomicUsize>,
        logs: Arc<AtomicUsize>,
        metrics: Arc<AtomicUsize>,
    }

    #[tonic::async_trait]
    impl TraceService for Collector {
        async fn export(
            &self,
            _request: tonic::Request<ExportTraceServiceRequest>,
        ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
            self.traces.fetch_add(1, Ordering::Relaxed);
            Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
        }
    }

    #[tonic::async_trait]
    impl LogsService for Collector {
        async fn export(
            &self,
            _request: tonic::Request<ExportLogsServiceRequest>,
        ) -> Result<tonic::Response<ExportLogsServiceResponse>, tonic::Status> {
            self.logs.fetch_add(1, Ordering::Relaxed);
            Ok(tonic::Response::new(ExportLogsServiceResponse::default()))
        }
    }

    #[tonic::async_trait]
    impl MetricsService for Collector {
        async fn export(
            &self,
            _request: tonic::Request<ExportMetricsServiceRequest>,
        ) -> Result<tonic::Response<ExportMetricsServiceResponse>, tonic::Status> {
            self.metrics.fetch_add(1, Ordering::Relaxed);
            Ok(tonic::Response::new(ExportMetricsServiceResponse::default()))
        }
    }

    fn trace_signal() -> RelaySignal {
        RelaySignal::Traces(
            ExportTraceServiceRequest {
                resource_spans: vec![ResourceSpans::default()],
            }
            .encode_to_vec(),
        )
    }

    fn trace_signal_with_resource(resource: Resource) -> RelaySignal {
        RelaySignal::Traces(
            ExportTraceServiceRequest {
                resource_spans: vec![ResourceSpans {
                    resource: Some(resource),
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
        )
    }

    fn logs_signal() -> RelaySignal {
        RelaySignal::Logs(
            ExportLogsServiceRequest {
                resource_logs: vec![ResourceLogs::default()],
            }
            .encode_to_vec(),
        )
    }

    fn metrics_signal() -> RelaySignal {
        RelaySignal::Metrics(
            ExportMetricsServiceRequest {
                resource_metrics: vec![ResourceMetrics::default()],
            }
            .encode_to_vec(),
        )
    }

    fn metrics_request_with_empty_gauges(count: usize, add_boundary_value: bool) -> Vec<u8> {
        let mut metrics = vec![
            Metric {
                data: Some(metric::Data::Gauge(Gauge::default())),
                ..Default::default()
            };
            count
        ];
        if add_boundary_value {
            metrics[0].metadata.push(KeyValue {
                value: Some(AnyValue::default()),
                ..Default::default()
            });
        }
        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics,
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    #[derive(Clone)]
    struct BlockingTraceCollector {
        started: Arc<AtomicUsize>,
        release: Arc<Semaphore>,
    }

    impl Default for BlockingTraceCollector {
        fn default() -> Self {
            Self {
                started: Arc::new(AtomicUsize::new(0)),
                release: Arc::new(Semaphore::new(0)),
            }
        }
    }

    #[tonic::async_trait]
    impl TraceService for BlockingTraceCollector {
        async fn export(
            &self,
            _request: tonic::Request<ExportTraceServiceRequest>,
        ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
            self.started.fetch_add(1, Ordering::Relaxed);
            let permit = self
                .release
                .acquire()
                .await
                .expect("release semaphore open");
            permit.forget();
            Ok(tonic::Response::new(ExportTraceServiceResponse::default()))
        }
    }

    #[derive(Clone)]
    struct PartialSuccessTraceCollector {
        rejected_spans: i64,
        message: &'static str,
    }

    #[tonic::async_trait]
    impl TraceService for PartialSuccessTraceCollector {
        async fn export(
            &self,
            _request: tonic::Request<ExportTraceServiceRequest>,
        ) -> Result<tonic::Response<ExportTraceServiceResponse>, tonic::Status> {
            Ok(tonic::Response::new(ExportTraceServiceResponse {
                partial_success: Some(ExportTracePartialSuccess {
                    rejected_spans: self.rejected_spans,
                    error_message: self.message.into(),
                }),
            }))
        }
    }

    #[test]
    fn connect_rejects_invalid_endpoint_uri() {
        let err = OtelRelayExporter::connect("not a valid uri")
            .expect_err("an unparsable endpoint must not connect");
        assert!(matches!(err, ConnectError::InvalidUri(_)), "{err}");
    }

    #[test]
    fn connect_rejects_non_absolute_and_unsupported_endpoint_uris() {
        for endpoint in ["collector:4317", "/collector", "ftp://collector:4317"] {
            let error = OtelRelayExporter::connect(endpoint)
                .expect_err("only absolute HTTP(S) collector URIs are valid");
            assert!(matches!(error, ConnectError::InvalidUri(_)), "{endpoint}");
        }
    }

    #[tokio::test]
    async fn http_connect_is_lazy() {
        let exporter = OtelRelayExporter::connect("http://127.0.0.1:1")
            .expect("a valid endpoint must configure a lazy channel while unavailable");
        assert_eq!(exporter.enabled_signals(), RelaySignals::all());
    }

    #[tokio::test]
    async fn https_connect_configures_tls_lazily() {
        let exporter = OtelRelayExporter::connect("https://127.0.0.1:1")
            .expect("an HTTPS endpoint must configure TLS without connecting at startup");
        assert_eq!(exporter.enabled_signals(), RelaySignals::all());
    }

    #[tokio::test]
    async fn https_export_completes_a_tls_handshake() {
        let dir = tempfile::tempdir().expect("temporary certificate directory");
        generate_test_certs_with_ca(dir.path());
        let ca = fs::read(dir.path().join("ca.pem")).expect("test CA");
        let cert = fs::read(dir.path().join("server-cert.pem")).expect("server certificate");
        let key = fs::read(dir.path().join("server-key.pem")).expect("server key");

        let collector = Collector::default();
        let observed = collector.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("TLS collector listener");
        let endpoint = format!(
            "https://{}",
            listener.local_addr().expect("listener address")
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(cert, key)))?
                .add_service(TraceServiceServer::new(collector.clone()))
                .add_service(LogsServiceServer::new(collector.clone()))
                .add_service(MetricsServiceServer::new(collector))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .domain_name("localhost");
        let exporter = OtelRelayExporter::connect_with_signals_and_tls(
            &endpoint,
            RelaySignals::all(),
            Some(tls),
        )
        .expect("TLS exporter");
        exporter
            .export_raw(trace_signal())
            .await
            .expect("trace export over TLS");

        assert_eq!(observed.traces.load(Ordering::Relaxed), 1);
        shutdown_tx.send(()).expect("collector shutdown");
        server
            .await
            .expect("collector task")
            .expect("TLS collector");
    }

    async fn assert_tls_primary_or_fallback_export(primary_must_fail: bool) {
        let dir = tempfile::tempdir().expect("temporary certificate directory");
        generate_test_certs_with_ca(dir.path());
        let ca = fs::read(dir.path().join("ca.pem")).expect("test CA");
        let cert = fs::read(dir.path().join("server-cert.pem")).expect("server certificate");
        let key = fs::read(dir.path().join("server-key.pem")).expect("server key");

        let collector = Collector::default();
        let observed = collector.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("TLS collector listener");
        let endpoint = format!(
            "https://{}",
            listener.local_addr().expect("listener address")
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(cert, key)))?
                .add_service(TraceServiceServer::new(collector.clone()))
                .add_service(LogsServiceServer::new(collector.clone()))
                .add_service(MetricsServiceServer::new(collector))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let trusted = || {
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(ca.clone()))
                .domain_name("localhost")
        };
        // An empty DNS name fails while tonic constructs the TLS connector,
        // before any network I/O. It gives this test a deterministic way to
        // prove which side of the primary/fallback selection was used.
        let invalid = || ClientTlsConfig::new().domain_name("");
        let (primary, fallback) = if primary_must_fail {
            (invalid(), trusted())
        } else {
            (trusted(), invalid())
        };
        let transport = Endpoint::from_shared(endpoint).expect("collector endpoint");
        let channel = configure_tls_with_fallback(transport, primary, fallback)
            .expect("one TLS trust source must configure")
            .connect_lazy();
        OtelRelayExporter::from_channel(channel)
            .export_raw(trace_signal())
            .await
            .expect("trace export over selected TLS trust source");

        assert_eq!(observed.traces.load(Ordering::Relaxed), 1);
        shutdown_tx.send(()).expect("collector shutdown");
        server
            .await
            .expect("collector task")
            .expect("TLS collector");
    }

    #[tokio::test]
    async fn tls_primary_trust_suppresses_the_fallback() {
        assert_tls_primary_or_fallback_export(false).await;
    }

    #[tokio::test]
    async fn tls_fallback_is_used_when_primary_trust_cannot_load() {
        assert_tls_primary_or_fallback_export(true).await;
    }

    #[test]
    fn partial_success_is_reported_for_every_signal() {
        let trace_error = inspect_trace_response(ExportTraceServiceResponse {
            partial_success: Some(ExportTracePartialSuccess {
                rejected_spans: 1,
                error_message: "trace rejected".into(),
            }),
        })
        .expect_err("trace rejection must be surfaced");
        assert!(matches!(
            trace_error,
            ExportError::PartialSuccess {
                signal: "traces",
                rejected: 1,
                ..
            }
        ));

        let logs_error = inspect_logs_response(ExportLogsServiceResponse {
            partial_success: Some(ExportLogsPartialSuccess {
                rejected_log_records: 2,
                error_message: "logs rejected".into(),
            }),
        })
        .expect_err("log rejection must be surfaced");
        assert!(matches!(
            logs_error,
            ExportError::PartialSuccess {
                signal: "logs",
                rejected: 2,
                ..
            }
        ));

        let metrics_error = inspect_metrics_response(ExportMetricsServiceResponse {
            partial_success: Some(ExportMetricsPartialSuccess {
                rejected_data_points: 3,
                error_message: "metrics rejected".into(),
            }),
        })
        .expect_err("metric rejection must be surfaced");
        assert!(matches!(
            metrics_error,
            ExportError::PartialSuccess {
                signal: "metrics",
                rejected: 3,
                ..
            }
        ));
    }

    #[test]
    fn zero_rejection_partial_success_is_a_sanitized_warning() {
        let unsafe_message = format!("line\n{}", "x".repeat(400));
        let message = inspect_partial_success("traces", Some((0, unsafe_message)))
            .expect("a collector suggestion must not fail the export")
            .expect("a nonempty collector suggestion must be reported");
        assert_eq!(message.chars().count(), MAX_PARTIAL_SUCCESS_MESSAGE_CHARS);
        assert!(!message.chars().any(char::is_control));

        assert!(
            inspect_partial_success("traces", Some((0, String::new())))
                .expect("an empty partial-success response is a full success")
                .is_none(),
            "an empty partial-success response has no warning"
        );
    }

    #[tokio::test]
    async fn collector_suggestion_does_not_increment_export_failures() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(PartialSuccessTraceCollector {
                    rejected_spans: 0,
                    message: "collector recommends smaller batches",
                }))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let exporter = OtelRelayExporter::from_channel(channel);
        exporter
            .export_raw(trace_signal())
            .await
            .expect("a zero-rejection collector suggestion is a successful export");

        assert_eq!(
            exporter.export_failure_counts(RelaySignalKind::Traces),
            (0, 0)
        );
        assert_eq!(
            exporter.collector_warning_counts(RelaySignalKind::Traces),
            (1, 1)
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn collector_rejection_remains_an_export_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(PartialSuccessTraceCollector {
                    rejected_spans: 1,
                    message: "collector rejected one span",
                }))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let exporter = Arc::new(OtelRelayExporter::from_channel(channel));
        assert!(exporter.try_spawn_export(trace_signal(), "sb-test".into()));

        tokio::time::timeout(Duration::from_secs(2), async {
            while exporter.export_failure_counts(RelaySignalKind::Traces) != (1, 1)
                || exporter.available_resident_slots() != MAX_RESIDENT_DECODED_REQUESTS
                || exporter.available_export_slots() != MAX_CONCURRENT_EXPORTS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a collector rejection should be counted as an export failure");
        assert_eq!(
            exporter.collector_warning_counts(RelaySignalKind::Traces),
            (0, 0)
        );

        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn export_raw_rejects_undecodable_signal_bytes() {
        // A lazy channel performs no I/O, so the decode failure surfaces
        // before any RPC is attempted and no collector is needed.
        let exporter = OtelRelayExporter::lazy_for_test();
        for signal in [
            RelaySignal::Traces(vec![0xff, 0xff, 0xff]),
            RelaySignal::Logs(vec![0xff, 0xff, 0xff]),
            RelaySignal::Metrics(vec![0xff, 0xff, 0xff]),
        ] {
            let err = exporter
                .export_raw(signal)
                .await
                .expect_err("garbage bytes must not decode as an OTLP request");
            assert!(
                matches!(
                    err,
                    ExportError::MalformedProtobuf { .. } | ExportError::Decode { .. }
                ),
                "{err}"
            );
        }
    }

    #[tokio::test]
    async fn preflight_rejects_compact_structural_amplification_for_every_signal() {
        let count = MAX_STRUCTURAL_ITEMS_PER_REQUEST;
        let signals = [
            RelaySignal::Traces(
                ExportTraceServiceRequest {
                    resource_spans: vec![ResourceSpans {
                        scope_spans: vec![ScopeSpans {
                            spans: vec![Span::default(); count],
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                }
                .encode_to_vec(),
            ),
            RelaySignal::Logs(
                ExportLogsServiceRequest {
                    resource_logs: vec![ResourceLogs {
                        scope_logs: vec![ScopeLogs {
                            log_records: vec![LogRecord::default(); count],
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                }
                .encode_to_vec(),
            ),
            RelaySignal::Metrics(
                ExportMetricsServiceRequest {
                    resource_metrics: vec![ResourceMetrics {
                        scope_metrics: vec![ScopeMetrics {
                            metrics: vec![Metric::default(); count],
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                }
                .encode_to_vec(),
            ),
        ];
        let exporter = OtelRelayExporter::lazy_for_test();

        for signal in signals {
            let encoded_len = match &signal {
                RelaySignal::Traces(data)
                | RelaySignal::Logs(data)
                | RelaySignal::Metrics(data) => data.len(),
            };
            assert!(
                encoded_len < MAX_RELAY_PAYLOAD_BYTES,
                "the malicious request must pass the byte limit"
            );
            let error = exporter
                .export_raw(signal)
                .await
                .expect_err("structural amplification must fail before typed decode");
            assert!(
                matches!(error, ExportError::StructuralItemLimit { .. }),
                "{error}"
            );
        }
    }

    #[test]
    fn preflight_rejects_ten_thousand_empty_gauges_at_gateway_boundary() {
        // Each Metric and its present-but-empty Gauge are separate protobuf
        // messages even though the encoded request remains compact.
        let data = metrics_request_with_empty_gauges(10_000, false);
        assert!(
            data.len() < MAX_RELAY_PAYLOAD_BYTES,
            "the regression request must pass the byte limit"
        );

        let error = structural_preflight(RelaySignalKind::Metrics, &data)
            .expect_err("empty nested gauges must consume the structural budget");
        assert!(
            matches!(error, ExportError::StructuralItemLimit { .. }),
            "{error}"
        );
    }

    #[test]
    fn empty_gauges_match_the_exact_gateway_structural_boundary() {
        // The request contains two group edges plus (Metric + Gauge) * N.
        // A present empty metadata KeyValue/AnyValue pair contributes two
        // more edges, making the even 16K boundary exactly reachable.
        const FIXED_ITEMS: usize = 4;
        let remaining = MAX_STRUCTURAL_ITEMS_PER_REQUEST - FIXED_ITEMS;
        assert_eq!(remaining % 2, 0, "test setup must reach the exact limit");
        let exact_gauges = remaining / 2;

        let exact = metrics_request_with_empty_gauges(exact_gauges, true);
        structural_preflight(RelaySignalKind::Metrics, &exact)
            .expect("a request at the exact structural limit must be accepted");

        let over = metrics_request_with_empty_gauges(exact_gauges + 1, true);
        let error = structural_preflight(RelaySignalKind::Metrics, &over)
            .expect_err("one additional empty gauge must exceed the limit");
        assert!(
            matches!(error, ExportError::StructuralItemLimit { .. }),
            "{error}"
        );
    }

    #[tokio::test]
    async fn preflight_counts_resource_entity_refs_and_their_key_arrays() {
        let exporter = OtelRelayExporter::lazy_for_test();
        let too_many_refs = Resource {
            entity_refs: vec![EntityRef::default(); MAX_STRUCTURAL_ITEMS_PER_REQUEST],
            ..Default::default()
        };
        let too_many_keys = Resource {
            entity_refs: vec![EntityRef {
                id_keys: vec![String::new(); MAX_STRUCTURAL_ITEMS_PER_REQUEST],
                description_keys: vec![String::new()],
                ..Default::default()
            }],
            ..Default::default()
        };

        for resource in [too_many_refs, too_many_keys] {
            let error = exporter
                .export_raw(trace_signal_with_resource(resource))
                .await
                .expect_err("resource entity structures must count against the preflight budget");
            assert!(
                matches!(error, ExportError::StructuralItemLimit { .. }),
                "{error}"
            );
        }
    }

    #[tokio::test]
    async fn exports_all_signals_over_one_collector_channel() {
        let collector = Collector::default();
        let observed = collector.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(collector.clone()))
                .add_service(LogsServiceServer::new(collector.clone()))
                .add_service(MetricsServiceServer::new(collector))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let exporter = OtelRelayExporter::connect(&endpoint).unwrap();
        exporter
            .export_raw(RelaySignal::Traces(
                ExportTraceServiceRequest {
                    resource_spans: vec![ResourceSpans::default()],
                }
                .encode_to_vec(),
            ))
            .await
            .unwrap();
        exporter
            .export_raw(RelaySignal::Logs(
                ExportLogsServiceRequest {
                    resource_logs: vec![ResourceLogs::default()],
                }
                .encode_to_vec(),
            ))
            .await
            .unwrap();
        exporter
            .export_raw(RelaySignal::Metrics(
                ExportMetricsServiceRequest {
                    resource_metrics: vec![ResourceMetrics::default()],
                }
                .encode_to_vec(),
            ))
            .await
            .unwrap();

        assert_eq!(observed.traces.load(Ordering::Relaxed), 1);
        assert_eq!(observed.logs.load(Ordering::Relaxed), 1);
        assert_eq!(observed.metrics.load(Ordering::Relaxed), 1);
        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn traces_only_drops_logs_and_metrics_at_gateway_boundary() {
        let collector = Collector::default();
        let observed = collector.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(collector.clone()))
                .add_service(LogsServiceServer::new(collector.clone()))
                .add_service(MetricsServiceServer::new(collector))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let exporter = Arc::new(OtelRelayExporter::from_channel_with_signals(
            channel,
            RelaySignals::traces_only(),
        ));

        assert!(exporter.try_spawn_export(trace_signal(), "sb-test".to_string()));
        assert!(!exporter.try_spawn_export(logs_signal(), "sb-test".to_string()));
        assert!(!exporter.try_spawn_export(metrics_signal(), "sb-test".to_string()));
        assert_eq!(exporter.disabled_signal_drops(), 2);
        assert_eq!(exporter.backpressure_drops(), 0);

        tokio::time::timeout(Duration::from_secs(2), async {
            while observed.traces.load(Ordering::Relaxed) != 1
                || exporter.available_export_slots() != MAX_CONCURRENT_EXPORTS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the enabled trace should reach the collector");
        assert_eq!(observed.logs.load(Ordering::Relaxed), 0);
        assert_eq!(observed.metrics.load(Ordering::Relaxed), 0);

        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn explicitly_enabled_logs_and_metrics_forward() {
        let collector = Collector::default();
        let observed = collector.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(collector.clone()))
                .add_service(LogsServiceServer::new(collector.clone()))
                .add_service(MetricsServiceServer::new(collector))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let exporter = Arc::new(OtelRelayExporter::from_channel_with_signals(
            channel,
            RelaySignals {
                traces: false,
                logs: true,
                metrics: true,
            },
        ));

        assert!(!exporter.try_spawn_export(trace_signal(), "sb-test".to_string()));
        assert!(exporter.try_spawn_export(logs_signal(), "sb-test".to_string()));
        assert!(exporter.try_spawn_export(metrics_signal(), "sb-test".to_string()));
        assert_eq!(exporter.disabled_signal_drops(), 1);

        tokio::time::timeout(Duration::from_secs(2), async {
            while observed.logs.load(Ordering::Relaxed) != 1
                || observed.metrics.load(Ordering::Relaxed) != 1
                || exporter.available_export_slots() != MAX_CONCURRENT_EXPORTS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the enabled log and metric signals should reach the collector");
        assert_eq!(observed.traces.load(Ordering::Relaxed), 0);

        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn export_raw_rejects_a_disabled_signal() {
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        let exporter =
            OtelRelayExporter::from_channel_with_signals(channel, RelaySignals::traces_only());

        let error = exporter
            .export_raw(logs_signal())
            .await
            .expect_err("direct exporter calls must honor the configured signal allowlist");
        assert!(matches!(
            error,
            ExportError::SignalDisabled { signal: "logs" }
        ));
    }

    #[tokio::test]
    async fn accepted_export_failures_are_counted_per_signal() {
        let exporter = Arc::new(OtelRelayExporter::lazy_for_test());
        let sandbox_ids = ["sb-traces", "sb-logs", "sb-metrics"];

        assert!(exporter.try_spawn_export(
            RelaySignal::Traces(vec![0xff, 0xff, 0xff]),
            sandbox_ids[0].to_string(),
        ));
        assert!(exporter.try_spawn_export(
            RelaySignal::Logs(vec![0xff, 0xff, 0xff]),
            sandbox_ids[1].to_string(),
        ));
        assert!(exporter.try_spawn_export(
            RelaySignal::Metrics(vec![0xff, 0xff, 0xff]),
            sandbox_ids[2].to_string(),
        ));

        tokio::time::timeout(Duration::from_secs(2), async {
            while exporter.export_failure_counts(RelaySignalKind::Traces).0 != 3
                || exporter.available_export_slots() != MAX_CONCURRENT_EXPORTS
                || sandbox_ids
                    .iter()
                    .any(|sandbox_id| exporter.sandbox_exports_in_flight(sandbox_id) != 0)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed accepted exports should be counted and release capacity");
        assert_eq!(
            exporter.export_failure_counts(RelaySignalKind::Traces),
            (3, 1)
        );
        assert_eq!(
            exporter.export_failure_counts(RelaySignalKind::Logs),
            (3, 1)
        );
        assert_eq!(
            exporter.export_failure_counts(RelaySignalKind::Metrics),
            (3, 1)
        );
    }

    #[tokio::test]
    async fn decoded_request_residency_is_globally_bounded_across_sandboxes() {
        let collector = BlockingTraceCollector::default();
        let observed = collector.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(collector))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let exporter = Arc::new(OtelRelayExporter::from_channel_with_limits(
            channel,
            RelaySignals::all(),
            MAX_CONCURRENT_EXPORTS,
            MAX_CONCURRENT_EXPORTS_PER_SANDBOX,
        ));

        for index in 0..MAX_RESIDENT_DECODED_REQUESTS {
            assert!(
                exporter.try_spawn_export(trace_signal(), format!("sb-{index}")),
                "each distinct sandbox should be admitted up to the global resident limit"
            );
        }
        assert!(
            !exporter.try_spawn_export(trace_signal(), "sb-over-limit".to_string()),
            "a fifth sandbox must not create a fifth resident decoded request"
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            while observed.started.load(Ordering::Relaxed) != MAX_RESIDENT_DECODED_REQUESTS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the collector should receive exactly the resident request budget");
        assert_eq!(exporter.available_resident_slots(), 0);
        assert_eq!(
            exporter.available_export_slots(),
            MAX_CONCURRENT_EXPORTS - MAX_RESIDENT_DECODED_REQUESTS,
            "the resident budget must be independent of the larger export-task budget"
        );
        assert_eq!(exporter.sandbox_exports_in_flight("sb-over-limit"), 0);
        assert_eq!(exporter.backpressure_drops(), 1);

        observed.release.add_permits(MAX_RESIDENT_DECODED_REQUESTS);
        tokio::time::timeout(Duration::from_secs(2), async {
            while exporter.available_resident_slots() != MAX_RESIDENT_DECODED_REQUESTS
                || exporter.available_export_slots() != MAX_CONCURRENT_EXPORTS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed exports should return resident and export capacity");

        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn production_limits_reserve_decoded_capacity_for_another_sandbox() {
        const {
            assert!(MAX_CONCURRENT_EXPORTS_PER_SANDBOX < MAX_RESIDENT_DECODED_REQUESTS);
        }

        let collector = BlockingTraceCollector::default();
        let observed = collector.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(collector))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let exporter = Arc::new(OtelRelayExporter::from_channel_with_signals(
            channel,
            RelaySignals::all(),
        ));

        for _ in 0..MAX_CONCURRENT_EXPORTS_PER_SANDBOX {
            assert!(exporter.try_spawn_export(trace_signal(), "sb-noisy".to_string()));
        }
        assert!(
            !exporter.try_spawn_export(trace_signal(), "sb-noisy".to_string()),
            "one sandbox must stop at its own export limit"
        );
        assert!(
            exporter.try_spawn_export(trace_signal(), "sb-neighbor".to_string()),
            "a different sandbox must retain decoded-resident capacity"
        );

        tokio::time::timeout(Duration::from_secs(2), async {
            while observed.started.load(Ordering::Relaxed) != MAX_CONCURRENT_EXPORTS_PER_SANDBOX + 1
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("collector should receive exports from both sandboxes");
        assert_eq!(
            exporter.available_resident_slots(),
            MAX_RESIDENT_DECODED_REQUESTS - MAX_CONCURRENT_EXPORTS_PER_SANDBOX - 1
        );
        assert_eq!(
            exporter.available_export_slots(),
            MAX_CONCURRENT_EXPORTS - MAX_CONCURRENT_EXPORTS_PER_SANDBOX - 1
        );
        assert_eq!(
            exporter.sandbox_exports_in_flight("sb-noisy"),
            MAX_CONCURRENT_EXPORTS_PER_SANDBOX
        );
        assert_eq!(exporter.sandbox_exports_in_flight("sb-neighbor"), 1);
        assert_eq!(exporter.backpressure_drops(), 1);

        observed
            .release
            .add_permits(MAX_CONCURRENT_EXPORTS_PER_SANDBOX + 1);
        tokio::time::timeout(Duration::from_secs(2), async {
            while exporter.available_export_slots() != MAX_CONCURRENT_EXPORTS
                || exporter.available_resident_slots() != MAX_RESIDENT_DECODED_REQUESTS
                || exporter.sandbox_exports_in_flight("sb-noisy") != 0
                || exporter.sandbox_exports_in_flight("sb-neighbor") != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed exports should return global and per-sandbox capacity");

        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stalled_collector_cannot_create_unbounded_export_tasks() {
        const LIMIT: usize = 2;

        let collector = BlockingTraceCollector::default();
        let observed = collector.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(TraceServiceServer::new(collector))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    async {
                        let _ = shutdown_rx.await;
                    },
                )
                .await
        });

        let channel = Channel::from_shared(endpoint)
            .unwrap()
            .connect()
            .await
            .unwrap();
        let exporter = Arc::new(OtelRelayExporter::from_channel_with_limit(
            channel,
            RelaySignals::all(),
            LIMIT,
        ));
        let trace = || {
            RelaySignal::Traces(
                ExportTraceServiceRequest {
                    resource_spans: vec![ResourceSpans::default()],
                }
                .encode_to_vec(),
            )
        };

        for _ in 0..LIMIT {
            assert!(exporter.try_spawn_export(trace(), "sb-test".to_string()));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while observed.started.load(Ordering::Relaxed) != LIMIT {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("collector should receive the bounded exports");
        assert_eq!(exporter.available_export_slots(), 0);
        assert!(
            !exporter.try_spawn_export(trace(), "sb-test".to_string()),
            "an export beyond the concurrency bound must be rejected before spawning"
        );
        assert_eq!(exporter.backpressure_drops(), 1);
        assert_eq!(observed.started.load(Ordering::Relaxed), LIMIT);

        observed.release.add_permits(LIMIT);
        tokio::time::timeout(Duration::from_secs(2), async {
            while exporter.available_export_slots() != LIMIT {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed exports should return their slots");

        shutdown_tx.send(()).unwrap();
        server.await.unwrap().unwrap();
    }
}
