// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP relay for the sandbox supervisor.
//!
//! Agent processes export OTLP traces, logs, and metrics to the reserved relay address
//! (`openshell_core::sandbox_env::OTLP_RELAY_ADDR`). The sandbox's seccomp
//! broker stages that connect for the supervisor, whose proxy hands the
//! staged stream to the [`OtlpConnectionServer`] instead of dialing upstream.
//! Signals are enriched with sandbox resource attributes and buffered in a
//! bounded channel. The supervisor session drains the buffer into its stream
//! once the gateway confirms `otel_export_traces_v1` (or legacy `otel_export`
//! during a supervisor-first rolling upgrade), and stops the receiver before
//! the main-process exit is reported so final spans still reach the gateway.

pub mod buffer;
pub mod enrichment;
pub mod receiver;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tracing::info;

use openshell_core::proto::supervisor_message;
use openshell_core::proto::{OtelExportData, SupervisorMessage, otel_export_data};

use buffer::{BufferMetrics, TelemetryItem, TelemetryReceiver, TelemetrySender};
pub use receiver::{ConnectionPermit, OtlpConnectionServer, ReceiverHandle};

/// Bounded time the receiver gets to finish in-flight requests on shutdown.
pub const RECEIVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

/// Leave headroom inside the outer three-second process-exit drain deadline
/// for the acknowledgement to return to the boundary owner.
const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_millis(2_500);

/// Default aggregate heap budget for buffered telemetry in one sandbox.
pub const DEFAULT_BUFFER_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Rate-limited OCSF relay sink that implements token bucket rate limiting
/// and sends accepted events through the OTEL buffer as OCSF bytes.
pub struct RateLimitedOcsfSink {
    buf_tx: TelemetrySender,
    tokens: std::sync::atomic::AtomicU32,
    max_tokens: u32,
    drop_count: AtomicU64,
    last_refill: std::sync::Mutex<std::time::Instant>,
}

impl RateLimitedOcsfSink {
    pub fn new(buf_tx: TelemetrySender, rate_per_sec: u32) -> Self {
        Self {
            buf_tx,
            tokens: std::sync::atomic::AtomicU32::new(rate_per_sec),
            max_tokens: rate_per_sec,
            drop_count: AtomicU64::new(0),
            last_refill: std::sync::Mutex::new(std::time::Instant::now()),
        }
    }

    fn try_acquire(&self) -> bool {
        self.refill();
        let mut current = self.tokens.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return false;
            }
            match self.tokens.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(updated) => current = updated,
            }
        }
    }

    fn refill(&self) {
        let Ok(mut last) = self.last_refill.lock() else {
            return;
        };
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(*last);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let new_tokens = (elapsed.as_secs_f64() * f64::from(self.max_tokens)) as u32;
        if new_tokens > 0 {
            *last = now;
            let max = self.max_tokens;
            self.tokens
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(new_tokens).min(max))
                })
                .ok();
        }
    }

    pub fn drops(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
    }
}

impl openshell_ocsf::OcsfRelaySink for RateLimitedOcsfSink {
    fn send(&self, json_bytes: Vec<u8>) {
        if self.try_acquire() {
            if self.buf_tx.send_ocsf(json_bytes).is_err() {
                self.drop_count.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            self.drop_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Configuration for the OTEL relay.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub buffer_capacity: usize,
    pub buffer_max_bytes: usize,
    pub enrichment_enabled: bool,
    pub ocsf_rate_limit: u32,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: 4096,
            buffer_max_bytes: DEFAULT_BUFFER_MAX_BYTES,
            enrichment_enabled: true,
            ocsf_rate_limit: 100,
        }
    }
}

/// Supervisor-owned sandbox identity used for OTLP resource enrichment.
///
/// The workspace name is watched rather than snapshotted because the
/// supervisor learns it from `GetSandboxConfig` after the relay starts.
#[derive(Debug, Clone)]
pub struct SandboxMetadata {
    pub sandbox_id: String,
    pub sandbox_name: String,
    pub workspace_name: watch::Receiver<String>,
    pub workload_unix_uid: u32,
    pub workload_image_reference: String,
}

/// Wrap a buffered telemetry item in the session message the gateway expects.
pub fn export_message(sandbox_id: &str, item: TelemetryItem) -> SupervisorMessage {
    let export = match item {
        TelemetryItem::Trace(data) => OtelExportData {
            sandbox_id: sandbox_id.to_string(),
            signal: Some(otel_export_data::Signal::TraceData(data)),
            ocsf_events: Vec::new(),
        },
        TelemetryItem::Logs(data) => OtelExportData {
            sandbox_id: sandbox_id.to_string(),
            signal: Some(otel_export_data::Signal::LogsData(data)),
            ocsf_events: Vec::new(),
        },
        TelemetryItem::Metrics(data) => OtelExportData {
            sandbox_id: sandbox_id.to_string(),
            signal: Some(otel_export_data::Signal::MetricsData(data)),
            ocsf_events: Vec::new(),
        },
        TelemetryItem::Ocsf(data) => OtelExportData {
            sandbox_id: sandbox_id.to_string(),
            signal: None,
            ocsf_events: vec![data],
        },
    };
    SupervisorMessage {
        payload: Some(supervisor_message::Payload::OtelExport(export)),
    }
}

/// Encoded size of the session envelope that would carry `item`.
///
/// All fields used here have one-byte protobuf keys. Calculating the nested
/// length-delimited fields avoids cloning a payload solely to call
/// [`prost::Message::encoded_len`]. Tests compare this calculation against
/// the generated message implementation.
pub fn export_message_encoded_len(sandbox_id: &str, item: &TelemetryItem) -> usize {
    fn varint_len(mut value: usize) -> usize {
        let mut len = 1;
        while value >= 0x80 {
            value >>= 7;
            len += 1;
        }
        len
    }

    fn length_delimited_field_len(value_len: usize) -> usize {
        1 + varint_len(value_len) + value_len
    }

    let inner_len = length_delimited_field_len(sandbox_id.len())
        + match item {
            TelemetryItem::Trace(data)
            | TelemetryItem::Logs(data)
            | TelemetryItem::Metrics(data)
            | TelemetryItem::Ocsf(data) => length_delimited_field_len(data.len()),
        };
    length_delimited_field_len(inner_len)
}

/// Queue telemetry on the dedicated, byte-sized session lane. The caller
/// configures this channel with capacity one, independently of the control
/// lane, so telemetry remains non-blocking and cannot queue ahead of
/// heartbeats or relay-control messages.
pub(crate) fn try_send_export(
    tx: &mpsc::Sender<SupervisorMessage>,
    message: SupervisorMessage,
) -> bool {
    tx.try_send(message).is_ok()
}

/// Start the relay: build the bounded buffer and the connection server.
///
/// Called before networking starts so the server is ready for the first
/// staged stream. Returns the server the proxy serves reserved-destination
/// streams with, and the lifecycle the supervisor session drives.
pub fn start(
    config: &RelayConfig,
    metadata: SandboxMetadata,
) -> (Arc<OtlpConnectionServer>, RelayLifecycle) {
    let (buf_tx, buffer) =
        buffer::new_telemetry_buffer(config.buffer_capacity, config.buffer_max_bytes);
    let (server, receiver) = OtlpConnectionServer::new(buf_tx, metadata, config.enrichment_enabled);
    info!(
        relay = openshell_core::sandbox_env::OTLP_RELAY_ADDR,
        buffer_capacity = config.buffer_capacity,
        buffer_max_bytes = config.buffer_max_bytes,
        enrichment = config.enrichment_enabled,
        "OTEL relay started"
    );
    (server, RelayLifecycle::Running { receiver, buffer })
}

/// Relay state owned by the supervisor session loop.
///
/// Lives in the session's reconnect loop frame so the receiver and the buffer
/// survive gateway reconnects. Forwarding is gated per session on the
/// confirmed versioned signal capabilities. It also accepts legacy
/// `otel_export` for traces when connected to an older gateway during a
/// supervisor-first rolling upgrade. Between sessions, items accumulate in
/// the bounded buffer.
pub enum RelayLifecycle {
    /// Receiver serving and buffer accepting.
    Running {
        receiver: ReceiverHandle,
        buffer: TelemetryReceiver,
    },
    /// Relay disabled or already drained.
    Stopped,
}

impl RelayLifecycle {
    /// The relay is unavailable on this platform or disabled by configuration.
    pub const fn stopped() -> Self {
        Self::Stopped
    }

    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }

    /// Buffer counters while running.
    pub fn buffer_metrics(&self) -> Option<BufferMetrics> {
        match self {
            Self::Running { buffer, .. } => Some(buffer.metrics().clone()),
            Self::Stopped => None,
        }
    }

    /// Record telemetry dropped after it left the in-memory buffer but before
    /// it entered the negotiated supervisor session.
    pub fn record_session_drop(&self) {
        if let Self::Running { buffer, .. } = self {
            buffer.metrics().record_session_drop();
        }
    }

    /// Next buffered item. Pends forever unless running, so it is safe to use
    /// as a `select!` arm. Yields `None` once the receiver and all its
    /// connections are gone.
    pub async fn next_item(&mut self) -> Option<TelemetryItem> {
        match self {
            Self::Running { buffer, .. } => buffer.recv().await,
            Self::Stopped => std::future::pending().await,
        }
    }

    /// Stop accepting, close connections (bounded by
    /// [`RECEIVER_SHUTDOWN_TIMEOUT`]), then push everything still buffered into
    /// `tx`. Ends in [`RelayLifecycle::Stopped`]. Queue admission is allowed to
    /// wait only within [`SESSION_DRAIN_TIMEOUT`], after which the unsent
    /// remainder is accounted as dropped.
    pub async fn stop_and_drain<F>(
        &mut self,
        sandbox_id: &str,
        tx: &mpsc::Sender<SupervisorMessage>,
        should_forward: F,
    ) where
        F: FnMut(&TelemetryItem) -> bool,
    {
        self.stop_and_drain_with_timeout(sandbox_id, tx, SESSION_DRAIN_TIMEOUT, should_forward)
            .await;
    }

    async fn stop_and_drain_with_timeout<F>(
        &mut self,
        sandbox_id: &str,
        tx: &mpsc::Sender<SupervisorMessage>,
        timeout: Duration,
        mut should_forward: F,
    ) where
        F: FnMut(&TelemetryItem) -> bool,
    {
        let Self::Running {
            receiver,
            mut buffer,
        } = std::mem::replace(self, Self::Stopped)
        else {
            return;
        };

        let deadline = tokio::time::Instant::now() + timeout;
        receiver.shutdown().await;

        let items = buffer.drain();
        let buffered = items.len();
        let mut forwarded = 0usize;
        for item in items {
            if !should_forward(&item) {
                buffer.metrics().record_session_drop();
                continue;
            }
            if tokio::time::Instant::now() >= deadline {
                buffer.metrics().record_session_drop();
                continue;
            }
            match tokio::time::timeout_at(deadline, tx.send(export_message(sandbox_id, item))).await
            {
                Ok(Ok(())) => forwarded += 1,
                Ok(Err(_)) | Err(_) => buffer.metrics().record_session_drop(),
            }
        }
        info!(
            buffered,
            forwarded,
            buffer_drops = buffer.metrics().drops(),
            session_drops = buffer.metrics().session_drops(),
            "OTEL relay stopped"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_ocsf::OcsfRelaySink;
    use prost::Message;
    use receiver::test_util::{connect, metadata, request, sample_trace_body, send};

    fn small_config() -> RelayConfig {
        RelayConfig {
            buffer_capacity: 16,
            buffer_max_bytes: 1024 * 1024,
            ..RelayConfig::default()
        }
    }

    #[test]
    fn rate_limiter_acquires_initial_tokens() {
        let (buf_tx, _rx) = buffer::new_telemetry_buffer(64, 1024);
        let sink = RateLimitedOcsfSink::new(buf_tx, 10);

        for i in 0..10 {
            assert!(sink.try_acquire(), "token {i} should be available");
        }
        assert!(!sink.try_acquire(), "11th token should fail");
    }

    #[test]
    fn rate_limiter_drops_when_exhausted() {
        let (buf_tx, mut rx) = buffer::new_telemetry_buffer(64, 1024);
        let sink = RateLimitedOcsfSink::new(buf_tx, 2);

        sink.send(vec![1]);
        sink.send(vec![2]);
        sink.send(vec![3]);

        assert_eq!(sink.drops(), 1);
        let items = rx.drain();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn rate_limiter_refills_after_time() {
        let (buf_tx, _rx) = buffer::new_telemetry_buffer(64, 1024);
        let sink = RateLimitedOcsfSink::new(buf_tx, 100);

        for _ in 0..100 {
            sink.try_acquire();
        }
        assert!(!sink.try_acquire(), "should be exhausted");

        std::thread::sleep(Duration::from_millis(50));
        assert!(sink.try_acquire(), "should have refilled after 50ms");
    }

    #[test]
    fn export_message_wraps_all_signals_and_ocsf() {
        let msg = export_message("sb-1", TelemetryItem::Trace(vec![1, 2, 3]));
        let Some(supervisor_message::Payload::OtelExport(export)) = msg.payload else {
            panic!("expected OtelExport payload");
        };
        assert_eq!(export.sandbox_id, "sb-1");
        assert_eq!(
            export.signal,
            Some(otel_export_data::Signal::TraceData(vec![1, 2, 3]))
        );
        assert!(export.ocsf_events.is_empty());

        let msg = export_message("sb-1", TelemetryItem::Logs(vec![4, 5]));
        let Some(supervisor_message::Payload::OtelExport(export)) = msg.payload else {
            panic!("expected OtelExport payload");
        };
        assert_eq!(
            export.signal,
            Some(otel_export_data::Signal::LogsData(vec![4, 5]))
        );

        let msg = export_message("sb-1", TelemetryItem::Metrics(vec![6, 7]));
        let Some(supervisor_message::Payload::OtelExport(export)) = msg.payload else {
            panic!("expected OtelExport payload");
        };
        assert_eq!(
            export.signal,
            Some(otel_export_data::Signal::MetricsData(vec![6, 7]))
        );

        let msg = export_message("sb-1", TelemetryItem::Ocsf(vec![9]));
        let Some(supervisor_message::Payload::OtelExport(export)) = msg.payload else {
            panic!("expected OtelExport payload");
        };
        assert_eq!(export.signal, None);
        assert_eq!(export.ocsf_events, vec![vec![9]]);
    }

    #[test]
    fn calculated_export_size_matches_protobuf_for_every_signal() {
        for item in [
            TelemetryItem::Trace(vec![1, 2, 3]),
            TelemetryItem::Logs(vec![4, 5]),
            TelemetryItem::Metrics(vec![6]),
            TelemetryItem::Ocsf(vec![7, 8, 9, 10]),
        ] {
            assert_eq!(
                export_message_encoded_len("sandbox-with-a-longer-id", &item),
                export_message("sandbox-with-a-longer-id", item).encoded_len()
            );
        }
    }

    #[tokio::test]
    async fn stopped_lifecycle_pends_and_drains_as_noop() {
        let mut relay = RelayLifecycle::stopped();
        assert!(!relay.is_running());
        assert!(relay.buffer_metrics().is_none());

        let pended = tokio::time::timeout(Duration::from_millis(50), relay.next_item()).await;
        assert!(pended.is_err(), "a stopped relay must pend, not yield");

        let (tx, mut rx) = mpsc::channel(8);
        relay.stop_and_drain("sb-test", &tx, |_| true).await;
        assert!(matches!(relay, RelayLifecycle::Stopped));
        assert!(rx.try_recv().is_err(), "nothing to drain");
    }

    #[tokio::test]
    async fn start_is_running_before_any_stream_arrives() {
        let (server, relay) = start(&small_config(), metadata());
        assert!(relay.is_running());
        assert_eq!(relay.buffer_metrics().unwrap().depth(), 0);
        assert!(
            server.try_reserve().is_some(),
            "the server accepts streams before the session confirms anything"
        );
    }

    #[tokio::test]
    async fn stop_and_drain_flushes_buffered_items_into_tx() {
        let (server, mut relay) = start(&small_config(), metadata());
        let (tx, mut rx) = mpsc::channel(8);

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request(
                "POST",
                "/v1/traces",
                "application/x-protobuf",
                &sample_trace_body(),
            ),
        )
        .await;
        assert!(status.contains("200"), "unexpected status: {status}");
        assert_eq!(relay.buffer_metrics().unwrap().depth(), 1);

        relay.stop_and_drain("sb-test", &tx, |_| true).await;
        assert!(matches!(relay, RelayLifecycle::Stopped));
        assert!(
            server.try_reserve().is_none(),
            "the server refuses streams once drained"
        );

        let msg = rx.try_recv().expect("one drained export message");
        let Some(supervisor_message::Payload::OtelExport(export)) = msg.payload else {
            panic!("expected OtelExport payload");
        };
        assert_eq!(export.sandbox_id, "sb-test");
        assert!(matches!(
            export.signal,
            Some(otel_export_data::Signal::TraceData(_))
        ));
        assert!(rx.try_recv().is_err(), "no further messages expected");
    }

    #[tokio::test]
    async fn stop_and_drain_waits_for_session_capacity_and_flushes_all_items() {
        let (server, mut relay) = start(&small_config(), metadata());
        let (tx, mut rx) = mpsc::channel::<SupervisorMessage>(1);

        let mut client = connect(&server);
        for _ in 0..4 {
            let status = send(
                &mut client,
                &request(
                    "POST",
                    "/v1/traces",
                    "application/x-protobuf",
                    &sample_trace_body(),
                ),
            )
            .await;
            assert!(status.contains("200"), "unexpected status: {status}");
        }
        let metrics = relay.buffer_metrics().expect("running relay metrics");
        let consumer = tokio::spawn(async move {
            let mut received = 0usize;
            while let Some(message) = rx.recv().await {
                assert!(matches!(
                    message.payload,
                    Some(supervisor_message::Payload::OtelExport(_))
                ));
                received += 1;
                if received == 4 {
                    break;
                }
            }
            received
        });

        relay.stop_and_drain("sb-test", &tx, |_| true).await;

        assert_eq!(consumer.await.unwrap(), 4);
        assert_eq!(metrics.session_drops(), 0);
    }

    #[tokio::test]
    async fn stop_and_drain_bounds_full_session_queue_and_accounts_drops() {
        let (server, mut relay) = start(&small_config(), metadata());
        let (tx, mut rx) = mpsc::channel(1);

        let mut client = connect(&server);
        for _ in 0..4 {
            let status = send(
                &mut client,
                &request(
                    "POST",
                    "/v1/traces",
                    "application/x-protobuf",
                    &sample_trace_body(),
                ),
            )
            .await;
            assert!(status.contains("200"), "unexpected status: {status}");
        }
        let metrics = relay.buffer_metrics().expect("running relay metrics");

        relay
            .stop_and_drain_with_timeout("sb-test", &tx, Duration::from_millis(10), |_| true)
            .await;

        assert_eq!(
            rx.len(),
            1,
            "one telemetry frame may leave the relay buffer"
        );
        assert_eq!(metrics.session_drops(), 3);
        let _ = rx
            .try_recv()
            .expect("one telemetry item should be forwarded");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn telemetry_session_lane_allows_only_one_queued_frame() {
        let (tx, mut rx) = mpsc::channel(1);
        assert!(try_send_export(
            &tx,
            export_message("sb-test", TelemetryItem::Trace(vec![1]))
        ));
        assert!(
            !try_send_export(
                &tx,
                export_message("sb-test", TelemetryItem::Trace(vec![99]))
            ),
            "telemetry must not build a second unaccounted queue"
        );
        assert_eq!(rx.len(), 1);
        let _ = rx.try_recv().expect("one telemetry frame is queued");
    }
}
