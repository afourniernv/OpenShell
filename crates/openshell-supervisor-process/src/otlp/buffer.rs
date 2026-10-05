// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded telemetry buffer with ring-buffer drop semantics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

/// Distinguishes OTLP signals from OCSF events in the shared buffer.
#[derive(Debug)]
pub enum TelemetryItem {
    Trace(Vec<u8>),
    Logs(Vec<u8>),
    Metrics(Vec<u8>),
    Ocsf(Vec<u8>),
}

impl TelemetryItem {
    fn allocated_bytes(&self) -> usize {
        match self {
            Self::Trace(data) | Self::Logs(data) | Self::Metrics(data) | Self::Ocsf(data) => {
                data.capacity().max(1)
            }
        }
    }
}

#[derive(Debug)]
struct BufferedTelemetryItem {
    item: TelemetryItem,
    reserved_bytes: usize,
    _byte_permit: OwnedSemaphorePermit,
}

/// Why a telemetry item could not enter the bounded buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetrySendError {
    /// The item exceeds the complete byte budget by itself.
    TooLarge,
    /// The item-count or byte budget is currently exhausted.
    Full,
    /// The receiving side has shut down.
    Closed,
}

/// Shared drop/depth counters for the buffer.
#[derive(Debug, Clone)]
pub struct BufferMetrics {
    drop_count: Arc<AtomicU64>,
    session_drop_count: Arc<AtomicU64>,
    queue_depth: Arc<AtomicUsize>,
    queued_bytes: Arc<AtomicUsize>,
}

impl BufferMetrics {
    pub fn drops(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
    }

    pub fn session_drops(&self) -> u64 {
        self.session_drop_count.load(Ordering::Relaxed)
    }

    pub fn depth(&self) -> usize {
        self.queue_depth.load(Ordering::Relaxed)
    }

    pub fn bytes(&self) -> usize {
        self.queued_bytes.load(Ordering::Relaxed)
    }

    pub(crate) fn record_session_drop(&self) {
        self.session_drop_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Sender half of the telemetry buffer. Sends never block: when the buffer
/// is full, the new item is dropped and the drop counter increments.
#[derive(Clone)]
pub struct TelemetrySender {
    tx: mpsc::Sender<BufferedTelemetryItem>,
    byte_budget: Arc<Semaphore>,
    max_bytes: usize,
    metrics: BufferMetrics,
}

impl TelemetrySender {
    /// Send a telemetry item into the buffer. If the channel is full, the
    /// item is dropped and the drop counter is incremented.
    pub fn send(&self, item: TelemetryItem) -> Result<(), TelemetrySendError> {
        let reserved_bytes = item.allocated_bytes();
        let Ok(permits) = u32::try_from(reserved_bytes) else {
            self.metrics.drop_count.fetch_add(1, Ordering::Relaxed);
            return Err(TelemetrySendError::TooLarge);
        };
        if reserved_bytes > self.max_bytes {
            self.metrics.drop_count.fetch_add(1, Ordering::Relaxed);
            return Err(TelemetrySendError::TooLarge);
        }
        let byte_permit = Arc::clone(&self.byte_budget)
            .try_acquire_many_owned(permits)
            .map_err(|_| {
                self.metrics.drop_count.fetch_add(1, Ordering::Relaxed);
                TelemetrySendError::Full
            })?;

        // Account before publishing the entry: a receiver may dequeue it as
        // soon as `try_send` succeeds.
        self.metrics.queue_depth.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .queued_bytes
            .fetch_add(reserved_bytes, Ordering::Relaxed);
        let entry = BufferedTelemetryItem {
            item,
            reserved_bytes,
            _byte_permit: byte_permit,
        };
        match self.tx.try_send(entry) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
                self.metrics
                    .queued_bytes
                    .fetch_sub(reserved_bytes, Ordering::Relaxed);
                self.metrics.drop_count.fetch_add(1, Ordering::Relaxed);
                match error {
                    mpsc::error::TrySendError::Closed(_) => Err(TelemetrySendError::Closed),
                    mpsc::error::TrySendError::Full(_) => Err(TelemetrySendError::Full),
                }
            }
        }
    }

    pub fn send_trace(&self, data: Vec<u8>) -> Result<(), TelemetrySendError> {
        self.send(TelemetryItem::Trace(data))
    }

    pub fn send_logs(&self, data: Vec<u8>) -> Result<(), TelemetrySendError> {
        self.send(TelemetryItem::Logs(data))
    }

    pub fn send_metrics(&self, data: Vec<u8>) -> Result<(), TelemetrySendError> {
        self.send(TelemetryItem::Metrics(data))
    }

    pub fn send_ocsf(&self, data: Vec<u8>) -> Result<(), TelemetrySendError> {
        self.send(TelemetryItem::Ocsf(data))
    }

    pub fn metrics(&self) -> &BufferMetrics {
        &self.metrics
    }
}

/// Receiver half of the telemetry buffer.
pub struct TelemetryReceiver {
    rx: mpsc::Receiver<BufferedTelemetryItem>,
    metrics: BufferMetrics,
}

impl TelemetryReceiver {
    /// Receive the next buffered entry, or `None` if all senders are dropped.
    pub async fn recv(&mut self) -> Option<TelemetryItem> {
        let entry = self.rx.recv().await?;
        self.release_metrics(&entry);
        Some(entry.item)
    }

    /// Drain all currently buffered entries without waiting.
    pub fn drain(&mut self) -> Vec<TelemetryItem> {
        let mut items = Vec::new();
        while let Ok(entry) = self.rx.try_recv() {
            self.release_metrics(&entry);
            items.push(entry.item);
        }
        items
    }

    pub fn metrics(&self) -> &BufferMetrics {
        &self.metrics
    }

    fn release_metrics(&self, entry: &BufferedTelemetryItem) {
        self.metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
        self.metrics
            .queued_bytes
            .fetch_sub(entry.reserved_bytes, Ordering::Relaxed);
    }
}

impl Drop for TelemetryReceiver {
    fn drop(&mut self) {
        while let Ok(entry) = self.rx.try_recv() {
            self.release_metrics(&entry);
        }
    }
}

/// Create a new telemetry buffer pair with item and allocated-byte bounds.
pub fn new_telemetry_buffer(
    capacity: usize,
    max_bytes: usize,
) -> (TelemetrySender, TelemetryReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    let metrics = BufferMetrics {
        drop_count: Arc::new(AtomicU64::new(0)),
        session_drop_count: Arc::new(AtomicU64::new(0)),
        queue_depth: Arc::new(AtomicUsize::new(0)),
        queued_bytes: Arc::new(AtomicUsize::new(0)),
    };
    let byte_budget = Arc::new(Semaphore::new(max_bytes));
    (
        TelemetrySender {
            tx,
            byte_budget,
            max_bytes,
            metrics: metrics.clone(),
        },
        TelemetryReceiver { rx, metrics },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn buffer_drops_when_full() {
        let (tx, mut rx) = new_telemetry_buffer(2, 1024);

        tx.send_trace(vec![1]).unwrap();
        tx.send_trace(vec![2]).unwrap();
        assert_eq!(tx.send_trace(vec![3]), Err(TelemetrySendError::Full));

        assert_eq!(tx.metrics().drops(), 1);
        assert_eq!(tx.metrics().depth(), 2);

        let first = rx.recv().await.unwrap();
        assert!(matches!(first, TelemetryItem::Trace(v) if v == vec![1]));
        assert_eq!(rx.metrics().depth(), 1);
    }

    #[tokio::test]
    async fn drain_empties_buffer() {
        let (tx, mut rx) = new_telemetry_buffer(16, 1024);

        tx.send_trace(vec![1]).unwrap();
        tx.send_ocsf(vec![2]).unwrap();
        tx.send_logs(vec![3]).unwrap();
        tx.send_metrics(vec![4]).unwrap();

        let items = rx.drain();
        assert_eq!(items.len(), 4);
        assert!(matches!(&items[0], TelemetryItem::Trace(_)));
        assert!(matches!(&items[1], TelemetryItem::Ocsf(_)));
        assert!(matches!(&items[2], TelemetryItem::Logs(_)));
        assert!(matches!(&items[3], TelemetryItem::Metrics(_)));
        assert_eq!(rx.metrics().depth(), 0);
        assert_eq!(rx.metrics().bytes(), 0);
    }

    #[tokio::test]
    async fn depth_tracks_send_and_recv() {
        let (tx, mut rx) = new_telemetry_buffer(16, 1024);

        tx.send_trace(vec![1]).unwrap();
        tx.send_trace(vec![2]).unwrap();
        tx.send_trace(vec![3]).unwrap();
        assert_eq!(tx.metrics().depth(), 3);
        assert_eq!(tx.metrics().bytes(), 3);

        rx.recv().await.unwrap();
        assert_eq!(rx.metrics().depth(), 2);
        assert_eq!(rx.metrics().bytes(), 2);

        let remaining = rx.drain();
        assert_eq!(remaining.len(), 2);
        assert_eq!(rx.metrics().depth(), 0);
        assert_eq!(rx.metrics().bytes(), 0);
    }

    #[tokio::test]
    async fn drop_count_increments_on_each_overflow() {
        let (tx, _rx) = new_telemetry_buffer(2, 1024);

        tx.send_trace(vec![1]).unwrap();
        tx.send_trace(vec![2]).unwrap();
        assert_eq!(tx.metrics().drops(), 0);

        for _ in 0..5 {
            assert_eq!(tx.send_trace(vec![99]), Err(TelemetrySendError::Full));
        }
        assert_eq!(tx.metrics().drops(), 5);
        assert_eq!(tx.metrics().depth(), 2);
    }

    #[tokio::test]
    async fn metrics_shared_across_clones() {
        let (tx, mut rx) = new_telemetry_buffer(16, 1024);
        let tx2 = tx.clone();

        tx.send_trace(vec![1]).unwrap();
        tx2.send_trace(vec![2]).unwrap();
        tx.send_ocsf(vec![3]).unwrap();

        assert_eq!(tx.metrics().depth(), 3);
        assert_eq!(tx2.metrics().depth(), 3);

        rx.recv().await.unwrap();
        assert_eq!(tx.metrics().depth(), 2);
        assert_eq!(tx2.metrics().depth(), 2);
    }

    #[tokio::test]
    async fn recv_returns_none_when_all_senders_dropped() {
        let (tx, mut rx) = new_telemetry_buffer(16, 1024);
        tx.send_trace(vec![1]).unwrap();
        drop(tx);

        assert!(rx.recv().await.is_some());
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn byte_budget_is_shared_across_signals_and_released_on_receive() {
        let (tx, mut rx) = new_telemetry_buffer(16, 6);

        tx.send_trace(vec![1, 2, 3]).unwrap();
        tx.send_logs(vec![4, 5, 6]).unwrap();
        assert_eq!(tx.metrics().bytes(), 6);
        assert_eq!(tx.send_metrics(vec![7]), Err(TelemetrySendError::Full));

        assert!(matches!(rx.recv().await, Some(TelemetryItem::Trace(_))));
        assert_eq!(tx.metrics().bytes(), 3);
        tx.send_metrics(vec![7]).unwrap();
        assert_eq!(tx.metrics().bytes(), 4);
    }

    #[test]
    fn item_larger_than_byte_budget_is_rejected() {
        let (tx, _rx) = new_telemetry_buffer(16, 2);
        assert_eq!(
            tx.send_trace(vec![1, 2, 3]),
            Err(TelemetrySendError::TooLarge)
        );
        assert_eq!(tx.metrics().depth(), 0);
        assert_eq!(tx.metrics().bytes(), 0);
        assert_eq!(tx.metrics().drops(), 1);
    }
}
