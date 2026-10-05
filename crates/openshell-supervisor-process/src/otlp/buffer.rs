// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded telemetry buffer with ring-buffer drop semantics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::sync::mpsc;

use super::MAX_TELEMETRY_ITEM_BYTES;

/// Distinguishes trace data from OCSF events in the shared buffer.
#[derive(Debug)]
pub enum TelemetryItem {
    Trace(Vec<u8>),
    Logs(Vec<u8>),
    Metrics(Vec<u8>),
    Ocsf(Vec<u8>),
}

impl TelemetryItem {
    fn len(&self) -> usize {
        match self {
            Self::Trace(data) | Self::Logs(data) | Self::Metrics(data) | Self::Ocsf(data) => {
                data.len()
            }
        }
    }

    /// Heap bytes retained while this item is queued. Capacity, rather than
    /// length, prevents a small payload backed by a large allocation from
    /// bypassing the aggregate memory budget.
    fn allocated_bytes(&self) -> usize {
        match self {
            Self::Trace(data) | Self::Logs(data) | Self::Metrics(data) | Self::Ocsf(data) => {
                data.capacity()
            }
        }
    }
}

/// Why a telemetry item could not be admitted to the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TelemetrySendError {
    #[error("telemetry item exceeds the per-item size limit")]
    TooLarge,
    #[error("telemetry buffer is full")]
    Full,
    #[error("telemetry buffer is closed")]
    Closed,
}

/// Shared drop/depth counters for the buffer.
#[derive(Debug, Clone)]
pub struct BufferMetrics {
    drop_count: Arc<AtomicU64>,
    queue_depth: Arc<AtomicUsize>,
    queued_bytes: Arc<AtomicUsize>,
    byte_capacity: usize,
}

impl BufferMetrics {
    pub fn drops(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
    }

    pub fn depth(&self) -> usize {
        self.queue_depth.load(Ordering::Relaxed)
    }

    pub fn bytes(&self) -> usize {
        self.queued_bytes.load(Ordering::Relaxed)
    }

    pub const fn byte_capacity(&self) -> usize {
        self.byte_capacity
    }

    fn try_reserve_bytes(&self, bytes: usize) -> bool {
        let mut current = self.queued_bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(bytes) else {
                return false;
            };
            if next > self.byte_capacity {
                return false;
            }
            match self.queued_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(updated) => current = updated,
            }
        }
    }

    fn release(&self, item: &TelemetryItem) {
        self.queue_depth.fetch_sub(1, Ordering::Relaxed);
        self.queued_bytes
            .fetch_sub(item.allocated_bytes(), Ordering::Relaxed);
    }
}

/// Sender half of the telemetry buffer. Sends never block: when the buffer
/// is full, the new item is dropped and the drop counter increments.
#[derive(Clone)]
pub struct TelemetrySender {
    tx: mpsc::Sender<TelemetryItem>,
    metrics: BufferMetrics,
}

impl TelemetrySender {
    /// Send a telemetry item into the buffer. If the channel is full, the
    /// item is dropped and the drop counter is incremented.
    pub fn send(&self, item: TelemetryItem) -> Result<(), TelemetrySendError> {
        if item.len() > MAX_TELEMETRY_ITEM_BYTES {
            self.metrics.drop_count.fetch_add(1, Ordering::Relaxed);
            return Err(TelemetrySendError::TooLarge);
        }

        let allocated_bytes = item.allocated_bytes();
        if !self.metrics.try_reserve_bytes(allocated_bytes) {
            self.metrics.drop_count.fetch_add(1, Ordering::Relaxed);
            return Err(TelemetrySendError::Full);
        }

        // Publish accounting before the channel makes the item visible. A
        // receiver can otherwise dequeue and underflow the counters before a
        // successful sender increments them.
        self.metrics.queue_depth.fetch_add(1, Ordering::Relaxed);
        match self.tx.try_send(item) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.metrics.queue_depth.fetch_sub(1, Ordering::Relaxed);
                self.metrics
                    .queued_bytes
                    .fetch_sub(allocated_bytes, Ordering::Relaxed);
                self.metrics.drop_count.fetch_add(1, Ordering::Relaxed);
                match error {
                    mpsc::error::TrySendError::Full(_) => Err(TelemetrySendError::Full),
                    mpsc::error::TrySendError::Closed(_) => Err(TelemetrySendError::Closed),
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
    rx: mpsc::Receiver<TelemetryItem>,
    metrics: BufferMetrics,
}

impl TelemetryReceiver {
    /// Receive the next buffered entry, or `None` if all senders are dropped.
    pub async fn recv(&mut self) -> Option<TelemetryItem> {
        let item = self.rx.recv().await;
        if let Some(item) = &item {
            self.metrics.release(item);
        }
        item
    }

    /// Drain all currently buffered entries without waiting.
    pub fn drain(&mut self) -> Vec<TelemetryItem> {
        let mut items = Vec::new();
        while let Ok(item) = self.rx.try_recv() {
            self.metrics.release(&item);
            items.push(item);
        }
        items
    }

    pub fn metrics(&self) -> &BufferMetrics {
        &self.metrics
    }
}

impl Drop for TelemetryReceiver {
    fn drop(&mut self) {
        self.rx.close();
        while let Ok(item) = self.rx.try_recv() {
            self.metrics.release(&item);
        }
    }
}

/// Create a new telemetry buffer pair with the given capacity.
pub fn new_telemetry_buffer(
    item_capacity: usize,
    byte_capacity: usize,
) -> (TelemetrySender, TelemetryReceiver) {
    let (tx, rx) = mpsc::channel(item_capacity);
    let metrics = BufferMetrics {
        drop_count: Arc::new(AtomicU64::new(0)),
        queue_depth: Arc::new(AtomicUsize::new(0)),
        queued_bytes: Arc::new(AtomicUsize::new(0)),
        byte_capacity,
    };
    (
        TelemetrySender {
            tx,
            metrics: metrics.clone(),
        },
        TelemetryReceiver { rx, metrics },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BYTE_CAPACITY: usize = 1024;

    #[tokio::test]
    async fn buffer_drops_when_full() {
        let (tx, mut rx) = new_telemetry_buffer(2, TEST_BYTE_CAPACITY);

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
        let (tx, mut rx) = new_telemetry_buffer(16, TEST_BYTE_CAPACITY);

        tx.send_trace(vec![1]).unwrap();
        tx.send_ocsf(vec![2]).unwrap();
        tx.send_trace(vec![3]).unwrap();

        let items = rx.drain();
        assert_eq!(items.len(), 3);
        assert!(matches!(&items[0], TelemetryItem::Trace(_)));
        assert!(matches!(&items[1], TelemetryItem::Ocsf(_)));
        assert_eq!(rx.metrics().depth(), 0);
        assert_eq!(rx.metrics().bytes(), 0);
    }

    #[tokio::test]
    async fn depth_tracks_send_and_recv() {
        let (tx, mut rx) = new_telemetry_buffer(16, TEST_BYTE_CAPACITY);

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
    }

    #[tokio::test]
    async fn drop_count_increments_on_each_overflow() {
        let (tx, _rx) = new_telemetry_buffer(2, TEST_BYTE_CAPACITY);

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
        let (tx, mut rx) = new_telemetry_buffer(16, TEST_BYTE_CAPACITY);
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
        let (tx, mut rx) = new_telemetry_buffer(16, TEST_BYTE_CAPACITY);
        tx.send_trace(vec![1]).unwrap();
        drop(tx);

        assert!(rx.recv().await.is_some());
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn byte_budget_is_released_by_receive_and_drain() {
        let (tx, mut rx) = new_telemetry_buffer(16, 6);

        tx.send_trace(vec![1; 4]).unwrap();
        tx.send_ocsf(vec![2; 2]).unwrap();
        assert_eq!(tx.metrics().bytes(), 6);
        assert_eq!(tx.send_trace(vec![3]), Err(TelemetrySendError::Full));

        rx.recv().await.unwrap();
        assert_eq!(tx.metrics().bytes(), 2);
        tx.send_trace(vec![4; 4]).unwrap();
        assert_eq!(tx.metrics().bytes(), 6);

        assert_eq!(rx.drain().len(), 2);
        assert_eq!(tx.metrics().bytes(), 0);
        assert_eq!(tx.metrics().depth(), 0);
    }

    #[test]
    fn allocated_capacity_counts_against_byte_budget() {
        let (tx, _rx) = new_telemetry_buffer(16, 4);
        let mut data = Vec::with_capacity(5);
        data.push(1);

        assert_eq!(tx.send_trace(data), Err(TelemetrySendError::Full));
        assert_eq!(tx.metrics().bytes(), 0);
        assert_eq!(tx.metrics().depth(), 0);
    }

    #[test]
    fn closed_buffer_reports_closed_and_releases_queued_bytes() {
        let (tx, rx) = new_telemetry_buffer(16, TEST_BYTE_CAPACITY);
        tx.send_trace(vec![1; 8]).unwrap();
        drop(rx);

        assert_eq!(tx.metrics().bytes(), 0);
        assert_eq!(tx.metrics().depth(), 0);
        assert_eq!(tx.send_trace(vec![2]), Err(TelemetrySendError::Closed));
    }
}
