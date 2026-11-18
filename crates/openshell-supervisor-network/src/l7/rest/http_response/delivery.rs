// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{IoSlice, Result};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::Span;

pub(super) struct ResponseReader<'a, R> {
    inner: &'a mut R,
    eof: bool,
}

impl<'a, R> ResponseReader<'a, R> {
    pub(super) fn new(inner: &'a mut R) -> Self {
        Self { inner, eof: false }
    }

    pub(super) fn saw_eof(&self) -> bool {
        self.eof
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for ResponseReader<'_, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let can_read = buffer.remaining() > 0;
        let result = Pin::new(&mut *this.inner).poll_read(cx, buffer);
        if can_read && matches!(result, Poll::Ready(Ok(()))) && buffer.filled().len() == before {
            this.eof = true;
        }
        result
    }
}

/// Observe accepted wire bytes without changing or interpreting downstream I/O.
pub(super) struct ResponseWriter<'a, W> {
    inner: &'a mut W,
    span: Span,
    wire_bytes: u64,
    io_error: Option<&'static str>,
    outcome: &'static str,
}

impl<'a, W> ResponseWriter<'a, W> {
    pub(super) fn new(inner: &'a mut W, span: Span) -> Self {
        Self {
            inner,
            span,
            wire_bytes: 0,
            io_error: None,
            outcome: "cancelled",
        }
    }

    pub(super) fn outcome(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }

    pub(super) fn upstream_status(&self, status: Option<u16>) {
        if let Some(status) = status {
            self.span
                .record("openshell.response.upstream_status_code", i64::from(status));
        }
    }

    pub(super) fn selected_status(&self, status: Option<u16>) {
        if let Some(status) = status {
            self.span
                .record("openshell.response.selected_status_code", i64::from(status));
        }
    }

    pub(super) fn finish(&mut self, failed: bool) {
        if self.io_error.is_some() {
            self.outcome = "downstream_failed";
        } else if failed {
            self.outcome = "failed";
        } else if self.outcome == "cancelled" {
            // Middleware may return after delivering a replacement or stopping
            // a stream. Returning alone does not establish complete framing.
            self.outcome = "returned";
        }
    }

    fn record_write(&mut self, result: &Poll<Result<usize>>, nonempty: bool) {
        match result {
            Poll::Ready(Ok(written)) => {
                self.wire_bytes = self.wire_bytes.saturating_add(*written as u64);
                if *written == 0 && nonempty {
                    self.io_error.get_or_insert("write");
                }
            }
            Poll::Ready(Err(_)) => {
                self.io_error.get_or_insert("write");
            }
            Poll::Pending => {}
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for ResponseWriter<'_, W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(cx, bytes);
        this.record_write(&result, !bytes.is_empty());
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write_vectored(cx, buffers);
        this.record_write(&result, buffers.iter().any(|buffer| !buffer.is_empty()));
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_flush(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            this.io_error.get_or_insert("flush");
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_shutdown(cx);
        if matches!(result, Poll::Ready(Err(_))) {
            this.io_error.get_or_insert("shutdown");
        }
        result
    }
}

impl<W> Drop for ResponseWriter<'_, W> {
    fn drop(&mut self) {
        self.span
            .record("openshell.response.wire_bytes_written", self.wire_bytes);
        self.span.record(
            "openshell.response.delivery_outcome",
            if self.io_error.is_some() {
                "downstream_failed"
            } else {
                self.outcome
            },
        );
        if let Some(operation) = self.io_error {
            self.span
                .record("openshell.response.io_error_operation", operation);
        }
    }
}
