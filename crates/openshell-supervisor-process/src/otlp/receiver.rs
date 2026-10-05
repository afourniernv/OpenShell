// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP HTTP receiver served on supervisor-mediated streams.
//!
//! The agent exports to the reserved relay address. The sandbox's seccomp
//! broker stages that connect for the supervisor, whose proxy hands the
//! resulting duplex stream to [`OtlpConnectionServer::serve`] instead of
//! dialing upstream. The server speaks HTTP/1.1 on that stream and accepts
//! `POST /v1/traces` with protobuf or JSON bodies. No socket is ever bound.

use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tracing::{debug, warn};

use super::buffer::{TelemetrySendError, TelemetrySender};
use super::enrichment::{self, ContentType, EnrichmentError};
use super::{
    MAX_TELEMETRY_ITEM_BYTES, RECEIVER_SHUTDOWN_TIMEOUT, SandboxMetadata, admit_logs_message,
    admit_metrics_message, admit_trace_message,
};

/// Upper bound on concurrently served relay connections.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;
/// Bound concurrent CPU- and allocation-heavy body/decode/enrichment work
/// separately from lightweight keep-alive connections.
///
/// This is defense-in-depth for overload; it is not required by normal
/// Hermes export.
pub const MAX_CONCURRENT_PROCESSING_REQUESTS: usize = 4;
const MAX_BODY_SIZE: usize = MAX_TELEMETRY_ITEM_BYTES;

/// Time a client has to send request headers before the connection is closed.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Total time a client has to finish sending one request body.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Reservation for one relay connection.
///
/// Taken before the sandbox commits the workload socket, so an exhausted
/// server can refuse the open instead of resetting it after `RelayReady`.
pub struct ConnectionPermit {
    _permit: OwnedSemaphorePermit,
}

/// Serves OTLP HTTP on streams handed over by the mediation path.
///
/// One instance lives for the sandbox lifetime. Each stream is served on the
/// caller's task through [`OtlpConnectionServer::serve`]; the paired
/// [`ReceiverHandle`] owns shutdown.
pub struct OtlpConnectionServer {
    buf_tx: TelemetrySender,
    metadata: SandboxMetadata,
    enrichment_enabled: bool,
    body_read_timeout: Duration,
    connections: Arc<Semaphore>,
    processing: Arc<Semaphore>,
    /// `None` once shutdown has started. Watchers are minted under this lock,
    /// so none can be created after the shutdown signal is sent.
    graceful: Mutex<Option<GracefulShutdown>>,
    abort_rx: watch::Receiver<bool>,
}

/// Owns receiver shutdown.
pub struct ReceiverHandle {
    server: Arc<OtlpConnectionServer>,
    abort_tx: watch::Sender<bool>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl OtlpConnectionServer {
    /// Create a server and its shutdown handle.
    pub fn new(
        buf_tx: TelemetrySender,
        metadata: SandboxMetadata,
        enrichment_enabled: bool,
    ) -> (Arc<Self>, ReceiverHandle) {
        Self::new_with_body_read_timeout(buf_tx, metadata, enrichment_enabled, BODY_READ_TIMEOUT)
    }

    fn new_with_body_read_timeout(
        buf_tx: TelemetrySender,
        metadata: SandboxMetadata,
        enrichment_enabled: bool,
        body_read_timeout: Duration,
    ) -> (Arc<Self>, ReceiverHandle) {
        let (abort_tx, abort_rx) = watch::channel(false);
        let server = Arc::new(Self {
            buf_tx,
            metadata,
            enrichment_enabled,
            body_read_timeout,
            connections: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            processing: Arc::new(Semaphore::new(MAX_CONCURRENT_PROCESSING_REQUESTS)),
            graceful: Mutex::new(Some(GracefulShutdown::new())),
            abort_rx,
        });
        let handle = ReceiverHandle {
            server: Arc::clone(&server),
            abort_tx,
        };
        (server, handle)
    }

    /// Sender side of the relay buffer, for additional producers such as the
    /// OCSF sink.
    pub fn sender(&self) -> &TelemetrySender {
        &self.buf_tx
    }

    /// Reserve a connection slot. `None` when the server is shutting down or
    /// already serving [`MAX_CONCURRENT_CONNECTIONS`] streams.
    pub fn try_reserve(&self) -> Option<ConnectionPermit> {
        if lock(&self.graceful).is_none() {
            return None;
        }
        let permit = Arc::clone(&self.connections).try_acquire_owned().ok()?;
        Some(ConnectionPermit { _permit: permit })
    }

    fn watcher(&self) -> Option<Watcher> {
        lock(&self.graceful).as_ref().map(GracefulShutdown::watcher)
    }

    /// Serve one HTTP/1.1 connection on `stream` until the peer closes it,
    /// graceful shutdown drains it, or the abort deadline cuts it. Runs on the
    /// caller's task and releases `permit` when it returns.
    pub async fn serve<S>(&self, permit: ConnectionPermit, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let Some(watcher) = self.watcher() else {
            debug!("OTLP receiver: stream arrived during shutdown, dropping");
            return;
        };

        let buf_tx = self.buf_tx.clone();
        let metadata = self.metadata.clone();
        let enrichment_enabled = self.enrichment_enabled;
        let body_read_timeout = self.body_read_timeout;
        let processing = Arc::clone(&self.processing);
        let svc = service_fn(move |req| {
            let buf_tx = buf_tx.clone();
            let metadata = metadata.clone();
            let processing = Arc::clone(&processing);
            async move {
                handle_request(
                    req,
                    &buf_tx,
                    &metadata,
                    enrichment_enabled,
                    body_read_timeout,
                    processing,
                )
                .await
            }
        });

        let mut builder = http1::Builder::new();
        // A timer is mandatory once any timeout is configured; hyper panics in
        // `serve_connection` otherwise.
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_READ_TIMEOUT);
        let conn = watcher.watch(builder.serve_connection(TokioIo::new(stream), svc));

        let mut abort_rx = self.abort_rx.clone();
        tokio::select! {
            result = conn => {
                if let Err(e) = result {
                    debug!(error = %e, "OTLP HTTP connection error");
                }
            }
            _ = abort_rx.wait_for(|aborted| *aborted) => {
                debug!("OTLP receiver: aborting connection after graceful timeout");
            }
        }
        drop(permit);
    }
}

impl ReceiverHandle {
    /// Stop accepting new streams, disable keep-alive on every open
    /// connection, wait up to [`RECEIVER_SHUTDOWN_TIMEOUT`] for in-flight
    /// requests, then cut stragglers. Always returns within roughly the
    /// timeout. A second call is a no-op.
    pub async fn shutdown(self) {
        let Some(graceful) = lock(&self.server.graceful).take() else {
            return;
        };
        if tokio::time::timeout(RECEIVER_SHUTDOWN_TIMEOUT, graceful.shutdown())
            .await
            .is_err()
        {
            warn!(
                open_connections =
                    MAX_CONCURRENT_CONNECTIONS - self.server.connections.available_permits(),
                "OTLP receiver: aborting connections still open after graceful timeout"
            );
            self.abort_tx.send_replace(true);
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    buf_tx: &TelemetrySender,
    metadata: &SandboxMetadata,
    enrichment_enabled: bool,
    body_read_timeout: Duration,
    processing: Arc<Semaphore>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let signal = match (req.method(), req.uri().path()) {
        (&Method::POST, "/v1/traces") => SignalKind::Traces,
        (&Method::POST, "/v1/logs") => SignalKind::Logs,
        (&Method::POST, "/v1/metrics") => SignalKind::Metrics,
        _ => {
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("{\"error\":\"not found\"}")))
                .unwrap());
        }
    };

    let Some(content_type) = parse_content_type(req.headers()) else {
        return Ok(Response::builder()
            .status(StatusCode::UNSUPPORTED_MEDIA_TYPE)
            .body(Full::new(Bytes::from(
                "{\"error\":\"unsupported content type\"}",
            )))
            .unwrap());
    };

    // Reserve processing capacity before accepting the body into memory. Keep
    // the permit through body collection, typed decode, and enrichment.
    let Ok(processing_permit) = processing.try_acquire_owned() else {
        warn!("OTLP processing capacity exhausted");
        return Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("retry-after", "1")
            .body(Full::new(Bytes::from(
                "{\"error\":\"telemetry processing unavailable\"}",
            )))
            .unwrap());
    };

    let limited = http_body_util::Limited::new(req.into_body(), MAX_BODY_SIZE);
    let body =
        match tokio::time::timeout(body_read_timeout, http_body_util::BodyExt::collect(limited))
            .await
        {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(error))
                if error
                    .downcast_ref::<http_body_util::LengthLimitError>()
                    .is_some() =>
            {
                warn!(
                    max_body_bytes = MAX_BODY_SIZE,
                    "OTLP request body too large"
                );
                return Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Full::new(Bytes::from(
                        "{\"error\":\"request body too large\"}",
                    )))
                    .unwrap());
            }
            Ok(Err(error)) => {
                warn!(%error, "failed to read OTLP request body");
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from(
                        "{\"error\":\"failed to read body\"}",
                    )))
                    .unwrap());
            }
            Err(_) => {
                warn!(
                    timeout_seconds = body_read_timeout.as_secs(),
                    "OTLP request body timed out"
                );
                return Ok(Response::builder()
                    .status(StatusCode::REQUEST_TIMEOUT)
                    .body(Full::new(Bytes::from(
                        "{\"error\":\"request body timed out\"}",
                    )))
                    .unwrap());
            }
        };

    let metadata_for_processing = metadata.clone();
    let processed = tokio::task::spawn_blocking(move || {
        let _processing_permit = processing_permit;
        match signal {
            SignalKind::Traces => enrichment::enrich_spans(
                &body,
                content_type,
                &metadata_for_processing,
                enrichment_enabled,
            ),
            SignalKind::Logs => enrichment::enrich_logs(
                &body,
                content_type,
                &metadata_for_processing,
                enrichment_enabled,
            ),
            SignalKind::Metrics => enrichment::enrich_metrics(
                &body,
                content_type,
                &metadata_for_processing,
                enrichment_enabled,
            ),
        }
    })
    .await;

    let processed = match processed {
        Ok(processed) => processed,
        Err(error) => {
            warn!(%error, "OTLP processing task failed");
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from(
                    "{\"error\":\"telemetry processing failed\"}",
                )))
                .unwrap());
        }
    };

    match processed {
        Ok(enriched) => {
            let enriched = match signal {
                SignalKind::Traces => admit_trace_message(&metadata.sandbox_id, enriched),
                SignalKind::Logs => admit_logs_message(&metadata.sandbox_id, enriched),
                SignalKind::Metrics => admit_metrics_message(&metadata.sandbox_id, enriched),
            };
            let enriched = match enriched {
                Ok(enriched) => enriched,
                Err(encoded_bytes) => {
                    warn!(encoded_bytes, "OTLP export exceeds session message limit");
                    return Ok(Response::builder()
                        .status(StatusCode::PAYLOAD_TOO_LARGE)
                        .body(Full::new(Bytes::from(
                            "{\"error\":\"OTLP export too large\"}",
                        )))
                        .unwrap());
                }
            };

            let queued = match signal {
                SignalKind::Traces => buf_tx.send_trace(enriched),
                SignalKind::Logs => buf_tx.send_logs(enriched),
                SignalKind::Metrics => buf_tx.send_metrics(enriched),
            };
            match queued {
                Ok(()) => {
                    let (response_content_type, response_body) = match content_type {
                        ContentType::Protobuf => ("application/x-protobuf", Bytes::new()),
                        ContentType::Json => ("application/json", Bytes::from_static(b"{}")),
                    };
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("content-type", response_content_type)
                        .body(Full::new(response_body))
                        .unwrap())
                }
                Err(TelemetrySendError::TooLarge) => Ok(Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Full::new(Bytes::from(
                        "{\"error\":\"OTLP export too large\"}",
                    )))
                    .unwrap()),
                Err(TelemetrySendError::Full | TelemetrySendError::Closed) => {
                    warn!("OTLP telemetry buffer unavailable");
                    Ok(Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .header("retry-after", "1")
                        .body(Full::new(Bytes::from(
                            "{\"error\":\"telemetry buffer unavailable\"}",
                        )))
                        .unwrap())
                }
            }
        }
        Err(EnrichmentError::ProtobufDecode(error)) => {
            warn!(%error, "malformed protobuf OTLP request");
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(
                    "{\"error\":\"malformed protobuf request\"}",
                )))
                .unwrap())
        }
        Err(EnrichmentError::JsonDecode(error)) => {
            warn!(%error, "malformed JSON OTLP request");
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from(
                    "{\"error\":\"malformed JSON request\"}",
                )))
                .unwrap())
        }
        Err(error @ EnrichmentError::StructuralLimit { .. }) => {
            warn!(%error, "OTLP request exceeds structural limits after decode");
            Ok(Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Full::new(Bytes::from(
                    "{\"error\":\"OTLP request exceeds structural limits\"}",
                )))
                .unwrap())
        }
    }
}

#[derive(Clone, Copy)]
enum SignalKind {
    Traces,
    Logs,
    Metrics,
}

fn parse_content_type(headers: &hyper::HeaderMap) -> Option<ContentType> {
    let ct = headers.get("content-type")?.to_str().ok()?;
    if ct.starts_with("application/x-protobuf") {
        Some(ContentType::Protobuf)
    } else if ct.starts_with("application/json") {
        Some(ContentType::Json)
    } else {
        None
    }
}

/// In-memory HTTP helpers shared by the receiver and lifecycle tests. They
/// stand in for the boundary duplex stream the proxy hands over in
/// production.
#[cfg(test)]
pub(crate) mod test_util {
    use std::sync::Arc;
    use std::time::Duration;

    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::metrics::v1::{
        Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, metric,
    };
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

    use super::OtlpConnectionServer;
    use crate::otlp::SandboxMetadata;

    pub fn metadata() -> SandboxMetadata {
        SandboxMetadata {
            sandbox_id: "sb-test".into(),
            workspace_id: "ws-test".into(),
            policy: "policy".into(),
            user: "1000".into(),
            image: "image".into(),
            driver: "docker".into(),
        }
    }

    pub fn sample_trace_body() -> Vec<u8> {
        sample_trace_request().encode_to_vec()
    }

    pub fn sample_trace_json_body() -> Vec<u8> {
        serde_json::to_vec(&sample_trace_request()).expect("serialize trace request")
    }

    pub fn sample_logs_body() -> Vec<u8> {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    log_records: vec![LogRecord::default()],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    pub fn sample_metrics_body() -> Vec<u8> {
        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics: vec![Metric {
                        data: Some(metric::Data::Gauge(Gauge {
                            data_points: vec![NumberDataPoint::default()],
                        })),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    fn sample_trace_request() -> ExportTraceServiceRequest {
        ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    spans: vec![Span {
                        name: "test-span".into(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
    }

    pub fn request(method: &str, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        req.extend_from_slice(body);
        req
    }

    /// Open a client stream whose server half is served on a spawned task,
    /// the way the proxy hook serves a staged boundary stream.
    pub fn connect(server: &Arc<OtlpConnectionServer>) -> DuplexStream {
        let (client, server_half) = tokio::io::duplex(64 * 1024);
        let permit = server.try_reserve().expect("connection slot");
        let server = Arc::clone(server);
        tokio::spawn(async move { server.serve(permit, server_half).await });
        client
    }

    pub async fn send_response<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        req: &[u8],
    ) -> Vec<u8> {
        stream.write_all(req).await.expect("write request");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .expect("response within 5s")
                .expect("read response");
            assert!(n > 0, "connection closed before response head");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head_end = head_end + 4;
                let head = String::from_utf8_lossy(&buf[..head_end]);
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if buf.len() >= head_end + content_length {
                    return buf;
                }
            }
        }
    }

    pub async fn send<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, req: &[u8]) -> String {
        let response = send_response(stream, req).await;
        let head = String::from_utf8_lossy(&response);
        head.lines().next().unwrap_or_default().to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::test_util::{
        connect, metadata, request, sample_logs_body, sample_metrics_body, sample_trace_body,
        sample_trace_json_body, send, send_response,
    };
    use super::*;
    use crate::otlp::buffer::{TelemetryReceiver, new_telemetry_buffer};

    fn start() -> (Arc<OtlpConnectionServer>, ReceiverHandle, TelemetryReceiver) {
        let (buf_tx, buf_rx) = new_telemetry_buffer(16, crate::otlp::DEFAULT_BUFFER_BYTE_CAPACITY);
        let (server, handle) = OtlpConnectionServer::new(buf_tx, metadata(), true);
        (server, handle, buf_rx)
    }

    fn start_with_limits(
        item_capacity: usize,
        byte_capacity: usize,
    ) -> (Arc<OtlpConnectionServer>, ReceiverHandle, TelemetryReceiver) {
        let (buf_tx, buf_rx) = new_telemetry_buffer(item_capacity, byte_capacity);
        let (server, handle) = OtlpConnectionServer::new(buf_tx, metadata(), true);
        (server, handle, buf_rx)
    }

    #[tokio::test]
    async fn shutdown_completes_with_idle_keepalive_connection() {
        let (server, handle, buf_rx) = start();

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
        assert_eq!(buf_rx.metrics().depth(), 1);

        // The client keeps the HTTP/1.1 connection open. Shutdown must not
        // wait for it to go away on its own.
        let deadline = RECEIVER_SHUTDOWN_TIMEOUT + Duration::from_secs(1);
        tokio::time::timeout(deadline, handle.shutdown())
            .await
            .expect("shutdown must complete despite an open keep-alive connection");

        // The server closed the idle connection.
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("server close within 2s")
            .unwrap_or(0);
        assert_eq!(n, 0, "expected EOF from server after shutdown");
    }

    #[tokio::test]
    async fn shutdown_completes_with_half_sent_headers() {
        let (server, handle, _buf_rx) = start();

        let mut client = connect(&server);
        client
            .write_all(b"POST /v1/traces HTTP/1.1\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let deadline = RECEIVER_SHUTDOWN_TIMEOUT + Duration::from_secs(1);
        tokio::time::timeout(deadline, handle.shutdown())
            .await
            .expect("shutdown must complete with an in-progress request");
    }

    #[tokio::test]
    async fn status_codes_for_not_found_unsupported_media_type_and_ok() {
        let (server, handle, buf_rx) = start();

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request("GET", "/v1/traces", "application/x-protobuf", b""),
        )
        .await;
        assert!(status.contains("404"), "GET should be 404, got {status}");

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request("POST", "/v1/traces", "text/plain", b"x"),
        )
        .await;
        assert!(
            status.contains("415"),
            "text/plain should be 415, got {status}"
        );

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
        assert!(
            status.contains("200"),
            "valid protobuf should be 200, got {status}"
        );
        assert_eq!(buf_rx.metrics().depth(), 1);

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request(
                "POST",
                "/v1/logs",
                "application/x-protobuf",
                &sample_logs_body(),
            ),
        )
        .await;
        assert!(
            status.contains("200"),
            "valid logs should be 200, got {status}"
        );
        assert_eq!(buf_rx.metrics().depth(), 2);

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request(
                "POST",
                "/v1/metrics",
                "application/x-protobuf",
                &sample_metrics_body(),
            ),
        )
        .await;
        assert!(
            status.contains("200"),
            "valid metrics should be 200, got {status}"
        );
        assert_eq!(buf_rx.metrics().depth(), 3);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn json_request_gets_a_json_otlp_response() {
        let (server, handle, buf_rx) = start();

        let mut client = connect(&server);
        let response = send_response(
            &mut client,
            &request(
                "POST",
                "/v1/traces",
                "application/json",
                &sample_trace_json_body(),
            ),
        )
        .await;
        let response_text = String::from_utf8(response).expect("ASCII HTTP response");
        assert!(
            response_text.starts_with("HTTP/1.1 200"),
            "unexpected response: {response_text}"
        );
        assert!(
            response_text
                .to_ascii_lowercase()
                .contains("content-type: application/json"),
            "unexpected response: {response_text}"
        );
        assert!(response_text.ends_with("{}"));
        assert_eq!(buf_rx.metrics().depth(), 1);

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn structurally_oversized_request_returns_payload_too_large() {
        use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
        use opentelemetry_proto::tonic::trace::v1::ResourceSpans;
        use prost::Message;

        let (server, handle, buf_rx) = start();
        let body = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans::default(); enrichment::MAX_RESOURCE_SPANS + 1],
        }
        .encode_to_vec();

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request("POST", "/v1/traces", "application/x-protobuf", &body),
        )
        .await;

        assert!(status.contains("413"), "unexpected status: {status}");
        assert_eq!(buf_rx.metrics().depth(), 0);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn oversized_body_returns_payload_too_large() {
        let (server, handle, buf_rx) = start();
        let body = vec![0; MAX_BODY_SIZE + 1];

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request("POST", "/v1/traces", "application/x-protobuf", &body),
        )
        .await;

        assert!(status.contains("413"), "unexpected status: {status}");
        assert_eq!(buf_rx.metrics().depth(), 0);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn full_item_buffer_returns_service_unavailable() {
        let (server, handle, buf_rx) =
            start_with_limits(1, crate::otlp::DEFAULT_BUFFER_BYTE_CAPACITY);

        let mut first = connect(&server);
        let status = send(
            &mut first,
            &request(
                "POST",
                "/v1/traces",
                "application/x-protobuf",
                &sample_trace_body(),
            ),
        )
        .await;
        assert!(status.contains("200"), "unexpected status: {status}");

        let mut second = connect(&server);
        let status = send(
            &mut second,
            &request(
                "POST",
                "/v1/traces",
                "application/x-protobuf",
                &sample_trace_body(),
            ),
        )
        .await;
        assert!(status.contains("503"), "unexpected status: {status}");
        assert_eq!(buf_rx.metrics().depth(), 1);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn full_byte_buffer_returns_service_unavailable() {
        let (server, handle, buf_rx) = start_with_limits(16, 1);

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

        assert!(status.contains("503"), "unexpected status: {status}");
        assert_eq!(buf_rx.metrics().depth(), 0);
        assert_eq!(buf_rx.metrics().bytes(), 0);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn risk_control_bounds_processing_admission() {
        let (server, handle, buf_rx) = start();
        let held = Arc::clone(&server.processing)
            .acquire_many_owned(
                u32::try_from(MAX_CONCURRENT_PROCESSING_REQUESTS)
                    .expect("processing concurrency fits in u32"),
            )
            .await
            .unwrap();

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
        assert!(status.contains("503"), "unexpected status: {status}");
        assert_eq!(buf_rx.metrics().depth(), 0);

        drop(held);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn incomplete_body_hits_total_read_deadline() {
        let (buf_tx, _buf_rx) = new_telemetry_buffer(16, crate::otlp::DEFAULT_BUFFER_BYTE_CAPACITY);
        let (server, handle) = OtlpConnectionServer::new_with_body_read_timeout(
            buf_tx,
            metadata(),
            true,
            Duration::from_millis(25),
        );
        let mut client = connect(&server);
        client
            .write_all(
                b"POST /v1/traces HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-protobuf\r\nContent-Length: 10\r\n\r\nx",
            )
            .await
            .unwrap();
        let status = send(&mut client, b"").await;

        assert!(status.contains("408"), "unexpected status: {status}");
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn try_reserve_refuses_beyond_max_connections_and_recovers() {
        let (server, _handle, _buf_rx) = start();

        let mut permits: Vec<ConnectionPermit> = (0..MAX_CONCURRENT_CONNECTIONS)
            .map(|i| server.try_reserve().unwrap_or_else(|| panic!("slot {i}")))
            .collect();
        assert!(
            server.try_reserve().is_none(),
            "slot beyond the maximum must be refused"
        );

        drop(permits.pop());
        assert!(
            server.try_reserve().is_some(),
            "a released slot is available again"
        );
    }

    #[tokio::test]
    async fn try_reserve_refuses_after_shutdown() {
        let (server, handle, _buf_rx) = start();
        assert!(server.try_reserve().is_some());

        handle.shutdown().await;
        assert!(
            server.try_reserve().is_none(),
            "no new streams once shutdown has started"
        );
    }
}
