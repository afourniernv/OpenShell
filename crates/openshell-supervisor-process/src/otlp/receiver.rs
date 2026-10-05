// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OTLP HTTP receiver served on supervisor-mediated streams.
//!
//! The agent exports to the reserved relay address. The sandbox's seccomp
//! broker stages that connect for the supervisor, whose proxy hands the
//! resulting duplex stream to [`OtlpConnectionServer::serve`] instead of
//! dialing upstream. The server speaks HTTP/1.1 on that stream and accepts
//! `POST /v1/traces`, `/v1/logs`, and `/v1/metrics` with protobuf or JSON
//! bodies. No socket is ever bound.

use std::convert::Infallible;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use flate2::read::MultiGzDecoder;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tonic_types::pb::Status as RpcStatus;
use tracing::{debug, warn};

use super::buffer::{TelemetryItem, TelemetrySender};
use super::enrichment::{self, ContentType, EnrichmentError};
use super::{RECEIVER_SHUTDOWN_TIMEOUT, SandboxMetadata, export_message_encoded_len};

/// Upper bound on concurrently served relay connections.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;
/// Upper bound on requests that can concurrently buffer, decode, and enrich
/// agent-controlled OTLP bodies.
///
/// Keep this well below the connection limit so idle keep-alive connections
/// cannot multiply decoder memory pressure.
pub const MAX_CONCURRENT_REQUESTS: usize = 4;
const MAX_BODY_SIZE: usize = openshell_core::proto::MAX_GRPC_MESSAGE_SIZE;

/// Time a client has to send request headers before the connection is closed.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Overall time allowed to deliver one OTLP request body. This prevents a few
/// trickling clients from holding every decode/enrichment slot indefinitely.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentEncoding {
    Identity,
    Gzip,
}

#[derive(Debug)]
enum GzipDecodeError {
    Malformed(std::io::Error),
    TooLarge,
    Worker(tokio::task::JoinError),
}

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
    connections: Arc<Semaphore>,
    requests: Arc<Semaphore>,
    rejected_requests: Arc<AtomicU64>,
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
        let (abort_tx, abort_rx) = watch::channel(false);
        let server = Arc::new(Self {
            buf_tx,
            metadata,
            enrichment_enabled,
            connections: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            requests: Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS)),
            rejected_requests: Arc::new(AtomicU64::new(0)),
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
        let requests = Arc::clone(&self.requests);
        let rejected_requests = Arc::clone(&self.rejected_requests);
        let svc = service_fn(move |req| {
            let buf_tx = buf_tx.clone();
            let metadata = metadata.clone();
            let requests = Arc::clone(&requests);
            let rejected_requests = Arc::clone(&rejected_requests);
            async move {
                handle_request(
                    req,
                    &buf_tx,
                    &metadata,
                    enrichment_enabled,
                    requests,
                    &rejected_requests,
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
    requests: Arc<Semaphore>,
    rejected_requests: &AtomicU64,
) -> Result<Response<Full<Bytes>>, Infallible> {
    // OTLP error responses use the same representation as a supported request
    // content type. If the request does not declare one, protobuf is the only
    // unambiguous fallback.
    let response_content_type = parse_content_type(req.headers()).unwrap_or(ContentType::Protobuf);
    let signal = if req.method() == Method::POST {
        OtlpSignal::from_path(req.uri().path())
    } else {
        None
    };
    let Some(signal) = signal else {
        record_rejection(rejected_requests, "unsupported_route");
        return Ok(rpc_error_response(
            StatusCode::NOT_FOUND,
            response_content_type,
            "OTLP route not found",
        ));
    };

    let Some(content_type) = parse_content_type(req.headers()) else {
        record_rejection(rejected_requests, "unsupported_content_type");
        return Ok(rpc_error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ContentType::Protobuf,
            "unsupported OTLP content type",
        ));
    };

    let Ok(content_encoding) = parse_content_encoding(req.headers()) else {
        record_rejection(rejected_requests, "unsupported_content_encoding");
        return Ok(rpc_error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            content_type,
            "unsupported OTLP content encoding",
        ));
    };

    let Ok(request_permit) = requests.try_acquire_owned() else {
        record_rejection(rejected_requests, "receiver_busy");
        return Ok(rpc_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            content_type,
            "telemetry receiver busy",
        ));
    };

    let limited = http_body_util::Limited::new(req.into_body(), MAX_BODY_SIZE);
    let body =
        match tokio::time::timeout(BODY_READ_TIMEOUT, http_body_util::BodyExt::collect(limited))
            .await
        {
            Ok(Ok(collected)) => collected.to_bytes(),
            Ok(Err(e)) => {
                let status = if e.to_string().contains("length limit exceeded") {
                    debug!(
                        max_bytes = MAX_BODY_SIZE,
                        "OTLP request body exceeds relay message limit"
                    );
                    record_rejection(rejected_requests, "body_too_large");
                    StatusCode::PAYLOAD_TOO_LARGE
                } else {
                    debug!(error = %e, "failed to read OTLP request body");
                    record_rejection(rejected_requests, "body_read_failed");
                    StatusCode::BAD_REQUEST
                };
                return Ok(rpc_error_response(
                    status,
                    content_type,
                    "failed to read OTLP request body",
                ));
            }
            Err(_) => {
                debug!(
                    timeout_ms = BODY_READ_TIMEOUT.as_millis(),
                    "timed out reading OTLP request body"
                );
                record_rejection(rejected_requests, "body_read_timeout");
                return Ok(rpc_error_response(
                    StatusCode::REQUEST_TIMEOUT,
                    content_type,
                    "timed out reading OTLP request body",
                ));
            }
        };

    let (body, request_permit) = match decode_content(body, content_encoding, request_permit).await
    {
        Ok(body_and_permit) => body_and_permit,
        Err(GzipDecodeError::TooLarge) => {
            debug!(
                max_bytes = MAX_BODY_SIZE,
                "decompressed OTLP request body exceeds relay message limit"
            );
            record_rejection(rejected_requests, "decompressed_body_too_large");
            return Ok(rpc_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                content_type,
                "decompressed OTLP request exceeds relay message limit",
            ));
        }
        Err(GzipDecodeError::Malformed(error)) => {
            debug!(%error, "malformed gzip OTLP request body");
            record_rejection(rejected_requests, "malformed_gzip");
            return Ok(rpc_error_response(
                StatusCode::BAD_REQUEST,
                content_type,
                "malformed gzip OTLP request body",
            ));
        }
        Err(GzipDecodeError::Worker(error)) => {
            warn!(%error, "OTLP gzip decoder worker failed");
            record_rejection(rejected_requests, "gzip_worker_failed");
            return Ok(rpc_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                content_type,
                "failed to decode gzip OTLP request body",
            ));
        }
    };

    let worker_metadata = metadata.clone();
    let (enriched, _request_permit) =
        match run_blocking_with_permit(request_permit, move || match signal {
            OtlpSignal::Traces => {
                enrichment::enrich_spans(&body, content_type, &worker_metadata, enrichment_enabled)
            }
            OtlpSignal::Logs => {
                enrichment::enrich_logs(&body, content_type, &worker_metadata, enrichment_enabled)
            }
            OtlpSignal::Metrics => enrichment::enrich_metrics(
                &body,
                content_type,
                &worker_metadata,
                enrichment_enabled,
            ),
        })
        .await
        {
            Ok(enriched_and_permit) => enriched_and_permit,
            Err(error) => {
                warn!(%error, "OTLP decode/enrichment worker failed");
                record_rejection(rejected_requests, "enrichment_worker_failed");
                return Ok(rpc_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    content_type,
                    "failed to process OTLP request body",
                ));
            }
        };

    match enriched {
        Ok(enriched) => {
            let item = match signal {
                OtlpSignal::Traces => TelemetryItem::Trace(enriched),
                OtlpSignal::Logs => TelemetryItem::Logs(enriched),
                OtlpSignal::Metrics => TelemetryItem::Metrics(enriched),
            };
            let encoded_len = export_message_encoded_len(&metadata.sandbox_id, &item);
            if encoded_len > openshell_core::proto::MAX_GRPC_MESSAGE_SIZE {
                debug!(
                    encoded_len,
                    max_bytes = openshell_core::proto::MAX_GRPC_MESSAGE_SIZE,
                    "enriched OTLP request does not fit the supervisor session envelope"
                );
                record_rejection(rejected_requests, "enriched_envelope_too_large");
                return Ok(rpc_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    content_type,
                    "enriched OTLP request exceeds relay message limit",
                ));
            }
            if let Err(error) = buf_tx.send(item) {
                debug!(?error, "OTLP relay buffer rejected request");
                record_rejection(rejected_requests, "relay_buffer_unavailable");
                return Ok(rpc_error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    content_type,
                    "telemetry buffer unavailable",
                ));
            }
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
        Err(EnrichmentError::ProtobufDecode(e)) => {
            debug!(error = %e, "malformed protobuf OTLP request");
            record_rejection(rejected_requests, "malformed_protobuf");
            Ok(rpc_error_response(
                StatusCode::BAD_REQUEST,
                content_type,
                "malformed protobuf OTLP request",
            ))
        }
        Err(EnrichmentError::ProtobufWire(e)) => {
            debug!(error = e, "malformed protobuf OTLP request");
            record_rejection(rejected_requests, "malformed_protobuf");
            Ok(rpc_error_response(
                StatusCode::BAD_REQUEST,
                content_type,
                "malformed protobuf OTLP request",
            ))
        }
        Err(EnrichmentError::JsonDecode(e)) => {
            debug!(error = %e, "malformed JSON OTLP request");
            record_rejection(rejected_requests, "malformed_json");
            Ok(rpc_error_response(
                StatusCode::BAD_REQUEST,
                content_type,
                "malformed JSON OTLP request",
            ))
        }
        Err(EnrichmentError::ResourceGroupLimit {
            signal,
            groups,
            max,
        }) => {
            debug!(
                signal,
                groups, max, "OTLP request exceeds resource group limit"
            );
            record_rejection(rejected_requests, "resource_group_limit");
            Ok(rpc_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                content_type,
                "too many OTLP resource groups",
            ))
        }
        Err(EnrichmentError::StructuralItemLimit { signal, items, max }) => {
            debug!(
                signal,
                items, max, "OTLP request exceeds structural item limit"
            );
            record_rejection(rejected_requests, "structural_item_limit");
            Ok(rpc_error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                content_type,
                "too many OTLP structural items",
            ))
        }
    }
}

/// Decompress an OTLP body without running CPU-bound codec work on the async
/// reactor. Both the wire representation and the decoded representation are
/// bounded by [`MAX_BODY_SIZE`].
async fn decode_content(
    body: Bytes,
    encoding: ContentEncoding,
    request_permit: OwnedSemaphorePermit,
) -> Result<(Bytes, OwnedSemaphorePermit), GzipDecodeError> {
    if encoding == ContentEncoding::Identity {
        return Ok((body, request_permit));
    }

    let (decoded, request_permit) = run_blocking_with_permit(request_permit, move || {
        let decoder = MultiGzDecoder::new(body.as_ref());
        let mut limited = decoder.take((MAX_BODY_SIZE + 1) as u64);
        let mut output = Vec::with_capacity(body.len().min(MAX_BODY_SIZE));
        limited
            .read_to_end(&mut output)
            .map_err(GzipDecodeError::Malformed)?;
        if output.len() > MAX_BODY_SIZE {
            return Err(GzipDecodeError::TooLarge);
        }
        Ok(Bytes::from(output))
    })
    .await
    .map_err(GzipDecodeError::Worker)?;
    decoded.map(|body| (body, request_permit))
}

/// Run CPU-bound request work while making the semaphore reservation part of
/// the blocking task itself. Hyper may cancel the service future as soon as a
/// client disconnects, but `spawn_blocking` work cannot be cancelled once it
/// starts. Moving the permit into that task prevents disconnected clients from
/// freeing capacity while their gzip decoder or OTLP parser is still running.
async fn run_blocking_with_permit<T, F>(
    request_permit: OwnedSemaphorePermit,
    work: F,
) -> Result<(T, OwnedSemaphorePermit), tokio::task::JoinError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let output = work();
        (output, request_permit)
    })
    .await
}

/// Build an OTLP/HTTP error using the `google.rpc.Status` representation
/// required by the OTLP specification. The HTTP status carries the transport
/// error, so the protobuf status code may remain zero.
fn rpc_error_response(
    status: StatusCode,
    content_type: ContentType,
    message: &str,
) -> Response<Full<Bytes>> {
    let rpc_status = RpcStatus {
        code: 0,
        message: message.to_owned(),
        details: Vec::new(),
    };
    let (content_type, body) = match content_type {
        ContentType::Protobuf => (
            "application/x-protobuf",
            Bytes::from(prost::Message::encode_to_vec(&rpc_status)),
        ),
        ContentType::Json => (
            "application/json",
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "code": rpc_status.code,
                    "message": rpc_status.message,
                    "details": [],
                }))
                .expect("serializing google.rpc.Status cannot fail"),
            ),
        ),
    };
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(body))
        .expect("static OTLP error response is valid")
}

/// Increment the per-sandbox rejection count while keeping warning volume
/// logarithmic. Exact request details remain at DEBUG; WARN reports only the
/// first rejection and power-of-two milestones.
fn record_rejection(counter: &AtomicU64, reason: &'static str) -> bool {
    let count = counter.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    let should_warn = count.is_power_of_two();
    if should_warn {
        warn!(
            reason,
            rejected_requests = count,
            "OTLP receiver rejected agent telemetry"
        );
    }
    should_warn
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OtlpSignal {
    Traces,
    Logs,
    Metrics,
}

impl OtlpSignal {
    fn from_path(path: &str) -> Option<Self> {
        match path {
            "/v1/traces" => Some(Self::Traces),
            "/v1/logs" => Some(Self::Logs),
            "/v1/metrics" => Some(Self::Metrics),
            _ => None,
        }
    }
}

fn parse_content_type(headers: &hyper::HeaderMap) -> Option<ContentType> {
    let ct = headers.get("content-type")?.to_str().ok()?;
    let essence = ct.split_once(';').map_or(ct, |(essence, _)| essence).trim();
    if essence.eq_ignore_ascii_case("application/x-protobuf") {
        Some(ContentType::Protobuf)
    } else if essence.eq_ignore_ascii_case("application/json") {
        Some(ContentType::Json)
    } else {
        None
    }
}

fn parse_content_encoding(headers: &hyper::HeaderMap) -> Result<ContentEncoding, ()> {
    let mut values = headers.get_all("content-encoding").iter();
    let Some(value) = values.next() else {
        return Ok(ContentEncoding::Identity);
    };
    // OTLP/HTTP defines a single optional gzip content coding. Reject lists
    // and repeated fields instead of accidentally decoding only one layer.
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?.trim();
    if value.eq_ignore_ascii_case("identity") {
        Ok(ContentEncoding::Identity)
    } else if value.eq_ignore_ascii_case("gzip") {
        Ok(ContentEncoding::Gzip)
    } else {
        Err(())
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
    use opentelemetry_proto::tonic::logs::v1::ResourceLogs;
    use opentelemetry_proto::tonic::metrics::v1::ResourceMetrics;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

    use super::OtlpConnectionServer;
    use crate::otlp::SandboxMetadata;

    pub fn metadata() -> SandboxMetadata {
        let (_workspace_tx, workspace_name) = tokio::sync::watch::channel("ws-test".into());
        SandboxMetadata {
            sandbox_id: "sb-test".into(),
            sandbox_name: "sandbox-test".into(),
            workspace_name,
            workload_unix_uid: 1000,
            workload_image_reference: "image".into(),
        }
    }

    pub fn sample_trace_body() -> Vec<u8> {
        sample_trace_request().encode_to_vec()
    }

    pub fn sample_trace_json_body() -> Vec<u8> {
        serde_json::to_vec(&sample_trace_request()).expect("serialize trace request")
    }

    pub fn trace_body_with_span_name_len(name_len: usize) -> Vec<u8> {
        let mut request = sample_trace_request();
        request.resource_spans[0].scope_spans[0].spans[0].name = "x".repeat(name_len);
        request.encode_to_vec()
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

    pub fn sample_logs_body() -> Vec<u8> {
        sample_logs_request().encode_to_vec()
    }

    pub fn sample_logs_json_body() -> Vec<u8> {
        serde_json::to_vec(&sample_logs_request()).expect("serialize logs request")
    }

    fn sample_logs_request() -> ExportLogsServiceRequest {
        ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs::default()],
        }
    }

    pub fn sample_metrics_body() -> Vec<u8> {
        sample_metrics_request().encode_to_vec()
    }

    pub fn sample_metrics_json_body() -> Vec<u8> {
        serde_json::to_vec(&sample_metrics_request()).expect("serialize metrics request")
    }

    fn sample_metrics_request() -> ExportMetricsServiceRequest {
        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics::default()],
        }
    }

    pub fn request(method: &str, path: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        request_with_encoding(method, path, content_type, None, body)
    }

    pub fn request_with_encoding(
        method: &str,
        path: &str,
        content_type: &str,
        content_encoding: Option<&str>,
        body: &[u8],
    ) -> Vec<u8> {
        let content_encoding = content_encoding
            .map(|value| format!("Content-Encoding: {value}\r\n"))
            .unwrap_or_default();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {content_type}\r\n{content_encoding}Content-Length: {}\r\n\r\n",
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
            if let Some(head_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
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
    use std::io::Write as _;
    use std::time::Duration;

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::metrics::v1::{
        Gauge, Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, metric,
    };
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::test_util::{
        connect, metadata, request, request_with_encoding, sample_logs_body, sample_logs_json_body,
        sample_metrics_body, sample_metrics_json_body, sample_trace_body, sample_trace_json_body,
        send, send_response, trace_body_with_span_name_len,
    };
    use super::*;
    use crate::otlp::buffer::{TelemetryReceiver, new_telemetry_buffer};

    fn start() -> (Arc<OtlpConnectionServer>, ReceiverHandle, TelemetryReceiver) {
        let (buf_tx, buf_rx) = new_telemetry_buffer(16, 8 * 1024 * 1024);
        let (server, handle) = OtlpConnectionServer::new(buf_tx, metadata(), true);
        (server, handle, buf_rx)
    }

    fn gzip(body: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(body).expect("compress OTLP body");
        encoder.finish().expect("finish gzip stream")
    }

    fn response_head_and_body(response: &[u8]) -> (&str, &[u8]) {
        let head_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("HTTP response head")
            + 4;
        (
            std::str::from_utf8(&response[..head_end]).expect("ASCII HTTP response head"),
            &response[head_end..],
        )
    }

    fn protobuf_error(response: &[u8], expected_status: &str) -> RpcStatus {
        let (head, body) = response_head_and_body(response);
        assert!(
            head.starts_with(expected_status),
            "unexpected response: {head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/x-protobuf"),
            "unexpected response content type: {head}"
        );
        RpcStatus::decode(body).expect("protobuf google.rpc.Status")
    }

    fn json_error(response: &[u8], expected_status: &str) -> serde_json::Value {
        let (head, body) = response_head_and_body(response);
        assert!(
            head.starts_with(expected_status),
            "unexpected response: {head}"
        );
        assert!(
            head.to_ascii_lowercase()
                .contains("content-type: application/json"),
            "unexpected response content type: {head}"
        );
        serde_json::from_slice(body).expect("JSON google.rpc.Status")
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
        let response = send_response(
            &mut client,
            &request("GET", "/v1/traces", "application/x-protobuf", b""),
        )
        .await;
        let status = protobuf_error(&response, "HTTP/1.1 404");
        assert!(status.message.contains("not found"));

        let mut client = connect(&server);
        let response = send_response(
            &mut client,
            &request("POST", "/v1/traces", "text/plain", b"x"),
        )
        .await;
        let status = protobuf_error(&response, "HTTP/1.1 415");
        assert!(status.message.contains("content type"));

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

        handle.shutdown().await;
    }

    #[tokio::test]
    async fn accepts_all_signals_as_protobuf_and_json() {
        let (server, handle, mut buf_rx) = start();
        let requests = [
            ("/v1/traces", sample_trace_body(), sample_trace_json_body()),
            ("/v1/logs", sample_logs_body(), sample_logs_json_body()),
            (
                "/v1/metrics",
                sample_metrics_body(),
                sample_metrics_json_body(),
            ),
        ];

        for (path, protobuf, json) in requests {
            for (content_type, body) in [
                ("application/x-protobuf", protobuf),
                ("application/json", json),
            ] {
                let mut client = connect(&server);
                let response =
                    send_response(&mut client, &request("POST", path, content_type, &body)).await;
                let response = String::from_utf8(response).expect("ASCII HTTP response");
                assert!(
                    response.starts_with("HTTP/1.1 200"),
                    "{path} {content_type}: {response}"
                );
                assert!(
                    response
                        .to_ascii_lowercase()
                        .contains(&format!("content-type: {content_type}")),
                    "{path} {content_type}: {response}"
                );
                if content_type == "application/json" {
                    assert!(response.ends_with("{}"), "{path}: {response}");
                }
            }
        }

        assert_eq!(buf_rx.metrics().depth(), 6);
        let items = buf_rx.drain();
        assert!(matches!(&items[0], TelemetryItem::Trace(_)));
        assert!(matches!(&items[1], TelemetryItem::Trace(_)));
        assert!(matches!(&items[2], TelemetryItem::Logs(_)));
        assert!(matches!(&items[3], TelemetryItem::Logs(_)));
        assert!(matches!(&items[4], TelemetryItem::Metrics(_)));
        assert!(matches!(&items[5], TelemetryItem::Metrics(_)));
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn accepts_canonical_empty_json_for_every_signal() {
        let (server, handle, mut buf_rx) = start();

        for path in ["/v1/traces", "/v1/logs", "/v1/metrics"] {
            let mut client = connect(&server);
            let response = send_response(
                &mut client,
                &request("POST", path, "application/json", b"{}"),
            )
            .await;
            let (head, body) = response_head_and_body(&response);
            assert!(head.starts_with("HTTP/1.1 200"), "{path}: {head}");
            assert_eq!(body, b"{}", "{path}");
        }

        let items = buf_rx.drain();
        assert!(matches!(&items[0], TelemetryItem::Trace(body) if body.is_empty()));
        assert!(matches!(&items[1], TelemetryItem::Logs(body) if body.is_empty()));
        assert!(matches!(&items[2], TelemetryItem::Metrics(body) if body.is_empty()));
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn content_type_uses_exact_case_insensitive_essence() {
        let (server, handle, mut buf_rx) = start();

        let valid = [
            (
                "/v1/traces",
                "Application/X-Protobuf; proto=otlp",
                sample_trace_body(),
            ),
            (
                "/v1/logs",
                "APPLICATION/JSON ; Charset=UTF-8",
                b"{}".to_vec(),
            ),
        ];
        for (path, content_type, body) in valid {
            let mut client = connect(&server);
            let status = send(&mut client, &request("POST", path, content_type, &body)).await;
            assert!(status.contains("200"), "{content_type}: {status}");
        }

        for content_type in [
            "application/jsonp",
            "application/jsonp; charset=utf-8",
            "application/x-protobuf-extra",
            "text/application/json",
        ] {
            let mut client = connect(&server);
            let response = send_response(
                &mut client,
                &request("POST", "/v1/traces", content_type, b"{}"),
            )
            .await;
            let status = protobuf_error(&response, "HTTP/1.1 415");
            assert!(status.message.contains("content type"), "{content_type}");
        }

        assert_eq!(buf_rx.drain().len(), 2);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn accepts_gzip_for_every_signal_and_content_type() {
        let (server, handle, mut buf_rx) = start();
        let requests = [
            ("/v1/traces", sample_trace_body(), sample_trace_json_body()),
            ("/v1/logs", sample_logs_body(), sample_logs_json_body()),
            (
                "/v1/metrics",
                sample_metrics_body(),
                sample_metrics_json_body(),
            ),
        ];

        for (path, protobuf, json) in requests {
            for (content_type, body) in [
                ("application/x-protobuf", protobuf),
                ("application/json", json),
            ] {
                let compressed = gzip(&body);
                let mut client = connect(&server);
                let response = send_response(
                    &mut client,
                    &request_with_encoding("POST", path, content_type, Some("gzip"), &compressed),
                )
                .await;
                let (head, _) = response_head_and_body(&response);
                assert!(
                    head.starts_with("HTTP/1.1 200"),
                    "{path} {content_type}: {head}"
                );
            }
        }

        assert_eq!(buf_rx.metrics().depth(), 6);
        assert_eq!(buf_rx.drain().len(), 6);
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn rejects_unsupported_or_malformed_content_encoding_as_otlp_status() {
        let (server, handle, mut buf_rx) = start();

        let mut client = connect(&server);
        let response = send_response(
            &mut client,
            &request_with_encoding(
                "POST",
                "/v1/traces",
                "application/x-protobuf",
                Some("br"),
                &sample_trace_body(),
            ),
        )
        .await;
        let status = protobuf_error(&response, "HTTP/1.1 415");
        assert!(status.message.contains("content encoding"));

        let mut client = connect(&server);
        let response = send_response(
            &mut client,
            &request_with_encoding(
                "POST",
                "/v1/traces",
                "application/json",
                Some("gzip"),
                b"not a gzip stream",
            ),
        )
        .await;
        let status = json_error(&response, "HTTP/1.1 400");
        assert_eq!(status["code"], 0);
        assert_eq!(status["message"], "malformed gzip OTLP request body");

        assert!(buf_rx.drain().is_empty());
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn rejects_gzip_expansion_beyond_message_limit() {
        let (server, handle, mut buf_rx) = start();
        let compressed = gzip(&vec![0; MAX_BODY_SIZE + 1]);
        assert!(
            compressed.len() < MAX_BODY_SIZE,
            "compressed test body must pass the wire-size limit"
        );

        let mut client = connect(&server);
        let response = send_response(
            &mut client,
            &request_with_encoding(
                "POST",
                "/v1/traces",
                "application/json",
                Some("gzip"),
                &compressed,
            ),
        )
        .await;
        let status = json_error(&response, "HTTP/1.1 413");
        assert_eq!(status["code"], 0);
        assert!(status["message"].as_str().unwrap().contains("decompressed"));

        assert!(buf_rx.drain().is_empty());
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn decode_errors_use_google_rpc_status_in_request_representation() {
        let (server, handle, mut buf_rx) = start();

        let mut client = connect(&server);
        let response = send_response(
            &mut client,
            &request("POST", "/v1/traces", "application/x-protobuf", b"\xff"),
        )
        .await;
        let status = protobuf_error(&response, "HTTP/1.1 400");
        assert_eq!(status.code, 0);
        assert_eq!(status.message, "malformed protobuf OTLP request");

        let mut client = connect(&server);
        let response = send_response(
            &mut client,
            &request("POST", "/v1/traces", "application/json", b"{"),
        )
        .await;
        let status = json_error(&response, "HTTP/1.1 400");
        assert_eq!(status["code"], 0);
        assert_eq!(status["message"], "malformed JSON OTLP request");

        assert!(buf_rx.drain().is_empty());
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn rejects_enriched_envelope_that_exceeds_session_limit_before_ack() {
        let (server, handle, mut buf_rx) = start();
        let body = trace_body_with_span_name_len(MAX_BODY_SIZE - 256);
        assert!(body.len() <= MAX_BODY_SIZE, "raw body must pass HTTP limit");
        let enriched =
            enrichment::enrich_spans(&body, ContentType::Protobuf, &metadata(), true).unwrap();
        assert!(
            export_message_encoded_len("sb-test", &TelemetryItem::Trace(enriched))
                > openshell_core::proto::MAX_GRPC_MESSAGE_SIZE,
            "test body must exceed the shared limit only after enrichment/enveloping"
        );

        let mut client = connect(&server);
        let status = send(
            &mut client,
            &request("POST", "/v1/traces", "application/x-protobuf", &body),
        )
        .await;
        assert!(status.contains("413"), "oversize envelope got {status}");
        assert!(
            buf_rx.drain().is_empty(),
            "oversize item must not be queued"
        );

        // The receiver remains healthy and can acknowledge a later request.
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
        assert!(status.contains("200"), "receiver did not recover: {status}");
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

    #[test]
    fn request_processing_slots_are_bounded_and_recover() {
        let (server, _handle, _buf_rx) = start();
        let mut permits: Vec<OwnedSemaphorePermit> = (0..MAX_CONCURRENT_REQUESTS)
            .map(|i| {
                Arc::clone(&server.requests)
                    .try_acquire_owned()
                    .unwrap_or_else(|_| panic!("request slot {i}"))
            })
            .collect();
        assert!(
            Arc::clone(&server.requests).try_acquire_owned().is_err(),
            "request processing beyond the maximum must be refused"
        );

        drop(permits.pop());
        assert!(
            Arc::clone(&server.requests).try_acquire_owned().is_ok(),
            "a released request slot must be available again"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnected_request_keeps_slot_until_blocking_work_finishes() {
        let (server, _handle, _buf_rx) = start();
        let _other_permits: Vec<OwnedSemaphorePermit> = (1..MAX_CONCURRENT_REQUESTS)
            .map(|_| {
                Arc::clone(&server.requests)
                    .try_acquire_owned()
                    .expect("reserve other request slot")
            })
            .collect();
        let worker_permit = Arc::clone(&server.requests)
            .try_acquire_owned()
            .expect("reserve worker request slot");
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);

        // Dropping a Hyper service future on disconnect has the same
        // cancellation semantics as aborting this waiter: the blocking task
        // keeps running, and therefore must keep owning its request slot.
        let waiter = tokio::spawn(async move {
            run_blocking_with_permit(worker_permit, move || {
                started_tx.send(()).expect("signal worker start");
                release_rx.recv().expect("release worker");
            })
            .await
        });
        started_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("blocking worker starts");
        waiter.abort();
        assert!(
            waiter
                .await
                .expect_err("waiter is cancelled")
                .is_cancelled()
        );

        assert!(
            Arc::clone(&server.requests).try_acquire_owned().is_err(),
            "cancelled waiter must not free capacity while blocking work remains"
        );

        release_tx.send(()).expect("release blocking worker");
        let recovered = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(permit) = Arc::clone(&server.requests).try_acquire_owned() {
                    break permit;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("request slot recovers after blocking work exits");
        drop(recovered);
    }

    #[tokio::test]
    async fn rejects_excessive_resource_groups_before_enrichment() {
        let (server, handle, mut buf_rx) = start();
        let count = 1_025;
        let requests = [
            (
                "/v1/traces",
                ExportTraceServiceRequest {
                    resource_spans: vec![ResourceSpans::default(); count],
                }
                .encode_to_vec(),
            ),
            (
                "/v1/logs",
                ExportLogsServiceRequest {
                    resource_logs: vec![ResourceLogs::default(); count],
                }
                .encode_to_vec(),
            ),
            (
                "/v1/metrics",
                ExportMetricsServiceRequest {
                    resource_metrics: vec![ResourceMetrics::default(); count],
                }
                .encode_to_vec(),
            ),
        ];

        for (path, body) in requests {
            assert!(body.len() < MAX_BODY_SIZE, "test body must pass byte limit");
            let mut client = connect(&server);
            let response = send_response(
                &mut client,
                &request("POST", path, "application/x-protobuf", &body),
            )
            .await;
            let status = protobuf_error(&response, "HTTP/1.1 413");
            assert_eq!(status.code, 0, "{path}");
            assert!(status.message.contains("resource groups"), "{path}");
        }
        assert!(
            buf_rx.drain().is_empty(),
            "structurally excessive requests must not be queued"
        );
        handle.shutdown().await;
    }

    #[tokio::test]
    async fn rejects_excessive_nested_items_with_one_resource_group() {
        let (server, handle, mut buf_rx) = start();
        let count = enrichment::MAX_STRUCTURAL_ITEMS_PER_REQUEST;
        let requests = [
            (
                "/v1/traces",
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
            (
                "/v1/logs",
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
            (
                "/v1/metrics",
                ExportMetricsServiceRequest {
                    resource_metrics: vec![ResourceMetrics {
                        scope_metrics: vec![ScopeMetrics {
                            metrics: vec![Metric {
                                data: Some(metric::Data::Gauge(Gauge {
                                    data_points: vec![NumberDataPoint::default(); count],
                                })),
                                ..Default::default()
                            }],
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                }
                .encode_to_vec(),
            ),
        ];

        for (path, body) in requests {
            assert!(body.len() < MAX_BODY_SIZE, "test body must pass byte limit");
            let mut client = connect(&server);
            let status = send(
                &mut client,
                &request("POST", path, "application/x-protobuf", &body),
            )
            .await;
            assert!(status.contains("413"), "{path} got {status}");
        }
        assert!(
            buf_rx.drain().is_empty(),
            "structurally excessive requests must not be queued"
        );
        handle.shutdown().await;
    }

    #[test]
    fn rejection_warnings_are_sampled_at_power_of_two_milestones() {
        let counter = AtomicU64::new(0);
        let sampled: Vec<_> = (0..8).map(|_| record_rejection(&counter, "test")).collect();
        assert_eq!(
            sampled,
            vec![true, true, false, true, false, false, false, true]
        );
        assert_eq!(counter.load(Ordering::Relaxed), 8);
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
