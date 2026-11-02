// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! HTTP response relay and pre-return middleware integration.

use super::*;
use crate::l7::correlation::{
    MiddlewareObservation, MiddlewareOutcome, MiddlewarePhase, RequestCorrelation,
    ResponseDeliveryOutcome, ResponseSelectionCause, emit_ocsf,
};

/// Default wall-clock bound shared by whole-body stages in one response.
pub const DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT: std::time::Duration =
    std::time::Duration::from_mins(2);

/// Context retained from request evaluation for the matching response hook.
pub struct HttpResponseMiddlewareRelay<'a> {
    pub(crate) chain: &'a [openshell_supervisor_middleware::ChainEntry],
    pub(crate) runner: &'a openshell_supervisor_middleware::ChainRunner,
    pub(crate) request_context: RequestContext,
    pub(crate) target: HttpRequestTarget,
    pub(crate) policy_name: &'a str,
    pub(crate) generation_guard: Option<&'a PolicyGenerationGuard>,
    pub(crate) whole_body_timeout: std::time::Duration,
}

#[derive(Clone)]
pub(super) struct RelayResponseOptions<'a> {
    pub(super) websocket_extensions: WebSocketExtensionMode,
    pub(super) client_requested_upgrade: bool,
    pub(super) websocket: Option<WebSocketResponseValidation>,
    pub(super) observer: Option<&'a EndpointObserver>,
    pub(super) correlation: Option<&'a RequestCorrelation>,
}

impl Default for RelayResponseOptions<'_> {
    fn default() -> Self {
        Self {
            websocket_extensions: WebSocketExtensionMode::Preserve,
            client_requested_upgrade: true,
            websocket: None,
            observer: None,
            correlation: None,
        }
    }
}

pub(super) async fn relay_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
    options: RelayResponseOptions<'_>,
    response_middleware: Option<HttpResponseMiddlewareRelay<'_>>,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let correlation = options.correlation;
    if let Some(correlation) = correlation {
        correlation.begin_response_lifecycle();
    }
    let result = relay_response_inner(
        request_method,
        upstream,
        client,
        options,
        response_middleware,
    )
    .await;
    match &result {
        Ok(_) => {
            if let Some(correlation) = correlation {
                correlation.complete_pending_response_delivery();
            }
        }
        Err(error) => complete_response_error(correlation, error),
    }
    result
}

async fn relay_response_inner<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
    options: RelayResponseOptions<'_>,
    response_middleware: Option<HttpResponseMiddlewareRelay<'_>>,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let started_at = std::time::Instant::now();
    let response_generation_guard = response_middleware
        .as_ref()
        .and_then(|middleware| middleware.generation_guard);
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];

    // Forward interim responses unchanged, but retain the final response head
    // until response middleware preflight completes.
    let mut informational_header_bytes = 0;
    let mut header_end = loop {
        let header_end = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|end| end + 4);
        let remaining_header_bytes = MAX_HEADER_BYTES - informational_header_bytes;
        if header_end.is_some_and(|end| end > remaining_header_bytes)
            || (header_end.is_none() && buf.len() >= remaining_header_bytes)
        {
            if let Some(observer) = options.observer.as_ref() {
                observer.observe(EndpointResult::TransportFailed);
            }
            return Err(RelayError::protocol(
                "response_headers_too_large",
                "HTTP response headers exceed limit",
            )
            .into());
        }

        if let Some(header_end) = header_end {
            if let Err(error) = validate_http_response_header_block(&buf[..header_end]) {
                if let Some(observer) = options.observer.as_ref() {
                    observer.observe(EndpointResult::TransportFailed);
                }
                return Err(
                    RelayError::protocol("invalid_response_headers", error.to_string()).into(),
                );
            }
            let header_str = String::from_utf8_lossy(&buf[..header_end]);
            if matches!(
                parse_observed_http_status_code(&header_str),
                Some(100 | 102..=199)
            ) {
                informational_header_bytes += header_end;
                let sanitized = strip_platform_request_id_from_head(&buf[..header_end]);
                if let Some(guard) = response_generation_guard {
                    ensure_relay_generation_current(guard)?;
                }
                write_correlated_interim_bytes(client, &sanitized, options.correlation).await?;
                client.flush().await.map_err(RelayError::interim_flush)?;
                buf.drain(..header_end);
                continue;
            }
            break header_end;
        }

        let n = guarded_relay_read(response_generation_guard, async {
            upstream
                .read(&mut tmp)
                .await
                .map_err(RelayError::read)
                .map_err(miette::Report::new)
        })
        .await?;
        if let Some(guard) = response_generation_guard {
            ensure_relay_generation_current(guard)?;
        }
        if n == 0 {
            if let Some(observer) = options.observer.as_ref() {
                observer.observe(EndpointResult::TransportFailed);
            }
            if let Some(correlation) = options.correlation {
                send_incomplete_response(client, correlation).await?;
                finish_response(client, true).await?;
            } else if !buf.is_empty() {
                client.write_all(&buf).await.into_diagnostic()?;
            }
            return Ok(RelayOutcome::Consumed);
        }
        buf.extend_from_slice(&tmp[..n]);
    };

    let sanitized = strip_platform_request_id_from_head(&buf[..header_end]);
    if sanitized.len() != header_end {
        let overflow = buf.split_off(header_end);
        buf = sanitized;
        header_end = buf.len();
        buf.extend_from_slice(&overflow);
    }

    if let Some(correlation) = options.correlation {
        correlation.record_target_reached();
    }

    // Parse response framing
    let header_str = String::from_utf8_lossy(&buf[..header_end]);
    let observed_status = parse_observed_http_status_code(&header_str);
    if let (Some(correlation), Some(status_code)) = (options.correlation, observed_status) {
        correlation.record_upstream_response_status(status_code);
    }
    if let Some(observer) = options.observer.as_ref() {
        match observed_status {
            Some(status_code) if status_code < 400 => {
                observer.observe(EndpointResult::HttpResponseReceived);
            }
            Some(_) => observer.observe(EndpointResult::UpstreamRejected),
            None => observer.observe(EndpointResult::TransportFailed),
        }
    }
    let status_code = parse_status_code(&header_str).unwrap_or(200);
    let server_wants_close = parse_connection_close(&header_str);
    let http_10_closes_by_default =
        response_is_http_10(&header_str) && !parse_connection_keep_alive(&header_str);
    let event_stream = response_is_event_stream(&header_str);
    let body_length = parse_body_length(&header_str)
        .map_err(|error| RelayError::protocol("invalid_response_framing", error.to_string()))?;
    if let BodyLength::ContentLength(length) = body_length
        && u64::try_from(buf.len() - header_end).unwrap_or(u64::MAX) > length
    {
        return Err(RelayError::protocol(
            "content_length_overflow",
            "HTTP response body exceeds Content-Length",
        )
        .into());
    }

    debug!(
        status_code,
        ?body_length,
        server_wants_close,
        request_method,
        overflow_bytes = buf.len() - header_end,
        "relay_response framing"
    );

    // 101 Switching Protocols: the connection has been upgraded (e.g. to
    // WebSocket).  Forward the 101 headers to the client and signal the
    // caller to switch to raw bidirectional TCP relay.  Any bytes read
    // from upstream beyond the headers are overflow that belong to the
    // upgraded protocol and must be forwarded before switching.
    if status_code == 101 {
        if !options.client_requested_upgrade {
            return Err(RelayError::protocol(
                "unsolicited_switching_protocols",
                "upstream returned 101 Switching Protocols without a client upgrade request",
            )
            .into());
        }
        let (websocket_permessage_deflate, websocket_subprotocol) = validate_websocket_response(
            &header_str,
            options.websocket_extensions,
            options.websocket.as_ref(),
        )
        .map_err(|error| RelayError::protocol("invalid_websocket_handshake", error.to_string()))?;
        let final_head = final_response_head(&buf[..header_end], options.correlation);
        if let Some(guard) = response_generation_guard {
            ensure_relay_generation_current(guard)?;
        }
        select_allowed_response(options.correlation, status_code);
        write_correlated_response_bytes(client, &final_head, options.correlation, false).await?;
        client.flush().await.map_err(RelayError::flush)?;
        let overflow = buf[header_end..].to_vec();
        debug!(
            request_method,
            overflow_bytes = overflow.len(),
            "101 Switching Protocols — signaling protocol upgrade"
        );
        return Ok(RelayOutcome::Upgraded {
            overflow,
            websocket_permessage_deflate,
            websocket_subprotocol,
        });
    }

    if let Some(response_middleware) = response_middleware
        && let Some(outcome) = Box::pin(relay_response_through_middleware(
            request_method,
            upstream,
            client,
            response_middleware,
            &buf,
            header_end,
            status_code,
            body_length,
            server_wants_close || http_10_closes_by_default,
            event_stream,
            options.correlation,
        ))
        .await?
    {
        return if matches!(outcome, RelayOutcome::Consumed) {
            finish_response(client, true).await
        } else {
            Ok(outcome)
        };
    }

    let final_head = final_response_head(&buf[..header_end], options.correlation);

    // Bodiless responses (HEAD, 1xx, 204, 304): forward headers only, skip body
    if is_bodiless_response(request_method, status_code) {
        if let Some(guard) = response_generation_guard {
            ensure_relay_generation_current(guard)?;
        }
        select_allowed_response(options.correlation, status_code);
        write_correlated_response_bytes(client, &final_head, options.correlation, false).await?;
        let outcome =
            finish_response(client, server_wants_close || http_10_closes_by_default).await?;
        return Ok(outcome);
    }

    // No explicit framing (no Content-Length, no Transfer-Encoding).
    // Per RFC 7230 §3.3.3 the body is delimited by connection close.
    if matches!(body_length, BodyLength::None) {
        if server_wants_close || http_10_closes_by_default || event_stream {
            // Server indicated it will close, or this is a streaming response
            // such as SSE where the body is intentionally delimited by EOF.
            let before_end = &final_head[..final_head.len() - 2];
            if let Some(guard) = response_generation_guard {
                ensure_relay_generation_current(guard)?;
            }
            select_allowed_response(options.correlation, status_code);
            write_correlated_response_bytes(client, before_end, options.correlation, false).await?;
            if server_wants_close || http_10_closes_by_default {
                client
                    .write_all(b"Connection: close\r\n\r\n")
                    .await
                    .map_err(RelayError::write)?;
            } else {
                client.write_all(b"\r\n").await.map_err(RelayError::write)?;
            }
            let overflow = &buf[header_end..];
            if !overflow.is_empty() {
                if let Some(guard) = response_generation_guard {
                    ensure_relay_generation_current(guard)?;
                }
                client
                    .write_all(overflow)
                    .await
                    .map_err(RelayError::write)?;
                client.flush().await.map_err(RelayError::flush)?;
            }
            if event_stream {
                relay_until_eof_without_idle_timeout(upstream, client, response_generation_guard)
                    .await?;
            } else {
                match relay_until_eof(upstream, client, response_generation_guard).await? {
                    RelayUntilEofOutcome::Complete => {}
                    RelayUntilEofOutcome::IdleTimeout => {
                        record_response_idle_timeout(options.correlation);
                    }
                }
            }
            client.flush().await.map_err(RelayError::flush)?;
            client.shutdown().await.map_err(RelayError::shutdown)?;
            return Ok(RelayOutcome::Consumed);
        }
        // No Connection: close — an HTTP/1.1 keep-alive server that omits
        // framing headers has an empty body.  Forward headers and continue
        // the relay loop instead of blocking on relay_until_eof.
        debug!("BodyLength::None without Connection: close — treating body as empty");
        if let Some(guard) = response_generation_guard {
            ensure_relay_generation_current(guard)?;
        }
        select_allowed_response(options.correlation, status_code);
        write_correlated_response_bytes(client, &final_head, options.correlation, false).await?;
        client.flush().await.map_err(RelayError::flush)?;
        return Ok(RelayOutcome::Reusable);
    }

    // Hold buffered chunk framing until relay_chunked validates it.
    if let Some(guard) = response_generation_guard {
        ensure_relay_generation_current(guard)?;
    }
    select_allowed_response(options.correlation, status_code);
    write_correlated_response_bytes(client, &final_head, options.correlation, false).await?;
    let overflow = &buf[header_end..];
    let overflow_len = (buf.len() - header_end) as u64;

    // Forward remaining response body
    match body_length {
        BodyLength::ContentLength(len) => {
            if !overflow.is_empty() {
                if let Some(guard) = response_generation_guard {
                    ensure_relay_generation_current(guard)?;
                }
                client
                    .write_all(overflow)
                    .await
                    .map_err(RelayError::write)?;
            }
            let remaining = len - overflow_len;
            if remaining > 0 {
                relay_fixed(upstream, client, remaining, response_generation_guard).await?;
            }
        }
        BodyLength::Chunked => relay_chunked(upstream, client, overflow, response_generation_guard)
            .await
            .map_err(type_response_protocol_error)?,
        BodyLength::None => unreachable!(),
    }
    client.flush().await.map_err(RelayError::flush)?;
    debug!(
        request_method,
        elapsed_ms = started_at.elapsed().as_millis(),
        "relay_response complete (explicit framing)"
    );

    let outcome = finish_response(client, server_wants_close || http_10_closes_by_default).await?;
    Ok(outcome)
}

async fn send_incomplete_response<C: AsyncWrite + Unpin>(
    client: &mut C,
    correlation: &RequestCorrelation,
) -> Result<()> {
    record_upstream_response_error(Some(correlation), "upstream_response_incomplete");
    let body = serde_json::json!({
        "error": "upstream_response_incomplete",
        "request_id": correlation.request_id(),
    })
    .to_string();
    let response = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\n{}: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        openshell_core::token_grant_failure::REQUEST_ID_HEADER,
        correlation.request_id(),
        body.len(),
        body,
    );
    correlation.record_response_status(502);
    write_correlated_response_bytes(client, response.as_bytes(), Some(correlation), false).await?;
    client.flush().await.map_err(RelayError::flush)?;
    Ok(())
}

fn select_allowed_response(correlation: Option<&RequestCorrelation>, status_code: u16) {
    if let Some(correlation) = correlation {
        correlation.record_response_status(status_code);
        correlation.record_response_selection(
            ResponseSelectionCause::UpstreamResponse,
            "allowed",
            None,
        );
    }
}

fn record_denied_response(correlation: Option<&RequestCorrelation>, stage: &'static str) {
    if let Some(correlation) = correlation {
        correlation.record_response_status(403);
        correlation.record_response_selection(
            ResponseSelectionCause::MiddlewareDenied,
            "denied",
            Some(stage),
        );
    }
}

fn select_failure_response(
    correlation: Option<&RequestCorrelation>,
    cause: ResponseSelectionCause,
    http_outcome: &'static str,
    stage: &'static str,
) {
    if let Some(correlation) = correlation {
        correlation.record_response_status(502);
        correlation.record_response_selection(cause, http_outcome, Some(stage));
    }
}

fn record_upstream_response_error(correlation: Option<&RequestCorrelation>, stage: &'static str) {
    if let Some(correlation) = correlation {
        correlation.record_response_selection(
            ResponseSelectionCause::UpstreamTruncated,
            "upstream_error",
            Some(stage),
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct ResponseFailureClassification {
    cause: Option<ResponseSelectionCause>,
    delivery: ResponseDeliveryOutcome,
    http_outcome: &'static str,
    error_stage: &'static str,
}

fn type_response_protocol_error(error: miette::Report) -> miette::Report {
    if error.downcast_ref::<RelayError>().is_some() {
        error
    } else {
        RelayError::protocol("invalid_response_body", error.to_string()).into()
    }
}

fn complete_response_error(correlation: Option<&RequestCorrelation>, error: &miette::Report) {
    let Some(correlation) = correlation else {
        return;
    };
    let failure = classify_response_failure(error);
    let _ = correlation.record_response_partial_delivery();
    correlation.complete_response_failure(
        failure.delivery,
        failure.cause,
        failure.http_outcome,
        failure.error_stage,
    );
}

fn classify_response_failure(error: &miette::Report) -> ResponseFailureClassification {
    if let Some(relay_error) = error.downcast_ref::<RelayError>() {
        let (cause, delivery, http_outcome, error_stage) = match relay_error {
            RelayError::Write { stage, .. } => {
                let (cause, error_stage) = match stage {
                    RelayWriteStage::Write => (None, "downstream_response_write"),
                    RelayWriteStage::Flush => (None, "downstream_response_flush"),
                    RelayWriteStage::Shutdown => (None, "downstream_response_shutdown"),
                    RelayWriteStage::InterimWrite => (
                        Some(ResponseSelectionCause::PlatformError),
                        "downstream_interim_write",
                    ),
                    RelayWriteStage::InterimFlush => (
                        Some(ResponseSelectionCause::PlatformError),
                        "downstream_interim_flush",
                    ),
                };
                (
                    cause,
                    ResponseDeliveryOutcome::DownstreamIoError,
                    "platform_error",
                    error_stage,
                )
            }
            RelayError::IdleTimeout => (
                Some(ResponseSelectionCause::UpstreamIdleTimeout),
                ResponseDeliveryOutcome::CancelledOrIncomplete,
                "upstream_error",
                "upstream_response_idle_timeout",
            ),
            RelayError::Truncated(_) => (
                Some(ResponseSelectionCause::UpstreamTruncated),
                ResponseDeliveryOutcome::CancelledOrIncomplete,
                "upstream_error",
                "upstream_response_truncated",
            ),
            RelayError::Read(_) => (
                Some(ResponseSelectionCause::UpstreamIoError),
                ResponseDeliveryOutcome::CancelledOrIncomplete,
                "upstream_error",
                "upstream_response_read",
            ),
            RelayError::Protocol { .. } => (
                Some(ResponseSelectionCause::UpstreamProtocolError),
                ResponseDeliveryOutcome::CancelledOrIncomplete,
                "upstream_error",
                "upstream_response_protocol",
            ),
            RelayError::PolicyReloaded(_) => (
                Some(ResponseSelectionCause::PolicyReloaded),
                ResponseDeliveryOutcome::CancelledOrIncomplete,
                "platform_error",
                "response_policy_reload",
            ),
        };
        return ResponseFailureClassification {
            cause,
            delivery,
            http_outcome,
            error_stage,
        };
    }
    if let Some(stop) = error.downcast_ref::<ResponseMiddlewareStop>() {
        let denied = stop.failure.denial.is_some()
            || response_invocations_blocked(&stop.failure.diagnostics.invocations);
        return ResponseFailureClassification {
            cause: Some(if denied {
                ResponseSelectionCause::MiddlewareDenied
            } else {
                ResponseSelectionCause::MiddlewareFailed
            }),
            delivery: ResponseDeliveryOutcome::CancelledOrIncomplete,
            http_outcome: if denied { "denied" } else { "platform_error" },
            error_stage: if denied {
                "response_middleware_denied"
            } else {
                "response_middleware_failed"
            },
        };
    }
    ResponseFailureClassification {
        cause: Some(ResponseSelectionCause::Unknown),
        delivery: ResponseDeliveryOutcome::CancelledOrIncomplete,
        http_outcome: "platform_error",
        error_stage: "response_unknown",
    }
}

fn record_response_idle_timeout(correlation: Option<&RequestCorrelation>) {
    if let Some(correlation) = correlation {
        correlation.record_response_selection(
            ResponseSelectionCause::UpstreamIdleTimeout,
            "upstream_error",
            Some("upstream_response_idle_timeout"),
        );
        correlation
            .record_pending_response_delivery(ResponseDeliveryOutcome::CancelledOrIncomplete);
    }
}

fn validate_http_response_header_block(headers: &[u8]) -> Result<()> {
    if !headers.ends_with(b"\r\n\r\n") {
        return Err(miette!("HTTP response header block is incomplete"));
    }

    for (index, byte) in headers.iter().copied().enumerate() {
        match byte {
            b'\r' if headers.get(index + 1) != Some(&b'\n') => {
                return Err(miette!("HTTP response headers contain a bare CR"));
            }
            b'\n' if index == 0 || headers.get(index - 1) != Some(&b'\r') => {
                return Err(miette!("HTTP response headers contain a bare LF"));
            }
            _ => {}
        }
    }

    let header_lines = &headers[..headers.len() - 2];
    let mut lines = header_lines
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line));
    let status_line = lines
        .next()
        .ok_or_else(|| miette!("HTTP response status line is missing"))?;
    validate_http_response_status_line(status_line)?;

    while let Some(line) = lines.next() {
        if line.is_empty() {
            if lines.next().is_some() {
                return Err(miette!(
                    "HTTP response header block contains an unexpected empty line"
                ));
            }
            break;
        }
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            return Err(miette!(
                "HTTP response header continuation lines are not supported"
            ));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| miette!("HTTP response header field is malformed"))?;
        let name = &line[..colon];
        if name.last().is_some_and(|byte| matches!(byte, b' ' | b'\t')) {
            return Err(miette!(
                "HTTP response header field contains whitespace before the colon"
            ));
        }
        http::HeaderName::from_bytes(name)
            .map_err(|_| miette!("HTTP response field name is malformed"))?;
        http::HeaderValue::from_bytes(&line[colon + 1..])
            .map_err(|_| miette!("HTTP response field value is malformed"))?;
    }
    Ok(())
}

fn validate_http_response_status_line(status_line: &[u8]) -> Result<()> {
    let remainder = if let Some(remainder) = status_line.strip_prefix(b"HTTP/1.0 ") {
        remainder
    } else if let Some(remainder) = status_line.strip_prefix(b"HTTP/1.1 ") {
        remainder
    } else {
        return Err(miette!(
            "HTTP response status line must use HTTP/1.0 or HTTP/1.1"
        ));
    };
    if remainder.len() < 4 || remainder[3] != b' ' {
        return Err(miette!("HTTP response status line is malformed"));
    }
    http::StatusCode::from_bytes(&remainder[..3])
        .map_err(|_| miette!("HTTP response status code is invalid"))?;
    http::HeaderValue::from_bytes(&remainder[4..])
        .map_err(|_| miette!("HTTP response reason phrase is malformed"))?;
    Ok(())
}

fn final_response_head(headers: &[u8], correlation: Option<&RequestCorrelation>) -> Vec<u8> {
    let stripped = strip_platform_request_id_from_head(headers);
    let stripped = strip_platform_request_id_from_connection(&stripped);
    let Some(correlation) = correlation else {
        return stripped;
    };
    let Some(header_end) = stripped.windows(4).position(|window| window == b"\r\n\r\n") else {
        return stripped;
    };
    let receipt = format!(
        "{}: {}\r\n\r\n",
        openshell_core::token_grant_failure::REQUEST_ID_HEADER,
        correlation.request_id(),
    );
    let mut output = Vec::with_capacity(stripped.len() + receipt.len());
    output.extend_from_slice(&stripped[..header_end + 2]);
    output.extend_from_slice(receipt.as_bytes());
    output.extend_from_slice(&stripped[header_end + 4..]);
    output
}

fn strip_platform_request_id_from_connection(headers: &[u8]) -> Vec<u8> {
    let header_end = headers
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(headers.len(), |position| position + 4);
    let (header_block, buffered_suffix) = headers.split_at(header_end);
    let protected = openshell_core::token_grant_failure::REQUEST_ID_HEADER.as_bytes();
    let mut output = Vec::with_capacity(headers.len());
    let mut position = 0usize;

    while position < header_block.len() {
        let line_end = header_block[position..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map_or(header_block.len(), |end| position + end);
        let line = &header_block[position..line_end];
        if line.is_empty() {
            output.extend_from_slice(b"\r\n");
            break;
        }

        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            output.extend_from_slice(line);
            output.extend_from_slice(b"\r\n");
            position = line_end.saturating_add(2);
            continue;
        };
        let name = trim_ascii_ows(&line[..colon]);
        if !name.eq_ignore_ascii_case(b"connection") {
            output.extend_from_slice(line);
            output.extend_from_slice(b"\r\n");
            position = line_end.saturating_add(2);
            continue;
        }

        let mut removed_protected = false;
        let retained: Vec<_> = line[colon + 1..]
            .split(|byte| *byte == b',')
            .filter_map(|value| {
                let token = trim_ascii_ows(value);
                if token.eq_ignore_ascii_case(protected) {
                    removed_protected = true;
                    None
                } else if token.is_empty() {
                    None
                } else {
                    Some(token)
                }
            })
            .collect();
        if !removed_protected {
            output.extend_from_slice(line);
            output.extend_from_slice(b"\r\n");
        } else if !retained.is_empty() {
            output.extend_from_slice(&line[..=colon]);
            output.push(b' ');
            for (index, token) in retained.iter().enumerate() {
                if index > 0 {
                    output.extend_from_slice(b", ");
                }
                output.extend_from_slice(token);
            }
            output.extend_from_slice(b"\r\n");
        }
        position = line_end.saturating_add(2);
    }

    output.extend_from_slice(buffered_suffix);
    output
}

/// Body framing determines when delivery finishes, not whether another
/// request is permitted. Signal EOF (including TLS `close_notify`) before the
/// caller tears down a closing CONNECT tunnel; waiting for another request
/// deadlocks clients that are themselves waiting for EOF.
async fn finish_response<C>(client: &mut C, close: bool) -> Result<RelayOutcome>
where
    C: AsyncWrite + Unpin,
{
    client.flush().await.map_err(RelayError::flush)?;
    if close {
        client.shutdown().await.map_err(RelayError::shutdown)?;
        Ok(RelayOutcome::Consumed)
    } else {
        Ok(RelayOutcome::Reusable)
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_response_through_middleware<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
    middleware: HttpResponseMiddlewareRelay<'_>,
    buffered: &[u8],
    header_end: usize,
    status_code: u16,
    body_length: BodyLength,
    server_wants_close: bool,
    event_stream: bool,
    response_correlation: Option<&RequestCorrelation>,
) -> Result<Option<RelayOutcome>>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    if let Some(guard) = middleware.generation_guard {
        ensure_relay_generation_current(guard)?;
    }
    let header_bytes = &buffered[..header_end];
    // Ordinary responses retain the HTTP parser's byte-preserving behavior.
    // Response-specific normalization and limits apply only to selected hooks.
    if middleware.chain.is_empty() {
        return Ok(None);
    }
    let described_result = middleware
        .runner
        .describe_http_response_chain(middleware.chain)
        .await;
    if let Some(guard) = middleware.generation_guard {
        ensure_relay_generation_current(guard)?;
    }
    let described = match described_result {
        Ok(described) if described.is_empty() => return Ok(None),
        Ok(described) => described,
        Err(error) => {
            complete_response_middleware(response_correlation, MiddlewareOutcome::PlatformError);
            debug!(error = %error, "HTTP response middleware chain description failed");
            emit_http_response_middleware_failure(
                middleware.policy_name,
                &middleware.target,
                status_code,
                false,
                response_correlation,
            );
            send_response_delivery_failure(
                client,
                request_method,
                middleware.policy_name,
                &middleware.target,
                (
                    ResponseSelectionCause::MiddlewareFailed,
                    "platform_error",
                    "response_middleware_describe",
                ),
                true,
                response_correlation,
            )
            .await?;
            return Ok(Some(RelayOutcome::Consumed));
        }
    };
    let parsed = parse_response_head_for_middleware(header_bytes).map_err(|error| {
        miette::Report::new(RelayError::protocol(
            "invalid_response_headers",
            error.to_string(),
        ))
    });
    if let Some(guard) = middleware.generation_guard {
        ensure_relay_generation_current(guard)?;
    }
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            debug!(error = %error, "HTTP response head normalization failed");
            send_response_delivery_failure(
                client,
                request_method,
                middleware.policy_name,
                &middleware.target,
                (
                    ResponseSelectionCause::UpstreamProtocolError,
                    "upstream_error",
                    "response_middleware_headers",
                ),
                false,
                response_correlation,
            )
            .await?;
            return Ok(Some(RelayOutcome::Consumed));
        }
    };
    if let Some(correlation) = response_correlation {
        correlation.observe_middleware(MiddlewarePhase::Response, MiddlewareObservation::default());
    }
    let original_headers = parsed.headers.clone();
    let preserved_credential_headers = parsed.preserved_credential_headers;
    let upstream_declared_trailers = parsed.declared_trailers.clone();
    let connection_nominated_headers = parsed.connection_nominated.clone();
    let input = openshell_supervisor_middleware::HttpResponsePreflightInput {
        context: middleware.request_context,
        target: middleware.target.clone(),
        status_code,
        declared_body_length: match body_length {
            BodyLength::ContentLength(length) => Some(length),
            BodyLength::Chunked | BodyLength::None => None,
        },
        headers: parsed.headers,
        connection_nominated_headers: parsed.connection_nominated,
    };
    let preflight_result = if parsed.representable {
        let preflight = middleware
            .runner
            .preflight_described_http_response(described, input);
        RequestCorrelation::within_span(response_correlation, preflight).await
    } else {
        Ok(middleware
            .runner
            .http_response_input_unrepresentable(&described))
    };
    if let Some(guard) = middleware.generation_guard
        && let Err(error) = ensure_relay_generation_current(guard)
    {
        if let Ok(mut preflight) = preflight_result
            && let Some(session) = preflight.session.take()
        {
            session
                .end(openshell_core::proto::MiddlewareSessionEndReason::PolicyReload)
                .await;
        }
        return Err(error);
    }
    let preflight = match preflight_result {
        Ok(preflight) => preflight,
        Err(error) => {
            observe_response_admission_exhaustion(
                response_correlation,
                error
                    .downcast_ref::<openshell_supervisor_middleware::MiddlewareAdmissionExhausted>()
                    .is_some(),
            );
            complete_response_middleware(response_correlation, MiddlewareOutcome::PlatformError);
            debug!(error = %error, "HTTP response middleware preflight failed");
            emit_http_response_middleware_failure(
                middleware.policy_name,
                &middleware.target,
                status_code,
                false,
                response_correlation,
            );
            send_response_delivery_failure(
                client,
                request_method,
                middleware.policy_name,
                &middleware.target,
                (
                    ResponseSelectionCause::MiddlewareFailed,
                    "platform_error",
                    "response_middleware_preflight",
                ),
                true,
                response_correlation,
            )
            .await?;
            return Ok(Some(RelayOutcome::Consumed));
        }
    };
    observe_response_middleware(
        response_correlation,
        &preflight.invocations,
        preflight.headers != original_headers,
        preflight.session_capacity_exhausted,
        false,
    );
    debug!(
        configured_stage_count = middleware.chain.len(),
        active_session = preflight.session.is_some(),
        allowed = preflight.allowed,
        "HTTP response middleware preflight completed"
    );
    for event in crate::l7::middleware::middleware_finding_events(&preflight.findings) {
        emit_ocsf(response_correlation, event);
    }
    if !preflight.allowed {
        emit_http_response_middleware_invocations(
            middleware.policy_name,
            &middleware.target,
            status_code,
            &preflight.invocations,
            response_correlation,
        );
        let denied =
            preflight.denial.is_some() || response_invocations_blocked(&preflight.invocations);
        complete_response_middleware(
            response_correlation,
            if denied {
                MiddlewareOutcome::Denied
            } else {
                MiddlewareOutcome::PlatformError
            },
        );
        if let Some(denial) = preflight.denial.as_ref() {
            send_response_middleware_denial(
                client,
                request_method,
                middleware.policy_name,
                &middleware.target,
                denial,
                "response_middleware_preflight",
                response_correlation,
            )
            .await?;
        } else {
            emit_http_response_middleware_failure(
                middleware.policy_name,
                &middleware.target,
                status_code,
                false,
                response_correlation,
            );
            send_response_delivery_failure(
                client,
                request_method,
                middleware.policy_name,
                &middleware.target,
                (
                    ResponseSelectionCause::MiddlewareFailed,
                    "platform_error",
                    "response_middleware_preflight",
                ),
                true,
                response_correlation,
            )
            .await?;
        }
        return Ok(Some(RelayOutcome::Consumed));
    }
    emit_http_response_middleware_invocations(
        middleware.policy_name,
        &middleware.target,
        status_code,
        &preflight.invocations,
        response_correlation,
    );

    let Some(mut session) = preflight.session else {
        if preflight.headers == original_headers {
            complete_response_middleware(response_correlation, MiddlewareOutcome::Allowed);
            return Ok(None);
        }
        let status_line = response_status_line(header_bytes)?;
        complete_response_middleware(response_correlation, MiddlewareOutcome::Allowed);
        let outcome = relay_headers_only_response(
            request_method,
            upstream,
            client,
            &status_line,
            &preflight.headers,
            &preserved_credential_headers,
            &upstream_declared_trailers,
            &buffered[header_end..],
            status_code,
            body_length,
            server_wants_close,
            event_stream,
            middleware.generation_guard,
            response_correlation,
        )
        .await?;
        return Ok(Some(outcome));
    };

    let status_line = response_status_line(header_bytes)?;
    let supports_chunked_response = !status_line.starts_with("HTTP/1.0 ");
    let bodiless = is_bodiless_response(request_method, status_code);
    if bodiless {
        let finish_result = session.finish(Vec::new()).await;
        if let Some(guard) = middleware.generation_guard {
            ensure_relay_generation_current(guard)?;
        }
        let finish = match finish_result {
            Ok(finish) => finish,
            Err(error) => {
                observe_response_diagnostics(response_correlation, &error.diagnostics);
                observe_response_admission_exhaustion(
                    response_correlation,
                    error.admission_exhausted(),
                );
                let denial = response_middleware_failure_denial(&error);
                complete_response_middleware(
                    response_correlation,
                    if denial.is_some() {
                        MiddlewareOutcome::Denied
                    } else {
                        MiddlewareOutcome::PlatformError
                    },
                );
                debug!(error = %error, "HTTP response middleware finalization failed");
                emit_http_response_diagnostics(
                    middleware.policy_name,
                    &middleware.target,
                    status_code,
                    &error.diagnostics,
                    response_correlation,
                );
                if let Some(denial) = denial.as_ref() {
                    send_response_middleware_denial(
                        client,
                        request_method,
                        middleware.policy_name,
                        &middleware.target,
                        denial,
                        "response_middleware_finish",
                        response_correlation,
                    )
                    .await?;
                } else {
                    emit_http_response_middleware_failure(
                        middleware.policy_name,
                        &middleware.target,
                        status_code,
                        false,
                        response_correlation,
                    );
                    send_response_delivery_failure(
                        client,
                        request_method,
                        middleware.policy_name,
                        &middleware.target,
                        (
                            ResponseSelectionCause::MiddlewareFailed,
                            "platform_error",
                            "response_middleware_finish",
                        ),
                        true,
                        response_correlation,
                    )
                    .await?;
                }
                return Ok(Some(RelayOutcome::Consumed));
            }
        };
        observe_response_middleware(
            response_correlation,
            &finish.invocations,
            finish.strip_stale_integrity_headers,
            false,
            finish.diagnostics_truncated,
        );
        let mut headers = preflight.headers;
        emit_http_response_middleware_invocations(
            middleware.policy_name,
            &middleware.target,
            status_code,
            &finish.invocations,
            response_correlation,
        );
        for event in crate::l7::middleware::middleware_finding_events(&finish.findings) {
            emit_ocsf(response_correlation, event);
        }
        emit_http_response_diagnostic_truncation(
            middleware.policy_name,
            &middleware.target,
            finish.diagnostics_truncated,
            response_correlation,
        );
        if finish.strip_stale_integrity_headers {
            strip_response_integrity_headers(&mut headers);
        }
        let head = serialize_response_head(
            &status_line,
            &headers,
            &preserved_credential_headers,
            ResponseFraming::Preserve(body_length),
            server_wants_close,
            &[],
        );
        let head = final_response_head(&head, response_correlation);
        complete_response_middleware(response_correlation, MiddlewareOutcome::Allowed);
        select_allowed_response(response_correlation, status_code);
        write_correlated_response_bytes(client, &head, response_correlation, true).await?;
        client.flush().await.map_err(RelayError::flush)?;
        return Ok(Some(if server_wants_close {
            RelayOutcome::Consumed
        } else {
            RelayOutcome::Reusable
        }));
    }

    let whole_body = session.requires_whole_body();
    if whole_body {
        session.start_whole_body_deadline(middleware.whole_body_timeout);
    }
    let unit_limit = session.stream_unit_limit().max(1);
    let chunked_output = supports_chunked_response;
    let close_delimited_output = !supports_chunked_response;
    let declared_trailers = upstream_declared_trailers;
    let downstream_trailers = if chunked_output {
        declared_trailers.as_slice()
    } else {
        &[]
    };
    let streaming_head = serialize_response_head(
        &status_line,
        &preflight.headers,
        &preserved_credential_headers,
        if chunked_output {
            ResponseFraming::Chunked
        } else {
            ResponseFraming::Preserve(BodyLength::None)
        },
        server_wants_close || close_delimited_output,
        downstream_trailers,
    );
    let streaming_head = final_response_head(&streaming_head, response_correlation);
    let mut committed = false;
    if !whole_body {
        select_allowed_response(response_correlation, status_code);
        if let Err(error) =
            write_correlated_response_bytes(client, &streaming_head, response_correlation, true)
                .await
        {
            session
                .end(openshell_core::proto::MiddlewareSessionEndReason::DownstreamDisconnect)
                .await;
            return Err(error);
        }
        committed = true;
        if let Err(error) = client.flush().await {
            session
                .end(openshell_core::proto::MiddlewareSessionEndReason::DownstreamDisconnect)
                .await;
            return Err(RelayError::flush(error).into());
        }
    }

    let mut reader = BufferedResponseReader::new(upstream, &buffered[header_end..]);
    let body_result = relay_normalized_response_body(
        &mut reader,
        &mut session,
        client,
        body_length,
        server_wants_close,
        event_stream,
        &mut committed,
        chunked_output,
        &streaming_head,
        unit_limit,
        middleware.generation_guard,
        middleware.policy_name,
        &middleware.target,
        status_code,
        &connection_nominated_headers,
        response_correlation,
    )
    .await;
    let trailers = match body_result {
        Ok(trailers) => trailers,
        Err(error) => {
            let middleware_stop = error.downcast_ref::<ResponseMiddlewareStop>();
            let end_reason = if middleware
                .generation_guard
                .is_some_and(PolicyGenerationGuard::is_stale)
            {
                openshell_core::proto::MiddlewareSessionEndReason::PolicyReload
            } else if error
                .downcast_ref::<RelayError>()
                .is_some_and(|error| matches!(error, RelayError::Write { .. }))
            {
                openshell_core::proto::MiddlewareSessionEndReason::DownstreamDisconnect
            } else if middleware_stop.is_some_and(|stop| stop.failure.denial.is_some()) {
                openshell_core::proto::MiddlewareSessionEndReason::MiddlewareDenial
            } else if middleware_stop.is_some() {
                openshell_core::proto::MiddlewareSessionEndReason::MiddlewareFailure
            } else {
                openshell_core::proto::MiddlewareSessionEndReason::UpstreamDisconnect
            };
            session.end(end_reason).await;
            if committed {
                record_response_middleware_partial_delivery(response_correlation);
            }
            if let Some(stop) = middleware_stop {
                observe_response_diagnostics(response_correlation, &stop.failure.diagnostics);
                observe_response_admission_exhaustion(
                    response_correlation,
                    stop.failure.admission_exhausted(),
                );
                let denied = stop.failure.denial.is_some()
                    || response_invocations_blocked(&stop.failure.diagnostics.invocations);
                complete_response_middleware(
                    response_correlation,
                    if denied {
                        MiddlewareOutcome::Denied
                    } else {
                        MiddlewareOutcome::PlatformError
                    },
                );
            }
            if committed {
                if middleware_stop.is_some() {
                    emit_http_response_middleware_failure(
                        middleware.policy_name,
                        &middleware.target,
                        status_code,
                        true,
                        response_correlation,
                    );
                }
                return Err(error);
            }
            debug!(error = %error, "HTTP response processing failed before commitment");
            if let Some(denial) = middleware_stop.and_then(|stop| stop.failure.denial.as_ref()) {
                send_response_middleware_denial(
                    client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                    denial,
                    "response_middleware_body",
                    response_correlation,
                )
                .await?;
            } else {
                if middleware_stop.is_some() {
                    emit_http_response_middleware_failure(
                        middleware.policy_name,
                        &middleware.target,
                        status_code,
                        false,
                        response_correlation,
                    );
                }
                let failure = classify_response_failure(&error);
                send_response_delivery_failure(
                    client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                    (
                        failure.cause.unwrap_or(ResponseSelectionCause::Unknown),
                        failure.http_outcome,
                        failure.error_stage,
                    ),
                    true,
                    response_correlation,
                )
                .await?;
            }
            return Ok(Some(RelayOutcome::Consumed));
        }
    };

    if let Some(guard) = middleware.generation_guard
        && let Err(error) = ensure_relay_generation_current(guard)
    {
        if committed {
            record_response_middleware_partial_delivery(response_correlation);
        }
        session
            .end(openshell_core::proto::MiddlewareSessionEndReason::PolicyReload)
            .await;
        return Err(error);
    }

    let input_trailers = trailers.clone();
    let finish_result = session.finish(trailers).await;
    if let Some(guard) = middleware.generation_guard
        && let Err(error) = ensure_relay_generation_current(guard)
    {
        if committed {
            record_response_middleware_partial_delivery(response_correlation);
        }
        return Err(error);
    }
    let finish = match finish_result {
        Ok(finish) => finish,
        Err(error) => {
            observe_response_diagnostics(response_correlation, &error.diagnostics);
            observe_response_admission_exhaustion(
                response_correlation,
                error.admission_exhausted(),
            );
            if committed {
                record_response_middleware_partial_delivery(response_correlation);
            }
            complete_response_middleware(
                response_correlation,
                middleware_failure_outcome(error.denial.is_some(), &error.diagnostics),
            );
            emit_http_response_diagnostics(
                middleware.policy_name,
                &middleware.target,
                status_code,
                &error.diagnostics,
                response_correlation,
            );
            if committed {
                emit_http_response_middleware_failure(
                    middleware.policy_name,
                    &middleware.target,
                    status_code,
                    true,
                    response_correlation,
                );
                return Err(ResponseMiddlewareStop::new(error).into());
            }
            debug!(error = %error, "HTTP response middleware failed before commitment");
            if let Some(denial) = error.denial.as_ref() {
                send_response_middleware_denial(
                    client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                    denial,
                    "response_middleware_finish",
                    response_correlation,
                )
                .await?;
            } else {
                emit_http_response_middleware_failure(
                    middleware.policy_name,
                    &middleware.target,
                    status_code,
                    false,
                    response_correlation,
                );
                send_response_delivery_failure(
                    client,
                    request_method,
                    middleware.policy_name,
                    &middleware.target,
                    (
                        ResponseSelectionCause::MiddlewareFailed,
                        "platform_error",
                        "response_middleware_finish",
                    ),
                    true,
                    response_correlation,
                )
                .await?;
            }
            return Ok(Some(RelayOutcome::Consumed));
        }
    };
    observe_response_middleware(
        response_correlation,
        &finish.invocations,
        finish.strip_stale_integrity_headers || finish.trailers != input_trailers,
        false,
        finish.diagnostics_truncated,
    );
    emit_http_response_middleware_invocations(
        middleware.policy_name,
        &middleware.target,
        status_code,
        &finish.invocations,
        response_correlation,
    );
    for event in crate::l7::middleware::middleware_finding_events(&finish.findings) {
        emit_ocsf(response_correlation, event);
    }
    emit_http_response_diagnostic_truncation(
        middleware.policy_name,
        &middleware.target,
        finish.diagnostics_truncated,
        response_correlation,
    );

    if whole_body && !committed {
        let mut headers = preflight.headers;
        if finish.strip_stale_integrity_headers {
            strip_response_integrity_headers(&mut headers);
        }
        let Some(output_length) = finish
            .body_units
            .iter()
            .try_fold(0usize, |total, unit| total.checked_add(unit.len()))
        else {
            complete_response_middleware(response_correlation, MiddlewareOutcome::PlatformError);
            return Err(miette!("HTTP response middleware output length overflow"));
        };
        let framing = if finish.trailers.is_empty() || !supports_chunked_response {
            ResponseFraming::ContentLength(output_length as u64)
        } else {
            ResponseFraming::Chunked
        };
        let trailer_names: Vec<String> = if supports_chunked_response {
            finish
                .trailers
                .iter()
                .map(|header| header.name.clone())
                .collect()
        } else {
            Vec::new()
        };
        let head = serialize_response_head(
            &status_line,
            &headers,
            &preserved_credential_headers,
            framing,
            server_wants_close,
            &trailer_names,
        );
        let head = final_response_head(&head, response_correlation);
        complete_response_middleware(response_correlation, MiddlewareOutcome::Allowed);
        select_allowed_response(response_correlation, status_code);
        write_correlated_response_bytes(client, &head, response_correlation, true).await?;
        if matches!(framing, ResponseFraming::Chunked) {
            for unit in &finish.body_units {
                write_downstream_response_chunk(client, unit).await?;
            }
            write_response_trailers(client, &finish.trailers).await?;
        } else {
            for unit in &finish.body_units {
                client.write_all(unit).await.map_err(RelayError::write)?;
            }
        }
    } else {
        complete_response_middleware(response_correlation, MiddlewareOutcome::Allowed);
        for unit in &finish.body_units {
            if chunked_output {
                write_downstream_response_chunk(client, unit).await?;
            } else {
                client.write_all(unit).await.map_err(RelayError::write)?;
            }
        }
        if chunked_output {
            write_response_trailers(client, &finish.trailers).await?;
        }
    }
    client.flush().await.map_err(RelayError::flush)?;
    Ok(Some(
        if server_wants_close
            || (committed && close_delimited_output)
            || (matches!(body_length, BodyLength::None) && event_stream)
        {
            RelayOutcome::Consumed
        } else {
            RelayOutcome::Reusable
        },
    ))
}

#[allow(clippy::too_many_arguments)]
async fn relay_headers_only_response<U, C>(
    request_method: &str,
    upstream: &mut U,
    client: &mut C,
    status_line: &str,
    headers: &[HttpHeader],
    preserved_credential_headers: &[String],
    declared_trailers: &[String],
    overflow: &[u8],
    status_code: u16,
    body_length: BodyLength,
    server_wants_close: bool,
    event_stream: bool,
    generation_guard: Option<&PolicyGenerationGuard>,
    response_correlation: Option<&RequestCorrelation>,
) -> Result<RelayOutcome>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let head = serialize_response_head(
        status_line,
        headers,
        preserved_credential_headers,
        ResponseFraming::Preserve(body_length),
        server_wants_close,
        declared_trailers,
    );
    let head = final_response_head(&head, response_correlation);
    if let Some(guard) = generation_guard {
        ensure_relay_generation_current(guard)?;
    }
    select_allowed_response(response_correlation, status_code);
    write_correlated_response_bytes(client, &head, response_correlation, true).await?;

    if is_bodiless_response(request_method, status_code) {
        client.flush().await.map_err(RelayError::flush)?;
        let outcome = if server_wants_close {
            RelayOutcome::Consumed
        } else {
            RelayOutcome::Reusable
        };
        return Ok(outcome);
    }

    match body_length {
        BodyLength::ContentLength(length) => {
            if !overflow.is_empty() {
                if let Some(guard) = generation_guard {
                    ensure_relay_generation_current(guard)?;
                }
                client
                    .write_all(overflow)
                    .await
                    .map_err(RelayError::write)?;
            }
            let remaining = length - overflow.len() as u64;
            if remaining > 0 {
                relay_fixed(upstream, client, remaining, generation_guard).await?;
            }
        }
        BodyLength::Chunked => relay_chunked(upstream, client, overflow, generation_guard)
            .await
            .map_err(type_response_protocol_error)?,
        BodyLength::None if server_wants_close || event_stream => {
            if !overflow.is_empty() {
                if let Some(guard) = generation_guard {
                    ensure_relay_generation_current(guard)?;
                }
                client
                    .write_all(overflow)
                    .await
                    .map_err(RelayError::write)?;
            }
            let idle_timed_out = if event_stream {
                relay_until_eof_without_idle_timeout(upstream, client, generation_guard).await?;
                false
            } else {
                relay_until_eof(upstream, client, generation_guard).await?
                    == RelayUntilEofOutcome::IdleTimeout
            };
            client.flush().await.map_err(RelayError::flush)?;
            if idle_timed_out {
                record_response_idle_timeout(response_correlation);
            }
            return Ok(RelayOutcome::Consumed);
        }
        BodyLength::None => {
            if !overflow.is_empty() {
                if let Some(guard) = generation_guard {
                    ensure_relay_generation_current(guard)?;
                }
                client
                    .write_all(overflow)
                    .await
                    .map_err(RelayError::write)?;
            }
        }
    }
    client.flush().await.map_err(RelayError::flush)?;
    let outcome = if server_wants_close {
        RelayOutcome::Consumed
    } else {
        RelayOutcome::Reusable
    };
    Ok(outcome)
}

fn observe_response_middleware(
    correlation: Option<&RequestCorrelation>,
    invocations: &[openshell_supervisor_middleware::HttpResponseInvocation],
    mutated: bool,
    admission_exhausted: bool,
    diagnostics_truncated: bool,
) {
    let Some(correlation) = correlation else {
        return;
    };
    correlation.observe_middleware(
        MiddlewarePhase::Response,
        MiddlewareObservation {
            diagnostics_truncated,
            ..response_middleware_observation(invocations, mutated, admission_exhausted)
        },
    );
}

fn response_middleware_observation(
    invocations: &[openshell_supervisor_middleware::HttpResponseInvocation],
    mutated: bool,
    admission_exhausted: bool,
) -> MiddlewareObservation {
    let mut observation = MiddlewareObservation {
        mutated,
        admission_exhausted,
        ..Default::default()
    };
    for invocation in invocations {
        observation.mutated |= invocation.transformed;
        match invocation.outcome {
            openshell_supervisor_middleware::HttpResponseInvocationOutcome::Transform => {
                observation.mutated = true;
            }
            openshell_supervisor_middleware::HttpResponseInvocationOutcome::FailOpen => {
                observation.fail_open = true;
            }
            openshell_supervisor_middleware::HttpResponseInvocationOutcome::FailClosed => {
                observation.fail_closed = true;
            }
            _ => {}
        }
    }
    observation
}

fn observe_response_diagnostics(
    correlation: Option<&RequestCorrelation>,
    diagnostics: &openshell_supervisor_middleware::HttpResponseDiagnostics,
) {
    observe_response_middleware(
        correlation,
        &diagnostics.invocations,
        false,
        false,
        diagnostics.diagnostics_truncated,
    );
}

fn observe_response_admission_exhaustion(
    correlation: Option<&RequestCorrelation>,
    admission_exhausted: bool,
) {
    if admission_exhausted && let Some(correlation) = correlation {
        correlation.observe_middleware(
            MiddlewarePhase::Response,
            MiddlewareObservation {
                admission_exhausted: true,
                ..Default::default()
            },
        );
    }
}

fn record_response_delivery_started(correlation: Option<&RequestCorrelation>) {
    if let Some(correlation) = correlation {
        correlation.record_response_delivery_started();
    }
}

fn record_response_middleware_delivery_started(correlation: Option<&RequestCorrelation>) {
    if let Some(correlation) = correlation {
        correlation.record_response_delivery_started();
        correlation.observe_middleware(
            MiddlewarePhase::Response,
            MiddlewareObservation {
                delivery_started: true,
                ..Default::default()
            },
        );
    }
}

fn record_response_middleware_partial_delivery(correlation: Option<&RequestCorrelation>) {
    if let Some(correlation) = correlation
        && correlation.record_response_partial_delivery()
    {
        correlation.observe_middleware(
            MiddlewarePhase::Response,
            MiddlewareObservation {
                delivery_started: true,
                partial_delivery: true,
                ..Default::default()
            },
        );
    }
}

async fn write_correlated_interim_bytes<C: AsyncWrite + Unpin>(
    client: &mut C,
    bytes: &[u8],
    correlation: Option<&RequestCorrelation>,
) -> Result<()> {
    let mut written = 0usize;
    while written < bytes.len() {
        let count = client
            .write(&bytes[written..])
            .await
            .map_err(RelayError::interim_write)?;
        if count == 0 {
            return Err(RelayError::interim_write(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write interim HTTP response bytes",
            ))
            .into());
        }
        if let Some(correlation) = correlation {
            correlation.record_interim_response_delivery(count);
        }
        written += count;
    }
    Ok(())
}

async fn write_correlated_response_bytes<C: AsyncWrite + Unpin>(
    client: &mut C,
    bytes: &[u8],
    correlation: Option<&RequestCorrelation>,
    middleware_selected: bool,
) -> Result<()> {
    let mut written = 0usize;
    while written < bytes.len() {
        let count = client
            .write(&bytes[written..])
            .await
            .map_err(RelayError::write)?;
        if count == 0 {
            return Err(RelayError::write(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write HTTP response bytes",
            ))
            .into());
        }
        if written == 0 {
            if middleware_selected {
                record_response_middleware_delivery_started(correlation);
            } else {
                record_response_delivery_started(correlation);
            }
        }
        written += count;
    }
    Ok(())
}

async fn write_correlated_response_commit<C: AsyncWrite + Unpin>(
    client: &mut C,
    bytes: &[u8],
    correlation: Option<&RequestCorrelation>,
    committed: &mut bool,
) -> Result<()> {
    let mut written = 0usize;
    while written < bytes.len() {
        let count = client
            .write(&bytes[written..])
            .await
            .map_err(RelayError::write)?;
        if count == 0 {
            return Err(RelayError::write(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to write HTTP response bytes",
            ))
            .into());
        }
        if !*committed {
            *committed = true;
            record_response_middleware_delivery_started(correlation);
        }
        written += count;
    }
    Ok(())
}

fn complete_response_middleware(
    correlation: Option<&RequestCorrelation>,
    outcome: MiddlewareOutcome,
) {
    if let Some(correlation) = correlation {
        correlation.complete_middleware(MiddlewarePhase::Response, outcome);
    }
}

fn response_invocations_blocked(
    invocations: &[openshell_supervisor_middleware::HttpResponseInvocation],
) -> bool {
    invocations.iter().any(|invocation| {
        invocation.outcome
            == openshell_supervisor_middleware::HttpResponseInvocationOutcome::BlockDelivery
    })
}

fn middleware_failure_outcome(
    explicit_denial: bool,
    diagnostics: &openshell_supervisor_middleware::HttpResponseDiagnostics,
) -> MiddlewareOutcome {
    if explicit_denial || response_invocations_blocked(&diagnostics.invocations) {
        MiddlewareOutcome::Denied
    } else {
        MiddlewareOutcome::PlatformError
    }
}

fn response_middleware_failure_denial(
    failure: &openshell_supervisor_middleware::HttpResponseMiddlewareFailure,
) -> Option<openshell_supervisor_middleware::MiddlewareDenial> {
    failure.denial.clone().or_else(|| {
        failure
            .diagnostics
            .invocations
            .iter()
            .find(|invocation| {
                invocation.outcome
                    == openshell_supervisor_middleware::HttpResponseInvocationOutcome::BlockDelivery
            })
            .map(
                |invocation| openshell_supervisor_middleware::MiddlewareDenial {
                    config_name: invocation.config_name.clone(),
                    reason_code: invocation.reason_code.clone(),
                },
            )
    })
}

fn emit_http_response_middleware_invocations(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    invocations: &[openshell_supervisor_middleware::HttpResponseInvocation],
    correlation: Option<&RequestCorrelation>,
) {
    for event in
        http_response_middleware_invocation_events(policy_name, target, status_code, invocations)
    {
        emit_ocsf(correlation, event);
    }
    for invocation in invocations {
        if let Some(event) =
            http_response_middleware_fail_open_finding_event(policy_name, target, invocation)
        {
            emit_ocsf(correlation, event);
        }
        if let Some(event) =
            http_response_middleware_block_finding_event(policy_name, target, invocation)
        {
            emit_ocsf(correlation, event);
        }
    }
}

fn emit_http_response_diagnostics(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    diagnostics: &openshell_supervisor_middleware::HttpResponseDiagnostics,
    correlation: Option<&RequestCorrelation>,
) {
    emit_http_response_middleware_invocations(
        policy_name,
        target,
        status_code,
        &diagnostics.invocations,
        correlation,
    );
    for event in crate::l7::middleware::middleware_finding_events(&diagnostics.findings) {
        emit_ocsf(correlation, event);
    }
    emit_http_response_diagnostic_truncation(
        policy_name,
        target,
        diagnostics.diagnostics_truncated,
        correlation,
    );
}

fn emit_http_response_diagnostic_truncation(
    policy_name: &str,
    target: &HttpRequestTarget,
    diagnostics_truncated: bool,
    correlation: Option<&RequestCorrelation>,
) {
    if !diagnostics_truncated {
        return;
    }
    emit_ocsf(
        correlation,
        http_response_diagnostic_truncation_event(policy_name, target),
    );
}

fn http_response_diagnostic_truncation_event(
    policy_name: &str,
    target: &HttpRequestTarget,
) -> openshell_ocsf::OcsfEvent {
    openshell_ocsf::DetectionFindingBuilder::new(ocsf_ctx())
        .severity(openshell_ocsf::SeverityId::Low)
        .finding_info(openshell_ocsf::FindingInfo::new(
            "openshell.middleware.http_response_diagnostics_truncated",
            "HTTP response middleware diagnostics truncated",
        ))
        .evidence_pairs(&[
            ("policy", policy_name),
            ("host", target.host.as_str()),
            ("phase", "pre_return"),
        ])
        .unmapped("phase", "pre_return")
        .message("HTTP response middleware diagnostic evidence exceeded the session budget")
        .build()
}

pub(super) fn http_response_middleware_invocation_events(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    invocations: &[openshell_supervisor_middleware::HttpResponseInvocation],
) -> Vec<openshell_ocsf::OcsfEvent> {
    invocations
        .iter()
        .map(|invocation| {
            let outcome = format!("{:?}", invocation.outcome).to_ascii_lowercase();
            let failed = invocation.failed;
            let blocked = invocation.outcome
                == openshell_supervisor_middleware::HttpResponseInvocationOutcome::BlockDelivery;
            openshell_ocsf::HttpActivityBuilder::new(ocsf_ctx())
            .activity(openshell_ocsf::ActivityId::Other)
            .action(if blocked {
                openshell_ocsf::ActionId::Denied
            } else if failed {
                openshell_ocsf::ActionId::Other
            } else {
                openshell_ocsf::ActionId::Allowed
            })
            .disposition(if blocked {
                openshell_ocsf::DispositionId::Blocked
            } else if failed {
                openshell_ocsf::DispositionId::Error
            } else {
                openshell_ocsf::DispositionId::Allowed
            })
            .severity(if failed || blocked {
                openshell_ocsf::SeverityId::Medium
            } else {
                openshell_ocsf::SeverityId::Informational
            })
            .status(if failed || blocked {
                openshell_ocsf::StatusId::Failure
            } else {
                openshell_ocsf::StatusId::Success
            })
            .http_request(openshell_ocsf::HttpRequest::new(
                &target.method,
                openshell_ocsf::Url::new(
                    &target.scheme,
                    &target.host,
                    &target.path,
                    u16::try_from(target.port).unwrap_or_default(),
                ),
            ))
            .http_response(openshell_ocsf::HttpResponse { code: status_code })
            .dst_endpoint(openshell_ocsf::Endpoint::from_domain(
                &target.host,
                u16::try_from(target.port).unwrap_or_default(),
            ))
            .firewall_rule(policy_name, "supervisor-middleware")
            .unmapped("middleware_config", invocation.config_name.as_str())
            .unmapped(
                "middleware_implementation",
                invocation.implementation.as_str(),
            )
            .unmapped("response_middleware_outcome", outcome.as_str())
            .unmapped("sequence", invocation.sequence.unwrap_or_default())
            .unmapped("input_bytes", invocation.input_size)
            .unmapped("failed", failed)
            .message(format!(
                "HTTP_RESPONSE_MIDDLEWARE config={} implementation={} outcome={} sequence={} input_bytes={} failed={failed}",
                invocation.config_name,
                invocation.implementation,
                outcome,
                invocation.sequence.unwrap_or_default(),
                invocation.input_size,
            ))
                .build()
        })
        .collect()
}

fn http_response_middleware_block_finding_event(
    policy_name: &str,
    target: &HttpRequestTarget,
    invocation: &openshell_supervisor_middleware::HttpResponseInvocation,
) -> Option<openshell_ocsf::OcsfEvent> {
    if invocation.outcome
        != openshell_supervisor_middleware::HttpResponseInvocationOutcome::BlockDelivery
    {
        return None;
    }
    Some(
        openshell_ocsf::DetectionFindingBuilder::new(ocsf_ctx())
            .severity(openshell_ocsf::SeverityId::Medium)
            .finding_info(openshell_ocsf::FindingInfo::new(
                "openshell.middleware.http_response_blocked",
                "HTTP response blocked by middleware",
            ))
            .evidence_pairs(&[
                ("policy", policy_name),
                ("middleware_config", invocation.config_name.as_str()),
                (
                    "middleware_implementation",
                    invocation.implementation.as_str(),
                ),
                ("host", target.host.as_str()),
                ("phase", "pre_return"),
            ])
            .unmapped("middleware_config", invocation.config_name.as_str())
            .unmapped(
                "middleware_implementation",
                invocation.implementation.as_str(),
            )
            .unmapped("phase", "pre_return")
            .message("HTTP response delivery blocked by middleware")
            .build(),
    )
}

pub(super) fn http_response_middleware_fail_open_finding_event(
    policy_name: &str,
    target: &HttpRequestTarget,
    invocation: &openshell_supervisor_middleware::HttpResponseInvocation,
) -> Option<openshell_ocsf::OcsfEvent> {
    if !invocation.failed
        || invocation.outcome
            != openshell_supervisor_middleware::HttpResponseInvocationOutcome::FailOpen
    {
        return None;
    }
    let failure_category = invocation
        .failure_category
        .as_deref()
        .unwrap_or("middleware_failure");
    Some(
        openshell_ocsf::DetectionFindingBuilder::new(ocsf_ctx())
            .severity(openshell_ocsf::SeverityId::Medium)
            .finding_info(openshell_ocsf::FindingInfo::new(
                "openshell.middleware.http_response_fail_open",
                "HTTP response middleware failed open",
            ))
            .evidence_pairs(&[
                ("policy", policy_name),
                ("middleware_config", invocation.config_name.as_str()),
                (
                    "middleware_implementation",
                    invocation.implementation.as_str(),
                ),
                ("host", target.host.as_str()),
                ("phase", "pre_return"),
                ("failure_category", failure_category),
            ])
            .unmapped("middleware_config", invocation.config_name.as_str())
            .unmapped(
                "middleware_implementation",
                invocation.implementation.as_str(),
            )
            .unmapped("phase", "pre_return")
            .unmapped("failure_category", failure_category)
            .message("HTTP response middleware failed and response inspection was bypassed")
            .build(),
    )
}

fn emit_http_response_middleware_failure(
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    committed: bool,
    correlation: Option<&RequestCorrelation>,
) {
    let status_code = status_code.to_string();
    let event = openshell_ocsf::DetectionFindingBuilder::new(ocsf_ctx())
        .severity(openshell_ocsf::SeverityId::High)
        .finding_info(openshell_ocsf::FindingInfo::new(
            "openshell.middleware.http_response_failure",
            "HTTP response middleware delivery failure",
        ))
        .evidence_pairs(&[
            ("policy", policy_name),
            ("host", target.host.as_str()),
            (
                "commitment",
                if committed {
                    "after_commit"
                } else {
                    "before_commit"
                },
            ),
            ("upstream_status", status_code.as_str()),
        ])
        .message(if committed {
            "HTTP response middleware failed after response commitment"
        } else {
            "HTTP response middleware failed before response commitment"
        })
        .build();
    emit_ocsf(correlation, event);
}

#[derive(Debug)]
struct ParsedResponseHead {
    representable: bool,
    headers: Vec<HttpHeader>,
    preserved_credential_headers: Vec<String>,
    connection_nominated: Vec<String>,
    declared_trailers: Vec<String>,
}

fn parse_response_head_for_middleware(header_bytes: &[u8]) -> Result<ParsedResponseHead> {
    // Lossy decoding preserves ASCII syntax and control bytes for validation.
    // Never pass replacement text to middleware or use it for delivery.
    let header = String::from_utf8_lossy(header_bytes);
    let representable = std::str::from_utf8(header_bytes).is_ok();
    if parse_status_code(&header).is_none() {
        return Err(miette!("HTTP response status line is malformed"));
    }
    let mut nominated = HashSet::new();
    let mut declared_trailers = Vec::new();
    for line in header.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        validate_http_field_name(name)?;
        validate_http_field_value(value.trim())?;
        if name.eq_ignore_ascii_case("connection") {
            for token in value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
            {
                nominated.insert(token.to_ascii_lowercase());
            }
        } else if name.eq_ignore_ascii_case("trailer") {
            for token in parse_http_token_list(value)? {
                let token = token.to_ascii_lowercase();
                if !declared_trailers.contains(&token) {
                    declared_trailers.push(token);
                }
            }
        }
    }
    for trailer in &declared_trailers {
        if is_protected_response_field(trailer) || nominated.contains(trailer) {
            return Err(miette!("HTTP response declares a protected trailer field"));
        }
    }
    let mut headers = Vec::new();
    let mut preserved_credential_headers = Vec::new();
    for line in header.split("\r\n").skip(1).filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| miette!("Malformed HTTP response header field"))?;
        validate_http_field_name(name)?;
        validate_http_field_value(value.trim())?;
        let name = name.to_ascii_lowercase();
        if openshell_supervisor_middleware::headers::is_response_credential_header(&name) {
            // Middleware must not observe credential-bearing response fields.
            // Keep the original line separately so downstream delivery retains
            // its exact name, whitespace, and value bytes.
            preserved_credential_headers.push(line.to_string());
            continue;
        }
        if nominated.contains(&name) || is_hidden_response_field(&name) {
            continue;
        }
        headers.push(HttpHeader {
            name,
            value: value.trim().to_string(),
        });
    }
    let mut connection_nominated: Vec<_> = nominated.into_iter().collect();
    connection_nominated.sort();
    Ok(ParsedResponseHead {
        representable,
        headers: if representable { headers } else { Vec::new() },
        preserved_credential_headers: if representable {
            preserved_credential_headers
        } else {
            Vec::new()
        },
        connection_nominated,
        declared_trailers,
    })
}

fn validate_http_field_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(miette!("HTTP response field name is malformed"));
    }
    Ok(())
}

fn validate_http_field_value(value: &str) -> Result<()> {
    if value
        .bytes()
        .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
    {
        return Err(miette!("HTTP response field value contains a control byte"));
    }
    Ok(())
}

fn is_protected_response_field(name: &str) -> bool {
    name.eq_ignore_ascii_case(openshell_core::token_grant_failure::REQUEST_ID_HEADER)
        || name.eq_ignore_ascii_case("content-length")
        || is_hidden_response_field(name)
        || openshell_supervisor_middleware::headers::is_response_credential_header(name)
}

fn is_hidden_response_field(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn response_status_line(header_bytes: &[u8]) -> Result<String> {
    let line_end = header_bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| {
            RelayError::protocol(
                "invalid_response_status_line",
                "HTTP response status line is incomplete",
            )
        })?;
    std::str::from_utf8(&header_bytes[..line_end])
        .map(str::to_string)
        .map_err(|_| {
            RelayError::protocol(
                "invalid_response_status_line",
                "HTTP response status line contains invalid UTF-8",
            )
            .into()
        })
}

#[derive(Clone, Copy)]
enum ResponseFraming {
    Preserve(BodyLength),
    ContentLength(u64),
    Chunked,
}

fn serialize_response_head(
    status_line: &str,
    headers: &[HttpHeader],
    preserved_credential_headers: &[String],
    framing: ResponseFraming,
    connection_close: bool,
    trailer_names: &[String],
) -> Vec<u8> {
    let mut output = format!("{status_line}\r\n");
    for header in headers {
        // Content-Length is read-only middleware metadata. The relay emits the
        // final framing exactly once from `framing` below.
        if header.name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        output.push_str(&header.name);
        output.push_str(": ");
        output.push_str(&header.value);
        output.push_str("\r\n");
    }
    for header in preserved_credential_headers {
        output.push_str(header);
        output.push_str("\r\n");
    }
    match framing {
        ResponseFraming::Preserve(BodyLength::ContentLength(length))
        | ResponseFraming::ContentLength(length) => {
            write!(&mut output, "Content-Length: {length}\r\n")
                .expect("writing to a String cannot fail");
        }
        ResponseFraming::Preserve(BodyLength::Chunked) | ResponseFraming::Chunked => {
            output.push_str("Transfer-Encoding: chunked\r\n");
        }
        ResponseFraming::Preserve(BodyLength::None) => {}
    }
    if !trailer_names.is_empty() {
        output.push_str("Trailer: ");
        output.push_str(&trailer_names.join(", "));
        output.push_str("\r\n");
    }
    if connection_close {
        output.push_str("Connection: close\r\n");
    }
    output.push_str("\r\n");
    output.into_bytes()
}

pub(super) fn strip_response_integrity_headers(headers: &mut Vec<HttpHeader>) {
    headers.retain(|header| {
        !openshell_supervisor_middleware::is_stale_http_response_integrity_header(&header.name)
    });
}

struct BufferedResponseReader<'a, R> {
    upstream: &'a mut R,
    buffered: &'a [u8],
    position: usize,
    exact_buffer: Vec<u8>,
    exact_target: Option<usize>,
    line_buffer: Vec<u8>,
}

impl<'a, R: AsyncRead + Unpin> BufferedResponseReader<'a, R> {
    fn new(upstream: &'a mut R, buffered: &'a [u8]) -> Self {
        Self {
            upstream,
            buffered,
            position: 0,
            exact_buffer: Vec::new(),
            exact_target: None,
            line_buffer: Vec::new(),
        }
    }

    async fn read_some(&mut self, limit: usize) -> Result<Option<Vec<u8>>> {
        if self.position < self.buffered.len() {
            let end = self.position.saturating_add(limit).min(self.buffered.len());
            let data = self.buffered[self.position..end].to_vec();
            self.position = end;
            return Ok(Some(data));
        }
        let mut data = vec![0u8; limit.max(1)];
        let count = self
            .upstream
            .read(&mut data)
            .await
            .map_err(RelayError::read)?;
        if count == 0 {
            return Ok(None);
        }
        data.truncate(count);
        Ok(Some(data))
    }

    async fn read_exact_vec(&mut self, length: usize) -> Result<Vec<u8>> {
        match self.exact_target {
            Some(target) if target != length => {
                return Err(miette!("HTTP response reader exact-read state mismatch"));
            }
            None => {
                self.exact_target = Some(length);
                self.exact_buffer.reserve(length);
            }
            Some(_) => {}
        }
        while self.exact_buffer.len() < length {
            let remaining = length - self.exact_buffer.len();
            let Some(data) = self.read_some(remaining).await? else {
                return Err(RelayError::Truncated("HTTP response body ended unexpectedly").into());
            };
            self.exact_buffer.extend_from_slice(&data);
        }
        self.exact_target = None;
        Ok(std::mem::take(&mut self.exact_buffer))
    }

    async fn read_line(&mut self) -> Result<Vec<u8>> {
        loop {
            let Some(byte) = self.read_some(1).await? else {
                return Err(
                    RelayError::Truncated("HTTP response ended before line terminator").into(),
                );
            };
            self.line_buffer.push(byte[0]);
            if self.line_buffer.len() > MAX_HEADER_BYTES {
                return Err(RelayError::protocol(
                    "response_framing_line_too_large",
                    "HTTP response framing line exceeds limit",
                )
                .into());
            }
            if self.line_buffer.ends_with(b"\r\n") {
                self.line_buffer.truncate(self.line_buffer.len() - 2);
                return Ok(std::mem::take(&mut self.line_buffer));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay_normalized_response_body<R, C>(
    reader: &mut BufferedResponseReader<'_, R>,
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    body_length: BodyLength,
    server_wants_close: bool,
    event_stream: bool,
    committed: &mut bool,
    chunked_output: bool,
    commit_head: &[u8],
    unit_limit: usize,
    generation_guard: Option<&PolicyGenerationGuard>,
    policy_name: &str,
    target: &HttpRequestTarget,
    status_code: u16,
    connection_nominated_headers: &[String],
    response_correlation: Option<&RequestCorrelation>,
) -> Result<Vec<HttpHeader>>
where
    R: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut pending = Vec::with_capacity(unit_limit);
    let mut framing = ResponseOutputState {
        committed,
        chunked: chunked_output,
        commit_head,
        generation_guard,
        policy_name,
        target,
        status_code,
        response_correlation,
    };
    match body_length {
        BodyLength::ContentLength(mut remaining) => {
            while remaining > 0 {
                let length = usize::try_from(remaining)
                    .unwrap_or(unit_limit)
                    .min(unit_limit);
                let unit = read_response_payload_with_deadline(
                    reader,
                    length,
                    !pending.is_empty(),
                    session,
                    client,
                    &mut framing,
                )
                .await?;
                if let Some(guard) = generation_guard {
                    ensure_relay_generation_current(guard)?;
                }
                let partial = unit.len() < length;
                remaining -= unit.len() as u64;
                buffer_normalized_response_bytes(
                    session,
                    client,
                    &mut pending,
                    unit,
                    &mut framing,
                    unit_limit,
                )
                .await?;
                if partial {
                    flush_normalized_response_bytes(
                        session,
                        client,
                        std::mem::take(&mut pending),
                        &mut framing,
                    )
                    .await?;
                }
            }
            flush_normalized_response_bytes(session, client, pending, &mut framing).await?;
            Ok(Vec::new())
        }
        BodyLength::Chunked => {
            let mut size_line =
                read_response_line_with_deadline(reader, session, client, &mut framing).await?;
            loop {
                let chunk_size = parse_chunk_size_line(&size_line).map_err(|error| {
                    RelayError::protocol("invalid_chunk_size", error.to_string())
                })?;
                if chunk_size == 0 {
                    flush_normalized_response_bytes(session, client, pending, &mut framing).await?;
                    return read_response_trailers(
                        reader,
                        session,
                        client,
                        &mut framing,
                        connection_nominated_headers,
                    )
                    .await;
                }
                let mut remaining = chunk_size;
                while remaining > 0 {
                    let length = remaining.min(unit_limit);
                    let unit = read_response_payload_with_deadline(
                        reader,
                        length,
                        !pending.is_empty(),
                        session,
                        client,
                        &mut framing,
                    )
                    .await?;
                    if let Some(guard) = generation_guard {
                        ensure_relay_generation_current(guard)?;
                    }
                    let partial = unit.len() < length;
                    remaining -= unit.len();
                    buffer_normalized_response_bytes(
                        session,
                        client,
                        &mut pending,
                        unit,
                        &mut framing,
                        unit_limit,
                    )
                    .await?;
                    if partial {
                        flush_normalized_response_bytes(
                            session,
                            client,
                            std::mem::take(&mut pending),
                            &mut framing,
                        )
                        .await?;
                    }
                }
                let terminator = if let Ok(result) = tokio::time::timeout(
                    RESPONSE_UNIT_COALESCE_TIMEOUT,
                    guarded_relay_read(generation_guard, reader.read_exact_vec(2)),
                )
                .await
                {
                    result?
                } else {
                    flush_normalized_response_bytes(
                        session,
                        client,
                        std::mem::take(&mut pending),
                        &mut framing,
                    )
                    .await?;
                    read_exact_response_with_deadline(reader, 2, session, client, &mut framing)
                        .await?
                };
                if terminator != b"\r\n" {
                    return Err(RelayError::protocol(
                        "invalid_chunk_terminator",
                        "HTTP response chunk is missing its terminator",
                    )
                    .into());
                }
                size_line = if let Ok(line) = tokio::time::timeout(
                    RESPONSE_UNIT_COALESCE_TIMEOUT,
                    guarded_relay_read(generation_guard, reader.read_line()),
                )
                .await
                {
                    line?
                } else {
                    flush_normalized_response_bytes(
                        session,
                        client,
                        std::mem::take(&mut pending),
                        &mut framing,
                    )
                    .await?;
                    read_response_line_with_deadline(reader, session, client, &mut framing).await?
                };
            }
        }
        BodyLength::None if server_wants_close || event_stream => loop {
            // Cancel only input acquisition, never expiry or client writes.
            let wait = if pending.is_empty() {
                if event_stream {
                    None
                } else {
                    Some(RELAY_EOF_IDLE_TIMEOUT)
                }
            } else {
                Some(RESPONSE_UNIT_COALESCE_TIMEOUT)
            };
            let read_deadline = wait.map(|wait| tokio::time::Instant::now() + wait);
            let whole_deadline = session.whole_body_deadline();
            let deadline = match (read_deadline, whole_deadline) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            let next = if let Some(deadline) = deadline {
                if let Ok(result) = tokio::time::timeout_at(
                    deadline,
                    guarded_relay_read(generation_guard, reader.read_some(unit_limit)),
                )
                .await
                {
                    result?
                } else {
                    if whole_deadline.is_some_and(|d| d <= tokio::time::Instant::now()) {
                        expire_whole_body_deadline(session, client, &mut framing).await?;
                    } else if pending.is_empty() {
                        return Err(RelayError::IdleTimeout.into());
                    } else {
                        flush_normalized_response_bytes(
                            session,
                            client,
                            std::mem::take(&mut pending),
                            &mut framing,
                        )
                        .await?;
                    }
                    continue;
                }
            } else {
                guarded_relay_read(generation_guard, reader.read_some(unit_limit)).await?
            };
            let Some(unit) = next else {
                flush_normalized_response_bytes(session, client, pending, &mut framing).await?;
                return Ok(Vec::new());
            };
            if let Some(guard) = generation_guard {
                ensure_relay_generation_current(guard)?;
            }
            buffer_normalized_response_bytes(
                session,
                client,
                &mut pending,
                unit,
                &mut framing,
                unit_limit,
            )
            .await?;
        },
        BodyLength::None => {
            flush_normalized_response_bytes(session, client, pending, &mut framing).await?;
            Ok(Vec::new())
        }
    }
}

struct ResponseOutputState<'a> {
    committed: &'a mut bool,
    chunked: bool,
    commit_head: &'a [u8],
    generation_guard: Option<&'a PolicyGenerationGuard>,
    policy_name: &'a str,
    target: &'a HttpRequestTarget,
    status_code: u16,
    response_correlation: Option<&'a RequestCorrelation>,
}

#[derive(Debug)]
struct ResponseMiddlewareStop {
    failure: openshell_supervisor_middleware::HttpResponseMiddlewareFailure,
}

impl ResponseMiddlewareStop {
    fn new(failure: openshell_supervisor_middleware::HttpResponseMiddlewareFailure) -> Self {
        Self { failure }
    }
}

impl fmt::Display for ResponseMiddlewareStop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "HTTP response middleware stopped delivery: {}",
            self.failure
        )
    }
}

impl std::error::Error for ResponseMiddlewareStop {}

impl miette::Diagnostic for ResponseMiddlewareStop {}

async fn expire_whole_body_deadline<C: AsyncWrite + Unpin>(
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    framing: &mut ResponseOutputState<'_>,
) -> Result<()> {
    let output = session.expire_whole_body_deadline().await;
    let diagnostics = session.take_diagnostics();
    observe_response_diagnostics(framing.response_correlation, &diagnostics);
    if let Err(failure) = &output {
        observe_response_admission_exhaustion(
            framing.response_correlation,
            failure.admission_exhausted(),
        );
    }
    if let Some(guard) = framing.generation_guard {
        ensure_relay_generation_current(guard)?;
    }
    emit_http_response_diagnostics(
        framing.policy_name,
        framing.target,
        framing.status_code,
        &diagnostics,
        framing.response_correlation,
    );
    let output = output.map_err(ResponseMiddlewareStop::new)?;
    deliver_response_units(client, output, framing, session.requires_whole_body()).await
}

// Unit size is a maximum. Coalesce available payload without waiting for
// the rest of a transfer chunk, and finish expiry outside read timeouts.
async fn read_response_payload_with_deadline<R, C>(
    reader: &mut BufferedResponseReader<'_, R>,
    limit: usize,
    has_pending: bool,
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    framing: &mut ResponseOutputState<'_>,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut payload = Vec::new();
    let mut coalesce_deadline =
        has_pending.then(|| tokio::time::Instant::now() + RESPONSE_UNIT_COALESCE_TIMEOUT);
    loop {
        let whole_deadline = session.whole_body_deadline();
        let deadline = match (coalesce_deadline, whole_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let read = guarded_relay_read(
            framing.generation_guard,
            reader.read_some(limit - payload.len()),
        );
        let result = if let Some(deadline) = deadline {
            if let Ok(result) = tokio::time::timeout_at(deadline, read).await {
                result
            } else {
                if whole_deadline.is_some_and(|d| d <= tokio::time::Instant::now()) {
                    expire_whole_body_deadline(session, client, framing).await?;
                }
                if coalesce_deadline.is_some_and(|d| d <= tokio::time::Instant::now()) {
                    return Ok(payload);
                }
                continue;
            }
        } else {
            read.await
        };
        let data = result?.ok_or(RelayError::Truncated(
            "HTTP response body ended unexpectedly",
        ))?;
        payload.extend_from_slice(&data);
        if payload.len() == limit {
            return Ok(payload);
        }
        coalesce_deadline
            .get_or_insert_with(|| tokio::time::Instant::now() + RESPONSE_UNIT_COALESCE_TIMEOUT);
    }
}

async fn read_exact_response_with_deadline<R, C>(
    reader: &mut BufferedResponseReader<'_, R>,
    length: usize,
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    framing: &mut ResponseOutputState<'_>,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    loop {
        let Some(deadline) = session.whole_body_deadline() else {
            return guarded_relay_read(framing.generation_guard, reader.read_exact_vec(length))
                .await;
        };
        match tokio::time::timeout_at(
            deadline,
            guarded_relay_read(framing.generation_guard, reader.read_exact_vec(length)),
        )
        .await
        {
            Ok(result) => return result,
            Err(_) => expire_whole_body_deadline(session, client, framing).await?,
        }
    }
}

async fn read_response_line_with_deadline<R, C>(
    reader: &mut BufferedResponseReader<'_, R>,
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    framing: &mut ResponseOutputState<'_>,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    loop {
        let Some(deadline) = session.whole_body_deadline() else {
            return guarded_relay_read(framing.generation_guard, reader.read_line()).await;
        };
        match tokio::time::timeout_at(
            deadline,
            guarded_relay_read(framing.generation_guard, reader.read_line()),
        )
        .await
        {
            Ok(result) => return result,
            Err(_) => expire_whole_body_deadline(session, client, framing).await?,
        }
    }
}

async fn buffer_normalized_response_bytes<C: AsyncWrite + Unpin>(
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    pending: &mut Vec<u8>,
    data: Vec<u8>,
    framing: &mut ResponseOutputState<'_>,
    unit_limit: usize,
) -> Result<()> {
    pending.extend_from_slice(&data);
    while pending.len() >= unit_limit {
        let remainder = pending.split_off(unit_limit);
        let unit = std::mem::replace(pending, remainder);
        process_response_unit(session, client, unit, framing).await?;
    }
    Ok(())
}

async fn flush_normalized_response_bytes<C: AsyncWrite + Unpin>(
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    pending: Vec<u8>,
    framing: &mut ResponseOutputState<'_>,
) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    process_response_unit(session, client, pending, framing).await
}

async fn process_response_unit<C: AsyncWrite + Unpin>(
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    unit: Vec<u8>,
    framing: &mut ResponseOutputState<'_>,
) -> Result<()> {
    let output = session.push_body(unit).await;
    let diagnostics = session.take_diagnostics();
    observe_response_diagnostics(framing.response_correlation, &diagnostics);
    if let Err(failure) = &output {
        observe_response_admission_exhaustion(
            framing.response_correlation,
            failure.admission_exhausted(),
        );
    }
    if let Some(guard) = framing.generation_guard {
        ensure_relay_generation_current(guard)?;
    }
    emit_http_response_diagnostics(
        framing.policy_name,
        framing.target,
        framing.status_code,
        &diagnostics,
        framing.response_correlation,
    );
    let output = output.map_err(ResponseMiddlewareStop::new)?;
    deliver_response_units(client, output, framing, session.requires_whole_body()).await
}

async fn deliver_response_units<C: AsyncWrite + Unpin>(
    client: &mut C,
    output: Vec<Vec<u8>>,
    framing: &mut ResponseOutputState<'_>,
    whole_body_pending: bool,
) -> Result<()> {
    if !*framing.committed && !output.is_empty() {
        if whole_body_pending {
            return Err(miette!(
                "whole-body response middleware released output before finalization"
            ));
        }
        select_allowed_response(framing.response_correlation, framing.status_code);
        write_correlated_response_commit(
            client,
            framing.commit_head,
            framing.response_correlation,
            framing.committed,
        )
        .await?;
        client.flush().await.map_err(RelayError::flush)?;
    }
    if *framing.committed {
        for unit in output {
            if framing.chunked {
                write_downstream_response_chunk(client, &unit).await?;
            } else {
                client.write_all(&unit).await.map_err(RelayError::write)?;
            }
        }
        client.flush().await.map_err(RelayError::flush)?;
    }
    Ok(())
}

async fn write_downstream_response_chunk<C: AsyncWrite + Unpin>(
    client: &mut C,
    payload: &[u8],
) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }
    client
        .write_all(format!("{:X}\r\n", payload.len()).as_bytes())
        .await
        .map_err(RelayError::write)?;
    client.write_all(payload).await.map_err(RelayError::write)?;
    client.write_all(b"\r\n").await.map_err(RelayError::write)?;
    Ok(())
}

async fn read_response_trailers<R, C>(
    reader: &mut BufferedResponseReader<'_, R>,
    session: &mut openshell_supervisor_middleware::HttpResponseSession,
    client: &mut C,
    framing: &mut ResponseOutputState<'_>,
    connection_nominated_headers: &[String],
) -> Result<Vec<HttpHeader>>
where
    R: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut trailers = Vec::new();
    loop {
        let line = read_response_line_with_deadline(reader, session, client, framing).await?;
        validate_chunk_trailer_line(&line)
            .map_err(|error| RelayError::protocol("invalid_chunk_trailer", error.to_string()))?;
        if line.is_empty() {
            return Ok(trailers);
        }
        let line = std::str::from_utf8(&line).map_err(|_| {
            RelayError::protocol(
                "invalid_chunk_trailer",
                "HTTP response trailer contains invalid UTF-8",
            )
        })?;
        let (name, value) = line.split_once(':').ok_or_else(|| {
            RelayError::protocol(
                "invalid_chunk_trailer",
                "HTTP response trailer is malformed",
            )
        })?;
        validate_http_field_name(name)
            .map_err(|error| RelayError::protocol("invalid_chunk_trailer", error.to_string()))?;
        validate_http_field_value(value.trim())
            .map_err(|error| RelayError::protocol("invalid_chunk_trailer", error.to_string()))?;
        let name = name.to_ascii_lowercase();
        if is_protected_response_field(&name) || connection_nominated_headers.contains(&name) {
            return Err(RelayError::protocol(
                "invalid_chunk_trailer",
                "HTTP response trailer uses a protected field name",
            )
            .into());
        }
        trailers.push(HttpHeader {
            name,
            value: value.trim().to_string(),
        });
        if trailers.len() > openshell_supervisor_middleware::MAX_MIDDLEWARE_HEADERS {
            return Err(RelayError::protocol(
                "invalid_chunk_trailer",
                "HTTP response trailer count exceeds limit",
            )
            .into());
        }
    }
}

async fn write_response_trailers<C: AsyncWrite + Unpin>(
    client: &mut C,
    trailers: &[HttpHeader],
) -> Result<()> {
    client
        .write_all(b"0\r\n")
        .await
        .map_err(RelayError::write)?;
    for trailer in trailers {
        client
            .write_all(format!("{}: {}\r\n", trailer.name, trailer.value).as_bytes())
            .await
            .map_err(RelayError::write)?;
    }
    client.write_all(b"\r\n").await.map_err(RelayError::write)?;
    Ok(())
}

async fn send_response_middleware_denial<C: AsyncWrite + Unpin>(
    client: &mut C,
    request_method: &str,
    policy_name: &str,
    target: &HttpRequestTarget,
    denial: &openshell_supervisor_middleware::MiddlewareDenial,
    stage: &'static str,
    correlation: Option<&RequestCorrelation>,
) -> Result<()> {
    let mut body = serde_json::Map::new();
    body.insert("error".into(), serde_json::json!("middleware_denied"));
    body.insert(
        "detail".into(),
        serde_json::json!("Response blocked by configured middleware"),
    );
    body.insert("policy".into(), serde_json::json!(policy_name));
    body.insert("middleware".into(), serde_json::json!(denial.config_name));
    if let Some(reason_code) = &denial.reason_code {
        body.insert("reason_code".into(), serde_json::json!(reason_code));
    }
    body.insert(
        "layer".into(),
        serde_json::json!("http_response_pre_return"),
    );
    body.insert("method".into(), serde_json::json!(target.method));
    body.insert("path".into(), serde_json::json!(target.path));
    body.insert("host".into(), serde_json::json!(target.host));
    body.insert("port".into(), serde_json::json!(target.port));
    let body = serde_json::to_vec(&serde_json::Value::Object(body)).into_diagnostic()?;
    let head = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-OpenShell-Policy: {policy_name}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    record_denied_response(correlation, stage);
    let head = final_response_head(head.as_bytes(), correlation);
    write_correlated_response_bytes(client, &head, correlation, true).await?;
    if !request_method.eq_ignore_ascii_case("HEAD") {
        client.write_all(&body).await.map_err(RelayError::write)?;
    }
    client.flush().await.map_err(RelayError::flush)?;
    Ok(())
}

async fn send_response_delivery_failure<C: AsyncWrite + Unpin>(
    client: &mut C,
    request_method: &str,
    policy_name: &str,
    target: &HttpRequestTarget,
    failure: (ResponseSelectionCause, &'static str, &'static str),
    middleware_selected: bool,
    correlation: Option<&RequestCorrelation>,
) -> Result<()> {
    let (cause, http_outcome, stage) = failure;
    let body = serde_json::to_vec(&serde_json::json!({
        "error": "response_delivery_failed",
        "detail": "The upstream request may have completed, but OpenShell could not deliver its response. Retrying may repeat upstream side effects.",
        "policy": policy_name,
        "layer": "http_response_pre_return",
        "method": target.method,
        "path": target.path,
        "host": target.host,
        "port": target.port,
    }))
    .into_diagnostic()?;
    let head = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-OpenShell-Policy: {policy_name}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    select_failure_response(correlation, cause, http_outcome, stage);
    let head = final_response_head(head.as_bytes(), correlation);
    write_correlated_response_bytes(client, &head, correlation, middleware_selected).await?;
    if !request_method.eq_ignore_ascii_case("HEAD") {
        client.write_all(&body).await.map_err(RelayError::write)?;
    }
    client.flush().await.map_err(RelayError::flush)?;
    Ok(())
}

/// Parse the HTTP status code from a response status line.
///
/// Expects the first line to look like `HTTP/1.1 200 OK`.
pub(super) fn parse_status_code(headers: &str) -> Option<u16> {
    let status_line = headers.lines().next()?;
    let code_str = status_line.split_whitespace().nth(1)?;
    code_str.parse().ok()
}

/// Parse a syntactically valid HTTP/1.x response status for endpoint reporting.
pub(super) fn parse_observed_http_status_code(headers: &str) -> Option<u16> {
    let status_line = headers.lines().next()?;
    let mut fields = status_line.split_whitespace();
    match fields.next()? {
        "HTTP/1.0" | "HTTP/1.1" => {}
        _ => return None,
    }
    let code = fields.next()?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    code.parse()
        .ok()
        .filter(|status| (100..=999).contains(status))
}

/// Check if the response headers contain `Connection: close`.
pub(super) fn parse_connection_close(headers: &str) -> bool {
    for line in headers.lines().skip(1) {
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("connection:") {
            let val = lower.split_once(':').map_or("", |(_, v)| v.trim());
            return val.contains("close");
        }
    }
    false
}

/// Check if an HTTP/1.0 response opts into a persistent connection.
pub(super) fn parse_connection_keep_alive(headers: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        let lower = line.to_ascii_lowercase();
        lower
            .strip_prefix("connection:")
            .is_some_and(|value| value.split(',').any(|token| token.trim() == "keep-alive"))
    })
}

pub(super) fn response_is_http_10(headers: &str) -> bool {
    headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        == Some("HTTP/1.0")
}

pub(super) fn response_is_event_stream(headers: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        let lower = line.to_ascii_lowercase();
        let Some(value) = lower.strip_prefix("content-type:") else {
            return false;
        };
        value
            .split(';')
            .next()
            .is_some_and(|mime| mime.trim() == "text/event-stream")
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT, HttpResponseMiddlewareRelay,
        RelayResponseOptions, ResponseFraming, WebSocketResponseValidation,
        http_response_diagnostic_truncation_event, parse_connection_keep_alive,
        parse_response_head_for_middleware, relay_response, response_is_http_10,
        response_middleware_failure_denial, response_middleware_observation,
        serialize_response_head, validate_http_response_header_block,
    };
    use crate::l7::correlation::MiddlewareObservation;
    use crate::l7::provider::{BodyLength, L7Request, RelayOutcome};
    use crate::l7::relay::L7EvalContext;
    use openshell_core::proto::{
        Decision, ExistingHeaderAction, HeaderMutation, HttpHeader, HttpRequestResult,
        HttpRequestTarget, HttpResponseBlockDelivery, HttpResponseBodyMode, HttpResponseBodyResult,
        HttpResponseBodySkipRemaining, HttpResponseBodyTransform, HttpResponseEvent,
        HttpResponseEventResult, HttpResponsePreflightInspect, HttpResponsePreflightResult,
        HttpResponseTrailersResult, MiddlewareBinding, MiddlewareManifest, RequestContext,
        SupervisorMiddlewareOperation, SupervisorMiddlewarePhase, WriteHeader, header_mutation,
        http_response_body_result, http_response_body_skip_remaining, http_response_body_transform,
        http_response_body_unit, http_response_event, http_response_event_result,
        http_response_preflight_result,
    };
    use std::collections::{HashMap, VecDeque};
    use std::pin::Pin;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    struct StreamingResponseMiddleware {
        body_mode: i32,
        body_delay: Option<std::time::Duration>,
        mutate_headers: bool,
    }

    struct BlockingResponseMiddleware;

    enum BodyTestAction {
        Block,
        ReloadAndSkipTransform(Arc<crate::opa::OpaEngine>),
    }

    struct BodyResponseMiddleware {
        action: BodyTestAction,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ReloadThenErrorPoint {
        Describe,
        Preflight,
        Finish,
    }

    struct ReloadThenErrorResponseMiddleware {
        point: ReloadThenErrorPoint,
        body_mode: i32,
        engine: Arc<crate::opa::OpaEngine>,
    }

    struct PartialThenErrorWriter {
        remaining_success: usize,
    }

    struct ReloadOnBodyReader {
        head: Vec<u8>,
        head_position: usize,
        body: Vec<u8>,
        body_position: usize,
        reloaded: bool,
        engine: Arc<crate::opa::OpaEngine>,
    }

    struct SegmentsThenPendingReader {
        segments: VecDeque<Vec<u8>>,
        segment_position: usize,
        pending_polled: Arc<AtomicBool>,
    }

    impl SegmentsThenPendingReader {
        fn new(
            segments: impl IntoIterator<Item = Vec<u8>>,
            pending_polled: Arc<AtomicBool>,
        ) -> Self {
            Self {
                segments: segments.into_iter().collect(),
                segment_position: 0,
                pending_polled,
            }
        }
    }

    impl AsyncRead for SegmentsThenPendingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            while let Some(segment) = self.segments.front() {
                if self.segment_position == segment.len() {
                    self.segments.pop_front();
                    self.segment_position = 0;
                    continue;
                }
                let remaining = &segment[self.segment_position..];
                let count = remaining.len().min(buffer.remaining());
                buffer.put_slice(&remaining[..count]);
                self.segment_position += count;
                return Poll::Ready(Ok(()));
            }
            self.pending_polled.store(true, Ordering::Release);
            Poll::Pending
        }
    }

    async fn wait_for_pending_read(pending_polled: &AtomicBool) {
        tokio::time::timeout(std::time::Duration::from_millis(100), async {
            while !pending_polled.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("response relay reached the pending read");
    }

    impl ReloadOnBodyReader {
        fn new(head: &[u8], body: &[u8], engine: Arc<crate::opa::OpaEngine>) -> Self {
            Self {
                head: head.to_vec(),
                head_position: 0,
                body: body.to_vec(),
                body_position: 0,
                reloaded: false,
                engine,
            }
        }
    }

    impl AsyncRead for ReloadOnBodyReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.head_position < self.head.len() {
                let remaining = &self.head[self.head_position..];
                let count = remaining.len().min(buffer.remaining());
                buffer.put_slice(&remaining[..count]);
                self.head_position += count;
                return Poll::Ready(Ok(()));
            }
            if !self.reloaded {
                self.engine
                    .reload(
                        include_str!("../../../data/sandbox-policy.rego"),
                        "network_policies: {}\n",
                    )
                    .expect("reload test policy");
                self.reloaded = true;
            }
            if self.body_position < self.body.len() {
                let remaining = &self.body[self.body_position..];
                let count = remaining.len().min(buffer.remaining());
                buffer.put_slice(&remaining[..count]);
                self.body_position += count;
            }
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct ControlledResponseWriter {
        bytes: Vec<u8>,
        zero_first_write: bool,
        shutdown_error: bool,
    }

    impl AsyncWrite for ControlledResponseWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.zero_first_write {
                self.zero_first_write = false;
                return Poll::Ready(Ok(0));
            }
            self.bytes.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.shutdown_error {
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "test shutdown failure",
                )))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for PartialThenErrorWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if self.remaining_success == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "test downstream disconnect",
                )));
            }
            let written = bytes.len().min(self.remaining_success);
            self.remaining_success -= written;
            Poll::Ready(Ok(written))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tonic::async_trait]
    impl openshell_supervisor_middleware::InProcessMiddleware for BlockingResponseMiddleware {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/blocking-response".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                    phase: SupervisorMiddlewarePhase::PreReturn as i32,
                    max_payload_bytes: 4096,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
                extension: Some(openshell_core::extension_protocol::extension_metadata(
                    openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                    "openshell/test-blocking-response",
                    "test",
                    [],
                )),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: openshell_supervisor_middleware::HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            Ok(HttpRequestResult {
                decision: Decision::Allow as i32,
                ..Default::default()
            })
        }

        async fn open_http_response_pre_return(
            &self,
            mut requests: mpsc::Receiver<HttpResponseEvent>,
        ) -> Result<openshell_supervisor_middleware::HttpResponseResultStream, tonic::Status>
        {
            let first = requests
                .recv()
                .await
                .ok_or_else(|| tonic::Status::invalid_argument("missing response preflight"))?;
            if !matches!(first.event, Some(http_response_event::Event::Preflight(_))) {
                return Err(tonic::Status::invalid_argument(
                    "expected response preflight",
                ));
            }
            let result = HttpResponseEventResult {
                result: Some(http_response_event_result::Result::PreflightResult(
                    HttpResponsePreflightResult {
                        action: Some(http_response_preflight_result::Action::BlockDelivery(
                            HttpResponseBlockDelivery {},
                        )),
                        reason_code: "test_block".into(),
                        ..Default::default()
                    },
                )),
            };
            Ok(Box::pin(futures::stream::iter([Ok(result)])))
        }
    }

    #[tonic::async_trait]
    impl openshell_supervisor_middleware::InProcessMiddleware for StreamingResponseMiddleware {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/streaming-response".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                    phase: SupervisorMiddlewarePhase::PreReturn as i32,
                    max_payload_bytes: 4096,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
                extension: Some(openshell_core::extension_protocol::extension_metadata(
                    openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                    "openshell/test-streaming-response",
                    "test",
                    [],
                )),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: openshell_supervisor_middleware::HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            Ok(HttpRequestResult {
                decision: Decision::Allow as i32,
                ..Default::default()
            })
        }

        async fn open_http_response_pre_return(
            &self,
            mut requests: mpsc::Receiver<HttpResponseEvent>,
        ) -> Result<openshell_supervisor_middleware::HttpResponseResultStream, tonic::Status>
        {
            let (sender, receiver) = mpsc::channel(4);
            let body_mode = self.body_mode;
            let body_delay = self.body_delay;
            let mutate_headers = self.mutate_headers;
            tokio::spawn(async move {
                while let Some(event) = requests.recv().await {
                    let Some(event) = event.event else {
                        break;
                    };
                    let result = match event {
                        http_response_event::Event::Preflight(_) => HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::PreflightResult(
                                HttpResponsePreflightResult {
                                    action: Some(http_response_preflight_result::Action::Inspect(
                                        HttpResponsePreflightInspect {
                                            body_mode,
                                            header_mutations: mutate_headers
                                                .then(|| HeaderMutation {
                                                    operation: Some(
                                                        header_mutation::Operation::Write(
                                                            WriteHeader {
                                                                name: "x-inspected".into(),
                                                                value: "true".into(),
                                                                on_existing:
                                                                    ExistingHeaderAction::Overwrite
                                                                        as i32,
                                                            },
                                                        ),
                                                    ),
                                                })
                                                .into_iter()
                                                .collect(),
                                        },
                                    )),
                                    ..Default::default()
                                },
                            )),
                        },
                        http_response_event::Event::Body(body) => {
                            if let Some(delay) = body_delay {
                                tokio::time::sleep(delay).await;
                            }
                            let Some(http_response_body_unit::Payload::Data(data)) = body.payload
                            else {
                                break;
                            };
                            HttpResponseEventResult {
                                result: Some(http_response_event_result::Result::BodyResult(
                                    HttpResponseBodyResult {
                                        sequence: body.sequence,
                                        action: Some(http_response_body_result::Action::Transform(
                                            HttpResponseBodyTransform {
                                                replacement: Some(
                                                    http_response_body_transform::Replacement::Data(
                                                        data,
                                                    ),
                                                ),
                                            },
                                        )),
                                        ..Default::default()
                                    },
                                )),
                            }
                        }
                        http_response_event::Event::Trailers(_) => HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::TrailersResult(
                                HttpResponseTrailersResult::default(),
                            )),
                        },
                        http_response_event::Event::SessionEnd(_) => break,
                    };
                    if sender.send(Ok(result)).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    #[tonic::async_trait]
    impl openshell_supervisor_middleware::InProcessMiddleware for BodyResponseMiddleware {
        async fn describe(&self) -> MiddlewareManifest {
            MiddlewareManifest {
                name: "test/body-response".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                    phase: SupervisorMiddlewarePhase::PreReturn as i32,
                    max_payload_bytes: 4096,
                    request_timeout: None,
                }],
                expected_audience: String::new(),
                extension: Some(openshell_core::extension_protocol::extension_metadata(
                    openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                    "openshell/test-body-response",
                    "test",
                    [],
                )),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: openshell_supervisor_middleware::HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            Ok(HttpRequestResult {
                decision: Decision::Allow as i32,
                ..Default::default()
            })
        }

        async fn open_http_response_pre_return(
            &self,
            mut requests: mpsc::Receiver<HttpResponseEvent>,
        ) -> Result<openshell_supervisor_middleware::HttpResponseResultStream, tonic::Status>
        {
            let (sender, receiver) = mpsc::channel(4);
            let action = match &self.action {
                BodyTestAction::Block => BodyTestAction::Block,
                BodyTestAction::ReloadAndSkipTransform(engine) => {
                    BodyTestAction::ReloadAndSkipTransform(Arc::clone(engine))
                }
            };
            tokio::spawn(async move {
                while let Some(event) = requests.recv().await {
                    let Some(event) = event.event else {
                        break;
                    };
                    let result = match event {
                        http_response_event::Event::Preflight(_) => HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::PreflightResult(
                                HttpResponsePreflightResult {
                                    action: Some(http_response_preflight_result::Action::Inspect(
                                        HttpResponsePreflightInspect {
                                            body_mode: HttpResponseBodyMode::StreamBytes as i32,
                                            header_mutations: Vec::new(),
                                        },
                                    )),
                                    ..Default::default()
                                },
                            )),
                        },
                        http_response_event::Event::Body(body) => {
                            let Some(http_response_body_unit::Payload::Data(data)) = body.payload
                            else {
                                break;
                            };
                            let action = match &action {
                                BodyTestAction::Block => {
                                    http_response_body_result::Action::BlockDelivery(
                                        HttpResponseBlockDelivery {},
                                    )
                                }
                                BodyTestAction::ReloadAndSkipTransform(engine) => {
                                    engine
                                        .reload(
                                            include_str!("../../../data/sandbox-policy.rego"),
                                            "network_policies: {}\n",
                                        )
                                        .expect("reload test policy");
                                    http_response_body_result::Action::SkipRemaining(
                                        HttpResponseBodySkipRemaining {
                                            current: Some(
                                                http_response_body_skip_remaining::Current::Transform(
                                                    HttpResponseBodyTransform {
                                                        replacement: Some(
                                                            http_response_body_transform::Replacement::Data(data),
                                                        ),
                                                    },
                                                ),
                                            ),
                                        },
                                    )
                                }
                            };
                            HttpResponseEventResult {
                                result: Some(http_response_event_result::Result::BodyResult(
                                    HttpResponseBodyResult {
                                        sequence: body.sequence,
                                        action: Some(action),
                                        reason_code: "test_body_action".into(),
                                        ..Default::default()
                                    },
                                )),
                            }
                        }
                        http_response_event::Event::Trailers(_) => HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::TrailersResult(
                                HttpResponseTrailersResult::default(),
                            )),
                        },
                        http_response_event::Event::SessionEnd(_) => break,
                    };
                    if sender.send(Ok(result)).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    impl ReloadThenErrorResponseMiddleware {
        fn reload_policy(&self) {
            self.engine
                .reload(
                    include_str!("../../../data/sandbox-policy.rego"),
                    "network_policies: {}\n",
                )
                .expect("reload test policy");
        }
    }

    #[tonic::async_trait]
    impl openshell_supervisor_middleware::InProcessMiddleware for ReloadThenErrorResponseMiddleware {
        async fn describe(&self) -> MiddlewareManifest {
            if self.point == ReloadThenErrorPoint::Describe {
                self.reload_policy();
            }
            MiddlewareManifest {
                name: "test/reload-then-error-response".into(),
                service_version: "test".into(),
                bindings: vec![MiddlewareBinding {
                    operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                    phase: SupervisorMiddlewarePhase::PreReturn as i32,
                    max_payload_bytes: if self.point == ReloadThenErrorPoint::Describe {
                        0
                    } else {
                        4096
                    },
                    request_timeout: None,
                }],
                expected_audience: String::new(),
                extension: Some(openshell_core::extension_protocol::extension_metadata(
                    openshell_core::extension_protocol::ExtensionFamily::SupervisorMiddleware,
                    "openshell/test-reload-then-error-response",
                    "test",
                    [],
                )),
            }
        }

        async fn validate_config(
            &self,
            _middleware_name: &str,
            _config: &prost_types::Struct,
        ) -> miette::Result<()> {
            Ok(())
        }

        async fn evaluate_http_request(
            &self,
            _request: openshell_supervisor_middleware::HttpRequestView<'_>,
        ) -> miette::Result<HttpRequestResult> {
            Ok(HttpRequestResult {
                decision: Decision::Allow as i32,
                ..Default::default()
            })
        }

        async fn open_http_response_pre_return(
            &self,
            mut requests: mpsc::Receiver<HttpResponseEvent>,
        ) -> Result<openshell_supervisor_middleware::HttpResponseResultStream, tonic::Status>
        {
            let first = requests
                .recv()
                .await
                .ok_or_else(|| tonic::Status::invalid_argument("missing response preflight"))?;
            if !matches!(first.event, Some(http_response_event::Event::Preflight(_))) {
                return Err(tonic::Status::invalid_argument(
                    "expected response preflight",
                ));
            }
            if self.point == ReloadThenErrorPoint::Preflight {
                self.reload_policy();
                return Err(tonic::Status::internal(
                    "test preflight failure after policy reload",
                ));
            }

            let (sender, receiver) = mpsc::channel(4);
            sender
                .send(Ok(HttpResponseEventResult {
                    result: Some(http_response_event_result::Result::PreflightResult(
                        HttpResponsePreflightResult {
                            action: Some(http_response_preflight_result::Action::Inspect(
                                HttpResponsePreflightInspect {
                                    body_mode: self.body_mode,
                                    header_mutations: Vec::new(),
                                },
                            )),
                            ..Default::default()
                        },
                    )),
                }))
                .await
                .map_err(|_| tonic::Status::unavailable("test response stream closed"))?;

            let point = self.point;
            let engine = Arc::clone(&self.engine);
            tokio::spawn(async move {
                while let Some(event) = requests.recv().await {
                    let Some(event) = event.event else {
                        break;
                    };
                    let result = match event {
                        http_response_event::Event::Body(body)
                            if point == ReloadThenErrorPoint::Finish && body.end_of_stream =>
                        {
                            engine
                                .reload(
                                    include_str!("../../../data/sandbox-policy.rego"),
                                    "network_policies: {}\n",
                                )
                                .expect("reload test policy");
                            let _ = sender
                                .send(Err(tonic::Status::internal(
                                    "test finish failure after policy reload",
                                )))
                                .await;
                            break;
                        }
                        http_response_event::Event::Body(body) => {
                            let Some(http_response_body_unit::Payload::Data(data)) = body.payload
                            else {
                                break;
                            };
                            HttpResponseEventResult {
                                result: Some(http_response_event_result::Result::BodyResult(
                                    HttpResponseBodyResult {
                                        sequence: body.sequence,
                                        action: Some(http_response_body_result::Action::Transform(
                                            HttpResponseBodyTransform {
                                                replacement: Some(
                                                    http_response_body_transform::Replacement::Data(
                                                        data,
                                                    ),
                                                ),
                                            },
                                        )),
                                        ..Default::default()
                                    },
                                )),
                            }
                        }
                        http_response_event::Event::Trailers(_) => HttpResponseEventResult {
                            result: Some(http_response_event_result::Result::TrailersResult(
                                HttpResponseTrailersResult::default(),
                            )),
                        },
                        http_response_event::Event::Preflight(_)
                        | http_response_event::Event::SessionEnd(_) => break,
                    };
                    if sender.send(Ok(result)).await.is_err() {
                        break;
                    }
                }
            });
            Ok(Box::pin(ReceiverStream::new(receiver)))
        }
    }

    fn test_correlation_for_method(
        request_id: &str,
        method: &str,
    ) -> crate::l7::correlation::RequestCorrelation {
        let request = L7Request {
            action: method.into(),
            target: "/data".into(),
            query_params: HashMap::new(),
            raw_header: b"GET /data HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
            body_length: BodyLength::None,
        };
        crate::l7::correlation::RequestCorrelation::with_request_id(
            &request,
            &L7EvalContext {
                host: "example.test".into(),
                port: 443,
                ..Default::default()
            },
            request_id.into(),
        )
    }

    fn test_correlation(request_id: &str) -> crate::l7::correlation::RequestCorrelation {
        test_correlation_for_method(request_id, "GET")
    }

    fn test_response_middleware<'a>(
        runner: &'a openshell_supervisor_middleware::ChainRunner,
        chain: &'a [openshell_supervisor_middleware::ChainEntry],
        request_id: &str,
    ) -> HttpResponseMiddlewareRelay<'a> {
        HttpResponseMiddlewareRelay {
            chain,
            runner,
            request_context: RequestContext {
                request_id: request_id.into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "GET".into(),
                path: "/data".into(),
                query: String::new(),
            },
            policy_name: "test-policy",
            generation_guard: None,
            whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
        }
    }

    fn response_terminal_event_for(
        capture: &openshell_ocsf::test_support::OcsfCapture,
        request_id: &str,
    ) -> serde_json::Value {
        let events = capture
            .json_events()
            .into_iter()
            .filter(|event| {
                event["firewall_rule"]["type"] == "response-correlation"
                    && event["metadata"]["correlation_uid"] == request_id
            })
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1, "one terminal delivery event");
        events.into_iter().next().expect("terminal event")
    }

    fn response_middleware_event_for(
        capture: &openshell_ocsf::test_support::OcsfCapture,
        request_id: &str,
    ) -> serde_json::Value {
        let events = capture
            .json_events()
            .into_iter()
            .filter(|event| {
                event["firewall_rule"]["type"] == "middleware-correlation"
                    && event["metadata"]["correlation_uid"] == request_id
                    && event["unmapped"]["middleware_phase"] == "response"
            })
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1, "one aggregate response middleware event");
        events.into_iter().next().expect("middleware event")
    }

    fn request_id_header_count(response: &[u8]) -> usize {
        String::from_utf8_lossy(response)
            .lines()
            .filter(|line| {
                line.split_once(':').is_some_and(|(name, _)| {
                    name.eq_ignore_ascii_case(
                        openshell_core::token_grant_failure::REQUEST_ID_HEADER,
                    )
                })
            })
            .count()
    }

    #[tokio::test]
    async fn allowed_final_response_carries_platform_receipt() {
        let correlation = test_correlation("receipt-1");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
        let mut client = Vec::new();

        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");

        assert!(matches!(outcome, RelayOutcome::Reusable));
        assert_eq!(request_id_header_count(&client), 1);
        assert!(String::from_utf8_lossy(&client).contains("x-openshell-request-id: receipt-1\r\n"));
    }

    #[tokio::test]
    async fn cancellation_before_final_head_emits_one_incomplete_terminal_event() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation("response-cancel-before-head");
        let (mut upstream, _upstream_peer) = tokio::io::duplex(64);
        let mut client = Vec::new();

        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                None,
            ),
        )
        .await
        .expect_err("relay remains pending before final head");
        drop(correlation);

        let event = response_terminal_event_for(&capture, "response-cancel-before-head");
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert_eq!(event["unmapped"]["response_selection_cause"], "cancelled");
        assert_eq!(event["unmapped"]["delivery_started"], false);
        assert_eq!(event["unmapped"]["partial_delivery"], false);
    }

    #[tokio::test]
    async fn unsolicited_switching_protocols_is_a_protocol_failure() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation("response-unsolicited-101");
        let mut upstream =
            &b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n"[..];
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                client_requested_upgrade: false,
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("unsolicited 101 must fail");
        assert!(client.is_empty());
        drop(correlation);

        let event = response_terminal_event_for(&capture, "response-unsolicited-101");
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "upstream_protocol_error"
        );
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert!(event.get("http_response").is_none());
        assert_eq!(event["unmapped"]["delivery_started"], false);
    }

    #[tokio::test]
    async fn invalid_websocket_handshake_is_a_correlated_upstream_protocol_failure() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let request_id = "response-invalid-websocket-accept";
        let correlation = test_correlation(request_id);
        let validation = WebSocketResponseValidation {
            expected_accept: "expected-accept".into(),
            expected_extension: None,
            offered_subprotocols: Vec::new(),
        };
        let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: invalid\r\n\r\n"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                client_requested_upgrade: true,
                websocket: Some(validation),
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("invalid upstream WebSocket handshake must fail");
        assert!(
            error
                .downcast_ref::<super::RelayError>()
                .is_some_and(|error| matches!(
                    error,
                    super::RelayError::Protocol {
                        code: "invalid_websocket_handshake",
                        ..
                    }
                )),
            "{error}"
        );
        assert!(client.is_empty(), "invalid 101 response reached the client");
        drop(correlation);

        let event = response_terminal_event_for(&capture, request_id);
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "upstream_protocol_error"
        );
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert_eq!(event["unmapped"]["upstream_http_status_code"], 101);
        assert!(event.get("http_response").is_none());
        assert!(
            event["unmapped"]
                .get("effective_http_status_code")
                .is_none()
        );
        assert_eq!(event["unmapped"]["delivery_started"], false);
        assert_eq!(event["unmapped"]["partial_delivery"], false);
    }

    #[tokio::test]
    async fn whole_body_cancellation_before_selection_has_no_effective_status() {
        use tokio::io::AsyncWriteExt as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation("response-whole-body-cancel");
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::WholeBodyBytes as i32,
                body_delay: None,
                mutate_headers: true,
            },
        ));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/streaming-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = test_response_middleware(&runner, &chain, "response-whole-body-cancel");
        let (mut upstream, mut upstream_peer) = tokio::io::duplex(256);
        upstream_peer
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nbody")
            .await
            .expect("seed partial response");
        let mut client = Vec::new();

        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                Some(middleware),
            ),
        )
        .await
        .expect_err("whole-body response remains pending");
        assert!(client.is_empty());
        drop(correlation);

        let event = response_terminal_event_for(&capture, "response-whole-body-cancel");
        assert_eq!(event["unmapped"]["response_selection_cause"], "cancelled");
        assert_eq!(event["unmapped"]["upstream_http_status_code"], 200);
        assert!(event.get("http_response").is_none());
        assert!(
            event["unmapped"]
                .get("effective_http_status_code")
                .is_none()
        );
        assert_eq!(event["unmapped"]["delivery_started"], false);
    }

    #[tokio::test]
    async fn whole_body_fail_open_timeout_selects_upstream_response_on_commit() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let request_id = "response-whole-body-fail-open-timeout";
        let correlation = test_correlation(request_id);
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::WholeBodyBytes as i32,
                body_delay: Some(std::time::Duration::from_millis(75)),
                mutate_headers: true,
            },
        ));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/streaming-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailOpen,
        }];
        let mut middleware = test_response_middleware(&runner, &chain, request_id);
        middleware.whole_body_timeout = std::time::Duration::from_millis(10);
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"[..];
        let mut client = Vec::new();

        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect("whole-body timeout fails open");
        assert!(matches!(outcome, RelayOutcome::Reusable));
        assert!(client.ends_with(b"hello"));
        drop(correlation);

        let event = response_terminal_event_for(&capture, request_id);
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "upstream_response"
        );
        assert_eq!(event["unmapped"]["response_delivery_outcome"], "complete");
        assert_eq!(event["unmapped"]["upstream_http_status_code"], 200);
        assert_eq!(event["http_response"]["code"], 200);
        assert_eq!(event["unmapped"]["delivery_started"], true);
        assert_eq!(event["unmapped"]["partial_delivery"], false);
    }

    #[tokio::test]
    async fn accepted_early_hints_are_separate_from_cancelled_final_delivery() {
        use tokio::io::AsyncWriteExt as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation("response-early-hints-cancel");
        let (mut upstream, mut upstream_peer) = tokio::io::duplex(256);
        upstream_peer
            .write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n")
            .await
            .expect("seed early hints");
        let mut client = Vec::new();

        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                None,
            ),
        )
        .await
        .expect_err("relay remains pending after early hints");
        assert!(client.starts_with(b"HTTP/1.1 103 Early Hints\r\n"));
        drop(correlation);

        let event = response_terminal_event_for(&capture, "response-early-hints-cancel");
        assert_eq!(event["unmapped"]["interim_delivery_started"], true);
        assert!(
            event["unmapped"]["interim_bytes_forwarded"]
                .as_u64()
                .is_some_and(|bytes| bytes > 0)
        );
        assert_eq!(event["unmapped"]["delivery_started"], false);
        assert_eq!(event["unmapped"]["partial_delivery"], false);
    }

    #[tokio::test]
    async fn response_head_reload_during_early_hints_is_not_forwarded() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let engine = Arc::new(
            crate::opa::OpaEngine::from_strings(
                include_str!("../../../data/sandbox-policy.rego"),
                "network_policies: {}\n",
            )
            .expect("test policy"),
        );
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .expect("generation guard");
        let request_id = "response-early-hints-reload-race";
        let correlation = test_correlation(request_id);
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                body_delay: None,
                mutate_headers: false,
            },
        ));
        let chain = Vec::new();
        let mut middleware = test_response_middleware(&runner, &chain, request_id);
        middleware.generation_guard = Some(&generation_guard);
        let mut upstream = ReloadOnBodyReader::new(
            b"",
            b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n",
            Arc::clone(&engine),
        );
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect_err("policy reload must win before forwarding early hints");
        assert!(
            error
                .downcast_ref::<super::RelayError>()
                .is_some_and(|error| matches!(error, super::RelayError::PolicyReloaded(_))),
            "{error}"
        );
        assert!(client.is_empty(), "stale early hints reached the client");
        drop(correlation);

        let event = response_terminal_event_for(&capture, request_id);
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "policy_reloaded"
        );
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert_eq!(event["unmapped"]["interim_delivery_started"], false);
        assert_eq!(event["unmapped"]["delivery_started"], false);
    }

    #[tokio::test]
    async fn idle_before_final_response_head_wakes_on_policy_reload() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let engine = Arc::new(
            crate::opa::OpaEngine::from_strings(
                include_str!("../../../data/sandbox-policy.rego"),
                "network_policies: {}\n",
            )
            .expect("test policy"),
        );
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .expect("generation guard");
        let request_id = "response-idle-before-head-reload";
        let correlation = test_correlation(request_id);
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                body_delay: None,
                mutate_headers: false,
            },
        ));
        let chain = Vec::new();
        let mut middleware = test_response_middleware(&runner, &chain, request_id);
        middleware.generation_guard = Some(&generation_guard);
        let pending_polled = Arc::new(AtomicBool::new(false));
        let mut upstream =
            SegmentsThenPendingReader::new(Vec::<Vec<u8>>::new(), Arc::clone(&pending_polled));
        let mut client = Vec::new();
        let mut relay = Box::pin(relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        ));

        tokio::select! {
            result = &mut relay => panic!("idle response finished before reload: {result:?}"),
            () = wait_for_pending_read(&pending_polled) => {}
        }
        engine
            .reload(
                include_str!("../../../data/sandbox-policy.rego"),
                "network_policies: {}\n",
            )
            .expect("reload test policy");
        let error = tokio::time::timeout(std::time::Duration::from_millis(100), &mut relay)
            .await
            .expect("policy reload wakes the response-head read")
            .expect_err("policy reload stops the response");
        assert!(
            error
                .downcast_ref::<super::RelayError>()
                .is_some_and(|error| matches!(error, super::RelayError::PolicyReloaded(_))),
            "{error}"
        );
        drop(relay);
        assert!(client.is_empty());
        drop(correlation);

        let event = response_terminal_event_for(&capture, request_id);
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "policy_reloaded"
        );
        assert_eq!(event["unmapped"]["delivery_started"], false);
        assert_eq!(event["unmapped"]["partial_delivery"], false);
    }

    #[tokio::test]
    async fn framed_response_reads_wake_on_policy_reload_without_stale_body_bytes() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        for (case_name, segments) in [
            (
                "fixed-payload",
                vec![b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".to_vec()],
            ),
            (
                "chunk-size",
                vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec()],
            ),
            (
                "chunk-payload",
                vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n".to_vec()],
            ),
            (
                "chunk-terminator",
                vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody".to_vec()],
            ),
            (
                "chunk-trailer",
                vec![b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec()],
            ),
        ] {
            let engine = Arc::new(
                crate::opa::OpaEngine::from_strings(
                    include_str!("../../../data/sandbox-policy.rego"),
                    "network_policies: {}\n",
                )
                .expect("test policy"),
            );
            let generation_guard = engine
                .generation_guard(engine.current_generation())
                .expect("generation guard");
            let request_id = format!("response-stalled-{case_name}-reload");
            let correlation = test_correlation(&request_id);
            let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
                StreamingResponseMiddleware {
                    body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                    body_delay: None,
                    mutate_headers: false,
                },
            ));
            let chain = Vec::new();
            let mut middleware = test_response_middleware(&runner, &chain, &request_id);
            middleware.generation_guard = Some(&generation_guard);
            let pending_polled = Arc::new(AtomicBool::new(false));
            let mut upstream =
                SegmentsThenPendingReader::new(segments, Arc::clone(&pending_polled));
            let mut client = Vec::new();
            let mut relay = Box::pin(relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                Some(middleware),
            ));

            tokio::select! {
                result = &mut relay => {
                    panic!("{case_name} response finished before reload: {result:?}")
                }
                () = wait_for_pending_read(&pending_polled) => {}
            }
            engine
                .reload(
                    include_str!("../../../data/sandbox-policy.rego"),
                    "network_policies: {}\n",
                )
                .expect("reload test policy");
            let error = tokio::time::timeout(std::time::Duration::from_millis(100), &mut relay)
                .await
                .expect("policy reload wakes the framed response read")
                .expect_err("policy reload stops the response");
            assert!(
                error
                    .downcast_ref::<super::RelayError>()
                    .is_some_and(|error| matches!(error, super::RelayError::PolicyReloaded(_))),
                "{case_name}: {error}"
            );
            drop(relay);
            let head_end = client
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
                .expect("final response head delivered before body acquisition");
            assert_eq!(
                &client[head_end..],
                b"",
                "{case_name} leaked stale body or chunk framing bytes"
            );
            drop(correlation);

            let event = response_terminal_event_for(&capture, &request_id);
            assert_eq!(
                event["unmapped"]["response_selection_cause"],
                "policy_reloaded"
            );
            assert_eq!(
                event["unmapped"]["response_delivery_outcome"],
                "cancelled_or_incomplete"
            );
            assert_eq!(event["unmapped"]["delivery_started"], true);
            assert_eq!(event["unmapped"]["partial_delivery"], true);
        }
    }

    #[tokio::test]
    async fn shutdown_failure_overrides_delivery_but_retains_upstream_selection() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation("response-shutdown-failure");
        let mut upstream =
            &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..];
        let mut client = ControlledResponseWriter {
            shutdown_error: true,
            ..Default::default()
        };

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("shutdown failure");
        drop(correlation);

        let event = response_terminal_event_for(&capture, "response-shutdown-failure");
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "upstream_response"
        );
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"],
            "downstream_io_error"
        );
        assert_eq!(event["unmapped"]["upstream_http_status_code"], 200);
        assert_eq!(event["unmapped"]["effective_http_status_code"], 200);
        assert_eq!(event["unmapped"]["delivery_started"], true);
        assert_eq!(event["unmapped"]["partial_delivery"], true);
    }

    #[tokio::test]
    async fn zero_byte_first_write_does_not_claim_delivery_started() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation("response-zero-write");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = ControlledResponseWriter {
            zero_first_write: true,
            ..Default::default()
        };

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("write zero");
        drop(correlation);

        let event = response_terminal_event_for(&capture, "response-zero-write");
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"],
            "downstream_io_error"
        );
        assert_eq!(event["unmapped"]["delivery_started"], false);
        assert_eq!(event["unmapped"]["partial_delivery"], false);
    }

    #[tokio::test]
    async fn content_length_overflow_is_rejected_before_final_head() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation("response-content-length-overflow");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbodyEXTRA"[..];
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("content-length overflow");
        assert!(client.is_empty());
        drop(correlation);

        let event = response_terminal_event_for(&capture, "response-content-length-overflow");
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "upstream_protocol_error"
        );
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert_eq!(event["unmapped"]["upstream_http_status_code"], 200);
        assert!(
            event["unmapped"]
                .get("effective_http_status_code")
                .is_none()
        );
        assert_eq!(event["unmapped"]["delivery_started"], false);
    }

    #[tokio::test]
    async fn malformed_chunk_is_typed_as_protocol_failure_after_head_delivery() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation("response-malformed-chunk");
        let mut upstream =
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\nbody\r\n"[..];
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("malformed chunk");
        assert!(client.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(!client.ends_with(b"body\r\n"));
        drop(correlation);

        let event = response_terminal_event_for(&capture, "response-malformed-chunk");
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "upstream_protocol_error"
        );
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert_eq!(event["unmapped"]["delivery_started"], true);
        assert_eq!(event["unmapped"]["partial_delivery"], true);
    }

    #[tokio::test]
    async fn complete_fixed_chunked_and_sse_responses_record_terminal_delivery() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(
                &provider,
                "response-correlation-test",
            ))
            .with(ocsf.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        for (request_id, response) in [
            (
                "response-fixed-complete",
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody".as_slice(),
            ),
            (
                "response-chunked-complete",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\n\r\n"
                    .as_slice(),
            ),
            (
                "response-sse-complete",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: ok\n\n"
                    .as_slice(),
            ),
        ] {
            let correlation = test_correlation(request_id);
            let mut upstream = response;
            let mut client = Vec::new();
            relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                None,
            )
            .await
            .expect("complete response relay");
            drop(correlation);
        }
        provider.force_flush().expect("flush spans");

        let spans = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .filter(|span| span.name == "openshell.http.enforcement")
            .map(|span| {
                span.attributes
                    .into_iter()
                    .map(|attribute| {
                        (
                            attribute.key.as_str().to_string(),
                            attribute.value.to_string(),
                        )
                    })
                    .collect::<std::collections::BTreeMap<_, _>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(spans.len(), 3);
        for attributes in spans {
            assert_eq!(
                attributes["openshell.upstream.http.response.status_code"],
                "200"
            );
            assert_eq!(attributes["http.response.status_code"], "200");
            assert_eq!(attributes["openshell.response.delivery_started"], "true");
            assert_eq!(attributes["openshell.response.partial_delivery"], "false");
            assert_eq!(
                attributes["openshell.response.delivery_outcome"],
                "complete"
            );
        }
        let events = ocsf
            .json_events()
            .into_iter()
            .filter(|event| event["firewall_rule"]["type"] == "response-correlation")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|event| {
            event["unmapped"]["response_event_kind"] == "delivery_terminal"
                && event["unmapped"]["response_delivery_outcome"] == "complete"
        }));
    }

    #[tokio::test]
    async fn downstream_disconnect_after_partial_head_write_is_correlated() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
            &provider,
            "response-correlation-test",
        ));
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let correlation = test_correlation("response-client-disconnect");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
        let mut client = PartialThenErrorWriter {
            remaining_success: 8,
        };

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("downstream disconnect");
        drop(correlation);
        provider.force_flush().expect("flush spans");

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        let attributes = span
            .attributes
            .into_iter()
            .map(|attribute| {
                (
                    attribute.key.as_str().to_string(),
                    attribute.value.to_string(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(attributes["openshell.response.delivery_started"], "true");
        assert_eq!(attributes["openshell.response.partial_delivery"], "true");
        assert_eq!(
            attributes["openshell.response.delivery_outcome"],
            "downstream_io_error"
        );
    }

    #[tokio::test]
    async fn truncated_fixed_response_is_not_reported_complete() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
            &provider,
            "response-correlation-test",
        ));
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let correlation = test_correlation("response-upstream-truncated");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nbody"[..];
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("truncated upstream response");
        drop(correlation);
        provider.force_flush().expect("flush spans");

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        let attributes = span
            .attributes
            .into_iter()
            .map(|attribute| {
                (
                    attribute.key.as_str().to_string(),
                    attribute.value.to_string(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            attributes["openshell.response.delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert_eq!(
            attributes["openshell.response.selection_cause"],
            "upstream_truncated"
        );
        assert_eq!(attributes["openshell.response.partial_delivery"], "true");
    }

    #[tokio::test]
    async fn middleware_truncated_fixed_and_chunked_bodies_select_complete_502() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        for (request_id, response) in [
            (
                "response-middleware-fixed-truncated",
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nbody".as_slice(),
            ),
            (
                "response-middleware-chunked-truncated",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbo".as_slice(),
            ),
        ] {
            let correlation = test_correlation(request_id);
            let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
                StreamingResponseMiddleware {
                    body_mode: HttpResponseBodyMode::WholeBodyBytes as i32,
                    body_delay: None,
                    mutate_headers: true,
                },
            ));
            let chain = vec![openshell_supervisor_middleware::ChainEntry {
                name: "response".into(),
                implementation: "test/streaming-response".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: openshell_supervisor_middleware::OnError::FailClosed,
            }];
            let middleware = test_response_middleware(&runner, &chain, request_id);
            let mut upstream = response;
            let mut client = Vec::new();

            let outcome = relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                Some(middleware),
            )
            .await
            .expect("pre-commit truncation gets a bounded fallback");
            assert!(matches!(outcome, RelayOutcome::Consumed));
            assert!(client.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
            drop(correlation);

            let event = response_terminal_event_for(&capture, request_id);
            assert_eq!(
                event["unmapped"]["response_selection_cause"],
                "upstream_truncated"
            );
            assert_eq!(event["unmapped"]["response_delivery_outcome"], "complete");
            assert_eq!(event["unmapped"]["upstream_http_status_code"], 200);
            assert_eq!(event["http_response"]["code"], 502);
            assert_eq!(event["unmapped"]["effective_http_status_code"], 502);
            assert_eq!(event["unmapped"]["partial_delivery"], false);
        }
    }

    #[tokio::test]
    async fn fallback_disconnect_preserves_the_precommit_upstream_cause() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation("response-fallback-disconnect");
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::WholeBodyBytes as i32,
                body_delay: None,
                mutate_headers: true,
            },
        ));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/streaming-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = test_response_middleware(&runner, &chain, "response-fallback-disconnect");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nbody"[..];
        let mut client = ControlledResponseWriter {
            zero_first_write: true,
            ..Default::default()
        };

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect_err("fallback head is not accepted downstream");
        drop(correlation);

        let event = response_terminal_event_for(&capture, "response-fallback-disconnect");
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "upstream_truncated"
        );
        assert_eq!(
            event["unmapped"]["response_delivery_outcome"],
            "downstream_io_error"
        );
        assert_eq!(event["unmapped"]["upstream_http_status_code"], 200);
        assert_eq!(event["http_response"]["code"], 502);
        assert_eq!(event["unmapped"]["delivery_started"], false);
        assert_eq!(event["unmapped"]["partial_delivery"], false);
    }

    #[tokio::test(start_paused = true)]
    async fn close_delimited_idle_timeout_is_not_reported_complete() {
        use tokio::io::AsyncWriteExt as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
            &provider,
            "response-correlation-test",
        ));
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let correlation = test_correlation("response-idle-timeout");
        let (mut upstream, mut upstream_peer) = tokio::io::duplex(256);
        upstream_peer
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody")
            .await
            .expect("seed response");
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("idle timeout consumes close-delimited response");
        drop(upstream_peer);
        drop(correlation);
        provider.force_flush().expect("flush spans");

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        let attributes = span
            .attributes
            .into_iter()
            .map(|attribute| {
                (
                    attribute.key.as_str().to_string(),
                    attribute.value.to_string(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            attributes["openshell.response.delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert_eq!(
            attributes["openshell.response.selection_cause"],
            "upstream_idle_timeout"
        );
        assert_eq!(attributes["openshell.http.outcome"], "upstream_error");
        assert_eq!(attributes["openshell.response.partial_delivery"], "true");
    }

    #[tokio::test]
    async fn branch08_response_middleware_denial_records_that_upstream_was_reached() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(
                &provider,
                "response-correlation-test",
            ))
            .with(ocsf.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation_for_method("response-denied", "POST");
        let runner =
            openshell_supervisor_middleware::ChainRunner::new(Arc::new(BlockingResponseMiddleware));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/blocking-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = HttpResponseMiddlewareRelay {
            chain: &chain,
            runner: &runner,
            request_context: RequestContext {
                request_id: "response-denied".into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "POST".into(),
                path: "/mutate".into(),
                query: String::new(),
            },
            policy_name: "test-policy",
            generation_guard: None,
            whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
        };
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        let outcome = relay_response(
            "POST",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect("middleware denial response");

        assert!(matches!(outcome, RelayOutcome::Consumed));
        assert!(client.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
        assert!(
            String::from_utf8_lossy(&client)
                .contains("x-openshell-request-id: response-denied\r\n")
        );
        drop(correlation);

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        let attributes = span
            .attributes
            .into_iter()
            .map(|attribute| {
                (
                    attribute.key.as_str().to_string(),
                    attribute.value.to_string(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(attributes["openshell.target.reached"], "true");
        assert_eq!(attributes["openshell.http.outcome"], "denied");
        assert_eq!(attributes["http.response.status_code"], "403");
        assert_eq!(
            attributes["openshell.upstream.http.response.status_code"],
            "200"
        );
        assert_eq!(attributes["openshell.response.delivery_started"], "true");
        assert_eq!(attributes["openshell.response.partial_delivery"], "false");
        assert_eq!(
            attributes["openshell.response.delivery_outcome"],
            "complete"
        );
        assert_eq!(
            attributes["openshell.response.selection_cause"],
            "middleware_denied"
        );
        assert_eq!(
            attributes["openshell.middleware.response.outcome"],
            "denied"
        );
        assert_eq!(attributes["openshell.middleware.response.mutated"], "false");
        assert_eq!(
            attributes["openshell.middleware.response.fail_open"],
            "false"
        );
        assert_eq!(
            attributes["openshell.middleware.response.fail_closed"],
            "false"
        );
        assert_eq!(
            attributes["openshell.error.stage"],
            "response_middleware_preflight"
        );
        let events = ocsf
            .json_events()
            .into_iter()
            .filter(|event| event["firewall_rule"]["type"] == "supervisor-middleware")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["metadata"]["correlation_uid"], "response-denied");
        assert_eq!(events[0]["action"], "Denied");
        assert_eq!(
            events[0]["unmapped"]["response_middleware_outcome"],
            "blockdelivery"
        );
    }

    #[tokio::test]
    async fn fully_delivered_middleware_failure_keeps_upstream_and_effective_statuses() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation("response-middleware-failure");
        let runner =
            openshell_supervisor_middleware::ChainRunner::new(Arc::new(BlockingResponseMiddleware));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/unavailable-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = HttpResponseMiddlewareRelay {
            chain: &chain,
            runner: &runner,
            request_context: RequestContext {
                request_id: "response-middleware-failure".into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "GET".into(),
                path: "/data".into(),
                query: String::new(),
            },
            policy_name: "test-policy",
            generation_guard: None,
            whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
        };
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect("canonical middleware failure response");
        assert!(matches!(outcome, RelayOutcome::Consumed));
        assert!(client.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
        drop(correlation);

        let event = response_terminal_event_for(&capture, "response-middleware-failure");
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "middleware_failed"
        );
        assert_eq!(event["unmapped"]["response_delivery_outcome"], "complete");
        assert_eq!(event["unmapped"]["upstream_http_status_code"], 200);
        assert_eq!(event["unmapped"]["effective_http_status_code"], 502);
        assert_eq!(event["unmapped"]["delivery_started"], true);
        assert_eq!(event["unmapped"]["partial_delivery"], false);
    }

    #[tokio::test]
    async fn bodiless_middleware_denial_and_failure_select_canonical_statuses() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        for (action_name, denied) in [("denied", true), ("failed", false)] {
            for (case_name, method, response, upstream_status) in [
                (
                    "head",
                    "HEAD",
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n".as_slice(),
                    200,
                ),
                (
                    "204",
                    "GET",
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".as_slice(),
                    204,
                ),
                (
                    "304",
                    "GET",
                    b"HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\n\r\n".as_slice(),
                    304,
                ),
            ] {
                let request_id = format!("response-bodiless-{case_name}-{action_name}");
                let correlation = test_correlation_for_method(&request_id, method);
                let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
                    BlockingResponseMiddleware,
                ));
                let chain = vec![openshell_supervisor_middleware::ChainEntry {
                    name: "response".into(),
                    implementation: if denied {
                        "test/blocking-response".into()
                    } else {
                        "test/unavailable-response".into()
                    },
                    order: 0,
                    config: prost_types::Struct::default(),
                    on_error: openshell_supervisor_middleware::OnError::FailClosed,
                }];
                let mut middleware = test_response_middleware(&runner, &chain, &request_id);
                middleware.target.method = method.into();
                let mut upstream = response;
                let mut client = Vec::new();

                let outcome = relay_response(
                    method,
                    &mut upstream,
                    &mut client,
                    RelayResponseOptions {
                        correlation: Some(&correlation),
                        ..Default::default()
                    },
                    Some(middleware),
                )
                .await
                .expect("bodiless middleware result gets a canonical response");
                assert!(matches!(outcome, RelayOutcome::Consumed));
                let effective_status = if denied { 403 } else { 502 };
                let expected_head = if denied {
                    b"HTTP/1.1 403 Forbidden\r\n".as_slice()
                } else {
                    b"HTTP/1.1 502 Bad Gateway\r\n".as_slice()
                };
                assert!(
                    client.starts_with(expected_head),
                    "{case_name}/{action_name}: {}",
                    String::from_utf8_lossy(&client)
                );
                drop(correlation);

                let event = response_terminal_event_for(&capture, &request_id);
                assert_eq!(
                    event["unmapped"]["response_selection_cause"],
                    if denied {
                        "middleware_denied"
                    } else {
                        "middleware_failed"
                    }
                );
                assert_eq!(event["unmapped"]["response_delivery_outcome"], "complete");
                assert_eq!(
                    event["unmapped"]["upstream_http_status_code"],
                    upstream_status
                );
                assert_eq!(event["http_response"]["code"], effective_status);
                let middleware_event = response_middleware_event_for(&capture, &request_id);
                assert_eq!(
                    middleware_event["unmapped"]["middleware_outcome"],
                    if denied { "denied" } else { "platform_error" }
                );
            }
        }
    }

    #[tokio::test]
    async fn response_finish_block_retains_an_explicit_denial() {
        let runner =
            openshell_supervisor_middleware::ChainRunner::new(Arc::new(BodyResponseMiddleware {
                action: BodyTestAction::Block,
            }));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/body-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let outcome = runner
            .preflight_http_response(
                &chain,
                openshell_supervisor_middleware::HttpResponsePreflightInput {
                    context: RequestContext::default(),
                    target: HttpRequestTarget {
                        scheme: "https".into(),
                        host: "example.test".into(),
                        port: 443,
                        method: "GET".into(),
                        path: "/data".into(),
                        query: String::new(),
                    },
                    status_code: 200,
                    declared_body_length: Some(0),
                    headers: Vec::new(),
                    connection_nominated_headers: Vec::new(),
                },
            )
            .await
            .expect("response preflight");
        let failure = outcome
            .session
            .expect("streaming response session")
            .finish(Vec::new())
            .await
            .expect_err("final body event is denied");

        let denial = response_middleware_failure_denial(&failure).expect("explicit denial");
        assert_eq!(denial.config_name, "response");
        assert_eq!(denial.reason_code.as_deref(), Some("test_body_action"));
    }

    #[tokio::test]
    async fn chain_description_failure_is_middleware_failed_not_upstream_protocol() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let request_id = "response-describe-failure";
        let correlation = test_correlation(request_id);
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                body_delay: None,
                mutate_headers: false,
            },
        ));
        let chain = (0..=openshell_supervisor_middleware::MAX_MIDDLEWARE_CHAIN_STAGES)
            .map(|index| openshell_supervisor_middleware::ChainEntry {
                name: format!("response-{index}"),
                implementation: "test/streaming-response".into(),
                order: i32::try_from(index).expect("bounded test index"),
                config: prost_types::Struct::default(),
                on_error: openshell_supervisor_middleware::OnError::FailClosed,
            })
            .collect::<Vec<_>>();
        let middleware = test_response_middleware(&runner, &chain, request_id);
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect("description failure gets a canonical 502");
        assert!(client.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
        drop(correlation);

        let event = response_terminal_event_for(&capture, request_id);
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "middleware_failed"
        );
        assert_eq!(event["unmapped"]["response_delivery_outcome"], "complete");
        assert_eq!(event["unmapped"]["upstream_http_status_code"], 200);
        assert_eq!(event["http_response"]["code"], 502);
        assert!(capture.json_events().iter().any(|event| {
            event["finding_info"]["uid"] == "openshell.middleware.http_response_failure"
                && event["metadata"]["correlation_uid"] == request_id
        }));
    }

    #[tokio::test]
    async fn policy_reload_wins_over_describe_preflight_and_finish_errors() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        for (case_name, point, method, body_mode) in [
            (
                "describe",
                ReloadThenErrorPoint::Describe,
                "GET",
                HttpResponseBodyMode::HeadersOnly,
            ),
            (
                "preflight",
                ReloadThenErrorPoint::Preflight,
                "GET",
                HttpResponseBodyMode::HeadersOnly,
            ),
            (
                "bodiless-finish",
                ReloadThenErrorPoint::Finish,
                "HEAD",
                HttpResponseBodyMode::WholeBodyBytes,
            ),
            (
                "normal-finish",
                ReloadThenErrorPoint::Finish,
                "GET",
                HttpResponseBodyMode::WholeBodyBytes,
            ),
            (
                "normal-finish-streaming",
                ReloadThenErrorPoint::Finish,
                "GET",
                HttpResponseBodyMode::StreamBytes,
            ),
        ] {
            let engine = Arc::new(
                crate::opa::OpaEngine::from_strings(
                    include_str!("../../../data/sandbox-policy.rego"),
                    "network_policies: {}\n",
                )
                .expect("test policy"),
            );
            let generation_guard = engine
                .generation_guard(engine.current_generation())
                .expect("generation guard");
            let request_id = format!("response-reload-then-error-{case_name}");
            let correlation = test_correlation_for_method(&request_id, method);
            let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
                ReloadThenErrorResponseMiddleware {
                    point,
                    body_mode: body_mode as i32,
                    engine: Arc::clone(&engine),
                },
            ));
            let chain = vec![openshell_supervisor_middleware::ChainEntry {
                name: "response".into(),
                implementation: "test/reload-then-error-response".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: openshell_supervisor_middleware::OnError::FailClosed,
            }];
            let mut middleware = test_response_middleware(&runner, &chain, &request_id);
            middleware.generation_guard = Some(&generation_guard);
            // Keep the middleware target body-capable in the HEAD case so the
            // test creates a session and reaches the relay's bodiless finish.
            let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
            let mut client = Vec::new();

            let error = relay_response(
                method,
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                Some(middleware),
            )
            .await
            .expect_err("policy reload must override the middleware error");
            assert!(
                error
                    .downcast_ref::<super::RelayError>()
                    .is_some_and(|error| matches!(error, super::RelayError::PolicyReloaded(_))),
                "{case_name}: {error}"
            );
            let committed = case_name == "normal-finish-streaming";
            if committed {
                assert!(
                    client.starts_with(b"HTTP/1.1 200 OK\r\n"),
                    "{case_name}: expected the response head to be committed"
                );
                let head_end = client
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|position| position + 4)
                    .expect("committed response head");
                assert_eq!(
                    &client[head_end..],
                    b"",
                    "{case_name}: stale response body reached the client"
                );
            } else {
                assert!(
                    client.is_empty(),
                    "{case_name}: stale middleware result reached the client"
                );
            }
            drop(correlation);

            let event = response_terminal_event_for(&capture, &request_id);
            assert_eq!(
                event["unmapped"]["response_selection_cause"], "policy_reloaded",
                "{case_name}"
            );
            assert_eq!(
                event["unmapped"]["response_delivery_outcome"], "cancelled_or_incomplete",
                "{case_name}"
            );
            assert_eq!(
                event["unmapped"]["upstream_http_status_code"], 200,
                "{case_name}"
            );
            if committed {
                assert_eq!(event["http_response"]["code"], 200, "{case_name}");
                assert_eq!(
                    event["unmapped"]["effective_http_status_code"], 200,
                    "{case_name}"
                );
            } else {
                assert!(event.get("http_response").is_none(), "{case_name}");
                assert!(
                    event["unmapped"]
                        .get("effective_http_status_code")
                        .is_none(),
                    "{case_name}"
                );
            }
            assert_eq!(
                event["unmapped"]["delivery_started"], committed,
                "{case_name}"
            );
            assert_eq!(
                event["unmapped"]["partial_delivery"], committed,
                "{case_name}"
            );
            assert!(!capture.json_events().iter().any(|event| {
                event["finding_info"]["uid"] == "openshell.middleware.http_response_failure"
                    && event["metadata"]["correlation_uid"] == request_id
            }));
            if case_name == "preflight" {
                let middleware_event = response_middleware_event_for(&capture, &request_id);
                assert_eq!(
                    middleware_event["unmapped"]["middleware_outcome"],
                    "incomplete"
                );
                assert_eq!(middleware_event["unmapped"]["fail_closed"], false);
            }
        }
    }

    #[tokio::test]
    async fn normalized_head_parse_failure_is_upstream_protocol_not_middleware_failure() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let request_id = "response-head-parse-failure";
        let correlation = test_correlation(request_id);
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                body_delay: None,
                mutate_headers: false,
            },
        ));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/streaming-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = test_response_middleware(&runner, &chain, request_id);
        let mut upstream = &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Content-Length\r\n\r\n0\r\n\r\n"[..];
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect("malformed normalized head gets a canonical 502");
        assert!(client.starts_with(b"HTTP/1.1 502 Bad Gateway\r\n"));
        drop(correlation);

        let event = response_terminal_event_for(&capture, request_id);
        assert_eq!(
            event["unmapped"]["response_selection_cause"],
            "upstream_protocol_error"
        );
        assert_eq!(event["unmapped"]["response_delivery_outcome"], "complete");
        assert_eq!(event["unmapped"]["upstream_http_status_code"], 200);
        assert_eq!(event["http_response"]["code"], 502);
        assert!(!capture.json_events().iter().any(|event| {
            event["finding_info"]["uid"] == "openshell.middleware.http_response_failure"
                && event["metadata"]["correlation_uid"] == request_id
        }));
        let events = capture.json_events();
        assert!(
            !events.iter().any(|event| {
                event["firewall_rule"]["type"] == "middleware-correlation"
                    && event["metadata"]["correlation_uid"] == request_id
            }),
            "{events:#?}"
        );
    }

    #[tokio::test]
    async fn streaming_response_middleware_aggregates_header_and_body_mutations() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
            &provider,
            "response-correlation-test",
        ));
        let correlation = tracing::subscriber::with_default(subscriber, || {
            test_correlation_for_method("response-streaming", "GET")
        });
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::StreamBytes as i32,
                body_delay: None,
                mutate_headers: true,
            },
        ));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/streaming-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = HttpResponseMiddlewareRelay {
            chain: &chain,
            runner: &runner,
            request_context: RequestContext {
                request_id: "response-streaming".into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "GET".into(),
                path: "/data".into(),
                query: String::new(),
            },
            policy_name: "test-policy",
            generation_guard: None,
            whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
        };
        let body = vec![b'a'; 9_000];
        let mut response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        response.extend_from_slice(&body);
        let mut upstream = response.as_slice();
        let mut client = Vec::new();

        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect("streaming middleware response");

        assert!(matches!(outcome, RelayOutcome::Reusable));
        assert!(String::from_utf8_lossy(&client).contains("x-inspected: true\r\n"));
        assert!(
            String::from_utf8_lossy(&client)
                .contains("x-openshell-request-id: response-streaming\r\n")
        );
        drop(correlation);

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        let attributes = span
            .attributes
            .into_iter()
            .map(|attribute| {
                (
                    attribute.key.as_str().to_string(),
                    attribute.value.to_string(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            attributes["openshell.middleware.response.outcome"],
            "allowed"
        );
        assert_eq!(attributes["openshell.middleware.response.mutated"], "true");
        assert_eq!(
            attributes["openshell.middleware.response.fail_open"],
            "false"
        );
        assert_eq!(attributes["openshell.request.id"], "response-streaming");
    }

    #[tokio::test]
    async fn streaming_body_denial_records_partial_delivery() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(
                &provider,
                "response-correlation-test",
            ))
            .with(ocsf.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        let correlation = test_correlation_for_method("response-partial-denial", "GET");
        let runner =
            openshell_supervisor_middleware::ChainRunner::new(Arc::new(BodyResponseMiddleware {
                action: BodyTestAction::Block,
            }));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/body-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = HttpResponseMiddlewareRelay {
            chain: &chain,
            runner: &runner,
            request_context: RequestContext {
                request_id: "response-partial-denial".into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "GET".into(),
                path: "/data".into(),
                query: String::new(),
            },
            policy_name: "test-policy",
            generation_guard: None,
            whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
        };
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect_err("streaming body denial follows response commitment");
        assert!(error.to_string().contains("stopped delivery"), "{error}");
        assert!(client.starts_with(b"HTTP/1.1 200 OK\r\n"));
        drop(correlation);
        provider.force_flush().expect("flush spans");

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        let attributes = span
            .attributes
            .into_iter()
            .map(|attribute| {
                (
                    attribute.key.as_str().to_string(),
                    attribute.value.to_string(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            attributes["openshell.middleware.response.outcome"],
            "denied"
        );
        assert_eq!(
            attributes["openshell.middleware.response.delivery_started"],
            "true"
        );
        assert_eq!(
            attributes["openshell.middleware.response.partial_delivery"],
            "true"
        );
        assert_eq!(attributes["openshell.response.delivery_started"], "true");
        assert_eq!(attributes["openshell.response.partial_delivery"], "true");
        assert_eq!(
            attributes["openshell.response.delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert_eq!(
            attributes["openshell.response.selection_cause"],
            "middleware_denied"
        );
        let events = ocsf
            .json_events()
            .into_iter()
            .filter(|event| event["firewall_rule"]["type"] == "middleware-correlation")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["disposition"], "Other");
        assert_eq!(events[0]["unmapped"]["partial_delivery"], true);
    }

    #[tokio::test]
    async fn stale_generation_preserves_skip_transform_observation() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry().with(openshell_otel::layer(
            &provider,
            "response-correlation-test",
        ));
        let correlation = tracing::subscriber::with_default(subscriber, || {
            test_correlation_for_method("response-stale-transform", "GET")
        });
        let engine = Arc::new(
            crate::opa::OpaEngine::from_strings(
                include_str!("../../../data/sandbox-policy.rego"),
                "network_policies: {}\n",
            )
            .expect("test policy"),
        );
        let generation_guard = engine
            .generation_guard(engine.current_generation())
            .expect("generation guard");
        let runner =
            openshell_supervisor_middleware::ChainRunner::new(Arc::new(BodyResponseMiddleware {
                action: BodyTestAction::ReloadAndSkipTransform(Arc::clone(&engine)),
            }));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/body-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = HttpResponseMiddlewareRelay {
            chain: &chain,
            runner: &runner,
            request_context: RequestContext {
                request_id: "response-stale-transform".into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "GET".into(),
                path: "/data".into(),
                query: String::new(),
            },
            policy_name: "test-policy",
            generation_guard: Some(&generation_guard),
            whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
        };
        let mut upstream = &b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect_err("policy reload must stop the stale response");
        assert!(
            error.to_string().contains("policy generation is stale"),
            "{error}"
        );
        drop(correlation);
        provider.force_flush().expect("flush spans");

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        let attributes = span
            .attributes
            .into_iter()
            .map(|attribute| {
                (
                    attribute.key.as_str().to_string(),
                    attribute.value.to_string(),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            attributes["openshell.middleware.response.outcome"],
            "incomplete"
        );
        assert_eq!(attributes["openshell.middleware.response.mutated"], "true");
        assert_eq!(
            attributes["openshell.middleware.response.delivery_started"],
            "true"
        );
        assert_eq!(
            attributes["openshell.middleware.response.partial_delivery"],
            "true"
        );
        assert_eq!(attributes["openshell.response.delivery_started"], "true");
        assert_eq!(attributes["openshell.response.partial_delivery"], "true");
        assert_eq!(
            attributes["openshell.response.delivery_outcome"],
            "cancelled_or_incomplete"
        );
        assert_eq!(
            attributes["openshell.response.selection_cause"],
            "policy_reloaded"
        );
    }

    #[tokio::test]
    async fn headers_only_close_delimited_and_sse_reads_stop_on_policy_reload() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        for (request_id, head) in [
            (
                "response-close-policy-reload",
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody".as_slice(),
            ),
            (
                "response-sse-policy-reload",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: body\n\n"
                    .as_slice(),
            ),
        ] {
            let engine = Arc::new(
                crate::opa::OpaEngine::from_strings(
                    include_str!("../../../data/sandbox-policy.rego"),
                    "network_policies: {}\n",
                )
                .expect("test policy"),
            );
            let generation_guard = engine
                .generation_guard(engine.current_generation())
                .expect("generation guard");
            let correlation = test_correlation(request_id);
            let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
                StreamingResponseMiddleware {
                    body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                    body_delay: None,
                    mutate_headers: true,
                },
            ));
            let chain = vec![openshell_supervisor_middleware::ChainEntry {
                name: "response".into(),
                implementation: "test/streaming-response".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: openshell_supervisor_middleware::OnError::FailClosed,
            }];
            let mut middleware = test_response_middleware(&runner, &chain, request_id);
            middleware.generation_guard = Some(&generation_guard);
            let pending_polled = Arc::new(AtomicBool::new(false));
            let mut upstream =
                SegmentsThenPendingReader::new([head.to_vec()], Arc::clone(&pending_polled));
            let mut client = Vec::new();
            let mut relay = Box::pin(relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                Some(middleware),
            ));

            tokio::select! {
                result = &mut relay => panic!("idle response finished before reload: {result:?}"),
                () = wait_for_pending_read(&pending_polled) => {}
            }
            engine
                .reload(
                    include_str!("../../../data/sandbox-policy.rego"),
                    "network_policies: {}\n",
                )
                .expect("reload test policy");
            let error = tokio::time::timeout(std::time::Duration::from_millis(100), &mut relay)
                .await
                .expect("policy reload wakes the idle read")
                .expect_err("policy reload stops the response");
            assert!(error.to_string().contains("generation changed"), "{error}");
            drop(relay);
            drop(correlation);

            let event = response_terminal_event_for(&capture, request_id);
            assert_eq!(
                event["unmapped"]["response_selection_cause"],
                "policy_reloaded"
            );
            assert_eq!(
                event["unmapped"]["response_delivery_outcome"],
                "cancelled_or_incomplete"
            );
            assert_eq!(event["unmapped"]["delivery_started"], true);
            assert_eq!(event["unmapped"]["partial_delivery"], true);
        }
    }

    #[tokio::test]
    async fn headers_only_body_bytes_racing_policy_reload_are_never_forwarded() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry().with(capture.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();

        for (case_name, head, body) in [
            (
                "fixed",
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".as_slice(),
                b"body".as_slice(),
            ),
            (
                "chunked",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".as_slice(),
                b"4\r\nbody\r\n0\r\n\r\n".as_slice(),
            ),
            (
                "close",
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".as_slice(),
                b"body".as_slice(),
            ),
            (
                "sse",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n".as_slice(),
                b"data: body\n\n".as_slice(),
            ),
        ] {
            let engine = Arc::new(
                crate::opa::OpaEngine::from_strings(
                    include_str!("../../../data/sandbox-policy.rego"),
                    "network_policies: {}\n",
                )
                .expect("test policy"),
            );
            let generation_guard = engine
                .generation_guard(engine.current_generation())
                .expect("generation guard");
            let request_id = format!("response-data-reload-race-{case_name}");
            let correlation = test_correlation(&request_id);
            let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
                StreamingResponseMiddleware {
                    body_mode: HttpResponseBodyMode::HeadersOnly as i32,
                    body_delay: None,
                    mutate_headers: false,
                },
            ));
            let chain = vec![openshell_supervisor_middleware::ChainEntry {
                name: "response".into(),
                implementation: "test/streaming-response".into(),
                order: 0,
                config: prost_types::Struct::default(),
                on_error: openshell_supervisor_middleware::OnError::FailClosed,
            }];
            let mut middleware = test_response_middleware(&runner, &chain, &request_id);
            middleware.generation_guard = Some(&generation_guard);
            let mut upstream = ReloadOnBodyReader::new(head, body, Arc::clone(&engine));
            let mut client = Vec::new();

            let error = relay_response(
                "GET",
                &mut upstream,
                &mut client,
                RelayResponseOptions {
                    correlation: Some(&correlation),
                    ..Default::default()
                },
                Some(middleware),
            )
            .await
            .expect_err("stale policy stops body delivery");
            assert!(
                error
                    .downcast_ref::<super::RelayError>()
                    .is_some_and(|error| matches!(error, super::RelayError::PolicyReloaded(_))),
                "{case_name}: {error}"
            );
            let head_end = client
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
                .expect("final response head delivered");
            assert_eq!(
                &client[head_end..],
                b"",
                "{case_name} leaked stale body bytes"
            );
            drop(correlation);

            let event = response_terminal_event_for(&capture, &request_id);
            assert_eq!(
                event["unmapped"]["response_selection_cause"],
                "policy_reloaded"
            );
            assert_eq!(
                event["unmapped"]["response_delivery_outcome"],
                "cancelled_or_incomplete"
            );
            assert_eq!(event["unmapped"]["delivery_started"], true);
            assert_eq!(event["unmapped"]["partial_delivery"], true);
        }
    }

    #[test]
    fn response_middleware_observation_maps_bounded_outcomes() {
        let invocation = |outcome| openshell_supervisor_middleware::HttpResponseInvocation {
            config_name: "not-exported".into(),
            implementation: "not-exported".into(),
            outcome,
            sequence: None,
            input_size: 17,
            output_size: None,
            transformed: outcome
                == openshell_supervisor_middleware::HttpResponseInvocationOutcome::Transform,
            failed: false,
            stage_disabled: false,
            reason_code: None,
            failure_category: None,
        };
        let mut invocations = vec![
            invocation(openshell_supervisor_middleware::HttpResponseInvocationOutcome::Transform),
            invocation(openshell_supervisor_middleware::HttpResponseInvocationOutcome::FailOpen),
            invocation(openshell_supervisor_middleware::HttpResponseInvocationOutcome::FailClosed),
        ];
        let mut skip_transform = invocation(
            openshell_supervisor_middleware::HttpResponseInvocationOutcome::SkipRemaining,
        );
        skip_transform.transformed = true;
        invocations.push(skip_transform);
        let observation = response_middleware_observation(&invocations, false, true);

        assert_eq!(
            observation,
            MiddlewareObservation {
                mutated: true,
                fail_open: true,
                fail_closed: true,
                admission_exhausted: true,
                ..Default::default()
            }
        );
    }

    #[test]
    fn response_diagnostic_truncation_event_is_bounded() {
        let event = http_response_diagnostic_truncation_event(
            "test-policy",
            &HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "GET".into(),
                path: "/private".into(),
                query: "secret=value".into(),
            },
        )
        .to_json()
        .expect("serialize truncation event");

        assert_eq!(event["severity"], "Low");
        assert_eq!(
            event["finding_info"]["uid"],
            "openshell.middleware.http_response_diagnostics_truncated"
        );
        assert_eq!(event["unmapped"]["phase"], "pre_return");
        let encoded = serde_json::to_string(&event).expect("encode truncation event");
        assert!(!encoded.contains("/private"));
        assert!(!encoded.contains("secret=value"));
    }

    #[tokio::test]
    async fn upstream_receipt_is_replaced_by_platform_receipt() {
        let correlation = test_correlation("trusted");
        let mut upstream =
            &b"HTTP/1.1 200 OK\r\nX-OpenShell-Request-ID: forged\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");

        assert!(!String::from_utf8_lossy(&client).contains("forged"));
        assert!(String::from_utf8_lossy(&client).contains("x-openshell-request-id: trusted\r\n"));
        assert_eq!(request_id_header_count(&client), 1);
    }

    #[tokio::test]
    async fn ordinary_response_removes_receipt_connection_nomination() {
        let correlation = test_correlation("trusted");
        let mut upstream = &b"HTTP/1.1 200 OK\r\n\
            Connection: X-OpenShell-Request-ID\r\n\
            cOnNeCtIoN: keep-alive, x-OpEnShElL-rEqUeSt-Id\r\n\
            X-OpenShell-Request-ID: forged-head\r\n\
            Trailer: x-openshell-request-id, X-Checksum\r\n\
            Transfer-Encoding: chunked\r\n\r\n\
            4\r\nbody\r\n\
            0\r\n\
            x-OPENshell-request-ID: forged-trailer\r\n\
            X-Checksum: ok\r\n\r\n"[..];
        let mut client = Vec::new();

        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");

        assert!(matches!(outcome, RelayOutcome::Reusable));
        let delivered = String::from_utf8(client).expect("HTTP response is UTF-8");
        let head = delivered
            .split_once("\r\n\r\n")
            .expect("response head terminator")
            .0;
        let connection_headers: Vec<_> = head
            .lines()
            .filter(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("connection"))
            })
            .collect();
        assert_eq!(connection_headers, ["cOnNeCtIoN: keep-alive"]);
        assert!(!delivered.contains("forged"), "{delivered}");
        assert!(head.contains("Trailer: X-Checksum"), "{head}");
        assert!(delivered.contains("0\r\nX-Checksum: ok\r\n\r\n"));
        assert!(head.contains("x-openshell-request-id: trusted"), "{head}");
        assert_eq!(request_id_header_count(delivered.as_bytes()), 1);
    }

    #[tokio::test]
    async fn ordinary_response_rejects_folded_receipt_connection_nomination() {
        let correlation = test_correlation("trusted");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nConnection: keep-alive,\r\n X-OpenShell-Request-ID\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("folded response fields must fail closed");

        assert!(
            error
                .to_string()
                .contains("response header continuation lines are not supported"),
            "{error}"
        );
        assert!(client.is_empty());
    }

    #[tokio::test]
    async fn ordinary_response_rejects_bare_lf_receipt_smuggling() {
        let correlation = test_correlation("trusted");
        let mut upstream = &b"HTTP/1.1 200 OK\r\nX-Safe: yes\nX-OpenShell-Request-ID: forged\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("bare LF response fields must fail closed");

        assert!(error.to_string().contains("bare LF"), "{error}");
        assert!(client.is_empty());
    }

    #[test]
    fn response_head_validation_rejects_malformed_syntax() {
        let cases: &[(&str, &[u8])] = &[
            ("incomplete block", b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n"),
            ("bare LF", b"HTTP/1.1 200 OK\r\nX-Test: yes\n\r\n"),
            ("bare CR", b"HTTP/1.1 200 OK\r\nX-Test: yes\rX: no\r\n\r\n"),
            (
                "obsolete fold",
                b"HTTP/1.1 200 OK\r\nX-Test: yes\r\n continued\r\n\r\n",
            ),
            ("unsupported protocol", b"HTTP/2 200 OK\r\n\r\n"),
            ("invalid status range", b"HTTP/1.1 099 Nope\r\n\r\n"),
            ("non-numeric status", b"HTTP/1.1 2O0 Nope\r\n\r\n"),
            ("four-digit status", b"HTTP/1.1 2000 Nope\r\n\r\n"),
            ("missing reason separator", b"HTTP/1.1 200\r\n\r\n"),
            ("malformed field", b"HTTP/1.1 200 OK\r\nX-Test\r\n\r\n"),
            ("empty field name", b"HTTP/1.1 200 OK\r\n: value\r\n\r\n"),
            (
                "non-token field name",
                b"HTTP/1.1 200 OK\r\nBad Name: value\r\n\r\n",
            ),
            (
                "whitespace before colon",
                b"HTTP/1.1 200 OK\r\nX-Test : value\r\n\r\n",
            ),
            (
                "field control byte",
                b"HTTP/1.1 200 OK\r\nX-Test: value\x0bmore\r\n\r\n",
            ),
            (
                "field delete byte",
                b"HTTP/1.1 200 OK\r\nX-Test: value\x7f\r\n\r\n",
            ),
            ("reason control byte", b"HTTP/1.1 200 O\x00K\r\n\r\n"),
            (
                "early empty line",
                b"HTTP/1.1 200 OK\r\n\r\nX-Smuggled: yes\r\n\r\n",
            ),
        ];

        for (name, input) in cases {
            assert!(
                validate_http_response_header_block(input).is_err(),
                "{name} unexpectedly passed validation"
            );
        }
    }

    #[test]
    fn response_head_validation_accepts_supported_informational_and_upgrade_responses() {
        for response in [
            &b"HTTP/1.0 200 OK\r\nX-Test: yes\r\n\r\n"[..],
            &b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"[..],
            &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"[..],
        ] {
            validate_http_response_header_block(response).expect("valid HTTP/1.x response head");
        }
    }

    #[tokio::test]
    async fn response_middleware_rejects_forged_request_id_trailer() {
        let correlation = test_correlation("trusted");
        let runner = openshell_supervisor_middleware::ChainRunner::new(Arc::new(
            StreamingResponseMiddleware {
                body_mode: HttpResponseBodyMode::StreamBytes as i32,
                body_delay: None,
                mutate_headers: true,
            },
        ));
        let chain = vec![openshell_supervisor_middleware::ChainEntry {
            name: "response".into(),
            implementation: "test/streaming-response".into(),
            order: 0,
            config: prost_types::Struct::default(),
            on_error: openshell_supervisor_middleware::OnError::FailClosed,
        }];
        let middleware = HttpResponseMiddlewareRelay {
            chain: &chain,
            runner: &runner,
            request_context: RequestContext {
                request_id: "middleware-request".into(),
                sandbox_id: "sandbox-1".into(),
                ..Default::default()
            },
            target: HttpRequestTarget {
                scheme: "https".into(),
                host: "example.test".into(),
                port: 443,
                method: "GET".into(),
                path: "/data".into(),
                query: String::new(),
            },
            policy_name: "test-policy",
            generation_guard: None,
            whole_body_timeout: DEFAULT_HTTP_RESPONSE_WHOLE_BODY_TIMEOUT,
        };
        let mut upstream = &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nbody\r\n0\r\nX-OpenShell-Request-ID: forged\r\n\r\n"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            Some(middleware),
        )
        .await
        .expect_err("platform correlation trailers must fail closed");

        assert!(
            error.to_string().contains("protected field name"),
            "{error}"
        );
        let delivered = String::from_utf8_lossy(&client);
        assert!(!delivered.contains("forged"), "{delivered}");
        assert!(
            delivered.contains("x-openshell-request-id: trusted\r\n"),
            "{delivered}"
        );
        assert_eq!(request_id_header_count(&client), 1);
    }

    #[test]
    fn response_middleware_rejects_declared_request_id_trailer() {
        let error = parse_response_head_for_middleware(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-OpenShell-Request-ID\r\n\r\n",
        )
        .expect_err("platform correlation trailer declarations must fail closed");

        assert!(
            error.to_string().contains("protected trailer field"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn informational_responses_are_not_decorated_but_upgrade_receives_a_receipt() {
        let correlation = test_correlation("receipt-1");
        let mut upstream =
            &b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"[..];
        let mut client = Vec::new();

        relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");
        assert!(client.starts_with(b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n"));
        assert_eq!(request_id_header_count(&client), 1);

        let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-OpenShell-Request-ID: forged\r\n\r\n"[..];
        let mut client = Vec::new();
        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");
        assert!(matches!(outcome, RelayOutcome::Upgraded { .. }));
        assert_eq!(request_id_header_count(&client), 1);
        assert!(!String::from_utf8_lossy(&client).contains("forged"));
        assert!(String::from_utf8_lossy(&client).contains("x-openshell-request-id: receipt-1\r\n"));
    }

    #[tokio::test]
    async fn switching_protocols_removes_receipt_connection_nomination() {
        let correlation = test_correlation("trusted-upgrade");
        let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\n\
            Connection: X-OpenShell-Request-ID\r\n\
            cOnNeCtIoN: keep-alive, x-OpEnShElL-rEqUeSt-Id, UpGrAdE\r\n\
            Upgrade: websocket\r\n\
            X-OpenShell-Request-ID: forged\r\n\r\n"[..];
        let mut client = Vec::new();

        let outcome = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect("relay response");

        assert!(matches!(outcome, RelayOutcome::Upgraded { .. }));
        let delivered = String::from_utf8(client).expect("HTTP response is UTF-8");
        let connection_headers: Vec<_> = delivered
            .lines()
            .filter(|line| {
                line.split_once(':')
                    .is_some_and(|(name, _)| name.eq_ignore_ascii_case("connection"))
            })
            .collect();
        assert_eq!(connection_headers, ["cOnNeCtIoN: keep-alive, UpGrAdE"]);
        assert!(!delivered.contains("forged"), "{delivered}");
        assert!(
            delivered.contains("x-openshell-request-id: trusted-upgrade\r\n"),
            "{delivered}"
        );
        assert_eq!(request_id_header_count(delivered.as_bytes()), 1);
    }

    #[tokio::test]
    async fn switching_protocols_rejects_folded_receipt_connection_nomination() {
        let correlation = test_correlation("trusted-upgrade");
        let mut upstream = &b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade,\r\n\tX-OpenShell-Request-ID\r\nUpgrade: websocket\r\n\r\n"[..];
        let mut client = Vec::new();

        let error = relay_response(
            "GET",
            &mut upstream,
            &mut client,
            RelayResponseOptions {
                correlation: Some(&correlation),
                ..Default::default()
            },
            None,
        )
        .await
        .expect_err("folded upgrade fields must fail closed");

        assert!(
            error
                .to_string()
                .contains("response header continuation lines are not supported"),
            "{error}"
        );
        assert!(client.is_empty());
    }

    #[test]
    fn http_10_connection_persistence() {
        let default_close = "HTTP/1.0 200 OK\r\nServer: test\r\n\r\n";
        assert!(response_is_http_10(default_close));
        assert!(!parse_connection_keep_alive(default_close));

        let keep_alive = "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\n\r\n";
        assert!(response_is_http_10(keep_alive));
        assert!(parse_connection_keep_alive(keep_alive));
    }

    #[test]
    fn response_middleware_preflight_keeps_read_only_content_length() {
        let parsed = parse_response_head_for_middleware(
            b"HTTP/1.1 206 Partial Content\r\n\
              Content-Length: 5\r\n\
              Content-Encoding: gzip\r\n\
              Content-Range: bytes 0-4/10\r\n\
              Connection: x-hop\r\n\
              X-Hop: omitted\r\n\r\n",
        )
        .expect("parse response head");

        assert_eq!(
            parsed.headers,
            vec![
                HttpHeader {
                    name: "content-length".into(),
                    value: "5".into(),
                },
                HttpHeader {
                    name: "content-encoding".into(),
                    value: "gzip".into(),
                },
                HttpHeader {
                    name: "content-range".into(),
                    value: "bytes 0-4/10".into(),
                },
            ]
        );

        let nominated = parse_response_head_for_middleware(
            b"HTTP/1.1 200 OK\r\nConnection: Content-Length\r\nContent-Length: 5\r\n\r\n",
        )
        .expect("parse nominated response head");
        assert!(nominated.headers.is_empty());
    }

    #[test]
    fn response_middleware_serializes_only_relay_owned_framing() {
        let headers = vec![
            HttpHeader {
                name: "content-length".into(),
                value: "999".into(),
            },
            HttpHeader {
                name: "Content-Length".into(),
                value: "998".into(),
            },
            HttpHeader {
                name: "content-type".into(),
                value: "text/plain".into(),
            },
        ];

        for (framing, expected) in [
            (
                ResponseFraming::Preserve(BodyLength::ContentLength(5)),
                Some("Content-Length: 5\r\n"),
            ),
            (
                ResponseFraming::ContentLength(9),
                Some("Content-Length: 9\r\n"),
            ),
            (ResponseFraming::Chunked, None),
            (ResponseFraming::Preserve(BodyLength::None), None),
        ] {
            let serialized = String::from_utf8(serialize_response_head(
                "HTTP/1.1 200 OK",
                &headers,
                &[],
                framing,
                false,
                &[],
            ))
            .expect("serialized response head");

            assert_eq!(
                serialized
                    .lines()
                    .filter(|line| line.to_ascii_lowercase().starts_with("content-length:"))
                    .count(),
                usize::from(expected.is_some())
            );
            if let Some(expected) = expected {
                assert!(serialized.contains(expected));
            }
            if matches!(framing, ResponseFraming::Chunked) {
                assert!(serialized.contains("Transfer-Encoding: chunked\r\n"));
            }
        }
    }
}
