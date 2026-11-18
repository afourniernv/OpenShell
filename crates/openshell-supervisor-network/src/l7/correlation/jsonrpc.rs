// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded observations of actual JSON-RPC inspection passes, not execution.

use super::{RequestTrace, current_request};
use crate::l7::jsonrpc::{
    JsonRpcInspectionError, JsonRpcInspectionErrorKind, JsonRpcInspectionMode,
    JsonRpcInspectionOptions, JsonRpcRequestInfo,
};

const MAX_RECORDED_CALLS: usize = 64;

pub fn inspect(
    options: JsonRpcInspectionOptions,
    operation: impl FnOnce() -> JsonRpcRequestInfo,
) -> JsonRpcRequestInfo {
    let span = current_request()
        .filter(|scope| scope.inspected)
        .and_then(|scope| {
            scope
                .trace
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .map(RequestTrace::mcp_inspection_span)
        })
        .unwrap_or_else(tracing::Span::none);
    if span.is_disabled() {
        return operation();
    }

    let info = span.in_scope(operation);
    span.record(
        "openshell.mcp.protocol",
        match options.mode {
            JsonRpcInspectionMode::Mcp => "mcp",
            JsonRpcInspectionMode::JsonRpc => "jsonrpc",
        },
    );
    if let Some(revision) = info.mcp_revision.or(options.mcp_revision) {
        span.record("openshell.mcp.revision", revision.as_str());
    }
    span.record(
        "openshell.mcp.inspection.shape",
        if info.receive_stream {
            "receive_stream"
        } else if info.is_batch {
            "batch"
        } else {
            "single"
        },
    );
    let (requests, notifications) = info.calls.iter().take(MAX_RECORDED_CALLS).fold(
        (0_i64, 0_i64),
        |(requests, notifications), call| {
            if call.is_notification {
                (requests, notifications + 1)
            } else {
                (requests + 1, notifications)
            }
        },
    );
    span.record("openshell.mcp.request_count", requests);
    span.record("openshell.mcp.notification_count", notifications);
    span.record("openshell.mcp.has_response", info.has_response);
    span.record(
        "openshell.mcp.counts_truncated",
        info.calls.len() > MAX_RECORDED_CALLS,
    );

    let (outcome, failure) = match info.error.as_ref().map(JsonRpcInspectionError::kind) {
        None => ("accepted", None),
        // Transport selection may re-inspect under the selected profile.
        Some(JsonRpcInspectionErrorKind::RevisionNotSelected) => ("revision_required", None),
        Some(JsonRpcInspectionErrorKind::InvalidJson) => ("rejected", Some("invalid_json")),
        Some(JsonRpcInspectionErrorKind::InvalidMessage) => ("rejected", Some("invalid_message")),
        Some(JsonRpcInspectionErrorKind::McpProfileViolation) => {
            ("rejected", Some("mcp_profile_violation"))
        }
        Some(JsonRpcInspectionErrorKind::McpLifecycleViolation) => {
            ("rejected", Some("mcp_lifecycle_violation"))
        }
    };
    span.record("openshell.mcp.inspection.outcome", outcome);
    if let Some(reason) = failure {
        span.record("openshell.mcp.inspection.failure_kind", reason);
        span.record("openshell.request.failure_reason", reason);
        span.record("otel.status_code", "ERROR");
    } else {
        span.record("otel.status_code", "OK");
    }
    info
}

pub fn receive_stream(options: JsonRpcInspectionOptions) -> JsonRpcRequestInfo {
    inspect(options, JsonRpcRequestInfo::receive_stream)
}

#[cfg(test)]
mod tests;
