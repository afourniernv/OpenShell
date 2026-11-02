// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-request correlation for HTTP enforcement events.

use std::{
    collections::BTreeSet,
    future::Future,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use http::{HeaderMap, HeaderValue};
use openshell_ocsf::{
    ActionId, ActivityId, DispositionId, Endpoint, HttpActivityBuilder, HttpRequest, HttpResponse,
    OcsfEvent, SeverityId, StatusId, ocsf_emit,
};
use tracing::Instrument as _;

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;
use crate::l7::{L7Protocol, jsonrpc};

const JSONRPC_CORRELATED_COUNT_LIMIT: usize = 64;

#[derive(Debug)]
pub struct RequestCorrelation {
    request_id: String,
    span: tracing::Span,
    completed: AtomicBool,
    resources: Mutex<ResourceCorrelationState>,
    jsonrpc: Mutex<JsonRpcCorrelationState>,
    middleware_context: MiddlewareEventContext,
    middleware: Mutex<MiddlewareState>,
    credential: Mutex<CredentialState>,
    response: Mutex<ResponseDeliveryState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResponseSelectionCause {
    UpstreamResponse,
    UpstreamIoError,
    UpstreamTruncated,
    UpstreamIdleTimeout,
    UpstreamProtocolError,
    MiddlewareDenied,
    MiddlewareFailed,
    PolicyReloaded,
    Cancelled,
    PlatformError,
    Unknown,
}

impl ResponseSelectionCause {
    fn as_str(self) -> &'static str {
        match self {
            Self::UpstreamResponse => "upstream_response",
            Self::UpstreamIoError => "upstream_io_error",
            Self::UpstreamTruncated => "upstream_truncated",
            Self::UpstreamIdleTimeout => "upstream_idle_timeout",
            Self::UpstreamProtocolError => "upstream_protocol_error",
            Self::MiddlewareDenied => "middleware_denied",
            Self::MiddlewareFailed => "middleware_failed",
            Self::PolicyReloaded => "policy_reloaded",
            Self::Cancelled => "cancelled",
            Self::PlatformError => "platform_error",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResponseDeliveryOutcome {
    Complete,
    DownstreamIoError,
    CancelledOrIncomplete,
}

impl ResponseDeliveryOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::DownstreamIoError => "downstream_io_error",
            Self::CancelledOrIncomplete => "cancelled_or_incomplete",
        }
    }
}

#[derive(Debug, Default)]
struct ResponseDeliveryState {
    lifecycle_started: bool,
    upstream_status: Option<u16>,
    effective_status: Option<u16>,
    selection_cause: Option<ResponseSelectionCause>,
    http_outcome: Option<&'static str>,
    error_stage: Option<&'static str>,
    pending_delivery: Option<ResponseDeliveryOutcome>,
    interim_bytes_forwarded: u64,
    delivery_started: bool,
    partial_delivery: bool,
    terminal: Option<ResponseDeliveryOutcome>,
}

#[derive(Debug, Clone, Copy)]
struct ResponseDeliverySnapshot {
    upstream_status: Option<u16>,
    effective_status: Option<u16>,
    selection_cause: ResponseSelectionCause,
    interim_bytes_forwarded: u64,
    delivery_started: bool,
    partial_delivery: bool,
    delivery_outcome: ResponseDeliveryOutcome,
    http_outcome: &'static str,
    error_stage: Option<&'static str>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ResourceCorrelationState {
    policy_runtime_generation: Option<u64>,
    policy_endpoint: Option<PolicyEndpointResources>,
    provider_credential: Option<ProviderCredentialResources>,
}

#[derive(Debug, PartialEq, Eq)]
struct PolicyEndpointResources {
    policy_hash: String,
    endpoint_id: String,
}

#[derive(Debug, PartialEq, Eq)]
struct ProviderCredentialResources {
    environment_revision: String,
    installation_id: String,
}

#[derive(Debug, Default)]
struct JsonRpcCorrelationState {
    effective: Option<JsonRpcEffectiveSummary>,
    selected_mcp_revision: Option<openshell_core::mcp::McpProtocolVersion>,
    mcp_tools_call_observed: bool,
}

#[derive(Debug, Clone, Copy)]
struct JsonRpcEffectiveSummary {
    protocol: &'static str,
    message_kind: &'static str,
    inspection_outcome: &'static str,
    call_count: i64,
    notification_count: i64,
    counts_truncated: bool,
    has_response: bool,
    mcp_revision: Option<openshell_core::mcp::McpProtocolVersion>,
    mcp_method_classification: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredentialMechanism {
    StaticPlaceholder,
    TokenGrant,
    SigV4,
}

impl CredentialMechanism {
    const ALL: [Self; 3] = [Self::StaticPlaceholder, Self::TokenGrant, Self::SigV4];

    fn as_str(self) -> &'static str {
        match self {
            Self::StaticPlaceholder => "static_placeholder",
            Self::TokenGrant => "token_grant",
            Self::SigV4 => "sigv4",
        }
    }

    fn span_outcome_field(self) -> &'static str {
        match self {
            Self::StaticPlaceholder => "openshell.credential.static_placeholder.outcome",
            Self::TokenGrant => "openshell.credential.token_grant.outcome",
            Self::SigV4 => "openshell.credential.sigv4.outcome",
        }
    }

    fn ocsf_outcome_field(self) -> &'static str {
        match self {
            Self::StaticPlaceholder => "credential_static_placeholder_outcome",
            Self::TokenGrant => "credential_token_grant_outcome",
            Self::SigV4 => "credential_sigv4_outcome",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredentialSurface {
    Path,
    Query,
    Header,
    Body,
    Signature,
}

impl CredentialSurface {
    fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Query => "query",
            Self::Header => "header",
            Self::Body => "body",
            Self::Signature => "signature",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialOutcome {
    Prepared,
    Withheld,
    Denied,
    Unavailable,
    Stale,
    Incomplete,
}

impl CredentialOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Withheld => "withheld",
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
            Self::Stale => "stale",
            Self::Incomplete => "incomplete",
        }
    }

    fn precedence(self) -> u8 {
        match self {
            Self::Incomplete => 0,
            Self::Withheld => 1,
            Self::Prepared => 2,
            Self::Unavailable => 3,
            Self::Stale => 4,
            Self::Denied => 5,
        }
    }
}

#[derive(Debug, Default)]
struct CredentialState {
    selected: bool,
    mechanisms: BTreeSet<CredentialMechanism>,
    surfaces: BTreeSet<CredentialSurface>,
    outcome: Option<CredentialOutcome>,
    mechanism_outcomes: std::collections::BTreeMap<CredentialMechanism, CredentialOutcome>,
}

impl CredentialState {
    fn observe(&mut self, mechanism: CredentialMechanism, surface: CredentialSurface) {
        self.selected = true;
        self.mechanisms.insert(mechanism);
        self.surfaces.insert(surface);
    }

    fn complete(&mut self, outcome: CredentialOutcome) {
        if !self.selected && outcome != CredentialOutcome::Stale {
            return;
        }
        self.selected = true;

        merge_optional_credential_outcome(&mut self.outcome, outcome);
        if outcome == CredentialOutcome::Stale {
            for mechanism in &self.mechanisms {
                merge_credential_outcome(
                    self.mechanism_outcomes.entry(*mechanism).or_insert(outcome),
                    outcome,
                );
            }
        }
    }

    fn complete_mechanism(&mut self, mechanism: CredentialMechanism, outcome: CredentialOutcome) {
        if !self.mechanisms.contains(&mechanism) {
            return;
        }

        merge_optional_credential_outcome(&mut self.outcome, outcome);
        merge_credential_outcome(
            self.mechanism_outcomes.entry(mechanism).or_insert(outcome),
            outcome,
        );
    }

    fn snapshot(&self) -> Option<CredentialSnapshot> {
        self.selected.then(|| {
            let mechanism_outcomes = self
                .mechanisms
                .iter()
                .map(|mechanism| {
                    (
                        *mechanism,
                        self.mechanism_outcomes
                            .get(mechanism)
                            .copied()
                            .unwrap_or(CredentialOutcome::Incomplete),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>();
            let has_incomplete = mechanism_outcomes
                .values()
                .any(|outcome| *outcome == CredentialOutcome::Incomplete);
            let outcome = match self.outcome {
                Some(
                    outcome @ (CredentialOutcome::Denied
                    | CredentialOutcome::Stale
                    | CredentialOutcome::Unavailable),
                ) => outcome,
                _ if has_incomplete => CredentialOutcome::Incomplete,
                Some(outcome) => outcome,
                None => CredentialOutcome::Incomplete,
            };

            CredentialSnapshot {
                mechanisms: sorted_values(&self.mechanisms, CredentialMechanism::as_str),
                surfaces: sorted_values(&self.surfaces, CredentialSurface::as_str),
                outcome,
                mechanism_outcomes,
            }
        })
    }
}

fn merge_credential_outcome(current: &mut CredentialOutcome, outcome: CredentialOutcome) {
    if outcome.precedence() > current.precedence() {
        *current = outcome;
    }
}

fn merge_optional_credential_outcome(
    current: &mut Option<CredentialOutcome>,
    outcome: CredentialOutcome,
) {
    if current.is_none_or(|current| outcome.precedence() > current.precedence()) {
        *current = Some(outcome);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CredentialSnapshot {
    mechanisms: String,
    surfaces: String,
    outcome: CredentialOutcome,
    mechanism_outcomes: std::collections::BTreeMap<CredentialMechanism, CredentialOutcome>,
}

fn sorted_values<T: Copy + Ord>(values: &BTreeSet<T>, as_str: fn(T) -> &'static str) -> String {
    let mut values = values.iter().copied().map(as_str).collect::<Vec<_>>();
    values.sort_unstable();
    values.join(",")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiddlewarePhase {
    Request,
    Response,
}

impl MiddlewarePhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiddlewareOutcome {
    Allowed,
    Denied,
    PlatformError,
}

impl MiddlewareOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::PlatformError => "platform_error",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct MiddlewareObservation {
    pub mutated: bool,
    pub fail_open: bool,
    pub fail_closed: bool,
    pub admission_exhausted: bool,
    pub diagnostics_truncated: bool,
    pub delivery_started: bool,
    pub partial_delivery: bool,
}

impl MiddlewareObservation {
    fn merge(&mut self, other: Self) {
        self.mutated |= other.mutated;
        self.fail_open |= other.fail_open;
        self.fail_closed |= other.fail_closed;
        self.admission_exhausted |= other.admission_exhausted;
        self.diagnostics_truncated |= other.diagnostics_truncated;
        self.delivery_started |= other.delivery_started;
        self.partial_delivery |= other.partial_delivery;
    }
}

#[derive(Debug)]
struct MiddlewareEventContext {
    method: &'static str,
    host: String,
    port: u16,
    policy_name: String,
}

#[derive(Debug, Default)]
struct MiddlewareState {
    request: MiddlewarePhaseState,
    response: MiddlewarePhaseState,
}

impl MiddlewareState {
    fn phase_mut(&mut self, phase: MiddlewarePhase) -> &mut MiddlewarePhaseState {
        match phase {
            MiddlewarePhase::Request => &mut self.request,
            MiddlewarePhase::Response => &mut self.response,
        }
    }
}

#[derive(Debug, Default)]
struct MiddlewarePhaseState {
    selected: bool,
    completed: bool,
    observation: MiddlewareObservation,
}

impl RequestCorrelation {
    #[must_use]
    pub(crate) fn new(request: &L7Request, ctx: &L7EvalContext) -> Self {
        Self::build(request, ctx, uuid::Uuid::new_v4().to_string())
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_request_id(
        request: &L7Request,
        ctx: &L7EvalContext,
        request_id: String,
    ) -> Self {
        Self::build(request, ctx, request_id)
    }

    fn build(request: &L7Request, ctx: &L7EvalContext, request_id: String) -> Self {
        let method = bounded_http_method(&request.action);
        let sandbox_context = openshell_ocsf::ctx::ctx();
        let span = tracing::info_span!(
            "openshell.http.enforcement",
            "openshell.request.id" = %request_id,
            "openshell.sandbox.id" = tracing::field::Empty,
            "openshell.policy.runtime_generation" = tracing::field::Empty,
            "openshell.policy.hash" = tracing::field::Empty,
            "openshell.endpoint.id" = tracing::field::Empty,
            "openshell.provider.environment.revision" = tracing::field::Empty,
            "openshell.provider.credential.installation.id" = tracing::field::Empty,
            "http.request.method" = method,
            "server.address" = %ctx.host,
            "server.port" = ctx.port,
            "openshell.target.reached" = false,
            "openshell.request.delivery_started" = false,
            "openshell.policy.decision" = tracing::field::Empty,
            "openshell.enforcement.action" = tracing::field::Empty,
            "openshell.http.outcome" = tracing::field::Empty,
            "http.response.status_code" = tracing::field::Empty,
            "openshell.upstream.http.response.status_code" = tracing::field::Empty,
            "openshell.response.interim_delivery_started" = false,
            "openshell.response.interim_bytes_forwarded" = 0_i64,
            "openshell.response.selection_cause" = tracing::field::Empty,
            "openshell.response.delivery_started" = false,
            "openshell.response.partial_delivery" = false,
            "openshell.response.delivery_outcome" = tracing::field::Empty,
            "openshell.error.stage" = tracing::field::Empty,
            "openshell.middleware.request.outcome" = tracing::field::Empty,
            "openshell.middleware.request.mutated" = tracing::field::Empty,
            "openshell.middleware.request.fail_open" = tracing::field::Empty,
            "openshell.middleware.request.fail_closed" = tracing::field::Empty,
            "openshell.middleware.request.admission_exhausted" = tracing::field::Empty,
            "openshell.middleware.response.outcome" = tracing::field::Empty,
            "openshell.middleware.response.mutated" = tracing::field::Empty,
            "openshell.middleware.response.fail_open" = tracing::field::Empty,
            "openshell.middleware.response.fail_closed" = tracing::field::Empty,
            "openshell.middleware.response.admission_exhausted" = tracing::field::Empty,
            "openshell.middleware.response.diagnostics_truncated" = tracing::field::Empty,
            "openshell.middleware.response.delivery_started" = tracing::field::Empty,
            "openshell.middleware.response.partial_delivery" = tracing::field::Empty,
            "openshell.credential.outcome" = tracing::field::Empty,
            "openshell.credential.mechanisms" = tracing::field::Empty,
            "openshell.credential.surfaces" = tracing::field::Empty,
            "openshell.credential.static_placeholder.outcome" = tracing::field::Empty,
            "openshell.credential.token_grant.outcome" = tracing::field::Empty,
            "openshell.credential.sigv4.outcome" = tracing::field::Empty,
            "openshell.l7.protocol" = tracing::field::Empty,
            "openshell.jsonrpc.effective.message_kind" = tracing::field::Empty,
            "openshell.jsonrpc.effective.inspection_outcome" = tracing::field::Empty,
            "openshell.jsonrpc.effective.call_count" = tracing::field::Empty,
            "openshell.jsonrpc.effective.notification_count" = tracing::field::Empty,
            "openshell.jsonrpc.effective.counts_truncated" = tracing::field::Empty,
            "openshell.jsonrpc.effective.has_response" = tracing::field::Empty,
            "openshell.mcp.selected_protocol_revision" = tracing::field::Empty,
            "openshell.mcp.effective.protocol_revision" = tracing::field::Empty,
            "openshell.mcp.effective.method_classification" = tracing::field::Empty,
            "openshell.mcp.tools_call_observed" = tracing::field::Empty,
        );
        let headers = trace_headers(&request.raw_header);
        let _ = openshell_otel::set_parent_from_headers(&span, &headers);
        if !sandbox_context.sandbox_id.is_empty() {
            span.record("openshell.sandbox.id", sandbox_context.sandbox_id.as_str());
        }
        Self {
            request_id,
            span,
            completed: AtomicBool::new(false),
            resources: Mutex::new(ResourceCorrelationState::default()),
            jsonrpc: Mutex::new(JsonRpcCorrelationState::default()),
            middleware_context: MiddlewareEventContext {
                method,
                host: ctx.host.clone(),
                port: ctx.port,
                policy_name: ctx.policy_name.clone(),
            },
            middleware: Mutex::new(MiddlewareState::default()),
            credential: Mutex::new(CredentialState::default()),
            response: Mutex::new(ResponseDeliveryState::default()),
        }
    }

    #[must_use]
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(crate) async fn within_span<F>(correlation: Option<&Self>, future: F) -> F::Output
    where
        F: Future,
    {
        match correlation {
            Some(correlation) => future.instrument(correlation.span.clone()).await,
            None => future.await,
        }
    }

    pub(crate) fn record_policy_decision(&self, decision: &str) {
        self.span.record("openshell.policy.decision", decision);
    }

    pub(crate) fn record_enforcement_action(&self, action: &str) {
        self.span.record("openshell.enforcement.action", action);
    }

    pub(crate) fn record_final_http_outcome(&self, outcome: &str) {
        self.span.record("openshell.http.outcome", outcome);
        self.completed.store(true, Ordering::Release);
    }

    pub(crate) fn record_response_status(&self, status: u16) {
        self.span.record("http.response.status_code", status);
        let mut response = self
            .response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        response.effective_status = Some(status);
    }

    pub(crate) fn record_upstream_response_status(&self, status: u16) {
        let recorded = {
            let mut response = self
                .response
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            response.lifecycle_started = true;
            if response.upstream_status.is_some() {
                false
            } else {
                response.upstream_status = Some(status);
                true
            }
        };
        if recorded {
            self.span
                .record("openshell.upstream.http.response.status_code", status);
        }
    }

    pub(crate) fn record_target_reached(&self) {
        self.span.record("openshell.target.reached", true);
    }

    pub(crate) fn record_request_delivery_started(&self) {
        self.span.record("openshell.request.delivery_started", true);
    }

    pub(crate) fn record_error_stage(&self, stage: &str) {
        self.span.record("openshell.error.stage", stage);
    }

    pub(crate) fn record_policy_runtime_generation(&self, generation: u64) {
        {
            let mut resources = self
                .resources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if resources.policy_runtime_generation.is_some() {
                return;
            }
            resources.policy_runtime_generation = Some(generation);
        }
        self.span.record(
            "openshell.policy.runtime_generation",
            tracing::field::display(generation),
        );
    }

    pub(crate) fn record_selected_policy_endpoint(&self, policy_hash: &str, endpoint_id: &str) {
        {
            let mut resources = self
                .resources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if resources.policy_endpoint.is_some() {
                return;
            }
            let Some(policy_endpoint) = policy_endpoint_resources(policy_hash, endpoint_id) else {
                return;
            };
            resources.policy_endpoint = Some(policy_endpoint);
        }
        self.span.record("openshell.policy.hash", policy_hash);
        self.span.record("openshell.endpoint.id", endpoint_id);
    }

    pub(crate) fn record_provider_credential_snapshot(
        &self,
        snapshot: &openshell_core::provider_credentials::ProviderCredentialSnapshot,
    ) {
        let installation_id = {
            let mut resources = self
                .resources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if resources.provider_credential.is_some() {
                return;
            }
            let Ok(installation_id) = uuid::Uuid::parse_str(&snapshot.installation_id) else {
                return;
            };
            resources.provider_credential = Some(ProviderCredentialResources {
                environment_revision: snapshot.revision.to_string(),
                installation_id: installation_id.hyphenated().to_string(),
            });
            installation_id
        };
        self.span.record(
            "openshell.provider.environment.revision",
            tracing::field::display(snapshot.revision),
        );
        self.span.record(
            "openshell.provider.credential.installation.id",
            tracing::field::display(installation_id.hyphenated()),
        );
    }

    pub(crate) fn record_effective_jsonrpc_summary(
        &self,
        protocol: L7Protocol,
        info: &jsonrpc::JsonRpcRequestInfo,
    ) {
        let protocol_name = match protocol {
            L7Protocol::JsonRpc => "jsonrpc",
            L7Protocol::Mcp => "mcp",
            _ => return,
        };
        let call_count = info
            .calls
            .iter()
            .filter(|call| !call.is_notification)
            .count();
        let notification_count = info
            .calls
            .iter()
            .filter(|call| call.is_notification)
            .count();
        let counts_truncated = call_count > JSONRPC_CORRELATED_COUNT_LIMIT
            || notification_count > JSONRPC_CORRELATED_COUNT_LIMIT;

        let mut state = self
            .jsonrpc
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if protocol == L7Protocol::Mcp {
            if let Some(revision) = info.mcp_revision {
                state.selected_mcp_revision = Some(revision);
            }
            state.mcp_tools_call_observed |=
                info.calls.iter().any(|call| call.method == "tools/call");
        }
        state.effective = Some(JsonRpcEffectiveSummary {
            protocol: protocol_name,
            message_kind: jsonrpc_message_kind(info, call_count, notification_count),
            inspection_outcome: jsonrpc_inspection_outcome(info),
            call_count: i64::try_from(call_count.min(JSONRPC_CORRELATED_COUNT_LIMIT))
                .expect("bounded JSON-RPC call count fits i64"),
            notification_count: i64::try_from(
                notification_count.min(JSONRPC_CORRELATED_COUNT_LIMIT),
            )
            .expect("bounded JSON-RPC notification count fits i64"),
            counts_truncated,
            has_response: info.has_response,
            mcp_revision: if protocol == L7Protocol::Mcp {
                info.mcp_revision
            } else {
                None
            },
            mcp_method_classification: (protocol == L7Protocol::Mcp)
                .then(|| mcp_method_classification(info)),
        });
    }

    pub(crate) fn observe_credential(
        &self,
        mechanism: CredentialMechanism,
        surface: CredentialSurface,
    ) {
        self.credential
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observe(mechanism, surface);
    }

    #[must_use]
    pub(crate) fn has_credential_mechanism(&self, mechanism: CredentialMechanism) -> bool {
        self.credential
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .mechanisms
            .contains(&mechanism)
    }

    pub(crate) fn complete_credential(&self, outcome: CredentialOutcome) {
        self.credential
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .complete(outcome);
    }

    pub(crate) fn complete_credential_mechanism(
        &self,
        mechanism: CredentialMechanism,
        outcome: CredentialOutcome,
    ) {
        self.credential
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .complete_mechanism(mechanism, outcome);
    }

    pub(super) fn begin_response_lifecycle(&self) {
        self.response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .lifecycle_started = true;
    }

    pub(super) fn record_response_selection(
        &self,
        cause: ResponseSelectionCause,
        http_outcome: &'static str,
        error_stage: Option<&'static str>,
    ) {
        let mut response = self
            .response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        response.lifecycle_started = true;
        response.selection_cause = Some(cause);
        response.http_outcome = Some(http_outcome);
        response.error_stage = error_stage;
    }

    pub(super) fn record_pending_response_delivery(&self, outcome: ResponseDeliveryOutcome) {
        self.response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_delivery = Some(outcome);
    }

    pub(super) fn record_interim_response_delivery(&self, accepted: usize) {
        if accepted == 0 {
            return;
        }
        let bytes = {
            let mut response = self
                .response
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            response.lifecycle_started = true;
            response.interim_bytes_forwarded = response
                .interim_bytes_forwarded
                .saturating_add(u64::try_from(accepted).unwrap_or(u64::MAX));
            response.interim_bytes_forwarded
        };
        self.span
            .record("openshell.response.interim_delivery_started", true);
        self.span.record(
            "openshell.response.interim_bytes_forwarded",
            i64::try_from(bytes).unwrap_or(i64::MAX),
        );
    }

    pub(crate) fn record_response_delivery_started(&self) {
        {
            let mut response = self
                .response
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            response.lifecycle_started = true;
            response.delivery_started = true;
        }
        self.span
            .record("openshell.response.delivery_started", true);
    }

    pub(crate) fn record_response_partial_delivery(&self) -> bool {
        {
            let mut response = self
                .response
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !response.delivery_started {
                return false;
            }
            response.partial_delivery = true;
        }
        self.span
            .record("openshell.response.partial_delivery", true);
        true
    }

    pub(super) fn complete_pending_response_delivery(&self) {
        let delivery = self
            .response
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pending_delivery
            .unwrap_or(ResponseDeliveryOutcome::Complete);
        self.complete_response_delivery(delivery, None, None, None);
    }

    pub(super) fn complete_response_failure(
        &self,
        delivery: ResponseDeliveryOutcome,
        cause: Option<ResponseSelectionCause>,
        http_outcome: &'static str,
        error_stage: &'static str,
    ) {
        self.complete_response_delivery(delivery, cause, Some(http_outcome), Some(error_stage));
    }

    fn complete_response_delivery(
        &self,
        delivery: ResponseDeliveryOutcome,
        cause: Option<ResponseSelectionCause>,
        http_outcome: Option<&'static str>,
        error_stage: Option<&'static str>,
    ) {
        let snapshot = {
            let mut response = self
                .response
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if response.terminal.is_some() {
                return;
            }
            response.lifecycle_started = true;
            if let Some(cause) = cause {
                response.selection_cause = Some(cause);
            }
            if let Some(http_outcome) = http_outcome {
                response.http_outcome = Some(http_outcome);
            }
            if let Some(error_stage) = error_stage {
                response.error_stage = Some(error_stage);
            }
            if delivery != ResponseDeliveryOutcome::Complete && response.delivery_started {
                response.partial_delivery = true;
            }
            response.terminal = Some(delivery);
            ResponseDeliverySnapshot {
                upstream_status: response.upstream_status,
                effective_status: response.effective_status,
                selection_cause: response
                    .selection_cause
                    .unwrap_or(ResponseSelectionCause::Unknown),
                interim_bytes_forwarded: response.interim_bytes_forwarded,
                delivery_started: response.delivery_started,
                partial_delivery: response.partial_delivery,
                delivery_outcome: delivery,
                http_outcome: response.http_outcome.unwrap_or("incomplete"),
                error_stage: response.error_stage,
            }
        };

        self.span.record(
            "openshell.response.selection_cause",
            snapshot.selection_cause.as_str(),
        );
        self.span
            .record("openshell.response.delivery_outcome", delivery.as_str());
        self.span.record(
            "openshell.response.delivery_started",
            snapshot.delivery_started,
        );
        self.span.record(
            "openshell.response.partial_delivery",
            snapshot.partial_delivery,
        );
        self.span
            .record("openshell.http.outcome", snapshot.http_outcome);
        if let Some(stage) = snapshot.error_stage {
            self.span.record("openshell.error.stage", stage);
        }
        self.completed.store(true, Ordering::Release);
        self.emit(response_terminal_event(&self.middleware_context, snapshot));
    }

    pub(crate) fn observe_middleware(
        &self,
        phase: MiddlewarePhase,
        observation: MiddlewareObservation,
    ) {
        let mut middleware = self
            .middleware
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = middleware.phase_mut(phase);
        if state.completed {
            return;
        }
        state.selected = true;
        state.observation.merge(observation);
    }

    pub(crate) fn complete_middleware(&self, phase: MiddlewarePhase, outcome: MiddlewareOutcome) {
        self.finish_middleware(phase, outcome.as_str());
    }

    fn finish_middleware(&self, phase: MiddlewarePhase, outcome: &'static str) {
        let observation = {
            let mut middleware = self
                .middleware
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let state = middleware.phase_mut(phase);
            if state.completed {
                return;
            }
            state.selected = true;
            state.completed = true;
            state.observation
        };

        self.record_middleware_attributes(phase, outcome, observation);
        self.emit(middleware_aggregate_event(
            &self.middleware_context,
            phase,
            outcome,
            observation,
        ));
    }

    fn record_middleware_attributes(
        &self,
        phase: MiddlewarePhase,
        outcome: &'static str,
        observation: MiddlewareObservation,
    ) {
        match phase {
            MiddlewarePhase::Request => {
                let fields = (
                    "openshell.middleware.request.outcome",
                    "openshell.middleware.request.mutated",
                    "openshell.middleware.request.fail_open",
                    "openshell.middleware.request.fail_closed",
                    "openshell.middleware.request.admission_exhausted",
                );
                self.span.record(fields.0, outcome);
                self.span.record(fields.1, observation.mutated);
                self.span.record(fields.2, observation.fail_open);
                self.span.record(fields.3, observation.fail_closed);
                self.span.record(fields.4, observation.admission_exhausted);
            }
            MiddlewarePhase::Response => {
                let fields = (
                    "openshell.middleware.response.outcome",
                    "openshell.middleware.response.mutated",
                    "openshell.middleware.response.fail_open",
                    "openshell.middleware.response.fail_closed",
                    "openshell.middleware.response.admission_exhausted",
                    "openshell.middleware.response.diagnostics_truncated",
                    "openshell.middleware.response.delivery_started",
                    "openshell.middleware.response.partial_delivery",
                );
                self.span.record(fields.0, outcome);
                self.span.record(fields.1, observation.mutated);
                self.span.record(fields.2, observation.fail_open);
                self.span.record(fields.3, observation.fail_closed);
                self.span.record(fields.4, observation.admission_exhausted);
                self.span
                    .record(fields.5, observation.diagnostics_truncated);
                self.span.record(fields.6, observation.delivery_started);
                self.span.record(fields.7, observation.partial_delivery);
            }
        }
    }

    fn record_credential_attributes(&self, snapshot: &CredentialSnapshot) {
        self.span
            .record("openshell.credential.outcome", snapshot.outcome.as_str());
        if !snapshot.mechanisms.is_empty() {
            self.span.record(
                "openshell.credential.mechanisms",
                snapshot.mechanisms.as_str(),
            );
        }
        if !snapshot.surfaces.is_empty() {
            self.span
                .record("openshell.credential.surfaces", snapshot.surfaces.as_str());
        }
        for mechanism in CredentialMechanism::ALL {
            if let Some(outcome) = snapshot.mechanism_outcomes.get(&mechanism) {
                self.span
                    .record(mechanism.span_outcome_field(), outcome.as_str());
            }
        }
    }

    fn record_jsonrpc_attributes(&self) {
        let state = self
            .jsonrpc
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(summary) = state.effective else {
            return;
        };

        self.span.record("openshell.l7.protocol", summary.protocol);
        self.span.record(
            "openshell.jsonrpc.effective.message_kind",
            summary.message_kind,
        );
        self.span.record(
            "openshell.jsonrpc.effective.inspection_outcome",
            summary.inspection_outcome,
        );
        self.span
            .record("openshell.jsonrpc.effective.call_count", summary.call_count);
        self.span.record(
            "openshell.jsonrpc.effective.notification_count",
            summary.notification_count,
        );
        self.span.record(
            "openshell.jsonrpc.effective.counts_truncated",
            summary.counts_truncated,
        );
        self.span.record(
            "openshell.jsonrpc.effective.has_response",
            summary.has_response,
        );

        if summary.protocol == "mcp" {
            if let Some(revision) = state.selected_mcp_revision {
                self.span.record(
                    "openshell.mcp.selected_protocol_revision",
                    revision.as_str(),
                );
            }
            if let Some(revision) = summary.mcp_revision {
                self.span.record(
                    "openshell.mcp.effective.protocol_revision",
                    revision.as_str(),
                );
            }
            if let Some(classification) = summary.mcp_method_classification {
                self.span.record(
                    "openshell.mcp.effective.method_classification",
                    classification,
                );
            }
            self.span.record(
                "openshell.mcp.tools_call_observed",
                state.mcp_tools_call_observed,
            );
        }
    }

    pub(crate) fn emit(&self, mut event: OcsfEvent) {
        event.set_correlation_uid(self.request_id.clone());
        {
            let resources = self
                .resources
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            add_resource_fields(&mut event, &resources);
        }
        openshell_otel::with_span_context(&self.span, || {
            self.span.in_scope(|| ocsf_emit!(event));
        });
    }
}

pub fn emit_ocsf(correlation: Option<&RequestCorrelation>, event: OcsfEvent) {
    if let Some(correlation) = correlation {
        correlation.emit(event);
    } else {
        ocsf_emit!(event);
    }
}

fn policy_endpoint_resources(
    policy_hash: &str,
    endpoint_id: &str,
) -> Option<PolicyEndpointResources> {
    const ENDPOINT_PREFIX: &str = "endpoint:v1:";
    if !is_lower_hex_digest(policy_hash)
        || endpoint_id
            .strip_prefix(ENDPOINT_PREFIX)
            .is_none_or(|digest| !is_lower_hex_digest(digest))
    {
        return None;
    }
    Some(PolicyEndpointResources {
        policy_hash: policy_hash.to_string(),
        endpoint_id: endpoint_id.to_string(),
    })
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn add_resource_fields(event: &mut OcsfEvent, resources: &ResourceCorrelationState) {
    if let Some(generation) = resources.policy_runtime_generation {
        event.add_unmapped("policy_runtime_generation", generation.to_string());
    }
    if let Some(policy_endpoint) = &resources.policy_endpoint {
        event.add_unmapped("policy_hash", policy_endpoint.policy_hash.clone());
        event.add_unmapped("endpoint_id", policy_endpoint.endpoint_id.clone());
    }
    if let Some(provider_credential) = &resources.provider_credential {
        event.add_unmapped(
            "provider_environment_revision",
            provider_credential.environment_revision.clone(),
        );
        event.add_unmapped(
            "provider_credential_installation_id",
            provider_credential.installation_id.clone(),
        );
    }
}

fn jsonrpc_message_kind(
    info: &jsonrpc::JsonRpcRequestInfo,
    call_count: usize,
    notification_count: usize,
) -> &'static str {
    if info.error.is_some() {
        return "invalid";
    }
    if info.receive_stream {
        return "receive_stream";
    }
    if info.is_batch {
        return match (call_count > 0, notification_count > 0, info.has_response) {
            (true, false, false) => "batch_calls",
            (false, true, false) => "batch_notifications",
            (false, false, true) => "batch_responses",
            _ => "batch_mixed",
        };
    }
    match (call_count > 0, notification_count > 0, info.has_response) {
        (true, false, false) => "call",
        (false, true, false) => "notification",
        (false, false, true) => "response",
        (false, false, false) => "empty",
        _ => "mixed",
    }
}

fn jsonrpc_inspection_outcome(info: &jsonrpc::JsonRpcRequestInfo) -> &'static str {
    match info
        .error
        .as_ref()
        .map(jsonrpc::JsonRpcInspectionError::kind)
    {
        None => "accepted",
        Some(jsonrpc::JsonRpcInspectionErrorKind::InvalidJson) => "invalid_json",
        Some(jsonrpc::JsonRpcInspectionErrorKind::InvalidMessage) => "invalid_message",
        Some(jsonrpc::JsonRpcInspectionErrorKind::RevisionNotSelected) => "revision_not_selected",
        Some(jsonrpc::JsonRpcInspectionErrorKind::McpProfileViolation) => "mcp_profile_violation",
        Some(jsonrpc::JsonRpcInspectionErrorKind::McpLifecycleViolation) => {
            "mcp_lifecycle_violation"
        }
    }
}

fn mcp_method_classification(info: &jsonrpc::JsonRpcRequestInfo) -> &'static str {
    let mut core = false;
    let mut extension = false;
    let mut unclassified = false;
    for call in &info.calls {
        match call.mcp_classification {
            Some(jsonrpc::McpMethodClassification::Available) => core = true,
            Some(jsonrpc::McpMethodClassification::Extension) => extension = true,
            None => unclassified = true,
        }
    }
    match (core, extension, unclassified) {
        (false, false, false) => "none",
        (true, false, false) => "core",
        (false, true, false) => "extension",
        (true, true, false) => "mixed",
        _ => "unclassified",
    }
}

fn middleware_aggregate_event(
    context: &MiddlewareEventContext,
    phase: MiddlewarePhase,
    outcome: &'static str,
    observation: MiddlewareObservation,
) -> OcsfEvent {
    let (action, mut disposition, mut severity, status) = match outcome {
        "allowed" => (
            ActionId::Allowed,
            DispositionId::Allowed,
            SeverityId::Informational,
            StatusId::Success,
        ),
        "denied" => (
            ActionId::Denied,
            DispositionId::Blocked,
            SeverityId::Medium,
            StatusId::Failure,
        ),
        "platform_error" => (
            ActionId::Unknown,
            DispositionId::Error,
            SeverityId::Medium,
            StatusId::Failure,
        ),
        _ => (
            ActionId::Unknown,
            DispositionId::Unknown,
            SeverityId::Low,
            StatusId::Unknown,
        ),
    };
    if observation.admission_exhausted {
        severity = SeverityId::Medium;
    } else if observation.fail_open && severity == SeverityId::Informational {
        severity = SeverityId::Low;
    }
    if observation.partial_delivery {
        disposition = DispositionId::Other;
    }
    let message = match (outcome, observation.partial_delivery) {
        ("denied", true) => "Supervisor middleware stopped a partially delivered response",
        ("platform_error", true) => "Supervisor middleware failed after response delivery started",
        ("incomplete", true) => "Supervisor middleware response ended after delivery started",
        _ => "Supervisor middleware phase completed",
    };
    HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::for_http_method(context.method))
        .action(action)
        .disposition(disposition)
        .severity(severity)
        .status(status)
        .http_request(HttpRequest {
            http_method: context.method.parse().expect("bounded HTTP method"),
            url: None,
        })
        .dst_endpoint(Endpoint::from_domain(&context.host, context.port))
        .firewall_rule(&context.policy_name, "middleware-correlation")
        .unmapped("middleware_phase", phase.as_str())
        .unmapped("middleware_outcome", outcome)
        .unmapped("mutated", observation.mutated)
        .unmapped("fail_open", observation.fail_open)
        .unmapped("fail_closed", observation.fail_closed)
        .unmapped("admission_exhausted", observation.admission_exhausted)
        .unmapped("diagnostics_truncated", observation.diagnostics_truncated)
        .unmapped("delivery_started", observation.delivery_started)
        .unmapped("partial_delivery", observation.partial_delivery)
        .message(message)
        .build()
}

fn response_terminal_event(
    context: &MiddlewareEventContext,
    snapshot: ResponseDeliverySnapshot,
) -> OcsfEvent {
    let (severity, status, message) = match snapshot.delivery_outcome {
        ResponseDeliveryOutcome::Complete => (
            SeverityId::Informational,
            StatusId::Success,
            "HTTP response delivery completed",
        ),
        ResponseDeliveryOutcome::CancelledOrIncomplete => (
            SeverityId::Low,
            StatusId::Unknown,
            "HTTP response delivery did not complete",
        ),
        ResponseDeliveryOutcome::DownstreamIoError => (
            SeverityId::Medium,
            StatusId::Failure,
            "HTTP response delivery failed downstream",
        ),
    };
    let mut event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::for_http_method(context.method))
        .action(ActionId::Observed)
        .disposition(DispositionId::Logged)
        .severity(severity)
        .status(status)
        .http_request(HttpRequest {
            http_method: context.method.parse().expect("bounded HTTP method"),
            url: None,
        })
        .dst_endpoint(Endpoint::from_domain(&context.host, context.port))
        .firewall_rule(&context.policy_name, "response-correlation")
        .unmapped("response_event_kind", "delivery_terminal")
        .unmapped(
            "response_selection_cause",
            snapshot.selection_cause.as_str(),
        )
        .unmapped(
            "response_delivery_outcome",
            snapshot.delivery_outcome.as_str(),
        )
        .unmapped(
            "interim_delivery_started",
            snapshot.interim_bytes_forwarded > 0,
        )
        .unmapped("interim_bytes_forwarded", snapshot.interim_bytes_forwarded)
        .unmapped("delivery_started", snapshot.delivery_started)
        .unmapped("partial_delivery", snapshot.partial_delivery);
    if let Some(status) = snapshot.upstream_status {
        event = event.unmapped("upstream_http_status_code", status);
    }
    if let Some(status) = snapshot.effective_status {
        event = event
            .http_response(HttpResponse { code: status })
            .unmapped("effective_http_status_code", status);
    }
    event.message(message).build()
}

fn credential_aggregate_event(
    context: &MiddlewareEventContext,
    snapshot: &CredentialSnapshot,
) -> OcsfEvent {
    let (severity, status, message) = match snapshot.outcome {
        CredentialOutcome::Prepared => (
            SeverityId::Informational,
            StatusId::Success,
            "Credential preparation completed",
        ),
        CredentialOutcome::Withheld => (
            SeverityId::Medium,
            StatusId::Success,
            "Credential use was withheld",
        ),
        CredentialOutcome::Denied => (
            SeverityId::Medium,
            StatusId::Failure,
            "Credential use was denied",
        ),
        CredentialOutcome::Unavailable => (
            SeverityId::Medium,
            StatusId::Failure,
            "Credential material was unavailable",
        ),
        CredentialOutcome::Stale => (
            SeverityId::Medium,
            StatusId::Failure,
            "Credential preparation became stale",
        ),
        CredentialOutcome::Incomplete => (
            SeverityId::Low,
            StatusId::Unknown,
            "Credential preparation did not complete",
        ),
    };
    let mut event = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
        .activity(ActivityId::for_http_method(context.method))
        .action(ActionId::Observed)
        .disposition(DispositionId::Logged)
        .severity(severity)
        .status(status)
        .http_request(HttpRequest {
            http_method: context.method.parse().expect("bounded HTTP method"),
            url: None,
        })
        .dst_endpoint(Endpoint::from_domain(&context.host, context.port))
        .firewall_rule(&context.policy_name, "credential-correlation")
        .unmapped("credential_outcome", snapshot.outcome.as_str());
    if !snapshot.mechanisms.is_empty() {
        event = event.unmapped("credential_mechanisms", snapshot.mechanisms.clone());
    }
    if !snapshot.surfaces.is_empty() {
        event = event.unmapped("credential_surfaces", snapshot.surfaces.clone());
    }
    for mechanism in CredentialMechanism::ALL {
        if let Some(outcome) = snapshot.mechanism_outcomes.get(&mechanism) {
            event = event.unmapped(mechanism.ocsf_outcome_field(), outcome.as_str());
        }
    }
    event.message(message).build()
}

fn bounded_http_method(method: &str) -> &'static str {
    [
        "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE",
    ]
    .into_iter()
    .find(|known| method.eq_ignore_ascii_case(known))
    .unwrap_or("OTHER")
}

impl Drop for RequestCorrelation {
    fn drop(&mut self) {
        let cancelled_response_cause = {
            let response = self
                .response
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (response.lifecycle_started && response.terminal.is_none())
                .then_some(response.selection_cause.is_none())
        };
        if let Some(selection_missing) = cancelled_response_cause {
            self.complete_response_failure(
                ResponseDeliveryOutcome::CancelledOrIncomplete,
                selection_missing.then_some(ResponseSelectionCause::Cancelled),
                "incomplete",
                "response_cancelled",
            );
        }
        for phase in [MiddlewarePhase::Request, MiddlewarePhase::Response] {
            let selected_and_unfinished = {
                let mut middleware = self
                    .middleware
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let state = middleware.phase_mut(phase);
                state.selected && !state.completed
            };
            if selected_and_unfinished {
                self.finish_middleware(phase, "incomplete");
            }
        }
        let credential = self
            .credential
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot();
        if let Some(snapshot) = credential {
            self.record_credential_attributes(&snapshot);
            self.emit(credential_aggregate_event(
                &self.middleware_context,
                &snapshot,
            ));
        }
        self.record_jsonrpc_attributes();
        if !self.completed.load(Ordering::Acquire) {
            self.span.record("openshell.http.outcome", "incomplete");
            self.span.record("openshell.error.stage", "unclassified");
        }
    }
}

pub fn trace_headers(raw_header: &[u8]) -> HeaderMap {
    let Some(header_end) = raw_header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 2)
    else {
        return HeaderMap::new();
    };

    let mut headers = HeaderMap::new();
    for line in raw_header[..header_end]
        .split(|byte| *byte == b'\n')
        .skip(1)
    {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(separator) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = trim_optional_whitespace(&line[..separator]);
        if !name.eq_ignore_ascii_case(b"traceparent") {
            continue;
        }
        let Ok(name) = http::HeaderName::from_bytes(name) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(trim_optional_whitespace(&line[separator + 1..]))
        else {
            continue;
        };
        if value.to_str().is_err() {
            continue;
        }
        headers.append(name, value);
    }
    headers
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> L7Request {
        L7Request {
            action: "GET".into(),
            target: "/data".into(),
            query_params: std::collections::HashMap::new(),
            raw_header: b"GET /data HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec(),
            body_length: crate::l7::provider::BodyLength::None,
        }
    }

    #[test]
    fn request_ids_are_unique_canonical_uuids() {
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };
        let first = RequestCorrelation::new(&request(), &ctx);
        let second = RequestCorrelation::new(&request(), &ctx);

        assert_ne!(first.request_id(), second.request_id());
        assert!(uuid::Uuid::parse_str(first.request_id()).is_ok());
        assert!(uuid::Uuid::parse_str(second.request_id()).is_ok());
    }

    #[test]
    fn request_span_stays_current_across_future_yields() {
        tracing::subscriber::with_default(tracing_subscriber::registry(), || {
            let correlation = RequestCorrelation::new(
                &request(),
                &L7EvalContext {
                    host: "example.test".into(),
                    port: 443,
                    ..Default::default()
                },
            );
            let request_span_id = correlation.span.id().expect("request span has an id");
            let ambient = tracing::info_span!("ambient");
            let ambient_span_id = ambient.id().expect("ambient span has an id");
            ambient.in_scope(|| {
                for selected in [Some(&correlation), None] {
                    let expected = Some(if selected.is_some() {
                        request_span_id.clone()
                    } else {
                        ambient_span_id.clone()
                    });
                    let mut yielded = false;
                    let current = futures::executor::block_on(RequestCorrelation::within_span(
                        selected,
                        futures::future::poll_fn(|cx| {
                            assert_eq!(tracing::Span::current().id(), expected);
                            if yielded {
                                std::task::Poll::Ready(tracing::Span::current().id())
                            } else {
                                yielded = true;
                                cx.waker().wake_by_ref();
                                std::task::Poll::Pending
                            }
                        }),
                    ));

                    assert_eq!(current, expected);
                    assert_eq!(tracing::Span::current().id(), ambient.id());
                }
            });
        });
    }

    #[test]
    fn extracts_only_traceparent_and_preserves_duplicates() {
        let headers = trace_headers(
            b"GET / HTTP/1.1\r\nHost: example.com\r\nX-OpenShell-Request-ID: forged\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nTraceParent: 00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01\r\ntracestate: vendor=value\r\n\r\n",
        );
        assert_eq!(headers.get_all("traceparent").iter().count(), 2);
        assert!(headers.get("tracestate").is_none());
        assert!(headers.get("x-openshell-request-id").is_none());
    }

    #[test]
    fn unrelated_obs_text_does_not_discard_valid_trace_context() {
        let headers = trace_headers(
            b"GET / HTTP/1.1\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nx-observation-note: contains traceparent: but is not a field\r\n\r\n",
        );

        assert_eq!(headers.get_all("traceparent").iter().count(), 1);
    }

    #[test]
    fn non_ascii_traceparent_is_rejected_and_tracestate_is_ignored() {
        let headers = trace_headers(
            b"GET / HTTP/1.1\r\ntraceparent: \xff\r\ntracestate: vendor=value\r\n\r\n",
        );

        assert!(headers.get("traceparent").is_none());
        assert!(headers.get("tracestate").is_none());
    }

    #[test]
    fn records_only_bounded_enforcement_outcome_fields() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };

        tracing::subscriber::with_default(subscriber, || {
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &ctx,
                "00000000-0000-4000-8000-000000000001".into(),
            );
            correlation.record_policy_decision("deny");
            correlation.record_enforcement_action("block");
            correlation.record_final_http_outcome("denied");
            correlation.record_response_status(403);
            correlation.record_error_stage("policy");
            correlation.record_target_reached();
        });

        let span = exporter
            .get_finished_spans()
            .unwrap()
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .unwrap();
        let attributes = span
            .attributes
            .into_iter()
            .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(attributes["openshell.policy.decision"], "deny");
        assert_eq!(attributes["openshell.enforcement.action"], "block");
        assert_eq!(attributes["openshell.http.outcome"], "denied");
        assert_eq!(attributes["http.response.status_code"], "403");
        assert_eq!(attributes["openshell.error.stage"], "policy");
        assert_eq!(attributes["openshell.target.reached"], "true");
    }

    #[test]
    fn response_terminal_delivery_is_exactly_once_and_drop_marks_cancellation() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter)
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"))
            .with(ocsf.clone());
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            policy_name: "api-policy".into(),
            ..Default::default()
        };

        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let complete =
                RequestCorrelation::with_request_id(&request(), &ctx, correlation_id(30));
            complete.record_upstream_response_status(200);
            complete.record_response_status(200);
            complete.record_response_selection(
                ResponseSelectionCause::UpstreamResponse,
                "allowed",
                None,
            );
            complete.record_response_delivery_started();
            complete.complete_pending_response_delivery();
            complete.complete_response_failure(
                ResponseDeliveryOutcome::DownstreamIoError,
                None,
                "platform_error",
                "downstream_response_write",
            );
            drop(complete);

            let cancelled =
                RequestCorrelation::with_request_id(&request(), &ctx, correlation_id(31));
            cancelled.record_upstream_response_status(202);
            drop(cancelled);

            let cancelled_after_selection =
                RequestCorrelation::with_request_id(&request(), &ctx, correlation_id(32));
            cancelled_after_selection.begin_response_lifecycle();
            cancelled_after_selection.record_upstream_response_status(200);
            cancelled_after_selection.record_response_status(200);
            cancelled_after_selection.record_response_selection(
                ResponseSelectionCause::UpstreamResponse,
                "allowed",
                None,
            );
            cancelled_after_selection.record_response_delivery_started();
            drop(cancelled_after_selection);
        });
        provider.force_flush().expect("flush spans");

        let events = ocsf
            .json_events()
            .into_iter()
            .filter(|event| event["firewall_rule"]["type"] == "response-correlation")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 3, "one terminal event per response lifecycle");
        let outcomes = events
            .iter()
            .map(|event| {
                (
                    event["metadata"]["correlation_uid"]
                        .as_str()
                        .expect("correlation uid"),
                    event["unmapped"]["response_delivery_outcome"]
                        .as_str()
                        .expect("terminal outcome"),
                )
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(outcomes[correlation_id(30).as_str()], "complete");
        assert_eq!(
            outcomes[correlation_id(31).as_str()],
            "cancelled_or_incomplete"
        );
        assert_eq!(
            outcomes[correlation_id(32).as_str()],
            "cancelled_or_incomplete"
        );
        let selected_then_cancelled = events
            .iter()
            .find(|event| event["metadata"]["correlation_uid"] == correlation_id(32))
            .expect("selected then cancelled event");
        assert_eq!(
            selected_then_cancelled["unmapped"]["response_selection_cause"],
            "upstream_response"
        );
    }

    #[test]
    fn resource_correlation_is_first_write_wins_and_preserves_u64_max() {
        use std::sync::Arc;
        use tracing_subscriber::layer::SubscriberExt as _;

        struct ThreadContextReset;
        impl Drop for ThreadContextReset {
            fn drop(&mut self) {
                openshell_ocsf::ctx::bind_thread_ctx(None);
            }
        }

        let event_context = openshell_ocsf::EventContext {
            sandbox_id: "sandbox-resource-test".into(),
            sandbox_name: "resource-test".into(),
            container_image: "example.invalid/resource-test:latest".into(),
            hostname: "resource-test".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            proxy_ip: "127.0.0.1".parse().unwrap(),
            proxy_port: 3128,
            origin: openshell_ocsf::EventOrigin::Supervisor,
        };
        openshell_ocsf::ctx::bind_thread_ctx(Some(Arc::new(event_context)));
        let _reset = ThreadContextReset;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"))
            .with(ocsf.clone());

        let first_policy_hash = "a".repeat(64);
        let first_endpoint_id = format!("endpoint:v1:{}", "b".repeat(64));
        let second_policy_hash = "c".repeat(64);
        let second_endpoint_id = format!("endpoint:v1:{}", "d".repeat(64));
        let first_snapshot = openshell_core::provider_credentials::ProviderCredentialSnapshot {
            installation_id: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA".into(),
            revision: u64::MAX,
            ..Default::default()
        };
        let second_snapshot = openshell_core::provider_credentials::ProviderCredentialSnapshot {
            installation_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            revision: 7,
            ..Default::default()
        };

        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &L7EvalContext {
                    host: "api.example.test".into(),
                    port: 443,
                    ..Default::default()
                },
                correlation_id(12),
            );
            correlation.record_policy_runtime_generation(u64::MAX);
            correlation.record_policy_runtime_generation(7);
            correlation.record_selected_policy_endpoint(&first_policy_hash, &first_endpoint_id);
            correlation.record_selected_policy_endpoint(&second_policy_hash, &second_endpoint_id);
            correlation.record_provider_credential_snapshot(&first_snapshot);
            correlation.record_provider_credential_snapshot(&second_snapshot);
            correlation.emit(
                HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(ActivityId::for_http_method("GET"))
                    .action(ActionId::Allowed)
                    .severity(SeverityId::Informational)
                    .http_request(HttpRequest {
                        http_method: "GET".parse().unwrap(),
                        url: None,
                    })
                    .unmapped("existing", "preserved")
                    .build(),
            );
            correlation.record_final_http_outcome("allowed");
        });
        provider.force_flush().expect("flush spans");

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        assert_eq!(span.dropped_attributes_count, 0);
        for key in [
            "openshell.policy.runtime_generation",
            "openshell.provider.environment.revision",
        ] {
            let attribute = span
                .attributes
                .iter()
                .find(|attribute| attribute.key.as_str() == key)
                .expect("revision attribute");
            assert_eq!(attribute.value, u64::MAX.to_string().into());
        }
        let raw_keys = span
            .attributes
            .iter()
            .map(|attribute| attribute.key.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            raw_keys.len(),
            raw_keys.iter().copied().collect::<BTreeSet<_>>().len(),
            "OTLP span must contain each attribute key exactly once"
        );
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
        assert_eq!(attributes["openshell.sandbox.id"], "sandbox-resource-test");
        assert_eq!(
            attributes["openshell.policy.runtime_generation"],
            u64::MAX.to_string()
        );
        assert_eq!(attributes["openshell.policy.hash"], first_policy_hash);
        assert_eq!(attributes["openshell.endpoint.id"], first_endpoint_id);
        assert_eq!(
            attributes["openshell.provider.environment.revision"],
            u64::MAX.to_string()
        );
        assert_eq!(
            attributes["openshell.provider.credential.installation.id"],
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );

        let events = ocsf.json_events();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["container"]["uid"], "sandbox-resource-test");
        assert_eq!(event["unmapped"]["existing"], "preserved");
        assert_eq!(
            event["unmapped"]["policy_runtime_generation"],
            u64::MAX.to_string()
        );
        assert_eq!(event["unmapped"]["policy_hash"], first_policy_hash);
        assert_eq!(event["unmapped"]["endpoint_id"], first_endpoint_id);
        assert_eq!(
            event["unmapped"]["provider_environment_revision"],
            u64::MAX.to_string()
        );
        assert_eq!(
            event["unmapped"]["provider_credential_installation_id"],
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        );
        assert!(event["unmapped"].get("sandbox_id").is_none());
    }

    #[test]
    fn invalid_resource_identities_are_omitted_without_consuming_first_write() {
        use tracing_subscriber::layer::SubscriberExt as _;

        const SENTINEL: &str = "SENTINEL_PRIVATE_RESOURCE_VALUE";
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"))
            .with(ocsf.clone());
        let valid_policy_hash = "e".repeat(64);
        let valid_endpoint_id = format!("endpoint:v1:{}", "f".repeat(64));
        let invalid_snapshot = openshell_core::provider_credentials::ProviderCredentialSnapshot {
            installation_id: SENTINEL.into(),
            revision: 99,
            ..Default::default()
        };
        let valid_snapshot = openshell_core::provider_credentials::ProviderCredentialSnapshot {
            installation_id: "12345678-1234-4234-8234-123456789abc".into(),
            revision: 42,
            ..Default::default()
        };

        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &L7EvalContext {
                    host: "api.example.test".into(),
                    port: 443,
                    ..Default::default()
                },
                correlation_id(13),
            );
            correlation.record_selected_policy_endpoint(SENTINEL, SENTINEL);
            correlation.record_selected_policy_endpoint(&valid_policy_hash, &valid_endpoint_id);
            correlation.record_provider_credential_snapshot(&invalid_snapshot);
            correlation.record_provider_credential_snapshot(&valid_snapshot);
            correlation.emit(
                HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                    .activity(ActivityId::for_http_method("GET"))
                    .action(ActionId::Allowed)
                    .severity(SeverityId::Informational)
                    .http_request(HttpRequest {
                        http_method: "GET".parse().unwrap(),
                        url: None,
                    })
                    .build(),
            );
            correlation.record_final_http_outcome("allowed");
        });
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
        assert_eq!(attributes["openshell.policy.hash"], valid_policy_hash);
        assert_eq!(attributes["openshell.endpoint.id"], valid_endpoint_id);
        assert_eq!(attributes["openshell.provider.environment.revision"], "42");
        assert_eq!(
            attributes["openshell.provider.credential.installation.id"],
            "12345678-1234-4234-8234-123456789abc"
        );
        assert!(!format!("{attributes:?}").contains(SENTINEL));
        let events = ocsf.json_events();
        assert_eq!(events.len(), 1);
        assert!(!serde_json::to_string(&events).unwrap().contains(SENTINEL));
    }

    #[test]
    fn custom_method_is_bounded_in_telemetry() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };
        let mut custom = request();
        custom.action = "SENTINEL-UNTRUSTED-METHOD".into();

        tracing::subscriber::with_default(subscriber, || {
            let correlation = RequestCorrelation::with_request_id(
                &custom,
                &ctx,
                "00000000-0000-4000-8000-000000000002".into(),
            );
            correlation.record_final_http_outcome("denied");
        });

        let span = exporter
            .get_finished_spans()
            .unwrap()
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .unwrap();
        let method = span
            .attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == "http.request.method")
            .expect("method attribute");
        assert_eq!(method.value.to_string(), "OTHER");
    }

    #[test]
    fn mcp_summary_is_bounded_and_omits_caller_controlled_values() {
        use tracing_subscriber::layer::SubscriberExt as _;

        const SENTINEL: &str = "SENTINEL_PRIVATE_MCP_METHOD_OR_TOOL";
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let calls = (0..140)
            .map(|index| jsonrpc::JsonRpcCallInfo {
                method: if index == 0 {
                    "tools/call".into()
                } else {
                    format!("{SENTINEL}-{index}")
                },
                params: std::collections::HashMap::from([(
                    "name".into(),
                    format!("{SENTINEL}-parameter-{index}"),
                )]),
                tool: Some(format!("{SENTINEL}-tool-{index}")),
                mcp_classification: Some(if index % 3 == 0 {
                    jsonrpc::McpMethodClassification::Extension
                } else {
                    jsonrpc::McpMethodClassification::Available
                }),
                is_notification: index % 2 == 0,
            })
            .collect();
        let info = jsonrpc::JsonRpcRequestInfo {
            calls,
            is_batch: true,
            receive_stream: false,
            has_response: false,
            mcp_revision: Some(openshell_core::mcp::McpProtocolVersion::V2026_07_28),
            mcp_http_metadata: None,
            error: None,
        };

        tracing::subscriber::with_default(subscriber, || {
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &L7EvalContext {
                    host: "mcp.example.test".into(),
                    port: 443,
                    ..Default::default()
                },
                correlation_id(10),
            );
            correlation.record_effective_jsonrpc_summary(L7Protocol::Mcp, &info);
            correlation.record_final_http_outcome("allowed");
        });
        provider.force_flush().expect("flush spans");

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        assert_eq!(span.dropped_attributes_count, 0);
        let raw_keys = span
            .attributes
            .iter()
            .map(|attribute| attribute.key.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            raw_keys.len(),
            raw_keys.iter().copied().collect::<BTreeSet<_>>().len(),
            "OTLP span must contain each attribute key exactly once"
        );
        let call_count = span
            .attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == "openshell.jsonrpc.effective.call_count")
            .expect("call count attribute");
        assert_eq!(format!("{:?}", call_count.value), "I64(64)");
        let notification_count = span
            .attributes
            .iter()
            .find(|attribute| {
                attribute.key.as_str() == "openshell.jsonrpc.effective.notification_count"
            })
            .expect("notification count attribute");
        assert_eq!(format!("{:?}", notification_count.value), "I64(64)");
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

        assert_eq!(attributes["openshell.l7.protocol"], "mcp");
        assert_eq!(
            attributes["openshell.jsonrpc.effective.message_kind"],
            "batch_mixed"
        );
        assert_eq!(
            attributes["openshell.jsonrpc.effective.inspection_outcome"],
            "accepted"
        );
        assert_eq!(attributes["openshell.jsonrpc.effective.call_count"], "64");
        assert_eq!(
            attributes["openshell.jsonrpc.effective.notification_count"],
            "64"
        );
        assert_eq!(
            attributes["openshell.jsonrpc.effective.counts_truncated"],
            "true"
        );
        assert_eq!(
            attributes["openshell.jsonrpc.effective.has_response"],
            "false"
        );
        assert_eq!(
            attributes["openshell.mcp.selected_protocol_revision"],
            "2026-07-28"
        );
        assert_eq!(
            attributes["openshell.mcp.effective.protocol_revision"],
            "2026-07-28"
        );
        assert_eq!(
            attributes["openshell.mcp.effective.method_classification"],
            "mixed"
        );
        assert_eq!(attributes["openshell.mcp.tools_call_observed"], "true");
        assert!(!format!("{attributes:?}").contains(SENTINEL));
        assert!(attributes.keys().all(|key| {
            !key.contains("method_name")
                && !key.contains("tool_name")
                && !key.contains("params")
                && !key.contains("request_id_value")
        }));
    }

    #[test]
    fn effective_mcp_summary_preserves_that_a_tools_call_was_observed() {
        use tracing_subscriber::layer::SubscriberExt as _;

        const SENTINEL: &str = "SENTINEL_PRIVATE_CORRUPTED_MCP_BODY";
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let original = jsonrpc::JsonRpcRequestInfo {
            calls: vec![jsonrpc::JsonRpcCallInfo {
                method: "tools/call".into(),
                params: std::collections::HashMap::new(),
                tool: Some(format!("{SENTINEL}-tool")),
                mcp_classification: Some(jsonrpc::McpMethodClassification::Available),
                is_notification: false,
            }],
            is_batch: false,
            receive_stream: false,
            has_response: false,
            mcp_revision: Some(openshell_core::mcp::McpProtocolVersion::V2026_07_28),
            mcp_http_metadata: None,
            error: None,
        };
        let transformed = jsonrpc::parse_jsonrpc_body_with_options(
            format!("{SENTINEL} is not JSON").as_bytes(),
            jsonrpc::JsonRpcInspectionOptions::mcp_selected(
                openshell_core::mcp::McpProtocolVersion::V2026_07_28,
                true,
            ),
        );

        tracing::subscriber::with_default(subscriber, || {
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &L7EvalContext {
                    host: "mcp.example.test".into(),
                    port: 443,
                    ..Default::default()
                },
                correlation_id(11),
            );
            correlation.record_effective_jsonrpc_summary(L7Protocol::Mcp, &original);
            correlation.record_effective_jsonrpc_summary(L7Protocol::Mcp, &transformed);
            correlation.record_final_http_outcome("denied");
        });
        provider.force_flush().expect("flush spans");

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        assert_eq!(span.dropped_attributes_count, 0);
        let raw_keys = span
            .attributes
            .iter()
            .map(|attribute| attribute.key.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            raw_keys.len(),
            raw_keys.iter().copied().collect::<BTreeSet<_>>().len(),
            "OTLP span must contain each attribute key exactly once"
        );
        let call_count = span
            .attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == "openshell.jsonrpc.effective.call_count")
            .expect("call count attribute");
        assert_eq!(format!("{:?}", call_count.value), "I64(0)");
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
            attributes["openshell.jsonrpc.effective.inspection_outcome"],
            "invalid_json"
        );
        assert_eq!(
            attributes["openshell.jsonrpc.effective.message_kind"],
            "invalid"
        );
        assert_eq!(attributes["openshell.jsonrpc.effective.call_count"], "0");
        assert_eq!(
            attributes["openshell.mcp.effective.method_classification"],
            "none"
        );
        assert_eq!(
            attributes["openshell.mcp.selected_protocol_revision"],
            "2026-07-28"
        );
        assert!(
            !attributes.contains_key("openshell.mcp.effective.protocol_revision"),
            "invalid transformed body must clear the effective revision"
        );
        assert_eq!(attributes["openshell.mcp.tools_call_observed"], "true");
        assert!(!format!("{attributes:?}").contains(SENTINEL));
    }

    #[test]
    fn unfinished_request_is_recorded_as_incomplete() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"));
        let ctx = L7EvalContext {
            host: "example.test".into(),
            port: 443,
            ..Default::default()
        };

        tracing::subscriber::with_default(subscriber, || {
            let _correlation = RequestCorrelation::with_request_id(
                &request(),
                &ctx,
                "00000000-0000-4000-8000-000000000002".into(),
            );
        });

        let span = exporter
            .get_finished_spans()
            .unwrap()
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .unwrap();
        let attributes = span
            .attributes
            .into_iter()
            .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(attributes["openshell.http.outcome"], "incomplete");
        assert_eq!(attributes["openshell.error.stage"], "unclassified");
    }

    #[test]
    fn malformed_or_incomplete_header_block_has_no_trace_context() {
        assert!(trace_headers(b"GET / HTTP/1.1\r\ntraceparent: value").is_empty());
        assert!(trace_headers(&[0xff, b'\r', b'\n', b'\r', b'\n']).is_empty());
    }

    #[test]
    fn middleware_observations_are_bounded_aggregated_and_emitted_once() {
        use tracing_subscriber::layer::SubscriberExt as _;

        const SENTINEL: &str = "SENTINEL_SECRET_MIDDLEWARE_VALUE";
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"))
            .with(ocsf.clone());
        let ctx = L7EvalContext {
            host: "api.example.test".into(),
            port: 443,
            policy_name: "api-policy".into(),
            ..Default::default()
        };
        let mut sensitive_request = request();
        sensitive_request.target = format!("/data?token={SENTINEL}");
        sensitive_request.raw_header = format!(
            "GET /data?token={SENTINEL} HTTP/1.1\r\nHost: api.example.test\r\nX-Secret: {SENTINEL}\r\n\r\n"
        )
        .into_bytes();

        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let correlation = RequestCorrelation::with_request_id(
                &sensitive_request,
                &ctx,
                "00000000-0000-4000-8000-000000000003".into(),
            );
            correlation.observe_middleware(
                MiddlewarePhase::Request,
                MiddlewareObservation {
                    mutated: true,
                    fail_open: true,
                    ..Default::default()
                },
            );
            correlation.observe_middleware(
                MiddlewarePhase::Request,
                MiddlewareObservation {
                    fail_closed: true,
                    ..Default::default()
                },
            );
            correlation.complete_middleware(MiddlewarePhase::Request, MiddlewareOutcome::Denied);
            correlation
                .complete_middleware(MiddlewarePhase::Request, MiddlewareOutcome::PlatformError);
            correlation.record_final_http_outcome("denied");
        });
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
        assert_eq!(attributes["openshell.middleware.request.outcome"], "denied");
        assert_eq!(attributes["openshell.middleware.request.mutated"], "true");
        assert_eq!(attributes["openshell.middleware.request.fail_open"], "true");
        assert_eq!(
            attributes["openshell.middleware.request.fail_closed"],
            "true"
        );
        assert_eq!(
            attributes["openshell.middleware.request.admission_exhausted"],
            "false"
        );

        let events = ocsf
            .json_events()
            .into_iter()
            .filter(|event| event["firewall_rule"]["type"] == "middleware-correlation")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1, "one aggregate event per completed phase");
        let event = &events[0];
        assert_eq!(event["metadata"]["correlation_uid"], correlation_id(3));
        assert_eq!(event["unmapped"]["middleware_phase"], "request");
        assert_eq!(event["unmapped"]["middleware_outcome"], "denied");
        assert_eq!(event["unmapped"]["mutated"], true);
        assert_eq!(event["unmapped"]["fail_open"], true);
        assert_eq!(event["unmapped"]["fail_closed"], true);
        assert_eq!(event["unmapped"]["admission_exhausted"], false);
        assert!(!serde_json::to_string(event).unwrap().contains(SENTINEL));
    }

    #[test]
    fn unfinished_selected_middleware_phase_is_emitted_once_as_incomplete() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"))
            .with(ocsf.clone());

        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &L7EvalContext {
                    host: "example.test".into(),
                    port: 443,
                    policy_name: "api-policy".into(),
                    ..Default::default()
                },
                correlation_id(4),
            );
            correlation.observe_middleware(
                MiddlewarePhase::Response,
                MiddlewareObservation {
                    admission_exhausted: true,
                    diagnostics_truncated: true,
                    ..Default::default()
                },
            );
        });
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
        assert_eq!(
            attributes["openshell.middleware.response.admission_exhausted"],
            "true"
        );
        assert_eq!(
            attributes["openshell.middleware.response.diagnostics_truncated"],
            "true"
        );
        let events = ocsf
            .json_events()
            .into_iter()
            .filter(|event| event["firewall_rule"]["type"] == "middleware-correlation")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["unmapped"]["middleware_phase"], "response");
        assert_eq!(events[0]["unmapped"]["middleware_outcome"], "incomplete");
        assert_eq!(events[0]["unmapped"]["diagnostics_truncated"], true);
        assert_eq!(events[0]["severity"], "Medium");
    }

    #[test]
    fn partial_response_denial_is_not_reported_as_fully_blocked() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"))
            .with(ocsf.clone());

        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &L7EvalContext {
                    host: "example.test".into(),
                    port: 443,
                    policy_name: "api-policy".into(),
                    ..Default::default()
                },
                correlation_id(5),
            );
            correlation.observe_middleware(
                MiddlewarePhase::Response,
                MiddlewareObservation {
                    delivery_started: true,
                    partial_delivery: true,
                    ..Default::default()
                },
            );
            correlation.complete_middleware(MiddlewarePhase::Response, MiddlewareOutcome::Denied);
            correlation.record_final_http_outcome("denied");
        });
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
            attributes["openshell.middleware.response.delivery_started"],
            "true"
        );
        assert_eq!(
            attributes["openshell.middleware.response.partial_delivery"],
            "true"
        );

        let events = ocsf
            .json_events()
            .into_iter()
            .filter(|event| event["firewall_rule"]["type"] == "middleware-correlation")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["action"], "Denied");
        assert_eq!(events[0]["disposition"], "Other");
        assert_eq!(events[0]["unmapped"]["delivery_started"], true);
        assert_eq!(events[0]["unmapped"]["partial_delivery"], true);
        assert_eq!(
            events[0]["message"],
            "Supervisor middleware stopped a partially delivered response"
        );
    }

    #[test]
    fn allowed_fail_open_aggregate_is_elevated_above_informational() {
        let event = middleware_aggregate_event(
            &MiddlewareEventContext {
                method: "GET",
                host: "example.test".into(),
                port: 443,
                policy_name: "api-policy".into(),
            },
            MiddlewarePhase::Response,
            "allowed",
            MiddlewareObservation {
                fail_open: true,
                ..Default::default()
            },
        )
        .to_json()
        .expect("serialize aggregate event");

        assert_eq!(event["severity"], "Low");
    }

    #[test]
    fn unrelated_requests_omit_credential_correlation() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"))
            .with(ocsf.clone());

        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &L7EvalContext {
                    host: "example.test".into(),
                    port: 443,
                    policy_name: "api-policy".into(),
                    ..Default::default()
                },
                correlation_id(6),
            );
            correlation.record_final_http_outcome("allowed");
        });
        provider.force_flush().expect("flush spans");

        let span = exporter
            .get_finished_spans()
            .expect("finished spans")
            .into_iter()
            .find(|span| span.name == "openshell.http.enforcement")
            .expect("HTTP enforcement span");
        assert!(
            span.attributes
                .iter()
                .all(|attribute| { !attribute.key.as_str().starts_with("openshell.credential.") })
        );
        assert!(
            ocsf.json_events()
                .into_iter()
                .all(|event| { event["firewall_rule"]["type"] != "credential-correlation" })
        );
    }

    #[test]
    fn credential_mechanism_query_reflects_observations() {
        let correlation = RequestCorrelation::with_request_id(
            &request(),
            &L7EvalContext {
                host: "example.test".into(),
                port: 443,
                ..Default::default()
            },
            correlation_id(9),
        );

        assert!(!correlation.has_credential_mechanism(CredentialMechanism::StaticPlaceholder));
        correlation.observe_credential(
            CredentialMechanism::StaticPlaceholder,
            CredentialSurface::Path,
        );
        assert!(correlation.has_credential_mechanism(CredentialMechanism::StaticPlaceholder));
        assert!(!correlation.has_credential_mechanism(CredentialMechanism::TokenGrant));
        assert!(!correlation.has_credential_mechanism(CredentialMechanism::SigV4));
        correlation.record_final_http_outcome("denied");
    }

    #[test]
    fn credential_state_orders_sets_and_preserves_authoritative_outcome() {
        let mut state = CredentialState::default();
        assert_eq!(state.snapshot(), None);
        state.complete(CredentialOutcome::Unavailable);
        state.complete_mechanism(
            CredentialMechanism::StaticPlaceholder,
            CredentialOutcome::Prepared,
        );
        assert_eq!(state.snapshot(), None);
        state.observe(CredentialMechanism::TokenGrant, CredentialSurface::Query);
        state.observe(CredentialMechanism::SigV4, CredentialSurface::Signature);
        state.observe(
            CredentialMechanism::StaticPlaceholder,
            CredentialSurface::Header,
        );
        assert_eq!(
            state.snapshot(),
            Some(CredentialSnapshot {
                mechanisms: "sigv4,static_placeholder,token_grant".into(),
                surfaces: "header,query,signature".into(),
                outcome: CredentialOutcome::Incomplete,
                mechanism_outcomes: std::collections::BTreeMap::from([
                    (
                        CredentialMechanism::StaticPlaceholder,
                        CredentialOutcome::Incomplete,
                    ),
                    (
                        CredentialMechanism::TokenGrant,
                        CredentialOutcome::Incomplete,
                    ),
                    (CredentialMechanism::SigV4, CredentialOutcome::Incomplete),
                ]),
            })
        );
        state.complete_mechanism(CredentialMechanism::TokenGrant, CredentialOutcome::Withheld);
        state.complete_mechanism(
            CredentialMechanism::StaticPlaceholder,
            CredentialOutcome::Prepared,
        );
        state.complete_mechanism(CredentialMechanism::SigV4, CredentialOutcome::Unavailable);
        assert_eq!(
            state.snapshot().expect("selected credential work").outcome,
            CredentialOutcome::Unavailable
        );
        state.complete(CredentialOutcome::Stale);
        state.complete_mechanism(CredentialMechanism::SigV4, CredentialOutcome::Denied);
        state.complete_mechanism(
            CredentialMechanism::StaticPlaceholder,
            CredentialOutcome::Prepared,
        );
        state.observe(
            CredentialMechanism::StaticPlaceholder,
            CredentialSurface::Body,
        );

        assert_eq!(
            state.snapshot(),
            Some(CredentialSnapshot {
                mechanisms: "sigv4,static_placeholder,token_grant".into(),
                surfaces: "body,header,query,signature".into(),
                outcome: CredentialOutcome::Denied,
                mechanism_outcomes: std::collections::BTreeMap::from([
                    (
                        CredentialMechanism::StaticPlaceholder,
                        CredentialOutcome::Stale,
                    ),
                    (CredentialMechanism::TokenGrant, CredentialOutcome::Stale),
                    (CredentialMechanism::SigV4, CredentialOutcome::Denied),
                ]),
            })
        );
    }

    #[test]
    fn credential_aggregate_is_bounded_correlated_and_private() {
        use tracing_subscriber::layer::SubscriberExt as _;

        const SENTINEL: &str = "SENTINEL_CREDENTIAL_VALUE";
        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"))
            .with(ocsf.clone());
        let mut sensitive_request = request();
        sensitive_request.target = format!("/data?credential={SENTINEL}");
        sensitive_request.raw_header = format!(
            "GET /data?credential={SENTINEL} HTTP/1.1\r\nHost: api.example.test\r\nX-Credential: {SENTINEL}\r\n\r\n"
        )
        .into_bytes();

        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let correlation = RequestCorrelation::with_request_id(
                &sensitive_request,
                &L7EvalContext {
                    host: "api.example.test".into(),
                    port: 443,
                    policy_name: "api-policy".into(),
                    ..Default::default()
                },
                correlation_id(7),
            );
            correlation
                .observe_credential(CredentialMechanism::TokenGrant, CredentialSurface::Header);
            correlation.observe_credential(
                CredentialMechanism::StaticPlaceholder,
                CredentialSurface::Body,
            );
            correlation
                .observe_credential(CredentialMechanism::SigV4, CredentialSurface::Signature);
            correlation.observe_credential(
                CredentialMechanism::StaticPlaceholder,
                CredentialSurface::Path,
            );
            correlation.record_request_delivery_started();
            correlation.complete_credential_mechanism(
                CredentialMechanism::TokenGrant,
                CredentialOutcome::Withheld,
            );
            correlation.complete_credential_mechanism(
                CredentialMechanism::StaticPlaceholder,
                CredentialOutcome::Prepared,
            );
            correlation.record_final_http_outcome("allowed");
        });
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
        assert_eq!(attributes["openshell.credential.outcome"], "incomplete");
        assert_eq!(
            attributes["openshell.credential.mechanisms"],
            "sigv4,static_placeholder,token_grant"
        );
        assert_eq!(
            attributes["openshell.credential.surfaces"],
            "body,header,path,signature"
        );
        assert_eq!(
            attributes["openshell.credential.static_placeholder.outcome"],
            "prepared"
        );
        assert_eq!(
            attributes["openshell.credential.token_grant.outcome"],
            "withheld"
        );
        assert_eq!(
            attributes["openshell.credential.sigv4.outcome"],
            "incomplete"
        );
        assert_eq!(attributes["openshell.request.delivery_started"], "true");
        assert!(!format!("{attributes:?}").contains(SENTINEL));

        let events = ocsf
            .json_events()
            .into_iter()
            .filter(|event| event["firewall_rule"]["type"] == "credential-correlation")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["metadata"]["correlation_uid"], correlation_id(7));
        assert_eq!(event["action"], "Observed");
        assert_eq!(event["disposition"], "Logged");
        assert_eq!(event["status"], "Unknown");
        assert_eq!(event["unmapped"]["credential_outcome"], "incomplete");
        assert_eq!(
            event["unmapped"]["credential_mechanisms"],
            "sigv4,static_placeholder,token_grant"
        );
        assert_eq!(
            event["unmapped"]["credential_surfaces"],
            "body,header,path,signature"
        );
        assert_eq!(
            event["unmapped"]["credential_static_placeholder_outcome"],
            "prepared"
        );
        assert_eq!(
            event["unmapped"]["credential_token_grant_outcome"],
            "withheld"
        );
        assert_eq!(event["unmapped"]["credential_sigv4_outcome"], "incomplete");
        assert!(!serde_json::to_string(event).unwrap().contains(SENTINEL));
    }

    #[test]
    fn stale_credential_can_omit_mechanism_and_surface() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "correlation-test"))
            .with(ocsf.clone());

        tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            let correlation = RequestCorrelation::with_request_id(
                &request(),
                &L7EvalContext {
                    host: "example.test".into(),
                    port: 443,
                    policy_name: "api-policy".into(),
                    ..Default::default()
                },
                correlation_id(8),
            );
            correlation.complete_credential(CredentialOutcome::Stale);
            correlation.record_final_http_outcome("platform_error");
        });
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
        assert_eq!(attributes["openshell.credential.outcome"], "stale");
        assert!(!attributes.contains_key("openshell.credential.mechanisms"));
        assert!(!attributes.contains_key("openshell.credential.surfaces"));
        assert!(!attributes.contains_key("openshell.credential.static_placeholder.outcome"));
        assert!(!attributes.contains_key("openshell.credential.token_grant.outcome"));
        assert!(!attributes.contains_key("openshell.credential.sigv4.outcome"));

        let events = ocsf
            .json_events()
            .into_iter()
            .filter(|event| event["firewall_rule"]["type"] == "credential-correlation")
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["unmapped"]["credential_outcome"], "stale");
        assert!(events[0]["unmapped"].get("credential_mechanisms").is_none());
        assert!(events[0]["unmapped"].get("credential_surfaces").is_none());
        assert!(
            events[0]["unmapped"]
                .get("credential_static_placeholder_outcome")
                .is_none()
        );
        assert!(
            events[0]["unmapped"]
                .get("credential_token_grant_outcome")
                .is_none()
        );
        assert!(
            events[0]["unmapped"]
                .get("credential_sigv4_outcome")
                .is_none()
        );
    }

    fn correlation_id(suffix: u8) -> String {
        format!("00000000-0000-4000-8000-{suffix:012}")
    }
}
