// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-request correlation for HTTP enforcement events.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use http::{HeaderMap, HeaderValue};
use openshell_ocsf::{
    ActionId, Endpoint, HttpActivityBuilder, HttpRequest, HttpResponse, OcsfEvent, SeverityId,
    StatusId,
};
use tracing::Instrument as _;

use crate::l7::provider::L7Request;
use crate::l7::relay::L7EvalContext;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
pub struct RequestCorrelation {
    request_id: String,
    span: tracing::Span,
    // Keep the audit payload off the async state machine.
    state: Box<Mutex<RequestState>>,
}

#[derive(Debug)]
struct RequestState {
    primary: Option<OcsfEvent>,
    status: Option<u16>,
    upstream_status: Option<u16>,
    outcome: Option<&'static str>,
    policy_span: Option<tracing::Span>,
    middleware: [Option<MiddlewareState>; 2],
    credential: CredentialState,
    credential_span: Option<tracing::Span>,
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
    mechanisms: BTreeMap<CredentialMechanism, CredentialOutcome>,
    surfaces: BTreeSet<CredentialSurface>,
    outcome: Option<CredentialOutcome>,
}

impl CredentialState {
    fn observe(&mut self, mechanism: CredentialMechanism, surface: CredentialSurface) {
        self.selected = true;
        self.mechanisms
            .entry(mechanism)
            .or_insert(CredentialOutcome::Incomplete);
        self.surfaces.insert(surface);
    }

    fn complete(&mut self, outcome: CredentialOutcome) {
        if !self.selected && outcome != CredentialOutcome::Stale {
            return;
        }
        self.selected = true;

        merge_optional_credential_outcome(&mut self.outcome, outcome);
        if outcome == CredentialOutcome::Stale {
            for current in self.mechanisms.values_mut() {
                merge_credential_outcome(current, outcome);
            }
        }
    }

    fn complete_mechanism(&mut self, mechanism: CredentialMechanism, outcome: CredentialOutcome) {
        let Some(current) = self.mechanisms.get_mut(&mechanism) else {
            return;
        };

        merge_optional_credential_outcome(&mut self.outcome, outcome);
        merge_credential_outcome(current, outcome);
    }

    fn effective_outcome(&self) -> Option<CredentialOutcome> {
        self.selected.then(|| {
            let has_incomplete = self
                .mechanisms
                .values()
                .any(|outcome| *outcome == CredentialOutcome::Incomplete);
            match self.outcome {
                Some(
                    outcome @ (CredentialOutcome::Denied
                    | CredentialOutcome::Stale
                    | CredentialOutcome::Unavailable),
                ) => outcome,
                _ if has_incomplete => CredentialOutcome::Incomplete,
                Some(outcome) => outcome,
                None => CredentialOutcome::Incomplete,
            }
        })
    }

    fn snapshot(&self) -> Option<CredentialSnapshot> {
        self.effective_outcome().map(|outcome| CredentialSnapshot {
            mechanisms: sorted_values(self.mechanisms.keys().map(|value| value.as_str())),
            surfaces: sorted_values(self.surfaces.iter().map(|value| value.as_str())),
            outcome,
            mechanism_outcomes: self.mechanisms.clone(),
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
    mechanism_outcomes: BTreeMap<CredentialMechanism, CredentialOutcome>,
}

fn sorted_values(values: impl Iterator<Item = &'static str>) -> String {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    values.join(",")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MiddlewarePhase {
    Request,
    Response,
}

impl MiddlewarePhase {
    const fn index(self) -> usize {
        match self {
            Self::Request => 0,
            Self::Response => 1,
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
    const fn as_str(self) -> &'static str {
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

#[derive(Debug)]
struct MiddlewareState {
    span: Option<tracing::Span>,
    observation: MiddlewareObservation,
    completed: bool,
}

#[must_use]
pub struct MiddlewarePhaseGuard<'a> {
    correlation: &'a RequestCorrelation,
    phase: MiddlewarePhase,
}

impl Drop for MiddlewarePhaseGuard<'_> {
    fn drop(&mut self) {
        let span = {
            let mut state = self
                .correlation
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(middleware) = &mut state.middleware[self.phase.index()] else {
                return;
            };
            let span = middleware.span.take();
            if !middleware.completed
                && let Some(span) = &span
            {
                openshell_otel::mark_error(span);
            }
            span
        };
        if let Some(span) = span {
            close_span(span);
        }
    }
}

fn close_span(span: tracing::Span) {
    if let Some(dispatch) = span.with_subscriber(|(_, dispatch)| dispatch.clone()) {
        tracing::dispatcher::with_default(&dispatch, || drop(span));
    }
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
        let span = tracing::info_span!(
            "openshell.http.request",
            otel.kind = "server",
            otel.status_code = tracing::field::Empty,
            "openshell.request.id" = %request_id,
            "http.request.method" = method,
            "server.address" = %ctx.host,
            "server.port" = ctx.port,
            "openshell.policy.name" = %ctx.policy_name,
            "openshell.target.reached" = false,
            "openshell.request.delivery_started" = false,
            "openshell.policy.decision" = tracing::field::Empty,
            "openshell.enforcement.action" = tracing::field::Empty,
            "openshell.http.outcome" = tracing::field::Empty,
            "http.response.status_code" = tracing::field::Empty,
        );
        let headers = trace_headers(&request.raw_header);
        let _ = openshell_otel::set_parent_from_headers(&span, &headers);
        let fallback = HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
            .http_request(HttpRequest::new(method, ctx.ocsf_url("/")))
            .dst_endpoint(Endpoint::from_domain(&ctx.host, ctx.port))
            .firewall_rule(&ctx.policy_name, "l7")
            .message("HTTP request ended before a response was selected")
            .build();
        Self {
            request_id,
            span,
            state: Box::new(Mutex::new(RequestState {
                primary: Some(fallback),
                status: None,
                upstream_status: None,
                outcome: None,
                policy_span: None,
                middleware: [None, None],
                credential: CredentialState::default(),
                credential_span: None,
            })),
        }
    }

    #[must_use]
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }

    pub(crate) fn observe_response<'a, C>(&'a self, client: &'a mut C) -> AuditedClient<'a, C> {
        AuditedClient {
            inner: client,
            correlation: self,
            head: ResponseHead::default(),
        }
    }

    pub(crate) async fn within_span<F>(&self, future: F) -> F::Output
    where
        F: Future,
    {
        future.instrument(self.span.clone()).await
    }

    pub(crate) async fn within_middleware<F: Future>(
        &self,
        phase: MiddlewarePhase,
        future: F,
    ) -> F::Output {
        future.instrument(self.middleware_span(phase)).await
    }

    pub(crate) fn record_policy_decision(&self, decision: &str) {
        self.span.record("openshell.policy.decision", decision);
        let policy_span = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .policy_span
            .take();
        if let Some(span) = policy_span {
            span.record("openshell.policy.decision", decision);
        }
    }

    pub(crate) fn evaluate_policy<T>(&self, operation: impl FnOnce() -> T) -> T {
        let span = tracing::info_span!(
            parent: &self.span,
            "openshell.policy.evaluate",
            "openshell.policy.decision" = tracing::field::Empty,
        );
        let result = span.in_scope(operation);
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .policy_span = Some(span);
        result
    }

    pub(crate) fn record_enforcement_action(&self, action: &str) {
        self.span.record("openshell.enforcement.action", action);
    }

    pub(crate) fn record_final_http_outcome(&self, outcome: &'static str) {
        self.span.record("openshell.http.outcome", outcome);
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outcome = Some(outcome);
    }

    pub(crate) fn record_response_status(&self, status: u16) {
        self.span.record("http.response.status_code", status);
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .status = Some(status);
    }

    pub(crate) fn record_upstream_status(&self, status: u16) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .upstream_status = Some(status);
    }

    pub(crate) fn record_target_reached(&self) {
        self.span.record("openshell.target.reached", true);
    }

    pub(crate) fn record_request_delivery_started(&self) {
        self.span.record("openshell.request.delivery_started", true);
        self.finish_credential_span();
    }

    fn credential_span(&self, state: &mut RequestState) {
        state.credential_span.get_or_insert_with(|| {
            self.span
                .with_subscriber(|(_, dispatch)| {
                    tracing::dispatcher::with_default(dispatch, || {
                        tracing::info_span!(parent: &self.span, "openshell.credential.prepare",
                    otel.status_code = tracing::field::Empty,
                    "openshell.credential.outcome" = tracing::field::Empty,
                    "openshell.credential.mechanisms" = tracing::field::Empty,
                    "openshell.credential.surfaces" = tracing::field::Empty,
                    "openshell.credential.static_placeholder.outcome" = tracing::field::Empty,
                    "openshell.credential.token_grant.outcome" = tracing::field::Empty,
                    "openshell.credential.sigv4.outcome" = tracing::field::Empty)
                    })
                })
                .unwrap_or_else(tracing::Span::none)
        });
    }

    pub(crate) fn observe_credential(
        &self,
        mechanism: CredentialMechanism,
        surface: CredentialSurface,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.credential.observe(mechanism, surface);
        self.credential_span(&mut state);
    }

    pub(crate) fn has_credential_mechanism(&self, mechanism: CredentialMechanism) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .credential
            .mechanisms
            .contains_key(&mechanism)
    }

    pub(crate) fn complete_credential(&self, outcome: CredentialOutcome) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.credential.complete(outcome);
        if state.credential.selected {
            self.credential_span(&mut state);
        }
    }

    pub(crate) fn complete_credential_mechanism(
        &self,
        mechanism: CredentialMechanism,
        outcome: CredentialOutcome,
    ) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .credential
            .complete_mechanism(mechanism, outcome);
    }

    pub(crate) async fn within_credential<F: Future>(&self, future: F) -> F::Output {
        let span = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .credential_span
            .clone()
            .unwrap_or_else(tracing::Span::none);
        future.instrument(span).await
    }

    fn finish_credential_span(&self) {
        let (span, snapshot) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(span) = state.credential_span.take() else {
                return;
            };
            (span, state.credential.snapshot())
        };
        if let Some(snapshot) = snapshot {
            span.record("openshell.credential.outcome", snapshot.outcome.as_str());
            span.record(
                "openshell.credential.mechanisms",
                snapshot.mechanisms.as_str(),
            );
            span.record("openshell.credential.surfaces", snapshot.surfaces.as_str());
            for mechanism in CredentialMechanism::ALL {
                if let Some(outcome) = snapshot.mechanism_outcomes.get(&mechanism) {
                    span.record(mechanism.span_outcome_field(), outcome.as_str());
                }
            }
            if !matches!(
                snapshot.outcome,
                CredentialOutcome::Prepared | CredentialOutcome::Withheld
            ) {
                openshell_otel::mark_error(&span);
            }
        }
    }

    pub(crate) fn record_error_stage(&self, _stage: &str) {
        openshell_otel::mark_error(&self.span);
    }

    pub(crate) fn middleware_span(&self, phase: MiddlewarePhase) -> tracing::Span {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.middleware[phase.index()]
            .get_or_insert_with(|| MiddlewareState {
                span: Some(
                    self.span
                        .with_subscriber(|(_, dispatch)| {
                            tracing::dispatcher::with_default(dispatch, || match phase {
                                MiddlewarePhase::Request => tracing::info_span!(parent: &self.span,
                    "openshell.middleware.request", otel.status_code = tracing::field::Empty,
                    "openshell.middleware.outcome" = "incomplete",
                    "openshell.middleware.mutated" = false,
                    "openshell.middleware.fail_open" = false,
                    "openshell.middleware.fail_closed" = false,
                    "openshell.middleware.admission_exhausted" = false,
                    "openshell.middleware.diagnostics_truncated" = false,
                    "openshell.response.delivery_started" = false,
                    "openshell.response.partial_delivery" = false),
                                MiddlewarePhase::Response => {
                                    tracing::info_span!(parent: &self.span,
                    "openshell.middleware.response", otel.status_code = tracing::field::Empty,
                    "openshell.middleware.outcome" = "incomplete",
                    "openshell.middleware.mutated" = false,
                    "openshell.middleware.fail_open" = false,
                    "openshell.middleware.fail_closed" = false,
                    "openshell.middleware.admission_exhausted" = false,
                    "openshell.middleware.diagnostics_truncated" = false,
                    "openshell.response.delivery_started" = false,
                    "openshell.response.partial_delivery" = false)
                                }
                            })
                        })
                        .unwrap_or_else(tracing::Span::none),
                ),
                observation: MiddlewareObservation::default(),
                completed: false,
            })
            .span
            .clone()
            .unwrap_or_else(tracing::Span::none)
    }

    pub(crate) fn begin_middleware(&self, phase: MiddlewarePhase) -> MiddlewarePhaseGuard<'_> {
        drop(self.middleware_span(phase));
        MiddlewarePhaseGuard {
            correlation: self,
            phase,
        }
    }

    pub(crate) fn observe_middleware(
        &self,
        phase: MiddlewarePhase,
        observation: MiddlewareObservation,
    ) {
        let span = self.middleware_span(phase);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(middleware) = &mut state.middleware[phase.index()] else {
            return;
        };
        if middleware.completed {
            return;
        }
        let merged = &mut middleware.observation;
        let previous = *merged;
        merged.mutated |= observation.mutated;
        merged.fail_open |= observation.fail_open;
        merged.fail_closed |= observation.fail_closed;
        merged.admission_exhausted |= observation.admission_exhausted;
        merged.diagnostics_truncated |= observation.diagnostics_truncated;
        merged.delivery_started |= observation.delivery_started;
        merged.partial_delivery |= observation.partial_delivery;
        // Repeated SDK attribute writes consume the span limit, even for the same key.
        for (field, before, after) in [
            (
                "openshell.middleware.mutated",
                previous.mutated,
                merged.mutated,
            ),
            (
                "openshell.middleware.fail_open",
                previous.fail_open,
                merged.fail_open,
            ),
            (
                "openshell.middleware.fail_closed",
                previous.fail_closed,
                merged.fail_closed,
            ),
            (
                "openshell.middleware.admission_exhausted",
                previous.admission_exhausted,
                merged.admission_exhausted,
            ),
            (
                "openshell.middleware.diagnostics_truncated",
                previous.diagnostics_truncated,
                merged.diagnostics_truncated,
            ),
            (
                "openshell.response.delivery_started",
                previous.delivery_started,
                merged.delivery_started,
            ),
            (
                "openshell.response.partial_delivery",
                previous.partial_delivery,
                merged.partial_delivery,
            ),
        ] {
            if before != after {
                span.record(field, after);
            }
        }
        if let Some(primary) = &mut state.primary {
            for (key, value) in [
                ("middleware_fail_open", observation.fail_open),
                ("middleware_fail_closed", observation.fail_closed),
                (
                    "middleware_admission_exhausted",
                    observation.admission_exhausted,
                ),
            ] {
                if value && let OcsfEvent::HttpActivity(primary) = primary {
                    primary
                        .base
                        .unmapped
                        .get_or_insert_with(|| serde_json::json!({}))[key] = true.into();
                }
            }
        }
    }

    pub(crate) fn complete_middleware(&self, phase: MiddlewarePhase, outcome: MiddlewareOutcome) {
        let span = self.middleware_span(phase);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(middleware) = &mut state.middleware[phase.index()] {
            if middleware.completed {
                return;
            }
            middleware.completed = true;
            span.record("openshell.middleware.outcome", outcome.as_str());
            if outcome != MiddlewareOutcome::Allowed {
                openshell_otel::mark_error(&span);
            }
        }
    }

    pub(crate) fn record_response_delivery_started(&self) {
        self.observe_middleware(
            MiddlewarePhase::Response,
            MiddlewareObservation {
                delivery_started: true,
                ..Default::default()
            },
        );
    }

    pub(crate) fn record_response_partial_delivery(&self) {
        self.observe_middleware(
            MiddlewarePhase::Response,
            MiddlewareObservation {
                delivery_started: true,
                partial_delivery: true,
                ..Default::default()
            },
        );
    }

    pub(crate) fn emit(&self, event: OcsfEvent) {
        if matches!(event, OcsfEvent::HttpActivity(_)) {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(primary) = &mut state.primary {
                *primary = event;
            }
        } else {
            self.emit_correlated(event);
        }
    }

    pub(crate) fn response_selected(&self, status: u16) {
        self.record_response_status(status);
        self.emit_primary(false);
    }

    fn emit_primary(&self, incomplete: bool) {
        self.finish_credential_span();
        let (mut event, status, upstream_status, outcome) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let Some(primary) = state.primary.take() else {
                return;
            };
            let mut primary = primary;
            if let Some(outcome) = state.credential.effective_outcome()
                && outcome != CredentialOutcome::Prepared
                && let OcsfEvent::HttpActivity(http) = &mut primary
            {
                http.base
                    .unmapped
                    .get_or_insert_with(|| serde_json::json!({}))["credential_outcome"] =
                    outcome.as_str().into();
            }
            (primary, state.status, state.upstream_status, state.outcome)
        };
        if let OcsfEvent::HttpActivity(http) = &mut event {
            http.http_response = status.map(|code| HttpResponse { code });
            if let Some(upstream) = upstream_status.filter(|upstream| Some(*upstream) != status) {
                let unmapped = http
                    .base
                    .unmapped
                    .get_or_insert_with(|| serde_json::json!({}));
                unmapped["upstream_response_code"] = serde_json::json!(upstream);
            }
            if incomplete && outcome.is_none() {
                http.base.status = Some(StatusId::Failure);
                http.base.status_detail = Some("request_incomplete".into());
                http.base.severity = SeverityId::Low;
            }
            if outcome == Some("denied") {
                if http.action != Some(ActionId::Denied) {
                    http.base.message = Some("HTTP request blocked after policy admission".into());
                }
                http.action = Some(ActionId::Denied);
                http.disposition = Some(openshell_ocsf::DispositionId::Blocked);
                http.base.status = Some(StatusId::Failure);
                http.base.severity = SeverityId::Medium;
            } else if matches!(outcome, Some("platform_error" | "upstream_error")) {
                http.base.status = Some(StatusId::Failure);
                http.base.status_detail = outcome.map(str::to_owned);
                http.base.severity = SeverityId::Low;
            }
        }
        self.emit_correlated(event);
    }

    fn emit_correlated(&self, mut event: OcsfEvent) {
        event.set_correlation_uid(self.request_id.clone());
        self.span
            .in_scope(|| crate::telemetry::emit_correlated(event));
    }
}

pub fn emit_ocsf(correlation: Option<&RequestCorrelation>, event: OcsfEvent) {
    if let Some(correlation) = correlation {
        correlation.emit_correlated(event);
    } else {
        crate::telemetry::egress_emit!(event);
    }
}

#[cfg(test)]
pub fn test_request_attributes(
    spans: &[opentelemetry_sdk::trace::SpanData],
    request_id: Option<&str>,
) -> BTreeMap<String, String> {
    let root = spans
        .iter()
        .find(|span| {
            span.name == "openshell.http.request"
                && request_id.is_none_or(|id| {
                    span.attributes.iter().any(|attribute| {
                        attribute.key.as_str() == "openshell.request.id"
                            && attribute.value.to_string() == id
                    })
                })
        })
        .expect("request root");
    assert!(
        root.attributes
            .iter()
            .all(|attribute| !attribute.key.as_str().starts_with("openshell.credential.")),
        "credential detail belongs on a child span"
    );
    let mut attributes = root
        .attributes
        .iter()
        .map(|attribute| (attribute.key.to_string(), attribute.value.to_string()))
        .collect::<BTreeMap<_, _>>();
    for child in spans.iter().filter(|span| {
        span.name == "openshell.credential.prepare"
            && span.parent_span_id == root.span_context.span_id()
    }) {
        assert_eq!(child.span_context.trace_id(), root.span_context.trace_id());
        attributes.extend(
            child
                .attributes
                .iter()
                .map(|attribute| (attribute.key.to_string(), attribute.value.to_string())),
        );
    }
    attributes
}

pub fn emit_phase_events(
    correlation: Option<&RequestCorrelation>,
    phase: MiddlewarePhase,
    events: impl IntoIterator<Item = OcsfEvent>,
) {
    let Some(correlation) = correlation else {
        crate::telemetry::emit_decision(events, None);
        return;
    };
    let span = correlation.middleware_span(phase);
    for mut event in events {
        if let OcsfEvent::HttpActivity(http) = &event {
            // Routine invocation records belong to the phase span. A late
            // failure is separate from the already-written primary record.
            let emitted = correlation
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .primary
                .is_none();
            if !emitted || http.base.status != Some(StatusId::Failure) {
                continue;
            }
        }
        event.set_correlation_uid(correlation.request_id.clone());
        span.in_scope(|| crate::telemetry::emit_correlated(event));
    }
}

/// Observe accepted response bytes without buffering or changing delivery.
pub struct AuditedClient<'a, C> {
    inner: &'a mut C,
    correlation: &'a RequestCorrelation,
    head: ResponseHead,
}

#[derive(Default)]
struct ResponseHead {
    prefix: [u8; 12],
    prefix_len: usize,
    delimiter: u32,
    complete: bool,
}

impl ResponseHead {
    fn accept(&mut self, bytes: &[u8], correlation: &RequestCorrelation) {
        for &byte in bytes {
            if self.complete {
                break;
            }
            if self.prefix_len < self.prefix.len() {
                self.prefix[self.prefix_len] = byte;
                self.prefix_len += 1;
            }
            self.delimiter = (self.delimiter << 8) | u32::from(byte);
            if self.delimiter != u32::from_be_bytes(*b"\r\n\r\n") {
                continue;
            }
            let status = std::str::from_utf8(&self.prefix[9..12])
                .ok()
                .and_then(|code| code.parse::<u16>().ok());
            if status.is_some_and(|code| (100..200).contains(&code) && code != 101) {
                *self = Self::default();
            } else {
                self.complete = true;
                if let Some(status) = status {
                    correlation.response_selected(status);
                }
            }
        }
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for AuditedClient<'_, C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for AuditedClient<'_, C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut *this.inner).poll_write(cx, bytes);
        if let Poll::Ready(Ok(accepted)) = result {
            this.head.accept(&bytes[..accepted], this.correlation);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
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
        if self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outcome
            .is_none()
        {
            self.span.record("openshell.http.outcome", "incomplete");
            openshell_otel::mark_error(&self.span);
        }
        self.emit_primary(true);
    }
}

fn trace_headers(raw_header: &[u8]) -> HeaderMap {
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

    #[test]
    fn effective_credential_outcome_preserves_selection_and_failure_precedence() {
        let mut state = CredentialState::default();
        assert_eq!(state.effective_outcome(), None);
        state.observe(
            CredentialMechanism::StaticPlaceholder,
            CredentialSurface::Header,
        );
        assert_eq!(
            state.effective_outcome(),
            Some(CredentialOutcome::Incomplete)
        );
        state.complete_mechanism(
            CredentialMechanism::StaticPlaceholder,
            CredentialOutcome::Prepared,
        );
        assert_eq!(state.effective_outcome(), Some(CredentialOutcome::Prepared));
        state.observe(CredentialMechanism::TokenGrant, CredentialSurface::Header);
        assert_eq!(
            state.effective_outcome(),
            Some(CredentialOutcome::Incomplete)
        );
        state.complete_mechanism(CredentialMechanism::TokenGrant, CredentialOutcome::Withheld);
        assert_eq!(state.effective_outcome(), Some(CredentialOutcome::Prepared));
        for outcome in [
            CredentialOutcome::Unavailable,
            CredentialOutcome::Stale,
            CredentialOutcome::Denied,
        ] {
            state.complete(outcome);
            assert_eq!(state.effective_outcome(), Some(outcome));
            assert_eq!(state.snapshot().unwrap().outcome, outcome);
        }
    }

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
            let expected = correlation.span.id().expect("request span has an id");
            let mut yielded = false;
            let current = futures::executor::block_on(correlation.within_span(
                futures::future::poll_fn(|cx| {
                    if yielded {
                        Poll::Ready(tracing::Span::current().id())
                    } else {
                        yielded = true;
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }),
            ));

            assert_eq!(current, Some(expected));
        });
    }

    #[test]
    fn middleware_phases_end_before_the_request_and_report_cancellation() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "middleware-lifetime"));
        tracing::subscriber::with_default(subscriber, || {
            let correlation = RequestCorrelation::new(&request(), &L7EvalContext::default());
            {
                let _phase = correlation.begin_middleware(MiddlewarePhase::Request);
                correlation
                    .complete_middleware(MiddlewarePhase::Request, MiddlewareOutcome::Allowed);
            }
            {
                let _cancelled = correlation.begin_middleware(MiddlewarePhase::Response);
            }
            let spans = exporter.get_finished_spans().unwrap();
            assert_eq!(spans.len(), 2, "only the phases have ended");
            let completed = spans
                .iter()
                .find(|span| span.name == "openshell.middleware.request")
                .unwrap();
            assert!(!matches!(
                completed.status,
                opentelemetry::trace::Status::Error { .. }
            ));
            let cancelled = spans
                .iter()
                .find(|span| span.name == "openshell.middleware.response")
                .unwrap();
            assert!(matches!(
                cancelled.status,
                opentelemetry::trace::Status::Error { .. }
            ));
            assert!(
                correlation
                    .middleware_span(MiddlewarePhase::Response)
                    .is_disabled()
            );
        });
        assert_eq!(exporter.get_finished_spans().unwrap().len(), 3);
    }

    #[test]
    fn repeated_middleware_observations_preserve_the_terminal_verdict() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let exporter = opentelemetry_sdk::trace::InMemorySpanExporterBuilder::new().build();
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_max_attributes_per_span(48)
            .with_simple_exporter(exporter.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(openshell_otel::layer(&provider, "middleware-attributes"));
        tracing::subscriber::with_default(subscriber, || {
            let correlation = RequestCorrelation::new(&request(), &L7EvalContext::default());
            for phase in [MiddlewarePhase::Request, MiddlewarePhase::Response] {
                let _phase = correlation.begin_middleware(phase);
                // OCSF correlation and remote RPCs can materialize the SDK span early.
                assert!(
                    correlation
                        .middleware_span(phase)
                        .in_scope(openshell_otel::current_ocsf_trace_correlation)
                        .is_some()
                );
                for _ in 0..1000 {
                    correlation.observe_middleware(phase, MiddlewareObservation::default());
                }
                correlation.observe_middleware(
                    phase,
                    MiddlewareObservation {
                        diagnostics_truncated: true,
                        partial_delivery: true,
                        ..Default::default()
                    },
                );
                correlation.complete_middleware(phase, MiddlewareOutcome::Denied);
            }
        });
        let spans = exporter.get_finished_spans().unwrap();
        let phases = spans
            .iter()
            .filter(|span| span.name.starts_with("openshell.middleware."))
            .collect::<Vec<_>>();
        assert_eq!(phases.len(), 2);
        for span in phases {
            let attributes = span
                .attributes
                .iter()
                .map(|attribute| (attribute.key.as_str(), attribute.value.to_string()))
                .collect::<BTreeMap<_, _>>();
            assert_eq!(attributes["openshell.middleware.outcome"], "denied");
            assert_eq!(
                attributes["openshell.middleware.diagnostics_truncated"],
                "true"
            );
            assert_eq!(attributes["openshell.response.partial_delivery"], "true");
            assert_eq!(span.dropped_attributes_count, 0);
        }
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
            assert!(!correlation.evaluate_policy(|| false));
            correlation.record_policy_decision("deny");
            correlation.record_enforcement_action("block");
            correlation.record_final_http_outcome("denied");
            correlation.record_response_status(403);
            correlation.record_error_stage("policy");
            correlation.record_target_reached();
        });

        let spans = exporter.get_finished_spans().unwrap();
        let span = spans
            .iter()
            .find(|span| span.name == "openshell.http.request")
            .unwrap();
        let policy = spans
            .iter()
            .find(|span| span.name == "openshell.policy.evaluate")
            .unwrap();
        assert_eq!(policy.parent_span_id, span.span_context.span_id());
        assert_eq!(span.span_kind, opentelemetry::trace::SpanKind::Server);
        let attributes = span
            .attributes
            .iter()
            .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(attributes["openshell.policy.decision"], "deny");
        assert_eq!(attributes["openshell.enforcement.action"], "block");
        assert_eq!(attributes["openshell.http.outcome"], "denied");
        assert_eq!(attributes["http.response.status_code"], "403");
        assert!(!attributes.contains_key("openshell.error.stage"));
        assert_eq!(attributes["openshell.target.reached"], "true");
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
            .find(|span| span.name == "openshell.http.request")
            .unwrap();
        let method = span
            .attributes
            .iter()
            .find(|attribute| attribute.key.as_str() == "http.request.method")
            .expect("method attribute");
        assert_eq!(method.value.to_string(), "OTHER");
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
            .find(|span| span.name == "openshell.http.request")
            .unwrap();
        let attributes = span
            .attributes
            .into_iter()
            .map(|kv| (kv.key.as_str().to_string(), kv.value.to_string()))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(attributes["openshell.http.outcome"], "incomplete");
        assert!(!attributes.contains_key("openshell.error.stage"));
    }

    #[test]
    fn malformed_or_incomplete_header_block_has_no_trace_context() {
        assert!(trace_headers(b"GET / HTTP/1.1\r\ntraceparent: value").is_empty());
        assert!(trace_headers(&[0xff, b'\r', b'\n', b'\r', b'\n']).is_empty());
    }

    #[tokio::test]
    async fn primary_record_waits_for_the_final_response_head_and_is_emitted_once() {
        use tokio::io::AsyncWriteExt as _;
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _subscriber = capture.install();
        let ctx = L7EvalContext::default();
        let correlation = RequestCorrelation::new(&request(), &ctx);
        let id = correlation.request_id().to_string();
        correlation.emit(
            HttpActivityBuilder::new(openshell_ocsf::ctx::ctx())
                .http_request(HttpRequest::new("GET", ctx.ocsf_url("/data")))
                .action(ActionId::Allowed)
                .build(),
        );
        let mut output = Vec::new();
        {
            let mut client = correlation.observe_response(&mut output);
            client
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n")
                .await
                .unwrap();
            assert!(capture.events().is_empty());
            client.write_all(b"\r\nbody").await.unwrap();
            let events = capture.json_events();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["http_response"]["code"], 200);
            assert_eq!(events[0]["metadata"]["correlation_uid"], id);
        }
        drop(correlation);
        assert_eq!(capture.events().len(), 1);
        assert!(output.ends_with(b"\r\n\r\nbody"));
    }

    #[test]
    fn request_ending_before_response_headers_still_has_one_primary_record() {
        let capture = openshell_ocsf::test_support::OcsfCapture::default();
        let _subscriber = capture.install();
        let correlation = RequestCorrelation::new(&request(), &L7EvalContext::default());
        let id = correlation.request_id().to_string();
        let mut head = ResponseHead::default();
        head.accept(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n", &correlation);
        assert!(capture.events().is_empty());
        drop(correlation);
        let events = capture.json_events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["metadata"]["correlation_uid"], id);
        assert_eq!(events[0]["status_detail"], "request_incomplete");
        assert!(events[0].get("http_response").is_none());
    }
}
