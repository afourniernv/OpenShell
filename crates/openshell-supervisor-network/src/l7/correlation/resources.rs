// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::OnceLock;

use openshell_ocsf::BaseEventData;
use tracing::Span;

use crate::l7::L7EndpointConfig;

#[derive(Debug, Default)]
pub(super) struct RequestResources {
    generation: OnceLock<String>,
    endpoint: OnceLock<SelectedEndpoint>,
    provider: OnceLock<SelectedProvider>,
}

#[derive(Debug)]
struct SelectedEndpoint {
    policy_hash: String,
    endpoint_id: String,
}

#[derive(Debug)]
struct SelectedProvider {
    revision: String,
    installation_id: String,
}

impl RequestResources {
    pub(super) fn record_generation(&self, generation: u64, span: &Span) {
        let generation = self.generation.get_or_init(|| generation.to_string());
        span.record("openshell.policy.runtime_generation", generation.as_str());
    }

    pub(super) fn record_endpoint(&self, config: &L7EndpointConfig, span: &Span) {
        if config.policy_hash.is_empty() || config.endpoint_id.is_empty() {
            return;
        }
        let selected = self.endpoint.get_or_init(|| SelectedEndpoint {
            policy_hash: config.policy_hash.clone(),
            endpoint_id: config.endpoint_id.clone(),
        });
        span.record("openshell.policy.hash", selected.policy_hash.as_str());
        span.record("openshell.endpoint.id", selected.endpoint_id.as_str());
    }

    pub(super) fn record_provider(&self, revision: u64, installation_id: &str, span: &Span) {
        let selected = self.provider.get_or_init(|| SelectedProvider {
            revision: revision.to_string(),
            installation_id: installation_id.to_owned(),
        });
        span.record(
            "openshell.provider.environment_revision",
            selected.revision.as_str(),
        );
        span.record(
            "openshell.provider.credential_installation_id",
            selected.installation_id.as_str(),
        );
    }

    pub(super) fn enrich(&self, event: &mut BaseEventData) {
        if let Some(generation) = self.generation.get() {
            event.add_unmapped("policy_runtime_generation", generation.as_str());
        }
        if let Some(selected) = self.endpoint.get() {
            event.add_unmapped("policy_hash", selected.policy_hash.as_str());
            event.add_unmapped("endpoint_id", selected.endpoint_id.as_str());
        }
        // Per-control records contain only selections already made when the
        // record is emitted; a later credential lookup cannot rewrite them.
        if let Some(selected) = self.provider.get() {
            event.add_unmapped("provider_environment_revision", selected.revision.as_str());
            event.add_unmapped(
                "provider_credential_installation_id",
                selected.installation_id.as_str(),
            );
        }
    }
}
