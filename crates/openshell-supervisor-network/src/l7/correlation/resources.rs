// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use openshell_core::provider_credentials::ProviderCredentialSnapshot;
use openshell_ocsf::OcsfEvent;

#[derive(Debug, Default)]
pub(super) struct RequestResources {
    policy_generation: Option<u64>,
    endpoint: Option<PolicyEndpoint>,
    provider: Option<ProviderInstallation>,
}

#[derive(Debug)]
struct PolicyEndpoint {
    policy_hash: String,
    endpoint_id: String,
}

#[derive(Debug)]
struct ProviderInstallation {
    revision: u64,
    installation_id: uuid::Uuid,
}

impl RequestResources {
    pub(super) fn record_policy_generation(&mut self, generation: u64) {
        self.policy_generation.get_or_insert(generation);
    }

    pub(super) fn record_endpoint(&mut self, policy_hash: &str, endpoint_id: &str) {
        if self.endpoint.is_some()
            || !is_digest(policy_hash)
            || endpoint_id
                .strip_prefix("endpoint:v1:")
                .is_none_or(|digest| !is_digest(digest))
        {
            return;
        }
        self.endpoint = Some(PolicyEndpoint {
            policy_hash: policy_hash.into(),
            endpoint_id: endpoint_id.into(),
        });
    }

    pub(super) fn record_provider(&mut self, snapshot: &ProviderCredentialSnapshot) {
        if self.provider.is_some() {
            return;
        }
        if let Ok(installation_id) = uuid::Uuid::parse_str(&snapshot.installation_id) {
            self.provider = Some(ProviderInstallation {
                revision: snapshot.revision,
                installation_id,
            });
        }
    }

    pub(super) fn enrich(&self, event: &mut OcsfEvent) {
        if let Some(generation) = self.policy_generation {
            event.add_unmapped("policy_runtime_generation", generation.to_string());
        }
        if let Some(endpoint) = &self.endpoint {
            event.add_unmapped("policy_hash", endpoint.policy_hash.clone());
            event.add_unmapped("endpoint_id", endpoint.endpoint_id.clone());
        }
        if let Some(provider) = &self.provider {
            event.add_unmapped(
                "provider_environment_revision",
                provider.revision.to_string(),
            );
            event.add_unmapped(
                "provider_credential_installation_id",
                provider.installation_id.hyphenated().to_string(),
            );
        }
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
