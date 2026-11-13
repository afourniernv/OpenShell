// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::opa::{NetworkInput, OpaEngine};
use openshell_core::provider_credentials::ProviderCredentialState;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt as _, DuplexStream};
use tracing::instrument::WithSubscriber as _;

const POLICY: &str = r"
version: 1
network_policies:
  resources:
    name: resources
    endpoints:
      - host: example.test
        port: 443
        protocol: rest
        rules:
          - allow: { method: GET, path: /data }
    binaries:
      - { path: /usr/bin/curl }
";

fn network_input() -> NetworkInput {
    NetworkInput {
        host: "example.test".into(),
        port: 443,
        binary_path: PathBuf::from("/usr/bin/curl"),
        binary_sha256: String::new(),
        ancestors: Vec::new(),
        cmdline_paths: Vec::new(),
    }
}

fn selected_config(engine: &OpaEngine) -> L7EndpointConfig {
    let raw = engine
        .query_endpoint_config(&network_input())
        .unwrap()
        .expect("configured endpoint");
    crate::l7::parse_l7_config(&raw).expect("REST endpoint")
}

async fn read_head(stream: &mut DuplexStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 8192, "bounded test header");
        bytes.push(stream.read_u8().await.expect("complete HTTP head"));
    }
    bytes
}

async fn exchange_requests(
    engine: &OpaEngine,
    state: &ProviderCredentialState,
    count: usize,
) -> Vec<String> {
    let config = selected_config(engine);
    let tunnel = engine
        .clone_engine_for_tunnel(engine.current_generation())
        .unwrap();
    let ctx = L7EvalContext {
        host: "example.test".into(),
        port: 443,
        request_default_port: Some(443),
        policy_name: "resources".into(),
        binary_path: "/usr/bin/curl".into(),
        provider_credentials: Some(state.clone()),
        ..Default::default()
    };
    let (mut app, mut client) = tokio::io::duplex(8192);
    let (mut relay_upstream, mut api) = tokio::io::duplex(8192);
    let relay = tokio::spawn(
        async move {
            relay_with_inspection(&config, tunnel, &mut client, &mut relay_upstream, &ctx).await
        }
        .with_current_subscriber(),
    );
    let target = tokio::spawn(async move {
        for index in 0..count {
            let request = read_head(&mut api).await;
            assert!(request.starts_with(b"GET /data HTTP/1.1\r\n"));
            let connection = if index + 1 == count {
                "close"
            } else {
                "keep-alive"
            };
            api.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: {connection}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        }
    });
    let mut receipts = Vec::new();
    for index in 0..count {
        if index > 0 {
            state.install_environment(
                42,
                HashMap::from([("KEY".into(), "SENTINEL-ROTATED-SECRET".into())]),
                HashMap::new(),
                HashMap::new(),
            );
        }
        app.write_all(b"GET /data HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .unwrap();
        let response = String::from_utf8(read_head(&mut app).await).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        let id = response
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("x-openshell-request-id")
                    .then(|| value.trim().to_owned())
            })
            .expect("protected receipt");
        receipts.push(id);
    }
    relay.await.unwrap().unwrap();
    target.await.unwrap();
    receipts
}

#[tokio::test]
async fn resource_revisions_follow_actual_requests_across_rotation_and_reload() {
    let mut policy = openshell_policy::parse_sandbox_policy(POLICY).unwrap();
    let engine = OpaEngine::from_proto(&policy).unwrap();
    let first_config = selected_config(&engine);
    let first_generation = engine.current_generation();
    let state = ProviderCredentialState::from_environment(
        41,
        HashMap::from([("KEY".into(), "SENTINEL-ORIGINAL-SECRET".into())]),
        HashMap::new(),
        HashMap::new(),
    );
    let first_snapshot = state.snapshot();
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let _subscriber = capture.install();
    let mut receipts = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        exchange_requests(&engine, &state, 2),
    )
    .await
    .unwrap();
    let second_snapshot = state.snapshot();
    let before_reload = capture.json_events();

    policy
        .network_policies
        .get_mut("resources")
        .unwrap()
        .name
        .push_str("-v2");
    engine.reload_from_proto(&policy).unwrap();
    let third_generation = engine.current_generation();
    let third_config = selected_config(&engine);
    assert_ne!(first_generation, third_generation);
    assert_ne!(first_config.policy_hash, third_config.policy_hash);
    state.install_environment(43, HashMap::new(), HashMap::new(), HashMap::new());
    let third_snapshot = state.snapshot();
    receipts.extend(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            exchange_requests(&engine, &state, 1),
        )
        .await
        .unwrap(),
    );

    let events = capture.json_events();
    assert_eq!(&events[..before_reload.len()], before_reload);
    assert_eq!(receipts.len(), 3);
    for ((id, snapshot), (generation, config)) in receipts
        .iter()
        .zip([first_snapshot, second_snapshot, third_snapshot])
        .zip([
            (first_generation, &first_config),
            (first_generation, &first_config),
            (third_generation, &third_config),
        ])
    {
        let records = events
            .iter()
            .filter(|event| {
                event["class_uid"] == 4002 && event["metadata"]["correlation_uid"] == *id
            })
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 1);
        let record = records[0];
        assert_eq!(
            record["unmapped"]["policy_runtime_generation"],
            generation.to_string()
        );
        assert_eq!(record["unmapped"]["policy_hash"], config.policy_hash);
        assert_eq!(record["unmapped"]["endpoint_id"], config.endpoint_id);
        assert_eq!(
            record["unmapped"]["provider_environment_revision"],
            snapshot.revision.to_string()
        );
        assert_eq!(
            record["unmapped"]["provider_credential_installation_id"],
            snapshot.installation_id
        );
        assert!(record.get("trace").is_none());
        assert_eq!(record["http_response"]["code"], 200);
    }
    assert!(!serde_json::to_string(&events).unwrap().contains("SENTINEL"));
}
