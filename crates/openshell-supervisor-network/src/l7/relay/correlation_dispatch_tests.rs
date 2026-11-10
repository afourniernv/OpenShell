// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Correlation contracts for the production single-config relay dispatch.

use super::L7EvalContext;
use crate::l7::L7EndpointConfig;
use crate::opa::{NetworkInput, OpaEngine, TunnelPolicyEngine};
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::layer::SubscriberExt as _;

const POLICY: &str = include_str!("../../../data/sandbox-policy.rego");

struct Fixture {
    config: L7EndpointConfig,
    tunnel_engine: TunnelPolicyEngine,
    middleware_engine: OpaEngine,
    ctx: L7EvalContext,
}

struct Exchange {
    response: Vec<u8>,
    forwarded: Vec<u8>,
    ocsf_events: Vec<serde_json::Value>,
}

fn fixture(data: &str, host: &str, policy_name: &str) -> Fixture {
    let middleware_engine = OpaEngine::from_strings(POLICY, data).expect("valid test policy");
    let input = NetworkInput {
        host: host.into(),
        port: 8000,
        binary_path: PathBuf::from("/usr/bin/python3"),
        binary_sha256: "unused".into(),
        ancestors: vec![],
        cmdline_paths: vec![],
    };
    let (endpoint_config, generation) = middleware_engine
        .query_endpoint_config_with_generation(&input)
        .expect("query endpoint config");
    let config = crate::l7::parse_l7_config(
        &endpoint_config.expect("single configured endpoint should match"),
    )
    .expect("parse endpoint config");
    let tunnel_engine = middleware_engine
        .clone_engine_for_tunnel(generation)
        .expect("pin test policy generation");
    let ctx = L7EvalContext {
        host: host.into(),
        port: 8000,
        request_default_port: Some(8000),
        policy_name: policy_name.into(),
        binary_path: "/usr/bin/python3".into(),
        ..Default::default()
    };
    Fixture {
        config,
        tunnel_engine,
        middleware_engine,
        ctx,
    }
}

async fn read_http_message<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
    let mut message = Vec::new();
    let mut byte = [0_u8; 1];
    while !message.ends_with(b"\r\n\r\n") {
        reader
            .read_exact(&mut byte)
            .await
            .expect("complete HTTP headers");
        message.push(byte[0]);
    }
    let headers = std::str::from_utf8(&message).expect("ASCII test headers");
    let body_len = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("numeric content length")
            })
        })
        .unwrap_or_default();
    let header_len = message.len();
    message.resize(header_len + body_len, 0);
    reader
        .read_exact(&mut message[header_len..])
        .await
        .expect("complete HTTP body");
    message
}

fn request_id(response: &[u8]) -> &str {
    let headers_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("complete response headers");
    std::str::from_utf8(&response[..headers_end])
        .expect("ASCII response headers")
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("x-openshell-request-id")
                .then(|| value.trim())
        })
        .expect("response carries a request receipt")
}

async fn run_allowed(
    fixture: Fixture,
    request: Vec<u8>,
    upstream_response: &'static [u8],
) -> Exchange {
    let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(ocsf.clone());
    let (mut app, mut relay_client) = tokio::io::duplex(32 * 1024);
    let (mut relay_upstream, mut upstream) = tokio::io::duplex(32 * 1024);
    let Fixture {
        config,
        tunnel_engine,
        middleware_engine,
        ctx,
    } = fixture;

    let exchange = async {
        tracing::callsite::rebuild_interest_cache();
        tokio::join!(
            crate::proxy::relay_inspected_http_stream_for_test(
                &mut relay_client,
                &mut relay_upstream,
                vec![config],
                tunnel_engine,
                &middleware_engine,
                &ctx,
            ),
            async {
                app.write_all(&request).await.expect("send request");
                app.flush().await.expect("flush request");
                read_http_message(&mut app).await
            },
            async {
                let forwarded = read_http_message(&mut upstream).await;
                upstream
                    .write_all(upstream_response)
                    .await
                    .expect("send upstream response");
                upstream.flush().await.expect("flush upstream response");
                forwarded
            },
        )
    }
    .with_subscriber(subscriber);
    let (relay, response, forwarded) =
        tokio::time::timeout(std::time::Duration::from_secs(5), Box::pin(exchange))
            .await
            .expect("single-config relay exchange completes");
    relay.expect("relay succeeds");
    Exchange {
        response,
        forwarded,
        ocsf_events: ocsf.json_events(),
    }
}

async fn run_denied(fixture: Fixture, request: Vec<u8>) -> Exchange {
    let ocsf = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(ocsf.clone());
    let (mut app, mut relay_client) = tokio::io::duplex(32 * 1024);
    let (mut relay_upstream, mut upstream) = tokio::io::duplex(32 * 1024);
    let Fixture {
        config,
        tunnel_engine,
        middleware_engine,
        ctx,
    } = fixture;

    let exchange = async {
        tracing::callsite::rebuild_interest_cache();
        tokio::join!(
            crate::proxy::relay_inspected_http_stream_for_test(
                &mut relay_client,
                &mut relay_upstream,
                vec![config],
                tunnel_engine,
                &middleware_engine,
                &ctx,
            ),
            async {
                app.write_all(&request).await.expect("send request");
                app.flush().await.expect("flush request");
                read_http_message(&mut app).await
            },
            async {
                let mut forwarded = Vec::new();
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    upstream.read_to_end(&mut forwarded),
                )
                .await;
                forwarded
            },
        )
    }
    .with_subscriber(subscriber);
    let (relay, response, forwarded) =
        tokio::time::timeout(std::time::Duration::from_secs(5), Box::pin(exchange))
            .await
            .expect("single-config denial completes");
    relay.expect("relay succeeds");
    Exchange {
        response,
        forwarded,
        ocsf_events: ocsf.json_events(),
    }
}

fn assert_primary_record<'a>(
    exchange: &'a Exchange,
    engine_type: &str,
    status: u16,
    action: &str,
    path: &str,
) -> &'a serde_json::Value {
    let receipt = request_id(&exchange.response);
    assert!(
        uuid::Uuid::parse_str(receipt).is_ok(),
        "canonical receipt: {receipt}"
    );
    let primary: Vec<_> = exchange
        .ocsf_events
        .iter()
        .filter(|event| event["class_uid"] == 4002)
        .collect();
    assert_eq!(
        primary.len(),
        1,
        "one HTTP Activity: {:?}",
        exchange.ocsf_events
    );
    let event = primary[0];
    assert_eq!(event["metadata"]["correlation_uid"], receipt);
    assert_eq!(event["firewall_rule"]["type"], engine_type);
    assert_eq!(event["http_response"]["code"], status);
    assert_eq!(event["action"], action);
    assert_eq!(event["http_request"]["url"]["path"], path);
    assert!(
        event.get("trace").is_none(),
        "receipts must work without tracing"
    );
    event
}

fn mcp_fixture() -> Fixture {
    fixture(
        r#"
network_policies:
  mcp_api:
    name: mcp_api
    endpoints:
      - host: mcp.example.test
        port: 8000
        path: /mcp
        protocol: mcp
        enforcement: enforce
        mcp:
          versions: ["2025-11-25"]
        rules:
          - allow:
              method: initialize
    binaries:
      - { path: /usr/bin/python3 }
"#,
        "mcp.example.test",
        "mcp_api",
    )
}

fn request(host: &str, path: &str, extra_headers: &str, body: &str) -> Vec<u8> {
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:8000\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
    .into_bytes()
}

#[tokio::test]
async fn inspected_keep_alive_requests_have_distinct_receipts_without_tracing() {
    let Fixture {
        config,
        tunnel_engine,
        middleware_engine,
        ctx,
    } = fixture(
        r"
network_policies:
  rest_api:
    name: rest_api
    endpoints:
      - host: rest.example.test
        port: 8000
        path: /item
        protocol: rest
        enforcement: enforce
        rules:
          - allow: { method: GET, path: /item }
    binaries:
      - { path: /usr/bin/python3 }
",
        "rest.example.test",
        "rest_api",
    );
    let capture = openshell_ocsf::test_support::OcsfCapture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());
    let (mut app, mut relay_client) = tokio::io::duplex(8192);
    let (mut relay_upstream, mut upstream) = tokio::io::duplex(8192);
    let exchange = async {
        tokio::join!(
            crate::proxy::relay_inspected_http_stream_for_test(
                &mut relay_client,
                &mut relay_upstream,
                vec![config],
                tunnel_engine,
                &middleware_engine,
                &ctx,
            ),
            async {
                let mut responses = Vec::new();
                for (sampled, connection) in [("01", "keep-alive"), ("00", "close")] {
                    let request = format!(
                        "GET /item HTTP/1.1\r\nHost: rest.example.test:8000\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-{sampled}\r\nConnection: {connection}\r\n\r\n",
                    );
                    app.write_all(request.as_bytes()).await.expect("send request");
                    app.flush().await.expect("flush request");
                    responses.push(read_http_message(&mut app).await);
                }
                responses
            },
            async {
                for connection in ["keep-alive", "close"] {
                    let request = read_http_message(&mut upstream).await;
                    assert!(request.starts_with(b"GET /item HTTP/1.1\r\n"));
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: {connection}\r\n\r\n");
                    upstream.write_all(response.as_bytes()).await.expect("upstream response");
                    upstream.flush().await.expect("flush response");
                }
            },
        )
    }.with_subscriber(subscriber);
    let (relay, responses, ()) =
        tokio::time::timeout(std::time::Duration::from_secs(5), Box::pin(exchange))
            .await
            .expect("two inspected requests complete");
    relay.expect("inspected relay");
    let receipts: Vec<_> = responses
        .iter()
        .map(|response| request_id(response))
        .collect();
    assert_eq!(receipts.len(), 2);
    assert_ne!(receipts[0], receipts[1]);
    let records: Vec<_> = capture
        .json_events()
        .into_iter()
        .filter(|event| event["class_uid"] == 4002)
        .collect();
    assert_eq!(
        records.len(),
        2,
        "one primary per inspected request: {records:?}"
    );
    for (record, receipt) in records.iter().zip(receipts) {
        assert!(uuid::Uuid::parse_str(receipt).is_ok());
        assert_eq!(record["metadata"]["correlation_uid"], receipt);
        assert_eq!(record["action"], "Allowed");
        assert_eq!(record["http_response"]["code"], 200);
        assert_eq!(record["http_request"]["url"]["path"], "/item");
        assert!(record.get("trace").is_none());
        assert!(
            !record
                .to_string()
                .contains("4bf92f3577b34da6a3ce929d0e0e4736")
        );
    }
}

#[tokio::test]
async fn production_single_mcp_allow_correlates_record_and_response_receipt() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
    let exchange = Box::pin(run_allowed(
        mcp_fixture(),
        request("mcp.example.test", "/mcp", "", body),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
    ))
    .await;

    assert!(exchange.forwarded.starts_with(b"POST /mcp HTTP/1.1\r\n"));
    assert!(exchange.response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_primary_record(&exchange, "l7-mcp", 200, "Allowed", "/mcp");
}

#[tokio::test]
async fn production_single_mcp_invalid_version_correlates_denial_and_receipt() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#;
    let exchange = Box::pin(run_denied(
        mcp_fixture(),
        request(
            "mcp.example.test",
            "/mcp",
            "MCP-Protocol-Version: 1900-01-01\r\n",
            body,
        ),
    ))
    .await;

    assert!(exchange.forwarded.is_empty());
    assert!(
        exchange
            .response
            .starts_with(b"HTTP/1.1 400 Bad Request\r\n")
    );
    assert!(
        String::from_utf8_lossy(&exchange.response).contains("unsupported_mcp_protocol_version")
    );
    assert_primary_record(&exchange, "l7-mcp", 400, "Denied", "/mcp");
}

#[tokio::test]
async fn production_single_mcp_policy_deny_correlates_record_and_receipt() {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
    let exchange = Box::pin(run_denied(
        mcp_fixture(),
        request(
            "mcp.example.test",
            "/mcp",
            "MCP-Protocol-Version: 2025-11-25\r\n",
            body,
        ),
    ))
    .await;

    assert!(exchange.forwarded.is_empty());
    assert!(exchange.response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
    let event = assert_primary_record(&exchange, "l7-mcp", 403, "Denied", "/mcp");
    assert!(
        event["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("JSONRPC_L7_REQUEST decision=deny"))
    );
}

#[tokio::test]
async fn production_single_graphql_allow_correlates_record_and_response_receipt() {
    let graphql = fixture(
        r"
network_policies:
  graphql_api:
    name: graphql_api
    endpoints:
      - host: graphql.example.test
        port: 8000
        path: /graphql
        protocol: graphql
        enforcement: enforce
        rules:
          - allow:
              operation_type: query
              fields: [viewer]
    binaries:
      - { path: /usr/bin/python3 }
",
        "graphql.example.test",
        "graphql_api",
    );
    let body = r#"{"query":"query { viewer }"}"#;
    let exchange = Box::pin(run_allowed(
        graphql,
        request("graphql.example.test", "/graphql", "", body),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 22\r\nConnection: close\r\n\r\n{\"data\":{\"viewer\":{}}}",
    ))
    .await;

    assert!(
        exchange
            .forwarded
            .starts_with(b"POST /graphql HTTP/1.1\r\n")
    );
    assert!(exchange.response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert_primary_record(&exchange, "l7-graphql", 200, "Allowed", "/graphql");
}
