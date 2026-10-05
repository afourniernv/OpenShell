// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Span enrichment: injects sandbox resource attributes into OTLP trace data.

use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;

use super::SandboxMetadata;

/// Attribute names whose values are derived by trusted `OpenShell` components.
///
/// Keep this as an explicit allowlist instead of reserving the entire
/// `openshell.*` namespace. That prevents a workload from contradicting the
/// identity attached by the supervisor without deleting unrelated application
/// attributes merely because they share a vendor prefix.
const AUTHORITATIVE_ATTRIBUTE_KEYS: [&str; 7] = [
    "openshell.telemetry.source",
    "openshell.sandbox.id",
    "openshell.workspace.id",
    "openshell.sandbox.policy",
    "openshell.sandbox.user",
    "openshell.sandbox.image",
    "openshell.sandbox.driver",
];

/// Content type of the incoming OTLP request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Protobuf,
    Json,
}

/// Enrich spans with sandbox resource attributes. Input can be protobuf or
/// JSON-encoded `ExportTraceServiceRequest`. Output is always protobuf.
///
/// When `enrichment_enabled` is false, sandbox metadata attributes are skipped
/// but `openshell.telemetry.source: "agent"` is always injected (relay marker).
pub fn enrich_spans(
    raw: &[u8],
    content_type: ContentType,
    attrs: &SandboxMetadata,
    enrichment_enabled: bool,
) -> Result<Vec<u8>, EnrichmentError> {
    let mut request = match content_type {
        ContentType::Protobuf => {
            ExportTraceServiceRequest::decode(raw).map_err(EnrichmentError::ProtobufDecode)?
        }
        ContentType::Json => serde_json::from_slice::<ExportTraceServiceRequest>(raw)
            .map_err(EnrichmentError::JsonDecode)?,
    };

    let extra_attrs = build_attributes(attrs, enrichment_enabled);

    for resource_spans in &mut request.resource_spans {
        let resource = resource_spans
            .resource
            .get_or_insert_with(Resource::default);

        strip_authoritative_attributes(&mut resource.attributes);

        for attr in &extra_attrs {
            resource.attributes.push(attr.clone());
        }

        // OTLP keeps resource, instrumentation-scope, span, event, and link
        // attributes in separate collections. Backends often make all of
        // them queryable together, so stripping only resource attributes
        // still lets an untrusted workload publish a contradictory OpenShell
        // identity at a narrower scope.
        for scope_spans in &mut resource_spans.scope_spans {
            if let Some(scope) = &mut scope_spans.scope {
                strip_authoritative_attributes(&mut scope.attributes);
            }
            for span in &mut scope_spans.spans {
                strip_authoritative_attributes(&mut span.attributes);
                for event in &mut span.events {
                    strip_authoritative_attributes(&mut event.attributes);
                }
                for link in &mut span.links {
                    strip_authoritative_attributes(&mut link.attributes);
                }
            }
        }
    }

    Ok(request.encode_to_vec())
}

fn strip_authoritative_attributes(attributes: &mut Vec<KeyValue>) {
    attributes.retain(|attribute| !AUTHORITATIVE_ATTRIBUTE_KEYS.contains(&attribute.key.as_str()));
}

fn build_attributes(meta: &SandboxMetadata, enrichment_enabled: bool) -> Vec<KeyValue> {
    let mut attrs = Vec::new();

    // Always inject the relay routing marker regardless of enrichment toggle
    attrs.push(kv("openshell.telemetry.source", "agent"));

    if enrichment_enabled {
        attrs.push(kv("openshell.sandbox.id", &meta.sandbox_id));
        attrs.push(kv("openshell.workspace.id", &meta.workspace_id));
        attrs.push(kv("openshell.sandbox.policy", &meta.policy));
        attrs.push(kv("openshell.sandbox.user", &meta.user));
        attrs.push(kv("openshell.sandbox.image", &meta.image));
        attrs.push(kv("openshell.sandbox.driver", &meta.driver));
    }

    attrs
}

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(
                opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(
                    value.to_string(),
                ),
            ),
        }),
        key_strindex: 0,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnrichmentError {
    #[error("protobuf decode failed: {0}")]
    ProtobufDecode(prost::DecodeError),
    #[error("JSON decode failed: {0}")]
    JsonDecode(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};
    use prost::Message;

    fn test_metadata() -> SandboxMetadata {
        SandboxMetadata {
            sandbox_id: "sb-123".into(),
            workspace_id: "ws-456".into(),
            policy: "default".into(),
            user: "test-user".into(),
            image: "test-image:latest".into(),
            driver: "docker".into(),
        }
    }

    fn make_trace_request() -> Vec<u8> {
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![Span {
                        name: "test-span".into(),
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        req.encode_to_vec()
    }

    #[test]
    fn enrichment_adds_all_attributes() {
        let raw = make_trace_request();
        let result = enrich_spans(&raw, ContentType::Protobuf, &test_metadata(), true).unwrap();

        let decoded = ExportTraceServiceRequest::decode(result.as_slice()).unwrap();
        let resource = decoded.resource_spans[0].resource.as_ref().unwrap();

        let attr_keys: Vec<&str> = resource.attributes.iter().map(|a| a.key.as_str()).collect();
        assert!(attr_keys.contains(&"openshell.sandbox.id"));
        assert!(attr_keys.contains(&"openshell.workspace.id"));
        assert!(attr_keys.contains(&"openshell.telemetry.source"));
    }

    #[test]
    fn enrichment_disabled_only_adds_source() {
        let raw = make_trace_request();
        let result = enrich_spans(&raw, ContentType::Protobuf, &test_metadata(), false).unwrap();

        let decoded = ExportTraceServiceRequest::decode(result.as_slice()).unwrap();
        let resource = decoded.resource_spans[0].resource.as_ref().unwrap();

        assert_eq!(resource.attributes.len(), 1);
        assert_eq!(resource.attributes[0].key, "openshell.telemetry.source");
    }

    #[test]
    fn enrichment_strips_agent_supplied_trusted_keys() {
        use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
        use opentelemetry_proto::tonic::resource::v1::Resource;

        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![
                        KeyValue {
                            key: "openshell.sandbox.id".into(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue(
                                    "agent-spoofed-id".into(),
                                )),
                            }),
                            key_strindex: 0,
                        },
                        KeyValue {
                            key: "openshell.telemetry.source".into(),
                            value: Some(AnyValue {
                                value: Some(any_value::Value::StringValue("fake".into())),
                            }),
                            key_strindex: 0,
                        },
                    ],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_spans: vec![],
                schema_url: String::new(),
            }],
        };
        let raw = req.encode_to_vec();

        let result = enrich_spans(&raw, ContentType::Protobuf, &test_metadata(), true).unwrap();
        let decoded = ExportTraceServiceRequest::decode(result.as_slice()).unwrap();
        let attrs = &decoded.resource_spans[0]
            .resource
            .as_ref()
            .unwrap()
            .attributes;

        let sandbox_ids: Vec<_> = attrs
            .iter()
            .filter(|a| a.key == "openshell.sandbox.id")
            .collect();
        assert_eq!(sandbox_ids.len(), 1, "should have exactly one sandbox.id");

        let sources = attrs
            .iter()
            .filter(|a| a.key == "openshell.telemetry.source")
            .count();
        assert_eq!(sources, 1, "should have exactly one telemetry.source");

        if let Some(AnyValue {
            value: Some(any_value::Value::StringValue(v)),
        }) = &sandbox_ids[0].value
        {
            assert_eq!(v, "sb-123", "should use supervisor's value, not agent's");
        }
    }

    #[test]
    fn enrichment_preserves_non_trusted_agent_attributes() {
        use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
        use opentelemetry_proto::tonic::resource::v1::Resource;

        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![KeyValue {
                        key: "my.custom.attr".into(),
                        value: Some(AnyValue {
                            value: Some(any_value::Value::StringValue("keep-me".into())),
                        }),
                        key_strindex: 0,
                    }],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_spans: vec![],
                schema_url: String::new(),
            }],
        };
        let raw = req.encode_to_vec();

        let result = enrich_spans(&raw, ContentType::Protobuf, &test_metadata(), true).unwrap();
        let decoded = ExportTraceServiceRequest::decode(result.as_slice()).unwrap();
        let attrs = &decoded.resource_spans[0]
            .resource
            .as_ref()
            .unwrap()
            .attributes;

        assert!(
            attrs.iter().any(|a| a.key == "my.custom.attr"),
            "custom agent attribute should be preserved"
        );
        assert!(
            attrs.iter().any(|a| a.key == "openshell.sandbox.id"),
            "enrichment attributes should also be present"
        );
    }

    #[test]
    fn enrichment_strips_authoritative_keys_from_every_attribute_owner() {
        use opentelemetry_proto::tonic::common::v1::{
            AnyValue, InstrumentationScope, KeyValue, any_value,
        };
        use opentelemetry_proto::tonic::resource::v1::Resource;
        use opentelemetry_proto::tonic::trace::v1::span;

        fn spoofed(key: &str) -> KeyValue {
            KeyValue {
                key: key.into(),
                value: Some(AnyValue {
                    value: Some(any_value::Value::StringValue("workload-controlled".into())),
                }),
                key_strindex: 0,
            }
        }

        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![
                        spoofed("openshell.sandbox.id"),
                        spoofed("openshell.application.phase"),
                    ],
                    ..Default::default()
                }),
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        attributes: vec![spoofed("openshell.workspace.id")],
                        ..Default::default()
                    }),
                    spans: vec![Span {
                        attributes: vec![spoofed("openshell.sandbox.policy")],
                        events: vec![span::Event {
                            attributes: vec![spoofed("openshell.sandbox.user")],
                            ..Default::default()
                        }],
                        links: vec![span::Link {
                            attributes: vec![spoofed("openshell.sandbox.driver")],
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let encoded = enrich_spans(
            &request.encode_to_vec(),
            ContentType::Protobuf,
            &test_metadata(),
            true,
        )
        .unwrap();
        let decoded = ExportTraceServiceRequest::decode(encoded.as_slice()).unwrap();
        let resource_spans = &decoded.resource_spans[0];
        let resource = resource_spans.resource.as_ref().unwrap();
        let scope_spans = &resource_spans.scope_spans[0];
        let span = &scope_spans.spans[0];

        assert_eq!(
            resource
                .attributes
                .iter()
                .find(|attribute| attribute.key == "openshell.sandbox.id")
                .and_then(|attribute| attribute.value.as_ref())
                .and_then(|value| value.value.as_ref()),
            Some(&any_value::Value::StringValue("sb-123".into())),
            "resource identity must come from the supervisor"
        );
        assert!(
            resource
                .attributes
                .iter()
                .any(|attribute| attribute.key == "openshell.application.phase"),
            "unreserved OpenShell application attributes must be preserved"
        );

        for attributes in [
            scope_spans.scope.as_ref().unwrap().attributes.as_slice(),
            span.attributes.as_slice(),
            span.events[0].attributes.as_slice(),
            span.links[0].attributes.as_slice(),
        ] {
            assert!(
                attributes
                    .iter()
                    .all(|attribute| !attribute.key.starts_with("openshell.")),
                "workload-controlled owners must not retain authoritative keys"
            );
        }
    }

    #[test]
    fn enrichment_handles_json_content_type() {
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: None,
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![Span {
                        name: "json-span".into(),
                        ..Default::default()
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        let json = serde_json::to_vec(&req).unwrap();

        let result = enrich_spans(&json, ContentType::Json, &test_metadata(), true).unwrap();

        let decoded = ExportTraceServiceRequest::decode(result.as_slice()).unwrap();
        let resource = decoded.resource_spans[0].resource.as_ref().unwrap();
        assert!(
            resource
                .attributes
                .iter()
                .any(|a| a.key == "openshell.telemetry.source")
        );
    }

    #[test]
    fn enrichment_rejects_invalid_protobuf() {
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC];
        let result = enrich_spans(&garbage, ContentType::Protobuf, &test_metadata(), true);
        assert!(
            matches!(result, Err(EnrichmentError::ProtobufDecode(_))),
            "should return ProtobufDecode error"
        );
    }
}
