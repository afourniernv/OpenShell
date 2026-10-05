// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Resource enrichment for relayed OTLP traces, logs, and metrics.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;

use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
use opentelemetry_proto::tonic::metrics::v1::{Exemplar, metric};
use opentelemetry_proto::tonic::resource::v1::Resource;
use prost::Message;
use serde::Deserialize;
use serde::de::{
    self, DeserializeOwned, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor,
};

use super::SandboxMetadata;

const MAX_RESOURCE_GROUPS_PER_REQUEST: usize = 1_024;
/// Maximum number of decoded OTLP container and attribute items processed in
/// one request. Typical SDK batches contain hundreds or low thousands of
/// items. A 16K ceiling leaves ample room for those batches while preventing
/// a compact protobuf body containing hundreds of thousands of empty nested
/// messages from multiplying enrichment and sanitization work.
pub(crate) const MAX_STRUCTURAL_ITEMS_PER_REQUEST: usize = 16 * 1_024;
/// Content type of the incoming OTLP request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Protobuf,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignalKind {
    Traces,
    Logs,
    Metrics,
}

impl SignalKind {
    fn name(self) -> &'static str {
        match self {
            Self::Traces => "traces",
            Self::Logs => "logs",
            Self::Metrics => "metrics",
        }
    }

    fn json_resource_field(self) -> &'static str {
        match self {
            Self::Traces => "resourceSpans",
            Self::Logs => "resourceLogs",
            Self::Metrics => "resourceMetrics",
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct TraceRequestJson {
    resource_spans: Vec<opentelemetry_proto::tonic::trace::v1::ResourceSpans>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct LogsRequestJson {
    resource_logs: Vec<opentelemetry_proto::tonic::logs::v1::ResourceLogs>,
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct MetricsRequestJson {
    resource_metrics: Vec<opentelemetry_proto::tonic::metrics::v1::ResourceMetrics>,
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
    preflight_request(raw, content_type, SignalKind::Traces)?;
    let (mut request, empty_any_value_marker) = match content_type {
        ContentType::Protobuf => (
            ExportTraceServiceRequest::decode(raw).map_err(EnrichmentError::ProtobufDecode)?,
            None,
        ),
        ContentType::Json => {
            let (request, marker) = decode_otlp_json::<TraceRequestJson>(raw)?;
            (
                ExportTraceServiceRequest {
                    resource_spans: request.resource_spans,
                },
                marker,
            )
        }
    };
    if let Some(marker) = empty_any_value_marker.as_deref() {
        restore_trace_empty_any_values(&mut request, marker);
    }
    enforce_resource_group_limit("traces", request.resource_spans.len())?;
    enforce_trace_structure_limit(&request)?;

    let extra_attrs = build_attributes(attrs, enrichment_enabled);

    for resource_spans in &mut request.resource_spans {
        enrich_resource(&mut resource_spans.resource, &extra_attrs);
        for scope_spans in &mut resource_spans.scope_spans {
            if let Some(scope) = &mut scope_spans.scope {
                strip_trusted_attributes(&mut scope.attributes);
            }
            for span in &mut scope_spans.spans {
                strip_trusted_attributes(&mut span.attributes);
                for event in &mut span.events {
                    strip_trusted_attributes(&mut event.attributes);
                }
                for link in &mut span.links {
                    strip_trusted_attributes(&mut link.attributes);
                }
            }
        }
    }

    // Enrichment itself adds protobuf messages. Re-scan the final wire form so
    // an HTTP success cannot acknowledge a request the gateway will
    // deterministically reject at the same protobuf boundary.
    let encoded = request.encode_to_vec();
    preflight_protobuf(&encoded, SignalKind::Traces)?;
    Ok(encoded)
}

/// Enrich log resources with the same trusted sandbox attributes as traces.
/// Input can be protobuf or JSON; output is always protobuf.
pub fn enrich_logs(
    raw: &[u8],
    content_type: ContentType,
    attrs: &SandboxMetadata,
    enrichment_enabled: bool,
) -> Result<Vec<u8>, EnrichmentError> {
    preflight_request(raw, content_type, SignalKind::Logs)?;
    let (mut request, empty_any_value_marker) = match content_type {
        ContentType::Protobuf => (
            ExportLogsServiceRequest::decode(raw).map_err(EnrichmentError::ProtobufDecode)?,
            None,
        ),
        ContentType::Json => {
            let (request, marker) = decode_otlp_json::<LogsRequestJson>(raw)?;
            (
                ExportLogsServiceRequest {
                    resource_logs: request.resource_logs,
                },
                marker,
            )
        }
    };
    if let Some(marker) = empty_any_value_marker.as_deref() {
        restore_log_empty_any_values(&mut request, marker);
    }
    enforce_resource_group_limit("logs", request.resource_logs.len())?;
    enforce_log_structure_limit(&request)?;
    let extra_attrs = build_attributes(attrs, enrichment_enabled);
    for resource_logs in &mut request.resource_logs {
        enrich_resource(&mut resource_logs.resource, &extra_attrs);
        for scope_logs in &mut resource_logs.scope_logs {
            if let Some(scope) = &mut scope_logs.scope {
                strip_trusted_attributes(&mut scope.attributes);
            }
            for log_record in &mut scope_logs.log_records {
                strip_trusted_attributes(&mut log_record.attributes);
            }
        }
    }
    let encoded = request.encode_to_vec();
    preflight_protobuf(&encoded, SignalKind::Logs)?;
    Ok(encoded)
}

/// Enrich metric resources with the same trusted sandbox attributes as traces.
/// Input can be protobuf or JSON; output is always protobuf.
pub fn enrich_metrics(
    raw: &[u8],
    content_type: ContentType,
    attrs: &SandboxMetadata,
    enrichment_enabled: bool,
) -> Result<Vec<u8>, EnrichmentError> {
    preflight_request(raw, content_type, SignalKind::Metrics)?;
    let (mut request, empty_any_value_marker) = match content_type {
        ContentType::Protobuf => (
            ExportMetricsServiceRequest::decode(raw).map_err(EnrichmentError::ProtobufDecode)?,
            None,
        ),
        ContentType::Json => {
            let (request, marker) = decode_otlp_json::<MetricsRequestJson>(raw)?;
            (
                ExportMetricsServiceRequest {
                    resource_metrics: request.resource_metrics,
                },
                marker,
            )
        }
    };
    if let Some(marker) = empty_any_value_marker.as_deref() {
        restore_metric_empty_any_values(&mut request, marker);
    }
    enforce_resource_group_limit("metrics", request.resource_metrics.len())?;
    enforce_metric_structure_limit(&request)?;
    let extra_attrs = build_attributes(attrs, enrichment_enabled);
    for resource_metrics in &mut request.resource_metrics {
        enrich_resource(&mut resource_metrics.resource, &extra_attrs);
        for scope_metrics in &mut resource_metrics.scope_metrics {
            if let Some(scope) = &mut scope_metrics.scope {
                strip_trusted_attributes(&mut scope.attributes);
            }
            for metric in &mut scope_metrics.metrics {
                strip_trusted_attributes(&mut metric.metadata);
                sanitize_metric_data(metric.data.as_mut());
            }
        }
    }
    let encoded = request.encode_to_vec();
    preflight_protobuf(&encoded, SignalKind::Metrics)?;
    Ok(encoded)
}

fn preflight_request(
    raw: &[u8],
    content_type: ContentType,
    signal: SignalKind,
) -> Result<(), EnrichmentError> {
    match content_type {
        ContentType::Protobuf => preflight_protobuf(raw, signal),
        ContentType::Json => preflight_json(raw, signal),
    }
}

/// Decode the OTLP JSON mapping while preserving the protobuf definition's
/// valid empty `AnyValue {}` representation.
///
/// `opentelemetry-proto` 0.32 rejects an empty object in its custom
/// `AnyValue` deserializer even though the proto explicitly permits an unset
/// oneof. Apply a narrow compatibility shim: replace empty JSON objects with a
/// unique string marker before the generated deserializer runs, then callers
/// restore marker-valued `AnyValue`s to `None`. Other generated messages
/// ignore the synthetic unknown field, so canonical empty request/resource
/// objects retain their normal defaults. The marker is chosen against the
/// parsed input, preventing a workload value from colliding with it.
fn decode_otlp_json<T>(raw: &[u8]) -> Result<(T, Option<String>), EnrichmentError>
where
    T: DeserializeOwned,
{
    let json =
        serde_json::from_slice::<serde_json::Value>(raw).map_err(EnrichmentError::JsonDecode)?;
    let marker = if contains_empty_json_object(&json) {
        Some(unique_empty_any_value_marker(&json))
    } else {
        None
    };
    // Preserve object field order while patching. Prost's flattened metric
    // oneof depends on the wire order emitted by OTLP serializers, whereas a
    // round trip through serde_json::Value sorts map keys by default.
    let normalized = marker.as_deref().map_or_else(
        || raw.to_vec(),
        |marker| patch_empty_json_objects(raw, marker),
    );
    let decoded = serde_json::from_slice(&normalized).map_err(EnrichmentError::JsonDecode)?;
    Ok((decoded, marker))
}

fn contains_empty_json_object(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            object.is_empty() || object.values().any(contains_empty_json_object)
        }
        serde_json::Value::Array(values) => values.iter().any(contains_empty_json_object),
        _ => false,
    }
}

fn unique_empty_any_value_marker(json: &serde_json::Value) -> String {
    const PREFIX: &str = "__openshell_empty_otlp_any_value_";
    let mut occupied = HashSet::new();
    collect_json_strings_and_keys(json, &mut occupied);
    for suffix in 0u64.. {
        let candidate = format!("{PREFIX}{suffix:x}");
        if !occupied.contains(candidate.as_str()) {
            return candidate;
        }
    }
    unreachable!("u64 marker space cannot be exhausted by a bounded OTLP request")
}

fn collect_json_strings_and_keys<'a>(
    value: &'a serde_json::Value,
    occupied: &mut HashSet<&'a str>,
) {
    match value {
        serde_json::Value::String(value) => {
            occupied.insert(value);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_strings_and_keys(value, occupied);
            }
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                occupied.insert(key);
                collect_json_strings_and_keys(value, occupied);
            }
        }
        _ => {}
    }
}

fn patch_empty_json_objects(raw: &[u8], marker: &str) -> Vec<u8> {
    let replacement = format!(r#"{{"stringValue":"{marker}"}}"#);
    let mut output = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'"' {
            let start = index;
            index += 1;
            while index < raw.len() {
                match raw[index] {
                    b'\\' => index = (index + 2).min(raw.len()),
                    b'"' => {
                        index += 1;
                        break;
                    }
                    _ => index += 1,
                }
            }
            output.extend_from_slice(&raw[start..index]);
            continue;
        }
        if raw[index] == b'{' {
            let mut close = index + 1;
            while close < raw.len() && raw[close].is_ascii_whitespace() {
                close += 1;
            }
            if raw.get(close) == Some(&b'}') {
                output.extend_from_slice(replacement.as_bytes());
                index = close + 1;
                continue;
            }
        }
        output.push(raw[index]);
        index += 1;
    }
    output
}

fn restore_trace_empty_any_values(request: &mut ExportTraceServiceRequest, marker: &str) {
    for resource_spans in &mut request.resource_spans {
        restore_resource_empty_any_values(resource_spans.resource.as_mut(), marker);
        for scope_spans in &mut resource_spans.scope_spans {
            if let Some(scope) = &mut scope_spans.scope {
                restore_attributes_empty_any_values(&mut scope.attributes, marker);
            }
            for span in &mut scope_spans.spans {
                restore_attributes_empty_any_values(&mut span.attributes, marker);
                for event in &mut span.events {
                    restore_attributes_empty_any_values(&mut event.attributes, marker);
                }
                for link in &mut span.links {
                    restore_attributes_empty_any_values(&mut link.attributes, marker);
                }
            }
        }
    }
}

fn restore_log_empty_any_values(request: &mut ExportLogsServiceRequest, marker: &str) {
    for resource_logs in &mut request.resource_logs {
        restore_resource_empty_any_values(resource_logs.resource.as_mut(), marker);
        for scope_logs in &mut resource_logs.scope_logs {
            if let Some(scope) = &mut scope_logs.scope {
                restore_attributes_empty_any_values(&mut scope.attributes, marker);
            }
            for record in &mut scope_logs.log_records {
                restore_attributes_empty_any_values(&mut record.attributes, marker);
                if let Some(body) = &mut record.body {
                    restore_empty_any_value(body, marker);
                }
            }
        }
    }
}

fn restore_metric_empty_any_values(request: &mut ExportMetricsServiceRequest, marker: &str) {
    for resource_metrics in &mut request.resource_metrics {
        restore_resource_empty_any_values(resource_metrics.resource.as_mut(), marker);
        for scope_metrics in &mut resource_metrics.scope_metrics {
            if let Some(scope) = &mut scope_metrics.scope {
                restore_attributes_empty_any_values(&mut scope.attributes, marker);
            }
            for metric in &mut scope_metrics.metrics {
                restore_attributes_empty_any_values(&mut metric.metadata, marker);
                restore_metric_data_empty_any_values(metric.data.as_mut(), marker);
            }
        }
    }
}

fn restore_resource_empty_any_values(resource: Option<&mut Resource>, marker: &str) {
    if let Some(resource) = resource {
        restore_attributes_empty_any_values(&mut resource.attributes, marker);
    }
}

fn restore_attributes_empty_any_values(attributes: &mut [KeyValue], marker: &str) {
    for attribute in attributes {
        if let Some(value) = &mut attribute.value {
            restore_empty_any_value(value, marker);
        }
    }
}

fn restore_empty_any_value(value: &mut AnyValue, marker: &str) {
    match value.value.as_mut() {
        Some(any_value::Value::StringValue(string)) if string == marker => {
            value.value = None;
        }
        Some(any_value::Value::ArrayValue(array)) => {
            for value in &mut array.values {
                restore_empty_any_value(value, marker);
            }
        }
        Some(any_value::Value::KvlistValue(list)) => {
            restore_attributes_empty_any_values(&mut list.values, marker);
        }
        _ => {}
    }
}

fn restore_metric_data_empty_any_values(data: Option<&mut metric::Data>, marker: &str) {
    match data {
        Some(metric::Data::Gauge(gauge)) => {
            for point in &mut gauge.data_points {
                restore_attributes_empty_any_values(&mut point.attributes, marker);
                restore_exemplar_empty_any_values(&mut point.exemplars, marker);
            }
        }
        Some(metric::Data::Sum(sum)) => {
            for point in &mut sum.data_points {
                restore_attributes_empty_any_values(&mut point.attributes, marker);
                restore_exemplar_empty_any_values(&mut point.exemplars, marker);
            }
        }
        Some(metric::Data::Histogram(histogram)) => {
            for point in &mut histogram.data_points {
                restore_attributes_empty_any_values(&mut point.attributes, marker);
                restore_exemplar_empty_any_values(&mut point.exemplars, marker);
            }
        }
        Some(metric::Data::ExponentialHistogram(histogram)) => {
            for point in &mut histogram.data_points {
                restore_attributes_empty_any_values(&mut point.attributes, marker);
                restore_exemplar_empty_any_values(&mut point.exemplars, marker);
            }
        }
        Some(metric::Data::Summary(summary)) => {
            for point in &mut summary.data_points {
                restore_attributes_empty_any_values(&mut point.attributes, marker);
            }
        }
        None => {}
    }
}

fn restore_exemplar_empty_any_values(exemplars: &mut [Exemplar], marker: &str) {
    for exemplar in exemplars {
        restore_attributes_empty_any_values(&mut exemplar.filtered_attributes, marker);
    }
}

#[derive(Debug, Clone, Copy)]
enum LimitViolation {
    ResourceGroups { groups: usize },
    StructuralItems { items: usize },
}

impl LimitViolation {
    fn into_error(self, signal: SignalKind) -> EnrichmentError {
        match self {
            Self::ResourceGroups { groups } => EnrichmentError::ResourceGroupLimit {
                signal: signal.name(),
                groups,
                max: MAX_RESOURCE_GROUPS_PER_REQUEST,
            },
            Self::StructuralItems { items } => EnrichmentError::StructuralItemLimit {
                signal: signal.name(),
                items,
                max: MAX_STRUCTURAL_ITEMS_PER_REQUEST,
            },
        }
    }
}

/// Validate and budget JSON without materializing a `serde_json::Value` or any
/// OTLP vectors. The visitor retains only parser state and one object key at a
/// time; every JSON array element consumes the same global structural budget.
fn preflight_json(raw: &[u8], signal: SignalKind) -> Result<(), EnrichmentError> {
    let mut budget = JsonPreflightBudget::new(signal);
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let result = JsonRequestSeed {
        budget: &mut budget,
    }
    .deserialize(&mut deserializer)
    .and_then(|()| deserializer.end());

    if let Some(violation) = budget.violation {
        return Err(violation.into_error(signal));
    }
    result.map_err(EnrichmentError::JsonDecode)
}

struct JsonPreflightBudget {
    signal: SignalKind,
    resource_groups: usize,
    items: usize,
    violation: Option<LimitViolation>,
}

impl JsonPreflightBudget {
    fn new(signal: SignalKind) -> Self {
        Self {
            signal,
            resource_groups: 0,
            items: 0,
            violation: None,
        }
    }

    fn add_resource_group<E: de::Error>(&mut self) -> Result<(), E> {
        self.resource_groups = self.resource_groups.saturating_add(1);
        if self.resource_groups > MAX_RESOURCE_GROUPS_PER_REQUEST {
            self.violation = Some(LimitViolation::ResourceGroups {
                groups: self.resource_groups,
            });
            return Err(E::custom("too many OTLP resource groups"));
        }
        self.add_item()
    }

    fn add_item<E: de::Error>(&mut self) -> Result<(), E> {
        self.items = self.items.saturating_add(1);
        if self.items > MAX_STRUCTURAL_ITEMS_PER_REQUEST {
            self.violation = Some(LimitViolation::StructuralItems { items: self.items });
            return Err(E::custom("too many OTLP structural items"));
        }
        Ok(())
    }
}

struct JsonRequestSeed<'a> {
    budget: &'a mut JsonPreflightBudget,
}

impl<'de> DeserializeSeed<'de> for JsonRequestSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_map(JsonRequestVisitor {
            budget: self.budget,
        })
    }
}

struct JsonRequestVisitor<'a> {
    budget: &'a mut JsonPreflightBudget,
}

impl<'de> Visitor<'de> for JsonRequestVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OTLP export request object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            if key == self.budget.signal.json_resource_field() {
                map.next_value_seed(JsonResourceGroupsSeed {
                    budget: &mut *self.budget,
                })?;
            } else {
                map.next_value_seed(JsonValueSeed {
                    budget: &mut *self.budget,
                })?;
            }
        }
        Ok(())
    }
}

struct JsonResourceGroupsSeed<'a> {
    budget: &'a mut JsonPreflightBudget,
}

impl<'de> DeserializeSeed<'de> for JsonResourceGroupsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_seq(JsonResourceGroupsVisitor {
            budget: self.budget,
        })
    }
}

struct JsonResourceGroupsVisitor<'a> {
    budget: &'a mut JsonPreflightBudget,
}

impl<'de> Visitor<'de> for JsonResourceGroupsVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array of OTLP resource groups")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(JsonResourceGroupSeed {
                budget: &mut *self.budget,
            })?
            .is_some()
        {}
        Ok(())
    }
}

struct JsonResourceGroupSeed<'a> {
    budget: &'a mut JsonPreflightBudget,
}

impl<'de> DeserializeSeed<'de> for JsonResourceGroupSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.budget.add_resource_group::<D::Error>()?;
        JsonValueSeed {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }
}

struct JsonArrayElementSeed<'a> {
    budget: &'a mut JsonPreflightBudget,
}

impl<'de> DeserializeSeed<'de> for JsonArrayElementSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        self.budget.add_item::<D::Error>()?;
        JsonValueSeed {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }
}

struct JsonValueSeed<'a> {
    budget: &'a mut JsonPreflightBudget,
}

impl<'de> DeserializeSeed<'de> for JsonValueSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonValueVisitor {
            budget: self.budget,
        })
    }
}

struct JsonValueVisitor<'a> {
    budget: &'a mut JsonPreflightBudget,
}

impl<'de> Visitor<'de> for JsonValueVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_i128<E>(self, _value: i128) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_u128<E>(self, _value: u128) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_borrowed_str<E>(self, _value: &'de str) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        JsonValueSeed {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        JsonValueSeed {
            budget: self.budget,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element_seed(JsonArrayElementSeed {
                budget: &mut *self.budget,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while map.next_key::<IgnoredAny>()?.is_some() {
            map.next_value_seed(JsonValueSeed {
                budget: &mut *self.budget,
            })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProtoMessageKind {
    Request(SignalKind),
    ResourceGroup(SignalKind),
    Resource,
    EntityRef,
    ScopeGroup(SignalKind),
    InstrumentationScope,
    Span,
    SpanEvent,
    SpanLink,
    LogRecord,
    KeyValue,
    AnyValue,
    ArrayValue,
    KeyValueList,
    Metric,
    Gauge,
    Sum,
    Histogram,
    ExponentialHistogram,
    Summary,
    NumberDataPoint,
    HistogramDataPoint,
    ExponentialHistogramDataPoint,
    ExponentialBuckets,
    SummaryDataPoint,
    Exemplar,
}

/// Scan the protobuf wire format before Prost creates any typed vectors. The
/// scanner follows only known message fields and uses borrowed slices, so its
/// memory use is independent of repeated-field cardinality.
fn preflight_protobuf(raw: &[u8], signal: SignalKind) -> Result<(), EnrichmentError> {
    let mut budget = StructuralBudget::new(signal.name());
    let mut resource_groups = 0;
    scan_proto_message(
        raw,
        ProtoMessageKind::Request(signal),
        &mut budget,
        &mut resource_groups,
        0,
    )
}

fn scan_proto_message(
    raw: &[u8],
    kind: ProtoMessageKind,
    budget: &mut StructuralBudget,
    resource_groups: &mut usize,
    depth: usize,
) -> Result<(), EnrichmentError> {
    if !openshell_core::proto::otlp_protobuf_nesting_depth_allowed(depth) {
        return Err(EnrichmentError::StructuralItemLimit {
            signal: budget.signal,
            items: MAX_STRUCTURAL_ITEMS_PER_REQUEST + 1,
            max: MAX_STRUCTURAL_ITEMS_PER_REQUEST,
        });
    }
    let mut reader = WireReader::new(raw);
    while let Some(field) = reader.next_field().map_err(protobuf_preflight_error)? {
        match kind {
            ProtoMessageKind::Request(signal) if field.number == 1 => {
                let nested = field.message_bytes()?;
                *resource_groups = resource_groups.saturating_add(1);
                enforce_resource_group_limit(signal.name(), *resource_groups)?;
                budget.add(1)?;
                scan_proto_message(
                    nested,
                    ProtoMessageKind::ResourceGroup(signal),
                    budget,
                    resource_groups,
                    depth + 1,
                )?;
            }
            ProtoMessageKind::ResourceGroup(signal) => match field.number {
                1 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::Resource,
                    budget,
                    resource_groups,
                    depth,
                )?,
                2 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::ScopeGroup(signal),
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::Resource => match field.number {
                1 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::KeyValue,
                    budget,
                    resource_groups,
                    depth,
                )?,
                3 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::EntityRef,
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::EntityRef if matches!(field.number, 3 | 4) => {
                field.require_length_delimited()?;
                budget.add(1)?;
            }
            ProtoMessageKind::ScopeGroup(signal) => match field.number {
                1 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::InstrumentationScope,
                    budget,
                    resource_groups,
                    depth,
                )?,
                2 => scan_repeated_proto_message(
                    field,
                    match signal {
                        SignalKind::Traces => ProtoMessageKind::Span,
                        SignalKind::Logs => ProtoMessageKind::LogRecord,
                        SignalKind::Metrics => ProtoMessageKind::Metric,
                    },
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::InstrumentationScope if field.number == 3 => {
                scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::KeyValue,
                    budget,
                    resource_groups,
                    depth,
                )?;
            }
            ProtoMessageKind::Span => match field.number {
                9 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::KeyValue,
                    budget,
                    resource_groups,
                    depth,
                )?,
                11 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::SpanEvent,
                    budget,
                    resource_groups,
                    depth,
                )?,
                13 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::SpanLink,
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::SpanEvent if field.number == 3 => scan_repeated_proto_message(
                field,
                ProtoMessageKind::KeyValue,
                budget,
                resource_groups,
                depth,
            )?,
            ProtoMessageKind::SpanLink if field.number == 4 => scan_repeated_proto_message(
                field,
                ProtoMessageKind::KeyValue,
                budget,
                resource_groups,
                depth,
            )?,
            ProtoMessageKind::LogRecord => match field.number {
                5 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::AnyValue,
                    budget,
                    resource_groups,
                    depth,
                )?,
                6 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::KeyValue,
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::KeyValue if field.number == 2 => scan_optional_proto_message(
                field,
                ProtoMessageKind::AnyValue,
                budget,
                resource_groups,
                depth,
            )?,
            ProtoMessageKind::AnyValue => match field.number {
                5 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::ArrayValue,
                    budget,
                    resource_groups,
                    depth,
                )?,
                6 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::KeyValueList,
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::ArrayValue if field.number == 1 => scan_repeated_proto_message(
                field,
                ProtoMessageKind::AnyValue,
                budget,
                resource_groups,
                depth,
            )?,
            ProtoMessageKind::KeyValueList if field.number == 1 => scan_repeated_proto_message(
                field,
                ProtoMessageKind::KeyValue,
                budget,
                resource_groups,
                depth,
            )?,
            ProtoMessageKind::Metric => match field.number {
                12 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::KeyValue,
                    budget,
                    resource_groups,
                    depth,
                )?,
                5 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::Gauge,
                    budget,
                    resource_groups,
                    depth,
                )?,
                7 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::Sum,
                    budget,
                    resource_groups,
                    depth,
                )?,
                9 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::Histogram,
                    budget,
                    resource_groups,
                    depth,
                )?,
                10 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::ExponentialHistogram,
                    budget,
                    resource_groups,
                    depth,
                )?,
                11 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::Summary,
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::Gauge | ProtoMessageKind::Sum if field.number == 1 => {
                scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::NumberDataPoint,
                    budget,
                    resource_groups,
                    depth,
                )?;
            }
            ProtoMessageKind::Histogram if field.number == 1 => scan_repeated_proto_message(
                field,
                ProtoMessageKind::HistogramDataPoint,
                budget,
                resource_groups,
                depth,
            )?,
            ProtoMessageKind::ExponentialHistogram if field.number == 1 => {
                scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::ExponentialHistogramDataPoint,
                    budget,
                    resource_groups,
                    depth,
                )?;
            }
            ProtoMessageKind::Summary if field.number == 1 => scan_repeated_proto_message(
                field,
                ProtoMessageKind::SummaryDataPoint,
                budget,
                resource_groups,
                depth,
            )?,
            ProtoMessageKind::NumberDataPoint => match field.number {
                5 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::Exemplar,
                    budget,
                    resource_groups,
                    depth,
                )?,
                7 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::KeyValue,
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::HistogramDataPoint => match field.number {
                6 | 7 => count_repeated_fixed64(field, budget)?,
                8 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::Exemplar,
                    budget,
                    resource_groups,
                    depth,
                )?,
                9 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::KeyValue,
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::ExponentialHistogramDataPoint => match field.number {
                1 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::KeyValue,
                    budget,
                    resource_groups,
                    depth,
                )?,
                8 | 9 => scan_optional_proto_message(
                    field,
                    ProtoMessageKind::ExponentialBuckets,
                    budget,
                    resource_groups,
                    depth,
                )?,
                11 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::Exemplar,
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::ExponentialBuckets if field.number == 2 => {
                count_repeated_varints(field, budget)?;
            }
            ProtoMessageKind::SummaryDataPoint => match field.number {
                6 => {
                    field.require_length_delimited()?;
                    budget.add(1)?;
                }
                7 => scan_repeated_proto_message(
                    field,
                    ProtoMessageKind::KeyValue,
                    budget,
                    resource_groups,
                    depth,
                )?,
                _ => {}
            },
            ProtoMessageKind::Exemplar if field.number == 7 => scan_repeated_proto_message(
                field,
                ProtoMessageKind::KeyValue,
                budget,
                resource_groups,
                depth,
            )?,
            _ => {}
        }
    }
    Ok(())
}

fn scan_optional_proto_message(
    field: WireField<'_>,
    kind: ProtoMessageKind,
    budget: &mut StructuralBudget,
    resource_groups: &mut usize,
    depth: usize,
) -> Result<(), EnrichmentError> {
    // Charge every known nested protobuf message exactly once at the field
    // edge. Optional and repeated message fields have the same wire shape, so
    // accounting for them differently lets a compact request pass here and be
    // rejected later by the gateway's wire preflight.
    budget.add(1)?;
    scan_proto_message(
        field.message_bytes()?,
        kind,
        budget,
        resource_groups,
        depth + 1,
    )
}

fn scan_repeated_proto_message(
    field: WireField<'_>,
    kind: ProtoMessageKind,
    budget: &mut StructuralBudget,
    resource_groups: &mut usize,
    depth: usize,
) -> Result<(), EnrichmentError> {
    scan_optional_proto_message(field, kind, budget, resource_groups, depth)
}

fn count_repeated_fixed64(
    field: WireField<'_>,
    budget: &mut StructuralBudget,
) -> Result<(), EnrichmentError> {
    match field.value {
        WireValue::Fixed64 => budget.add(1),
        WireValue::LengthDelimited(bytes) if bytes.len() % 8 == 0 => budget.add(bytes.len() / 8),
        WireValue::LengthDelimited(_) => Err(protobuf_preflight_error(
            "packed fixed64 field has a truncated value",
        )),
        _ => Err(protobuf_preflight_error(
            "repeated fixed64 field has the wrong wire type",
        )),
    }
}

fn count_repeated_varints(
    field: WireField<'_>,
    budget: &mut StructuralBudget,
) -> Result<(), EnrichmentError> {
    match field.value {
        WireValue::Varint => budget.add(1),
        WireValue::LengthDelimited(bytes) => {
            let mut position = 0;
            let mut count = 0usize;
            while position < bytes.len() {
                read_wire_varint(bytes, &mut position).map_err(protobuf_preflight_error)?;
                count = count.saturating_add(1);
                if budget.items.saturating_add(count) > MAX_STRUCTURAL_ITEMS_PER_REQUEST {
                    return budget.add(count);
                }
            }
            budget.add(count)
        }
        _ => Err(protobuf_preflight_error(
            "repeated varint field has the wrong wire type",
        )),
    }
}

#[derive(Debug, Clone, Copy)]
struct WireField<'a> {
    number: u32,
    value: WireValue<'a>,
}

impl<'a> WireField<'a> {
    fn message_bytes(self) -> Result<&'a [u8], EnrichmentError> {
        match self.value {
            WireValue::LengthDelimited(bytes) => Ok(bytes),
            _ => Err(protobuf_preflight_error(
                "protobuf message field has the wrong wire type",
            )),
        }
    }

    fn require_length_delimited(self) -> Result<(), EnrichmentError> {
        self.message_bytes().map(|_| ())
    }
}

#[derive(Debug, Clone, Copy)]
enum WireValue<'a> {
    Varint,
    Fixed64,
    LengthDelimited(&'a [u8]),
    Fixed32,
}

struct WireReader<'a> {
    raw: &'a [u8],
    position: usize,
}

impl<'a> WireReader<'a> {
    fn new(raw: &'a [u8]) -> Self {
        Self { raw, position: 0 }
    }

    fn next_field(&mut self) -> Result<Option<WireField<'a>>, &'static str> {
        if self.position == self.raw.len() {
            return Ok(None);
        }

        let key = read_wire_varint(self.raw, &mut self.position)?;
        let number = key >> 3;
        if number == 0 || number > 0x1fff_ffff {
            return Err("protobuf field number is invalid");
        }
        let number = u32::try_from(number).map_err(|_| "protobuf field number is invalid")?;
        let value = match key & 0x07 {
            0 => {
                read_wire_varint(self.raw, &mut self.position)?;
                WireValue::Varint
            }
            1 => {
                self.take(8)?;
                WireValue::Fixed64
            }
            2 => {
                let length = read_wire_varint(self.raw, &mut self.position)?;
                let length = usize::try_from(length)
                    .map_err(|_| "protobuf length does not fit in memory")?;
                WireValue::LengthDelimited(self.take(length)?)
            }
            5 => {
                self.take(4)?;
                WireValue::Fixed32
            }
            _ => return Err("protobuf field uses an unsupported wire type"),
        };
        Ok(Some(WireField { number, value }))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], &'static str> {
        let end = self
            .position
            .checked_add(length)
            .ok_or("protobuf field length overflow")?;
        let bytes = self
            .raw
            .get(self.position..end)
            .ok_or("protobuf field is truncated")?;
        self.position = end;
        Ok(bytes)
    }
}

fn read_wire_varint(raw: &[u8], position: &mut usize) -> Result<u64, &'static str> {
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *raw.get(*position).ok_or("protobuf varint is truncated")?;
        *position += 1;
        if index == 9 && byte > 1 {
            return Err("protobuf varint overflows u64");
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("protobuf varint is too long")
}

fn protobuf_preflight_error(message: &'static str) -> EnrichmentError {
    EnrichmentError::ProtobufWire(message)
}

fn enrich_resource(resource: &mut Option<Resource>, extra_attrs: &[KeyValue]) {
    let resource = resource.get_or_insert_with(Resource::default);
    // The entire `openshell.*` namespace is gateway-controlled. Strip values
    // supplied by the workload even when metadata enrichment is disabled, so
    // disabling enrichment cannot turn an untrusted sandbox attribute into a
    // trusted-looking one downstream.
    strip_trusted_attributes(&mut resource.attributes);
    resource.entity_refs.retain_mut(|entity_ref| {
        // Removing one member of a composite identity changes what the entity
        // means. Drop the whole reference if it tries to identify itself with
        // gateway-owned metadata; descriptive references can be sanitized
        // without mutating identity.
        if entity_ref
            .id_keys
            .iter()
            .any(|key| key.starts_with("openshell."))
        {
            return false;
        }
        strip_trusted_attribute_keys(&mut entity_ref.description_keys);
        true
    });
    resource.attributes.extend_from_slice(extra_attrs);
}

fn strip_trusted_attributes(attributes: &mut Vec<KeyValue>) {
    attributes.retain(|attribute| !attribute.key.starts_with("openshell."));
}

fn strip_trusted_attribute_keys(keys: &mut Vec<String>) {
    keys.retain(|key| !key.starts_with("openshell."));
}

fn sanitize_metric_data(data: Option<&mut metric::Data>) {
    match data {
        Some(metric::Data::Gauge(gauge)) => {
            for point in &mut gauge.data_points {
                strip_trusted_attributes(&mut point.attributes);
                sanitize_exemplars(&mut point.exemplars);
            }
        }
        Some(metric::Data::Sum(sum)) => {
            for point in &mut sum.data_points {
                strip_trusted_attributes(&mut point.attributes);
                sanitize_exemplars(&mut point.exemplars);
            }
        }
        Some(metric::Data::Histogram(histogram)) => {
            for point in &mut histogram.data_points {
                strip_trusted_attributes(&mut point.attributes);
                sanitize_exemplars(&mut point.exemplars);
            }
        }
        Some(metric::Data::ExponentialHistogram(histogram)) => {
            for point in &mut histogram.data_points {
                strip_trusted_attributes(&mut point.attributes);
                sanitize_exemplars(&mut point.exemplars);
            }
        }
        Some(metric::Data::Summary(summary)) => {
            for point in &mut summary.data_points {
                strip_trusted_attributes(&mut point.attributes);
            }
        }
        None => {}
    }
}

fn sanitize_exemplars(exemplars: &mut [Exemplar]) {
    for exemplar in exemplars {
        strip_trusted_attributes(&mut exemplar.filtered_attributes);
    }
}

fn enforce_resource_group_limit(
    signal: &'static str,
    groups: usize,
) -> Result<(), EnrichmentError> {
    if groups > MAX_RESOURCE_GROUPS_PER_REQUEST {
        return Err(EnrichmentError::ResourceGroupLimit {
            signal,
            groups,
            max: MAX_RESOURCE_GROUPS_PER_REQUEST,
        });
    }
    Ok(())
}

struct StructuralBudget {
    signal: &'static str,
    items: usize,
}

impl StructuralBudget {
    fn new(signal: &'static str) -> Self {
        Self { signal, items: 0 }
    }

    fn add(&mut self, count: usize) -> Result<(), EnrichmentError> {
        self.items = self.items.saturating_add(count);
        if self.items > MAX_STRUCTURAL_ITEMS_PER_REQUEST {
            return Err(EnrichmentError::StructuralItemLimit {
                signal: self.signal,
                items: self.items,
                max: MAX_STRUCTURAL_ITEMS_PER_REQUEST,
            });
        }
        Ok(())
    }

    fn attributes(&mut self, attributes: &[KeyValue]) -> Result<(), EnrichmentError> {
        self.add(attributes.len())?;
        for attribute in attributes {
            if let Some(value) = attribute.value.as_ref() {
                self.any_value(value)?;
            }
        }
        Ok(())
    }

    /// Count nested `AnyValue` containers iteratively. This includes log
    /// bodies and attribute values without making recursion depth itself an
    /// avenue for exhausting the supervisor stack.
    fn any_value(&mut self, root: &AnyValue) -> Result<(), EnrichmentError> {
        let mut pending = vec![root];
        while let Some(value) = pending.pop() {
            self.add(1)?;
            match value.value.as_ref() {
                Some(any_value::Value::ArrayValue(array)) => {
                    self.add(array.values.len())?;
                    pending.extend(array.values.iter());
                }
                Some(any_value::Value::KvlistValue(list)) => {
                    self.add(list.values.len())?;
                    for entry in &list.values {
                        if let Some(value) = entry.value.as_ref() {
                            pending.push(value);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn resource(&mut self, resource: Option<&Resource>) -> Result<(), EnrichmentError> {
        if let Some(resource) = resource {
            self.attributes(&resource.attributes)?;
            self.add(resource.entity_refs.len())?;
            for entity_ref in &resource.entity_refs {
                self.add(entity_ref.id_keys.len())?;
                self.add(entity_ref.description_keys.len())?;
            }
        }
        Ok(())
    }

    fn scope(
        &mut self,
        scope: Option<&opentelemetry_proto::tonic::common::v1::InstrumentationScope>,
    ) -> Result<(), EnrichmentError> {
        if let Some(scope) = scope {
            self.attributes(&scope.attributes)?;
        }
        Ok(())
    }

    fn exemplars(&mut self, exemplars: &[Exemplar]) -> Result<(), EnrichmentError> {
        self.add(exemplars.len())?;
        for exemplar in exemplars {
            self.attributes(&exemplar.filtered_attributes)?;
        }
        Ok(())
    }
}

fn enforce_trace_structure_limit(
    request: &ExportTraceServiceRequest,
) -> Result<(), EnrichmentError> {
    let mut budget = StructuralBudget::new("traces");
    budget.add(request.resource_spans.len())?;
    for resource_spans in &request.resource_spans {
        budget.resource(resource_spans.resource.as_ref())?;
        budget.add(resource_spans.scope_spans.len())?;
        for scope_spans in &resource_spans.scope_spans {
            budget.scope(scope_spans.scope.as_ref())?;
            budget.add(scope_spans.spans.len())?;
            for span in &scope_spans.spans {
                budget.attributes(&span.attributes)?;
                budget.add(span.events.len())?;
                for event in &span.events {
                    budget.attributes(&event.attributes)?;
                }
                budget.add(span.links.len())?;
                for link in &span.links {
                    budget.attributes(&link.attributes)?;
                }
            }
        }
    }
    Ok(())
}

fn enforce_log_structure_limit(request: &ExportLogsServiceRequest) -> Result<(), EnrichmentError> {
    let mut budget = StructuralBudget::new("logs");
    budget.add(request.resource_logs.len())?;
    for resource_logs in &request.resource_logs {
        budget.resource(resource_logs.resource.as_ref())?;
        budget.add(resource_logs.scope_logs.len())?;
        for scope_logs in &resource_logs.scope_logs {
            budget.scope(scope_logs.scope.as_ref())?;
            budget.add(scope_logs.log_records.len())?;
            for record in &scope_logs.log_records {
                budget.attributes(&record.attributes)?;
                if let Some(body) = record.body.as_ref() {
                    budget.any_value(body)?;
                }
            }
        }
    }
    Ok(())
}

fn enforce_metric_structure_limit(
    request: &ExportMetricsServiceRequest,
) -> Result<(), EnrichmentError> {
    let mut budget = StructuralBudget::new("metrics");
    budget.add(request.resource_metrics.len())?;
    for resource_metrics in &request.resource_metrics {
        budget.resource(resource_metrics.resource.as_ref())?;
        budget.add(resource_metrics.scope_metrics.len())?;
        for scope_metrics in &resource_metrics.scope_metrics {
            budget.scope(scope_metrics.scope.as_ref())?;
            budget.add(scope_metrics.metrics.len())?;
            for metric in &scope_metrics.metrics {
                budget.attributes(&metric.metadata)?;
                match metric.data.as_ref() {
                    Some(metric::Data::Gauge(gauge)) => {
                        budget.add(gauge.data_points.len())?;
                        for point in &gauge.data_points {
                            budget.attributes(&point.attributes)?;
                            budget.exemplars(&point.exemplars)?;
                        }
                    }
                    Some(metric::Data::Sum(sum)) => {
                        budget.add(sum.data_points.len())?;
                        for point in &sum.data_points {
                            budget.attributes(&point.attributes)?;
                            budget.exemplars(&point.exemplars)?;
                        }
                    }
                    Some(metric::Data::Histogram(histogram)) => {
                        budget.add(histogram.data_points.len())?;
                        for point in &histogram.data_points {
                            budget.attributes(&point.attributes)?;
                            budget.add(point.bucket_counts.len())?;
                            budget.add(point.explicit_bounds.len())?;
                            budget.exemplars(&point.exemplars)?;
                        }
                    }
                    Some(metric::Data::ExponentialHistogram(histogram)) => {
                        budget.add(histogram.data_points.len())?;
                        for point in &histogram.data_points {
                            budget.attributes(&point.attributes)?;
                            if let Some(positive) = point.positive.as_ref() {
                                budget.add(positive.bucket_counts.len())?;
                            }
                            if let Some(negative) = point.negative.as_ref() {
                                budget.add(negative.bucket_counts.len())?;
                            }
                            budget.exemplars(&point.exemplars)?;
                        }
                    }
                    Some(metric::Data::Summary(summary)) => {
                        budget.add(summary.data_points.len())?;
                        for point in &summary.data_points {
                            budget.attributes(&point.attributes)?;
                            budget.add(point.quantile_values.len())?;
                        }
                    }
                    None => {}
                }
            }
        }
    }
    Ok(())
}

fn build_attributes(meta: &SandboxMetadata, enrichment_enabled: bool) -> Vec<KeyValue> {
    let mut attrs = Vec::new();

    // Always inject the relay routing marker regardless of enrichment toggle
    attrs.push(kv("openshell.telemetry.source", "agent"));

    if enrichment_enabled {
        push_nonempty_attribute(&mut attrs, "openshell.sandbox.id", &meta.sandbox_id);
        push_nonempty_attribute(&mut attrs, "openshell.sandbox.name", &meta.sandbox_name);
        push_nonempty_attribute(
            &mut attrs,
            "openshell.workspace.name",
            &meta.workspace_name.borrow(),
        );
        attrs.push(kv_int(
            "openshell.workload.unix_uid",
            i64::from(meta.workload_unix_uid),
        ));
        push_nonempty_attribute(
            &mut attrs,
            "openshell.workload.image.reference",
            &meta.workload_image_reference,
        );
    }

    attrs
}

fn push_nonempty_attribute(attributes: &mut Vec<KeyValue>, key: &str, value: &str) {
    if !value.is_empty() {
        attributes.push(kv(key, value));
    }
}

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
        key_strindex: 0,
    }
}

fn kv_int(key: &str, value: i64) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::IntValue(value)),
        }),
        key_strindex: 0,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnrichmentError {
    #[error("protobuf decode failed: {0}")]
    ProtobufDecode(prost::DecodeError),
    #[error("protobuf wire preflight failed: {0}")]
    ProtobufWire(&'static str),
    #[error("JSON decode failed: {0}")]
    JsonDecode(serde_json::Error),
    #[error("OTLP {signal} request has {groups} resource groups; maximum is {max}")]
    ResourceGroupLimit {
        signal: &'static str,
        groups: usize,
        max: usize,
    },
    #[error("OTLP {signal} request has {items} structural items; maximum is {max}")]
    StructuralItemLimit {
        signal: &'static str,
        items: usize,
        max: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_proto::tonic::common::v1::{EntityRef, InstrumentationScope};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::metrics::v1::{
        ExponentialHistogram, ExponentialHistogramDataPoint, Gauge, Histogram, HistogramDataPoint,
        Metric, NumberDataPoint, ResourceMetrics, ScopeMetrics, Sum, Summary, SummaryDataPoint,
    };
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, span};
    use prost::Message;

    fn test_metadata() -> SandboxMetadata {
        let (_workspace_tx, workspace_name) = tokio::sync::watch::channel("ws-456".into());
        SandboxMetadata {
            sandbox_id: "sb-123".into(),
            sandbox_name: "sandbox-name".into(),
            workspace_name,
            workload_unix_uid: 1000,
            workload_image_reference: "test-image:latest".into(),
        }
    }

    fn enrich_signal(
        signal: SignalKind,
        raw: &[u8],
        content_type: ContentType,
    ) -> Result<Vec<u8>, EnrichmentError> {
        match signal {
            SignalKind::Traces => enrich_spans(raw, content_type, &test_metadata(), true),
            SignalKind::Logs => enrich_logs(raw, content_type, &test_metadata(), true),
            SignalKind::Metrics => enrich_metrics(raw, content_type, &test_metadata(), true),
        }
    }

    fn protobuf_request_with_resource(signal: SignalKind, resource: Resource) -> Vec<u8> {
        match signal {
            SignalKind::Traces => ExportTraceServiceRequest {
                resource_spans: vec![ResourceSpans {
                    resource: Some(resource),
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
            SignalKind::Logs => ExportLogsServiceRequest {
                resource_logs: vec![ResourceLogs {
                    resource: Some(resource),
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
            SignalKind::Metrics => ExportMetricsServiceRequest {
                resource_metrics: vec![ResourceMetrics {
                    resource: Some(resource),
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
        }
    }

    fn repeated_json(value: &str, count: usize) -> String {
        let mut output = String::with_capacity((value.len() + 1).saturating_mul(count));
        for index in 0..count {
            if index != 0 {
                output.push(',');
            }
            output.push_str(value);
        }
        output
    }

    fn json_request_with_resource(signal: SignalKind, resource: &str) -> Vec<u8> {
        format!(
            "{{\"{}\":[{{\"resource\":{resource}}}]}}",
            signal.json_resource_field()
        )
        .into_bytes()
    }

    fn protobuf_request_with_nested_items(signal: SignalKind, count: usize) -> Vec<u8> {
        match signal {
            SignalKind::Traces => ExportTraceServiceRequest {
                resource_spans: vec![ResourceSpans {
                    scope_spans: vec![ScopeSpans {
                        spans: vec![Span::default(); count],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
            SignalKind::Logs => ExportLogsServiceRequest {
                resource_logs: vec![ResourceLogs {
                    scope_logs: vec![ScopeLogs {
                        log_records: vec![LogRecord::default(); count],
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
            }
            .encode_to_vec(),
            SignalKind::Metrics => ExportMetricsServiceRequest {
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
        }
    }

    fn protobuf_request_with_resource_groups(signal: SignalKind, count: usize) -> Vec<u8> {
        match signal {
            SignalKind::Traces => ExportTraceServiceRequest {
                resource_spans: vec![ResourceSpans::default(); count],
            }
            .encode_to_vec(),
            SignalKind::Logs => ExportLogsServiceRequest {
                resource_logs: vec![ResourceLogs::default(); count],
            }
            .encode_to_vec(),
            SignalKind::Metrics => ExportMetricsServiceRequest {
                resource_metrics: vec![ResourceMetrics::default(); count],
            }
            .encode_to_vec(),
        }
    }

    fn metrics_request_with_empty_gauges(count: usize, add_metadata_item: bool) -> Vec<u8> {
        let mut metrics = vec![
            Metric {
                data: Some(metric::Data::Gauge(Gauge::default())),
                ..Default::default()
            };
            count
        ];
        if add_metadata_item {
            metrics[0].metadata.push(KeyValue {
                key: "boundary-marker".into(),
                ..Default::default()
            });
        }
        ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    metrics,
                    ..Default::default()
                }],
                ..Default::default()
            }],
        }
        .encode_to_vec()
    }

    fn json_request_with_nested_items(signal: SignalKind, count: usize) -> Vec<u8> {
        let items = repeated_json("{}", count);
        match signal {
            SignalKind::Traces => format!(
                "{{\"resourceSpans\":[{{\"scopeSpans\":[{{\"spans\":[{items}]}}]}}]}}"
            ),
            SignalKind::Logs => format!(
                "{{\"resourceLogs\":[{{\"scopeLogs\":[{{\"logRecords\":[{items}]}}]}}]}}"
            ),
            SignalKind::Metrics => format!(
                "{{\"resourceMetrics\":[{{\"scopeMetrics\":[{{\"metrics\":[{{\"gauge\":{{\"dataPoints\":[{items}]}}}}]}}]}}]}}"
            ),
        }
        .into_bytes()
    }

    fn assert_structural_limit(
        result: Result<Vec<u8>, EnrichmentError>,
        expected_signal: &'static str,
    ) {
        assert!(matches!(
            result,
            Err(EnrichmentError::StructuralItemLimit {
                signal,
                items,
                max: MAX_STRUCTURAL_ITEMS_PER_REQUEST,
            }) if signal == expected_signal && items > MAX_STRUCTURAL_ITEMS_PER_REQUEST
        ));
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

    fn has_sandbox_attributes(resource: &Resource) -> bool {
        resource
            .attributes
            .iter()
            .any(|attribute| attribute.key == "openshell.sandbox.id")
            && resource
                .attributes
                .iter()
                .any(|attribute| attribute.key == "openshell.telemetry.source")
    }

    fn workload_resource_with_spoofed_attributes() -> Resource {
        Resource {
            attributes: vec![
                kv("openshell.sandbox.id", "agent-spoofed-id"),
                kv("openshell.custom", "agent-controlled"),
                kv("service.name", "agent-service"),
            ],
            ..Default::default()
        }
    }

    fn assert_agent_namespace_sanitized(resource: &Resource) {
        let openshell_keys: Vec<_> = resource
            .attributes
            .iter()
            .filter(|attribute| attribute.key.starts_with("openshell."))
            .map(|attribute| attribute.key.as_str())
            .collect();
        assert_eq!(openshell_keys, vec!["openshell.telemetry.source"]);
        assert!(
            resource
                .attributes
                .iter()
                .any(|attribute| attribute.key == "service.name"),
            "non-OpenShell workload attributes must be preserved"
        );
    }

    fn spoofed_nested_attributes() -> Vec<KeyValue> {
        vec![
            kv("openshell.sandbox.id", "agent-spoofed-id"),
            kv("application.attribute", "preserve-me"),
        ]
    }

    fn assert_nested_namespace_sanitized(attributes: &[KeyValue]) {
        assert!(
            attributes
                .iter()
                .all(|attribute| !attribute.key.starts_with("openshell.")),
            "nested openshell.* attributes must be removed"
        );
        assert!(
            attributes
                .iter()
                .any(|attribute| attribute.key == "application.attribute"),
            "ordinary nested attributes must be preserved"
        );
    }

    #[test]
    fn enrichment_adds_truthful_attributes() {
        let raw = make_trace_request();
        let result = enrich_spans(&raw, ContentType::Protobuf, &test_metadata(), true).unwrap();

        let decoded = ExportTraceServiceRequest::decode(result.as_slice()).unwrap();
        let resource = decoded.resource_spans[0].resource.as_ref().unwrap();

        let attr_keys: Vec<&str> = resource.attributes.iter().map(|a| a.key.as_str()).collect();
        for expected in [
            "openshell.telemetry.source",
            "openshell.sandbox.id",
            "openshell.sandbox.name",
            "openshell.workspace.name",
            "openshell.workload.unix_uid",
            "openshell.workload.image.reference",
        ] {
            assert!(attr_keys.contains(&expected), "missing {expected}");
        }
        for removed in [
            "openshell.workspace.id",
            "openshell.sandbox.policy",
            "openshell.sandbox.user",
            "openshell.sandbox.image",
            "openshell.sandbox.driver",
        ] {
            assert!(
                !attr_keys.contains(&removed),
                "obsolete key {removed} present"
            );
        }

        let uid = resource
            .attributes
            .iter()
            .find(|attribute| attribute.key == "openshell.workload.unix_uid")
            .and_then(|attribute| attribute.value.as_ref())
            .and_then(|value| value.value.as_ref());
        assert_eq!(uid, Some(&any_value::Value::IntValue(1000)));
    }

    #[test]
    fn enrichment_omits_empty_trusted_metadata() {
        let mut metadata = test_metadata();
        let (_workspace_tx, workspace_name) = tokio::sync::watch::channel(String::new());
        metadata.workspace_name = workspace_name;
        metadata.sandbox_name.clear();
        metadata.workload_image_reference.clear();

        let result = enrich_spans(
            &make_trace_request(),
            ContentType::Protobuf,
            &metadata,
            true,
        )
        .unwrap();
        let decoded = ExportTraceServiceRequest::decode(result.as_slice()).unwrap();
        let attributes = &decoded.resource_spans[0]
            .resource
            .as_ref()
            .unwrap()
            .attributes;

        assert!(
            attributes
                .iter()
                .any(|attribute| attribute.key == "openshell.sandbox.id")
        );
        assert!(
            attributes.iter().all(|attribute| {
                attribute.key != "openshell.workspace.name"
                    && attribute.key != "openshell.sandbox.name"
                    && attribute.key != "openshell.workload.image.reference"
            }),
            "trusted attributes with empty values must be omitted"
        );
    }

    #[test]
    fn enrichment_reads_workspace_name_when_each_batch_arrives() {
        let (workspace_tx, workspace_name) = tokio::sync::watch::channel(String::new());
        let metadata = SandboxMetadata {
            workspace_name,
            ..test_metadata()
        };

        let before = enrich_spans(
            &make_trace_request(),
            ContentType::Protobuf,
            &metadata,
            true,
        )
        .unwrap();
        let before = ExportTraceServiceRequest::decode(before.as_slice()).unwrap();
        assert!(
            before.resource_spans[0]
                .resource
                .as_ref()
                .unwrap()
                .attributes
                .iter()
                .all(|attribute| attribute.key != "openshell.workspace.name")
        );

        workspace_tx.send_replace("workspace-discovered-later".into());
        let after = enrich_spans(
            &make_trace_request(),
            ContentType::Protobuf,
            &metadata,
            true,
        )
        .unwrap();
        let after = ExportTraceServiceRequest::decode(after.as_slice()).unwrap();
        let value = after.resource_spans[0]
            .resource
            .as_ref()
            .unwrap()
            .attributes
            .iter()
            .find(|attribute| attribute.key == "openshell.workspace.name")
            .and_then(|attribute| attribute.value.as_ref())
            .and_then(|value| value.value.as_ref());
        assert_eq!(
            value,
            Some(&any_value::Value::StringValue(
                "workspace-discovered-later".into()
            ))
        );
    }

    #[test]
    fn enrichment_disabled_strips_spoofed_namespace_for_every_signal() {
        let traces = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(workload_resource_with_spoofed_attributes()),
                ..Default::default()
            }],
        };
        let encoded = enrich_spans(
            &traces.encode_to_vec(),
            ContentType::Protobuf,
            &test_metadata(),
            false,
        )
        .unwrap();
        let decoded = ExportTraceServiceRequest::decode(encoded.as_slice()).unwrap();
        assert_agent_namespace_sanitized(decoded.resource_spans[0].resource.as_ref().unwrap());

        let logs = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(workload_resource_with_spoofed_attributes()),
                ..Default::default()
            }],
        };
        let encoded = enrich_logs(
            &logs.encode_to_vec(),
            ContentType::Protobuf,
            &test_metadata(),
            false,
        )
        .unwrap();
        let decoded = ExportLogsServiceRequest::decode(encoded.as_slice()).unwrap();
        assert_agent_namespace_sanitized(decoded.resource_logs[0].resource.as_ref().unwrap());

        let metrics = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(workload_resource_with_spoofed_attributes()),
                ..Default::default()
            }],
        };
        let encoded = enrich_metrics(
            &metrics.encode_to_vec(),
            ContentType::Protobuf,
            &test_metadata(),
            false,
        )
        .unwrap();
        let decoded = ExportMetricsServiceRequest::decode(encoded.as_slice()).unwrap();
        assert_agent_namespace_sanitized(decoded.resource_metrics[0].resource.as_ref().unwrap());
    }

    #[test]
    fn trace_enrichment_strips_nested_spoofed_namespace() {
        let request = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                scope_spans: vec![ScopeSpans {
                    scope: Some(InstrumentationScope {
                        attributes: spoofed_nested_attributes(),
                        ..Default::default()
                    }),
                    spans: vec![Span {
                        attributes: spoofed_nested_attributes(),
                        events: vec![span::Event {
                            attributes: spoofed_nested_attributes(),
                            ..Default::default()
                        }],
                        links: vec![span::Link {
                            attributes: spoofed_nested_attributes(),
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
            false,
        )
        .unwrap();
        let decoded = ExportTraceServiceRequest::decode(encoded.as_slice()).unwrap();
        let scope_spans = &decoded.resource_spans[0].scope_spans[0];
        assert_nested_namespace_sanitized(&scope_spans.scope.as_ref().unwrap().attributes);
        let span = &scope_spans.spans[0];
        assert_nested_namespace_sanitized(&span.attributes);
        assert_nested_namespace_sanitized(&span.events[0].attributes);
        assert_nested_namespace_sanitized(&span.links[0].attributes);
    }

    #[test]
    fn log_enrichment_strips_nested_spoofed_namespace() {
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                scope_logs: vec![ScopeLogs {
                    scope: Some(InstrumentationScope {
                        attributes: spoofed_nested_attributes(),
                        ..Default::default()
                    }),
                    log_records: vec![LogRecord {
                        attributes: spoofed_nested_attributes(),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let encoded = enrich_logs(
            &request.encode_to_vec(),
            ContentType::Protobuf,
            &test_metadata(),
            false,
        )
        .unwrap();
        let decoded = ExportLogsServiceRequest::decode(encoded.as_slice()).unwrap();
        let scope_logs = &decoded.resource_logs[0].scope_logs[0];
        assert_nested_namespace_sanitized(&scope_logs.scope.as_ref().unwrap().attributes);
        assert_nested_namespace_sanitized(&scope_logs.log_records[0].attributes);
    }

    #[test]
    fn metric_enrichment_strips_all_nested_spoofed_namespaces() {
        let exemplar = || Exemplar {
            filtered_attributes: spoofed_nested_attributes(),
            ..Default::default()
        };
        let number_point = || NumberDataPoint {
            attributes: spoofed_nested_attributes(),
            exemplars: vec![exemplar()],
            ..Default::default()
        };
        let make_metric = |data| Metric {
            metadata: spoofed_nested_attributes(),
            data: Some(data),
            ..Default::default()
        };
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                scope_metrics: vec![ScopeMetrics {
                    scope: Some(InstrumentationScope {
                        attributes: spoofed_nested_attributes(),
                        ..Default::default()
                    }),
                    metrics: vec![
                        make_metric(metric::Data::Gauge(Gauge {
                            data_points: vec![number_point()],
                        })),
                        make_metric(metric::Data::Sum(Sum {
                            data_points: vec![number_point()],
                            ..Default::default()
                        })),
                        make_metric(metric::Data::Histogram(Histogram {
                            data_points: vec![HistogramDataPoint {
                                attributes: spoofed_nested_attributes(),
                                exemplars: vec![exemplar()],
                                ..Default::default()
                            }],
                            ..Default::default()
                        })),
                        make_metric(metric::Data::ExponentialHistogram(ExponentialHistogram {
                            data_points: vec![ExponentialHistogramDataPoint {
                                attributes: spoofed_nested_attributes(),
                                exemplars: vec![exemplar()],
                                ..Default::default()
                            }],
                            ..Default::default()
                        })),
                        make_metric(metric::Data::Summary(Summary {
                            data_points: vec![SummaryDataPoint {
                                attributes: spoofed_nested_attributes(),
                                ..Default::default()
                            }],
                        })),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            }],
        };

        let encoded = enrich_metrics(
            &request.encode_to_vec(),
            ContentType::Protobuf,
            &test_metadata(),
            false,
        )
        .unwrap();
        let decoded = ExportMetricsServiceRequest::decode(encoded.as_slice()).unwrap();
        let scope_metrics = &decoded.resource_metrics[0].scope_metrics[0];
        assert_nested_namespace_sanitized(&scope_metrics.scope.as_ref().unwrap().attributes);
        for metric in &scope_metrics.metrics {
            assert_nested_namespace_sanitized(&metric.metadata);
            match metric.data.as_ref().unwrap() {
                metric::Data::Gauge(gauge) => assert_number_points_sanitized(&gauge.data_points),
                metric::Data::Sum(sum) => assert_number_points_sanitized(&sum.data_points),
                metric::Data::Histogram(histogram) => {
                    let point = &histogram.data_points[0];
                    assert_nested_namespace_sanitized(&point.attributes);
                    assert_nested_namespace_sanitized(&point.exemplars[0].filtered_attributes);
                }
                metric::Data::ExponentialHistogram(histogram) => {
                    let point = &histogram.data_points[0];
                    assert_nested_namespace_sanitized(&point.attributes);
                    assert_nested_namespace_sanitized(&point.exemplars[0].filtered_attributes);
                }
                metric::Data::Summary(summary) => {
                    assert_nested_namespace_sanitized(&summary.data_points[0].attributes);
                }
            }
        }
    }

    fn assert_number_points_sanitized(points: &[NumberDataPoint]) {
        assert_nested_namespace_sanitized(&points[0].attributes);
        assert_nested_namespace_sanitized(&points[0].exemplars[0].filtered_attributes);
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
    fn json_accepts_valid_empty_any_values_for_every_signal() {
        // These are independent OTLP/JSON fixtures rather than output from
        // opentelemetry-proto's serializer. Version 0.32 serializes an unset
        // AnyValue as null and, without our compatibility path, rejects the
        // specification-valid empty object on input.
        let trace = br#"{
            "resourceSpans": [{
                "resource": {"attributes": [{"key": "resource.empty", "value": {}}]},
                "scopeSpans": [{"spans": [{
                    "attributes": [{"key": "span.empty", "value": {}}]
                }]}]
            }]
        }"#;
        let encoded = enrich_spans(trace, ContentType::Json, &test_metadata(), true).unwrap();
        let decoded = ExportTraceServiceRequest::decode(encoded.as_slice()).unwrap();
        let resource = decoded.resource_spans[0].resource.as_ref().unwrap();
        assert_empty_any_value(&resource.attributes, "resource.empty");
        assert_empty_any_value(
            &decoded.resource_spans[0].scope_spans[0].spans[0].attributes,
            "span.empty",
        );

        let logs = br#"{
            "resourceLogs": [{
                "resource": {"attributes": [{"key": "resource.empty", "value": {}}]},
                "scopeLogs": [{"logRecords": [{
                    "body": {},
                    "attributes": [{"key": "log.empty", "value": {}}]
                }]}]
            }]
        }"#;
        let encoded = enrich_logs(logs, ContentType::Json, &test_metadata(), true).unwrap();
        let decoded = ExportLogsServiceRequest::decode(encoded.as_slice()).unwrap();
        let resource = decoded.resource_logs[0].resource.as_ref().unwrap();
        assert_empty_any_value(&resource.attributes, "resource.empty");
        let record = &decoded.resource_logs[0].scope_logs[0].log_records[0];
        assert_eq!(record.body.as_ref().unwrap().value, None);
        assert_empty_any_value(&record.attributes, "log.empty");

        let metrics = br#"{
            "resourceMetrics": [{
                "resource": {"attributes": [{"key": "metric.resource.empty", "value": {}}]}
            }]
        }"#;
        let encoded = enrich_metrics(metrics, ContentType::Json, &test_metadata(), true).unwrap();
        let decoded = ExportMetricsServiceRequest::decode(encoded.as_slice()).unwrap();
        let resource = decoded.resource_metrics[0].resource.as_ref().unwrap();
        assert_empty_any_value(&resource.attributes, "metric.resource.empty");
    }

    fn assert_empty_any_value(attributes: &[KeyValue], key: &str) {
        let attribute = attributes
            .iter()
            .find(|attribute| attribute.key == key)
            .unwrap_or_else(|| panic!("missing fixture attribute {key}"));
        assert_eq!(
            attribute
                .value
                .as_ref()
                .and_then(|value| value.value.as_ref()),
            None,
            "{key} must remain an empty AnyValue"
        );
    }

    #[test]
    fn empty_any_value_marker_cannot_collide_with_workload_strings() {
        let raw = br#"{
            "resourceSpans": [{"resource": {"attributes": [
                {"key": "legitimate", "value": {
                    "stringValue": "__openshell_empty_otlp_any_value_0"
                }},
                {"key": "empty", "value": {}}
            ]}}]
        }"#;

        let encoded = enrich_spans(raw, ContentType::Json, &test_metadata(), true).unwrap();
        let decoded = ExportTraceServiceRequest::decode(encoded.as_slice()).unwrap();
        let attributes = &decoded.resource_spans[0]
            .resource
            .as_ref()
            .unwrap()
            .attributes;
        assert_empty_any_value(attributes, "empty");
        let legitimate = attributes
            .iter()
            .find(|attribute| attribute.key == "legitimate")
            .unwrap();
        assert!(matches!(
            legitimate.value.as_ref().and_then(|value| value.value.as_ref()),
            Some(any_value::Value::StringValue(value))
                if value == "__openshell_empty_otlp_any_value_0"
        ));
    }

    #[test]
    fn empty_any_value_marker_indexes_many_collisions_once() {
        let mut object = serde_json::Map::new();
        for suffix in 0..4_096u64 {
            object.insert(
                format!("__openshell_empty_otlp_any_value_{suffix:x}"),
                serde_json::Value::Null,
            );
        }
        object.insert("empty".into(), serde_json::json!({}));

        assert_eq!(
            unique_empty_any_value_marker(&serde_json::Value::Object(object)),
            "__openshell_empty_otlp_any_value_1000"
        );
    }

    #[test]
    fn enrichment_strips_reserved_entity_ref_keys_for_every_signal_and_encoding() {
        let resource = Resource {
            attributes: vec![kv("service.name", "fixture")],
            entity_refs: vec![
                EntityRef {
                    r#type: "poisoned-composite".into(),
                    id_keys: vec!["openshell.sandbox.id".into(), "service.name".into()],
                    description_keys: vec!["service.version".into()],
                    ..Default::default()
                },
                EntityRef {
                    r#type: "service".into(),
                    id_keys: vec!["service.name".into()],
                    description_keys: vec![
                        "openshell.workload.image.reference".into(),
                        "service.version".into(),
                    ],
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let resource_json = serde_json::to_string(&resource).unwrap();

        for signal in [SignalKind::Traces, SignalKind::Logs, SignalKind::Metrics] {
            for (raw, content_type) in [
                (
                    protobuf_request_with_resource(signal, resource.clone()),
                    ContentType::Protobuf,
                ),
                (
                    json_request_with_resource(signal, &resource_json),
                    ContentType::Json,
                ),
            ] {
                let encoded = enrich_signal(signal, &raw, content_type).unwrap();
                let sanitized = match signal {
                    SignalKind::Traces => ExportTraceServiceRequest::decode(encoded.as_slice())
                        .unwrap()
                        .resource_spans
                        .remove(0)
                        .resource
                        .unwrap(),
                    SignalKind::Logs => ExportLogsServiceRequest::decode(encoded.as_slice())
                        .unwrap()
                        .resource_logs
                        .remove(0)
                        .resource
                        .unwrap(),
                    SignalKind::Metrics => ExportMetricsServiceRequest::decode(encoded.as_slice())
                        .unwrap()
                        .resource_metrics
                        .remove(0)
                        .resource
                        .unwrap(),
                };
                assert_eq!(
                    sanitized.entity_refs.len(),
                    1,
                    "reserved id key must drop the whole composite identity"
                );
                let entity_ref = &sanitized.entity_refs[0];
                assert_eq!(entity_ref.r#type, "service");
                assert_eq!(entity_ref.id_keys, ["service.name"]);
                assert_eq!(entity_ref.description_keys, ["service.version"]);
                assert!(
                    sanitized
                        .attributes
                        .iter()
                        .any(|attribute| { attribute.key == "openshell.sandbox.id" })
                );
            }
        }
    }

    #[test]
    fn log_enrichment_supports_protobuf_and_json() {
        let request = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs::default()],
        };
        for (raw, content_type) in [
            (request.encode_to_vec(), ContentType::Protobuf),
            (serde_json::to_vec(&request).unwrap(), ContentType::Json),
        ] {
            let result = enrich_logs(&raw, content_type, &test_metadata(), true).unwrap();
            let decoded = ExportLogsServiceRequest::decode(result.as_slice()).unwrap();
            assert!(has_sandbox_attributes(
                decoded.resource_logs[0].resource.as_ref().unwrap()
            ));
        }
    }

    #[test]
    fn metric_enrichment_supports_protobuf_and_json() {
        let request = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics::default()],
        };
        for (raw, content_type) in [
            (request.encode_to_vec(), ContentType::Protobuf),
            (serde_json::to_vec(&request).unwrap(), ContentType::Json),
        ] {
            let result = enrich_metrics(&raw, content_type, &test_metadata(), true).unwrap();
            let decoded = ExportMetricsServiceRequest::decode(result.as_slice()).unwrap();
            assert!(has_sandbox_attributes(
                decoded.resource_metrics[0].resource.as_ref().unwrap()
            ));
        }
    }

    #[test]
    fn enrichment_rejects_invalid_protobuf() {
        let garbage = vec![0xFF, 0xFE, 0xFD, 0xFC];
        let result = enrich_spans(&garbage, ContentType::Protobuf, &test_metadata(), true);
        assert!(
            matches!(
                result,
                Err(EnrichmentError::ProtobufDecode(_) | EnrichmentError::ProtobufWire(_))
            ),
            "should return a protobuf decode error"
        );
    }

    #[test]
    fn preflight_rejects_excess_resource_groups_for_every_signal_and_encoding() {
        let count = MAX_RESOURCE_GROUPS_PER_REQUEST + 1;
        for signal in [SignalKind::Traces, SignalKind::Logs, SignalKind::Metrics] {
            let protobuf = protobuf_request_with_resource_groups(signal, count);
            let json = format!(
                "{{\"{}\":[{}]}}",
                signal.json_resource_field(),
                repeated_json("{}", count)
            )
            .into_bytes();

            for (raw, content_type) in
                [(protobuf, ContentType::Protobuf), (json, ContentType::Json)]
            {
                assert!(
                    raw.len() < openshell_core::proto::MAX_GRPC_MESSAGE_SIZE,
                    "compact {signal:?} test request must fit the HTTP limit"
                );
                assert!(matches!(
                    enrich_signal(signal, &raw, content_type),
                    Err(EnrichmentError::ResourceGroupLimit {
                        signal: actual_signal,
                        groups,
                        max: MAX_RESOURCE_GROUPS_PER_REQUEST,
                    }) if actual_signal == signal.name() && groups == count
                ));
            }
        }
    }

    #[test]
    fn preflight_rejects_compact_amplification_for_every_signal_and_encoding() {
        let count = MAX_STRUCTURAL_ITEMS_PER_REQUEST;
        for signal in [SignalKind::Traces, SignalKind::Logs, SignalKind::Metrics] {
            for (raw, content_type) in [
                (
                    protobuf_request_with_nested_items(signal, count),
                    ContentType::Protobuf,
                ),
                (
                    json_request_with_nested_items(signal, count),
                    ContentType::Json,
                ),
            ] {
                assert!(
                    raw.len() < openshell_core::proto::MAX_GRPC_MESSAGE_SIZE,
                    "compact {signal:?} amplification request is {} bytes",
                    raw.len()
                );
                assert_structural_limit(enrich_signal(signal, &raw, content_type), signal.name());
            }
        }
    }

    #[test]
    fn post_enrichment_budget_rejects_every_signal_before_acknowledgement() {
        for signal in [SignalKind::Traces, SignalKind::Logs, SignalKind::Metrics] {
            let base_items = match signal {
                SignalKind::Traces | SignalKind::Logs => 2,
                SignalKind::Metrics => 4,
            };
            let raw = protobuf_request_with_nested_items(
                signal,
                MAX_STRUCTURAL_ITEMS_PER_REQUEST - base_items,
            );
            preflight_protobuf(&raw, signal)
                .expect("the workload request must fit exactly before enrichment");
            assert_structural_limit(
                enrich_signal(signal, &raw, ContentType::Protobuf),
                signal.name(),
            );
        }
    }

    #[test]
    fn post_enrichment_budget_accepts_every_signal_at_the_exact_final_limit() {
        // The default test metadata contributes one Resource wrapper, six
        // KeyValue wrappers, and six AnyValue wrappers.
        const ENRICHMENT_ITEMS: usize = 13;

        for signal in [SignalKind::Traces, SignalKind::Logs, SignalKind::Metrics] {
            let base_items = match signal {
                SignalKind::Traces | SignalKind::Logs => 2,
                SignalKind::Metrics => 4,
            };
            let raw = protobuf_request_with_nested_items(
                signal,
                MAX_STRUCTURAL_ITEMS_PER_REQUEST - base_items - ENRICHMENT_ITEMS,
            );
            let enriched = enrich_signal(signal, &raw, ContentType::Protobuf)
                .expect("the final enriched request should fit exactly");
            preflight_protobuf(&enriched, signal)
                .expect("the acknowledged request must pass the final wire budget");
        }
    }

    #[test]
    fn protobuf_preflight_rejects_ten_thousand_empty_gauges_before_acknowledgement() {
        // Each Metric and its present-but-empty Gauge are distinct protobuf
        // messages. The gateway charges both message edges, so the supervisor
        // must reject this compact request before acknowledging it over HTTP.
        let raw = metrics_request_with_empty_gauges(10_000, false);
        assert!(
            raw.len() < openshell_core::proto::MAX_GRPC_MESSAGE_SIZE,
            "the regression request must pass the byte limit"
        );

        assert_structural_limit(
            enrich_metrics(&raw, ContentType::Protobuf, &test_metadata(), true),
            "metrics",
        );
    }

    #[test]
    fn empty_gauges_match_the_exact_post_enrichment_gateway_boundary() {
        // Final wire accounting is:
        //   resource group + scope group + (Metric + Gauge) * N
        //   + one metadata KeyValue + enriched Resource/KeyValue/AnyValue.
        // The non-valued metadata item makes the 16K boundary reachable
        // exactly with an integral number of empty gauges.
        let enrichment_items = 1 + build_attributes(&test_metadata(), true).len() * 2;
        let fixed_items = 3;
        let remaining = MAX_STRUCTURAL_ITEMS_PER_REQUEST - enrichment_items - fixed_items;
        assert_eq!(remaining % 2, 0, "test setup must reach the exact limit");
        let exact_gauges = remaining / 2;

        let exact = metrics_request_with_empty_gauges(exact_gauges, true);
        let enriched = enrich_metrics(&exact, ContentType::Protobuf, &test_metadata(), true)
            .expect("the exact final gateway budget must be accepted");
        preflight_protobuf(&enriched, SignalKind::Metrics)
            .expect("acknowledged metrics must pass the gateway-equivalent wire budget");

        let over = metrics_request_with_empty_gauges(exact_gauges + 1, true);
        assert_structural_limit(
            enrich_metrics(&over, ContentType::Protobuf, &test_metadata(), true),
            "metrics",
        );
    }

    #[test]
    fn preflight_counts_resource_entity_refs_for_every_signal_and_encoding() {
        let count = MAX_STRUCTURAL_ITEMS_PER_REQUEST;
        for signal in [SignalKind::Traces, SignalKind::Logs, SignalKind::Metrics] {
            let protobuf = protobuf_request_with_resource(
                signal,
                Resource {
                    entity_refs: vec![EntityRef::default(); count],
                    ..Default::default()
                },
            );
            let json = json_request_with_resource(
                signal,
                &format!("{{\"entityRefs\":[{}]}}", repeated_json("{}", count)),
            );

            for (raw, content_type) in
                [(protobuf, ContentType::Protobuf), (json, ContentType::Json)]
            {
                assert!(
                    raw.len() < openshell_core::proto::MAX_GRPC_MESSAGE_SIZE,
                    "compact entity refs request is {} bytes",
                    raw.len()
                );
                assert_structural_limit(enrich_signal(signal, &raw, content_type), signal.name());
            }
        }
    }

    #[test]
    fn preflight_counts_both_entity_ref_key_arrays_for_every_signal_and_encoding() {
        let per_key_array = MAX_STRUCTURAL_ITEMS_PER_REQUEST / 2;
        let entity_ref_json = format!(
            "{{\"entityRefs\":[{{\"idKeys\":[{}],\"descriptionKeys\":[{}]}}]}}",
            repeated_json("\"\"", per_key_array),
            repeated_json("\"\"", per_key_array),
        );
        for signal in [SignalKind::Traces, SignalKind::Logs, SignalKind::Metrics] {
            let entity_ref = EntityRef {
                id_keys: vec![String::new(); per_key_array],
                description_keys: vec![String::new(); per_key_array],
                ..Default::default()
            };
            let protobuf = protobuf_request_with_resource(
                signal,
                Resource {
                    entity_refs: vec![entity_ref],
                    ..Default::default()
                },
            );
            let json = json_request_with_resource(signal, &entity_ref_json);

            for (raw, content_type) in
                [(protobuf, ContentType::Protobuf), (json, ContentType::Json)]
            {
                assert!(raw.len() < openshell_core::proto::MAX_GRPC_MESSAGE_SIZE);
                assert_structural_limit(enrich_signal(signal, &raw, content_type), signal.name());
            }
        }
    }

    #[test]
    fn canonical_empty_json_defaults_every_export_request() {
        for signal in [SignalKind::Traces, SignalKind::Logs, SignalKind::Metrics] {
            let encoded = enrich_signal(signal, b"{}", ContentType::Json).unwrap();
            assert!(
                encoded.is_empty(),
                "empty {signal:?} request should encode as the protobuf default"
            );
        }
    }
}
