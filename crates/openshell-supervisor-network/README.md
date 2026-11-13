# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Socket attribution tests pass a duplicate connected socket as a spawned child's
stdin. Re-executing the test binary checks multiple holders with the same binary
identity; executing a different binary checks ambiguous shared-socket identity.
The fixture kills and reaps the child when the parent test ends.

The manual proxy performance baseline still counts allocations. Its test-only
global allocator uses `openshell-driver-vm::allocation_tracking`; the unsafe
allocator implementation belongs to the VM crate. The VM dependency disables
default features, so this instrumentation does not
require the compute runtime or Unix-only sandbox library. It is a development
dependency only.

## Connections without inspection

Before the supervisor forwards a connection it cannot inspect (`tls: skip`, transparent TCP, h2c, unsupported tunnels, SQL passthrough), `uninspectable_traffic_gate` checks the matching middleware chain. Any `fail_closed` entry denies the connection, and an all-`fail_open` chain relays it with a bypass finding. For `tls: skip`, the gate runs before `200 Connection Established`, so a denial is a `403`.

## Sandbox instance inputs

`run_networking` takes a `SandboxInstanceNetwork` with the sandbox identity,
the sandbox instance's `GatewayEndpoint`, the SPIFFE Workload API socket for
provider token grants, the `policy.local` denial source, and proxy CA files.
None of these are read from the process environment, so one process can run
several sandbox instances. Each instance owns its provider token cache and
HTTP client; a token acquired for one sandbox is never served to another.
Without a Workload API socket, token grants fail closed. A process hosting
several instances serves `/v1/denials` from a per-instance
`SandboxInstanceDenialLog` instead of the shared shorthand log files.

## Reserved destinations

`preauthorize_transparent_open` matches a staged TCP open against the reserved
OTLP relay address (`openshell_core::sandbox_env::OTLP_RELAY_ADDR`) before host
mapping, policy evaluation, and SSRF checks. The address is an unroutable
label, so the proxy never dials it. When `run_networking` receives a
`ReservedDestination`, the proxy hands the workload stream to its
`ReservedStreamHandler`; a handler that refuses, for example at its connection
cap, turns the open into a resource-exhausted denial. Without a handler, the
proxy denies the open at once. It logs the first attempt at warn and later ones
at debug, and emits no OCSF denial event: a standard OpenTelemetry SDK retries
for the life of the agent, and one event per retry would flood the OCSF log.
The supervisor installs its OTLP relay receiver as the handler while the agent
trace relay is active.

## Static credential placement

Substitution checks the declared request location before writing upstream.
Credentials without placement metadata default to the Authorization header. HTTP placement violations return a safe 403 response;
WebSocket violations close the connection with policy denial. Both paths emit a
domain event and a detection finding without credential values or placeholders.
Explicit body and WebSocket
rewrite flags authorize those locations for ordinary static credentials. SigV4
signing retains the endpoint-scoped resolver's existing trusted access.

## HTTP enforcement correlation

Each inspected HTTP request has one UUID shared by middleware, OCSF
`metadata.correlation_uid`, and the protected `x-openshell-request-id` response
header. Application correlation must use another header. The receipt is only a
join key: it does not establish identity, authorization or complete delivery.
L4 and passthrough traffic do not provide this header guarantee.

The audit state commits one primary HTTP Activity record when the final response
head is written, with an early-termination fallback. It retains the original
request and process context while consolidating middleware and credential
outcomes. Routine outcomes do not add records; existing security findings and
post-header failure records remain distinct. A process crash or indefinitely
hung request cannot be finalized by the fallback.

Request IDs and audit outcomes do not depend on OpenTelemetry, sampling or
collector availability. Inspected requests have a supervisor-owned request span
and children around stages that actually run, with valid workload W3C context
only as an untrusted link. Their records never create an extra denial-only span,
even if the request span is disabled or unsampled. Other egress paths retain the
legacy bounded deny-span behavior. End HTTP tracing before an upgraded session.

Inspected request records retain the policy generation/hash, selected endpoint
identity and pinned provider installation/revision under OCSF `unmapped`.
Identities are captured at selection, not looked up when the record is emitted;
later reloads and rotations cannot rewrite historical records. Numeric revisions
are decimal strings to preserve their full width. Unknown identities are omitted.
The `openshell.upstream.send` stage measures request writes and flush; response
handling is measured separately. Receipt filtering preserves raw HTTP bytes
and borrows unchanged header blocks.

Selected middleware phases enrich those existing stage spans with bounded
outcomes and mutation, failure, admission and partial-delivery observations.
Legacy and current HTTP hooks share this reporting path. Current streamed
request phases remain open through body processing or cancellation; response
phases include finalization. Remote RPC transport status is separate from a
middleware decision. Findings retain the request UUID even without trace export.

Credential preparation enriches operation-owned child spans with the mechanism,
placement and bounded outcome, never secret material. The primary audit record
includes notable credential outcomes; successful preparation does not create an
extra routine record or establish that the target received the request.

MCP and JSON-RPC inspection spans cover each actual parse or reinspection,
including transport-selected schemas and middleware-transformed bodies. They
record bounded classifications, counts and revisions, never arguments, tool
names or raw errors. Dedicated body inspection starts after the request UUID and
configuration identities are assigned.

The owned `openshell.http.response` stage covers response delivery through final
flush and required shutdown. Its bounded fields distinguish response selection
from completion, including interim bytes, truncation, cancellation and downstream
failures. The primary record remains fixed at accepted final headers; a late
delivery failure adds one observational `response-correlation` record. Delivery
accounting and receipts work without a request span or trace exporter. Middleware
observations remain separate, and streaming hooks retain their final-byte and
policy-generation protections.
