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

## HTTP enforcement correlation

Inspected HTTP requests create an `openshell.http.enforcement` span. A single
valid, sampled W3C `traceparent` becomes its parent. OpenShell treats incoming
trace context as an untrusted correlation hint: malformed or duplicate values
are ignored, `tracestate` is not adopted into the enforcement span, and an
unsampled context becomes a link so a caller cannot suppress local enforcement
telemetry.

The network supervisor assigns each inspected request a UUID. It stores that
value in the enforcement span, in correlated OCSF events, and in the
`x-openshell-request-id` response header. OpenShell removes workload,
middleware, and upstream attempts to set that header on inspected HTTP paths.
The header is a correlation handle, not proof of an enforcement decision. A
consumer must match it to trusted OpenShell OTLP or OCSF output for the same
sandbox and trace, and must never authorize from the header alone. L4 and
passthrough traffic do not provide this anti-spoofing guarantee. Span
attributes distinguish the policy decision from the enforcement action and
final outcome, such as a local denial, an allowed response, or an upstream or
platform failure. An unfinished request is reported as incomplete. The
attributes never include credentials, query values, or request and response
bodies.

Resource identities are pinned on their first valid observation. Correlated
OCSF events borrow that state while copying their own fields, then release the
state lock before tracing dispatch. Revisions are exported as decimal strings
to preserve the full `u64` range.

When Supervisor Middleware is selected, the same span records separate bounded
request- and response-phase outcomes. Each phase reports whether middleware
allowed or denied the exchange, failed internally, mutated traffic, followed a
fail-open or fail-closed path, or exhausted admission capacity. OpenShell emits
one correlated OCSF aggregate for each completed phase. Middleware names,
configuration, findings, failure reasons, headers, and bodies remain outside
the correlated aggregate; existing detailed middleware events retain their
independent security-log lifecycle.
