# Process supervisor

`openshell-supervisor-process` owns the supervisor's process-facing runtime:
SSH access, the gateway session, log forwarding, and the OTLP telemetry
relay described below.

## Telemetry relay

The supervisor relays OpenTelemetry traces, logs, and metrics from agent processes to the
gateway over the session stream, so OTel-instrumented agents reach an
external collector without any sandbox egress.

The relay is opt-in on the gateway. When `[openshell.gateway.otlp]` is
configured, `agent_signals` defaults to traces. `CreateSandbox` sets
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` to
`http://192.0.0.8:4318/v1/traces`. Operators can explicitly add `logs` and
`metrics` to set the equivalent signal-specific variables for `/v1/logs` and
`/v1/metrics`. Each enabled protocol defaults to `http/protobuf`. A non-empty
generic endpoint suppresses injection for every signal. A non-empty
signal-specific endpoint or the valid but incompatible signal-specific `grpc`
protocol suppresses injection only for that signal, so a workload can
intentionally split destinations while the remaining signals still use the
relay. Existing `http/protobuf` and `http/json` values are retained
canonically. Blank and unknown protocol values use `http/protobuf`. The values
persist in the stored spec, so restarts inherit them.

`192.0.0.8` is the RFC 7600 dummy address and is never routed. A workload
connect to any non-loopback address is intercepted by the sandbox seccomp
broker and staged for the supervisor as a `PendingTcpOpen`, so the address is
a label the supervisor switches on. The proxy recognises it ahead of host
mapping, policy, and SSRF validation and hands the staged stream to the OTLP
receiver instead of dialing upstream. The receiver speaks HTTP/1.1 on that
stream and accepts `POST /v1/traces`, `/v1/logs`, and `/v1/metrics` as
protobuf or JSON. No socket is bound,
the driver outer fence is untouched, and the isolation contract and boundary
protocol are unchanged. Loopback cannot serve this purpose because the broker
completes loopback connects locally without mediation.

```
Agent process --> connect(192.0.0.8:4318) --> seccomp broker stages the open
  --> supervisor proxy, reserved destination --> OTLP receiver
  --> trusted signal resource enrichment (openshell.* namespace)
  --> bounded buffer (4096 items and 8 MiB, newest dropped when full)
  --> supervisor session (OtelExportData) --> gateway
  --> dedicated OtelRelayExporter --> external OTLP collector
```

The relay starts before networking, so the first staged stream finds it. The
supervisor advertises the legacy `otel_export` trace capability alongside
versioned `otel_export_traces_v1`, `otel_export_logs_v1`, and
`otel_export_metrics_v1` capabilities in `SupervisorHello`. Current gateways
confirm only the versioned capabilities enabled by `agent_signals`. A current
supervisor still accepts a legacy gateway's `otel_export` confirmation for
traces, which keeps trace delivery working during a supervisor-first rolling
upgrade. A current gateway deliberately does not confirm legacy `otel_export`,
so an old supervisor connected to a new gateway does not forward traces.
Forwarding is gated per signal and per session on confirmation. Items received
before a confirming session wait in the bounded buffer; unconfirmed signal
types are dropped with accounting rather than sent on a control stream that
cannot decode them. The receiver serves
at most 64 concurrent connections and refuses further opens before the
sandbox commits the socket, which the agent observes as `EAGAIN`.

Every forwarded signal resource always gains
`openshell.telemetry.source=agent` so collectors can separate agent telemetry
from gateway telemetry. With enrichment enabled it also gains
`openshell.sandbox.id`, `openshell.sandbox.name`, and the numeric
`openshell.workload.unix_uid`. The supervisor adds
`openshell.workspace.name` after workspace discovery and adds
`openshell.workload.image.reference` when the runtime supplies the configured
image reference. It strips the entire agent-supplied `openshell.*` namespace
before adding these trusted values, including when metadata enrichment is
disabled.

Both hops are non-blocking and at-most-once. An OTLP/HTTP success means the
request entered the supervisor's bounded local relay; it does not confirm that
the collector accepted it. The receiver uses `try_send` into an item- and
byte-bounded buffer. The session uses a separate, one-frame telemetry queue
and a control-first outbound stream, so telemetry cannot queue ahead of
heartbeats or relay-control messages. The gateway bounds concurrent collector
exports. Saturation drops telemetry with counters and rate-limited warnings
instead of stalling control traffic. Collector failures are reported
but are not retried or persisted; a later request reconnects lazily. After the
main process exits and before the exit is
reported, the supervisor asks the session to stop the receiver (no new
streams, keep-alive disabled, two seconds for in-flight requests, then
stragglers cut) and waits for session-queue capacity while flushing the buffer
onto the stream. The whole drain is bounded at three seconds so an unreachable
gateway cannot delay the report; anything still unsent at the internal
deadline is counted as a session drop.

The gateway forwards signal bytes through a dedicated `OtelRelayExporter`
rather than its own tracer provider, so the supervisor's resource attributes
survive. The collector channel connects lazily and reconnects after transient
failures. Non-empty OTLP `partial_success` responses are surfaced as warnings.
`OtelExportData` also carries OCSF events, which the gateway
re-emits on the `ocsf_relay` target; the supervisor-side OCSF sink is not
installed yet.

The log and metric protobuf variants use previously reserved field numbers, so
mixed binaries remain wire-compatible. Traces remain the configuration and
negotiation default. For a rolling upgrade, upgrade supervisors first: the old
gateway confirms legacy `otel_export`, which current supervisors continue to
honor for traces. After every supervisor advertises the versioned capabilities,
upgrade the gateway, then add `logs` and `metrics` to `agent_signals`. Upgrading
the gateway first leaves old supervisors without a confirmed trace capability;
their bounded buffers can eventually drop telemetry.
