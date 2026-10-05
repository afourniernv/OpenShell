# Process supervisor

`openshell-supervisor-process` owns the supervisor's process-facing runtime:
SSH access, the gateway session, log forwarding, and the OTLP telemetry
relay described below.

## Telemetry relay

The supervisor relays enabled OpenTelemetry trace, log, and metric data from agent processes to the
gateway over the session stream, so OTel-instrumented agents reach an
external collector without any sandbox egress.

The relay is opt-in on the gateway. When `[openshell.gateway.otlp]` is
configured with `sandbox_relay_enabled = true`, `CreateSandbox` sets
signal-specific endpoint to the reserved relay URL and its protocol to
`http/protobuf` in the sandbox environment unless the caller already selected a generic or signal-specific
endpoint. The values persist in the stored spec, so restarts inherit them.

`127.0.0.8:4318` is reserved by the sandbox seccomp broker. A workload connect
to that exact loopback address is staged for the supervisor as a
`PendingTcpOpen` instead of completing locally, so the address is a label the
supervisor switches on. The proxy recognises it ahead of host mapping, policy,
and SSRF validation and hands the staged stream to the OTLP receiver instead of
dialing upstream. The receiver speaks HTTP/1.1 on that stream and accepts
`POST /v1/traces`, `/v1/logs`, and `/v1/metrics` as protobuf or JSON. No socket
is bound, the driver outer fence is untouched, and the isolation contract and
boundary protocol are unchanged.

```
Agent process --> connect(127.0.0.8:4318) --> seccomp broker stages the open
  --> supervisor proxy, reserved destination --> OTLP receiver
  --> enrichment (openshell.sandbox.* resource attributes)
  --> bounded buffer (4096 items / 16 MiB, newest rejected when full)
  --> supervisor session (OtelExportData) --> gateway
  --> dedicated OtelRelayExporter --> external OTLP collector
```

The relay starts before networking, so the first staged stream finds it. The
supervisor advertises one capability per supported signal in `SupervisorHello`;
the gateway confirms each in `SessionAccepted` only when that signal is enabled.
Forwarding is gated per signal on that confirmation. Items received before a confirming session,
or while a session declines, wait in the bounded buffer. The receiver serves
at most 64 concurrent connections and refuses further opens before the
sandbox commits the socket, which the agent observes as `EAGAIN`.

Each request has a body deadline and a conservative size budget derived from
the gateway's gRPC message limit. The receiver admits at most four concurrent
body/decode/enrichment jobs. It limits resource-block amplification after
decode, then measures the exact session envelope before queueing it; the
post-decode check does not prevent allocations already performed by the
protobuf or JSON decoder. Queue overload is reported to the OTLP client rather
than acknowledged as delivered. The gateway independently caps collector
exports in flight so a collector outage cannot grow export tasks without
bound.

Forwarded telemetry resources gain `openshell.sandbox.id`, `openshell.workspace.id`,
`openshell.sandbox.policy`, `openshell.sandbox.user`,
`openshell.sandbox.image`, and `openshell.sandbox.driver`, and always
`openshell.telemetry.source=agent` so collectors can separate agent telemetry
from gateway telemetry. Agent-supplied values for these keys are replaced.

Both hops are non-blocking. The receiver uses `try_send` into the buffer and
the session uses `try_send` into its outbound channel, so telemetry can never
stall control traffic. After the main process exits and before the exit is
reported, the supervisor asks the session to stop the receiver (no new
streams, keep-alive disabled, two seconds for in-flight requests, then
stragglers cut) and flush the buffer onto the stream. The whole drain is
bounded at three seconds so an unreachable gateway cannot delay the report.

The gateway forwards trace, log, and metric bytes through a dedicated `OtelRelayExporter`
rather than its own tracer provider, so the supervisor's resource attributes
survive. `OtelExportData` also carries OCSF events, which the gateway
re-emits on the `ocsf_relay` target; the supervisor-side OCSF sink is not
installed yet.
