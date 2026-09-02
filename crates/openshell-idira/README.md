# OpenShell IDIRA client (private PoC)

`openshell-idira` is a small, read-only client for an IDIRA or
Conjur-compatible secrets service. It authenticates a gateway with an API key
read from a local file and fetches an already provisioned variable.

The crate does not implement provider profiles, credential storage, request
policy, middleware, or proxy injection. The gateway provider-refresh path owns
those responsibilities, including workspace-scoped reference construction.

## Current boundary

- API-key-file authentication only.
- HTTPS is required except for loopback tests.
- An optional PEM CA bundle supports private endpoints.
- Authentication tokens are cached only in memory, invalidated on `401`, and
  never logged.
- Client-material and transport failures emit sanitized operation and category
  fields for diagnosis. They never include file paths, references, URLs,
  credentials, tokens, or response bodies.
- Redirects are disabled so credentials cannot be replayed to another host.
- Secret values are returned exactly as received and response sizes are
  bounded.
- The client can read existing variables. It does not create, update, or delete
  IDIRA policy resources.

The first gateway integration is eager refresh. OpenShell fetches a variable on
a configured cadence and writes the value through its existing credential
runtime. The provider record stores an opaque handle, but the selected OpenShell
credential store holds the fetched value at rest. This is not just-in-time
retrieval. The server prefixes each relative provider reference with the
operator-owned IDIRA prefix and immutable OpenShell workspace ID before calling
this client.
The first PoC has no maximum-staleness policy; a failed eager refresh leaves the
last successfully stored value active.

JIT retrieval, IDIRA SWA/SPIFFE authentication, attestation, middleware access
to secrets, and a full `CredentialDriver` implementation are outside this PoC.
