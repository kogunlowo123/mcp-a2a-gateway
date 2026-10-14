# ADR-0002: Stateless Streamable HTTP with JSON responses on /mcp

- Status: Accepted
- Date: 2026-10-14

## Context

Stateful MCP sessions pin a client to the replica that created the session
(in-memory session table), which needs sticky routing and loses sessions on
rollout. The gateway's tools are request/response proxies that never stream
progress or send server-initiated requests.

## Decision

Run the SDK `MCPServer` with `stateless_http=True, json_response=True`. Both
protocol eras work: the 2026-07-28 per-request envelope is stateless by
design, and the handshake era is served without session tracking. Upstream
calls likewise open a short-lived SDK `Client` per operation.

## Consequences

- Any replica serves any request; the chart runs a plain Deployment behind a
  normal Service, and HPA scaling is safe.
- No upstream session is shared between agents, which removes a cross-tenant
  leakage path at the cost of one handshake per upstream call (or a discovery
  round trip on 2026-07-28 servers).
- Server-to-client features (sampling, elicitation, progress streams) are not
  proxied. A future version can add them behind session affinity if needed.
