# ADR-0001: Serve pinned tool definitions, never live ones

- Status: Accepted
- Date: 2026-10-14

## Context

An MCP server can change a tool's description or schema at any time. Because
tool descriptions are read by the model, a changed description is a prompt
injection channel ("rug pull", tool poisoning), and a changed schema can
silently widen what a tool accepts. Proxies that pass `tools/list` through
cannot detect either.

## Decision

Discovery stores each definition (name, title, description, input and output
schema, annotations) as a versioned draft with a SHA-256 over its canonical
JSON. A reviewer who did not run discovery approves a version, which pins that
exact definition. Agents are always shown the pinned definition. Before each
call the gateway compares the live digest (cached per server for
`definition_ttl_seconds`) with the pin and refuses the call on mismatch until
the new version is reviewed. Definitions whose text scores as instruction-like
need a written override to approve.

## Consequences

- An upstream change cannot reach a model without review; the worst case is
  that calls fail closed for up to the cache TTL plus review time.
- Upstream teams must coordinate releases with a gateway review (the drift
  alert and discovery report make that visible).
- The cache TTL is a tradeoff between upstream `tools/list` load and the
  window in which a changed upstream still receives calls; 0 checks every call.
