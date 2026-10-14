# ADR-0005: Official SDK client upstream, with a byte-limited transport

- Status: Accepted
- Date: 2026-10-14

## Context

MCP now has two protocol eras (initialize handshake and the 2026-07-28
per-request envelope with `server/discover`). Reimplementing the client
protocol in the gateway would drift from the specification. The gateway must
also enforce response size limits before untrusted bytes are parsed.

## Decision

Use the SDK `Client` in `auto` mode over `streamable_http_client`, with an
`httpx2` client whose transport (`LimitedTransport`) rejects a declared
`Content-Length` over the limit and aborts the stream once counted bytes cross
it. Errors are mapped to gateway errors; upstream JSON-RPC error text is not
relayed. Response caching in the SDK client is disabled so drift checks always
see the live listing.

## Consequences

- Protocol negotiation and framing follow the SDK; upgrades are dependency
  bumps covered by the e2e tests that run the SDK client and server in both
  eras.
- The SDK depends on `httpx2`; the gateway uses `httpx` for the fabric and
  A2A, so two HTTP stacks are installed.
- Output inspection runs on the parsed result, after the byte ceiling, so
  memory is bounded by the configured limit.
