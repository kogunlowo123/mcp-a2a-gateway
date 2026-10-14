# ADR-0003: RFC 8693 delegated credentials for every upstream hop

- Status: Accepted
- Date: 2026-10-14

## Context

Upstream MCP servers and remote agents need to know which agent is acting.
Forwarding the agent's own token (token passthrough) is forbidden by the MCP
authorization specification and would let any upstream replay it elsewhere. A
single gateway service credential hides the acting agent.

## Decision

For `delegated` upstreams and every A2A hop, the gateway asks the identity
fabric for a token exchange with the agent's credential as subject and the
gateway's own credential (obtained with its projected workload token, RFC
7523) as actor, requesting only the agent's scope that covers the action. The
fabric intersects that scope with the gateway's registration, caps depth and
lifetime, and records the `act` chain. Federated (partner) callers are never
exchanged onward.

## Consequences

- Upstreams see `sub` = acting agent and `act.sub` = gateway, narrowed to one
  scope, short-lived; suspension of either agent at the fabric invalidates it.
- One extra fabric round trip per call; the fabric is a hard dependency and
  the gateway fails closed when it is unavailable.
- The gateway's fabric registration must list the scopes it may delegate
  (literal intersection), which doubles as a ceiling on its blast radius.
- The fabric v0.1.0 does not take an RFC 8707 resource indicator, so the
  delegated token's audience is the platform audience; narrow scope and short
  lifetime are the mitigations (risk R6).
