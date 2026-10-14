# Agent specification

The gateway is a privileged platform agent: it holds its own identity in the
identity fabric and acts on behalf of other agents. This document states its
mandate in the terms the fabric requires of every registered agent.

## Role and mission

- **Purpose:** be the only path by which enterprise agents reach MCP tools
  and other agents, so that every such interaction is reviewed, authorized,
  inspected and attributable.
- **Business objective:** let teams adopt third-party and internal MCP servers
  and partner agents without each team re-implementing identity, approval,
  content safety and audit.
- **Protected resources:** pinned tool and card registry, approval records,
  delegated credentials in flight, audit chains, upstream service credentials.
- **Operating boundaries:** never executes tools itself; never forwards an
  agent's own credential; never routes a federated caller onward; never serves
  a tool definition or agent card a reviewer has not approved.
- **Delegated responsibility:** authorization policy is owned by AI
  governance (`policies/gateway-authorization.yaml`, CODEOWNERS); tool and card
  approval by security reviewers; individual high-risk calls by business
  approvers.

## Delegated scope

| Allowed | Disallowed | Risk | Escalation |
|---|---|---|---|
| Discover upstream tools and record drafts | Change what agents can call without review | MODERATE | Drift alert pages the platform on-call |
| Forward approved tool calls with a delegated credential | Forward the caller's token; call draft, revoked or post-sunset versions | HIGH | Denials and blocks are audited; deny spike ticket |
| Route A2A messages to approved cards within delegation limits | Exceed a domain's delegation depth or classification ceiling; re-delegate partner callers | HIGH | Approval required for high-risk targets |
| Hold calls for human approval | Execute `require_approval` calls without a matching approval | CRITICAL | Approval backlog alert |
| Block injected or credential-bearing content | Relay upstream error text or unvetted output | HIGH | Output-blocked spike pages security |

The gateway's own fabric registration should carry exactly the scopes it may
delegate (for example `mcp:crm:*`, `a2a:send:partner-research`); the fabric
intersects every exchange with them, so the registration is a hard ceiling on
what the gateway can ever be used for.

## Objectives

| Type | Definition | Target |
|---|---|---|
| SLO availability | Share of `/mcp` and `/a2a` requests answered without a gateway 5xx | 99.9% over 30 days |
| SLO latency | Gateway overhead on `tools/call` (excluding upstream time) at p95 | < 150 ms |
| SLI | `gateway:request_errors:ratio_5m`, `gateway_tool_call_duration_seconds` | Prometheus |
| KPI | Share of agent tool traffic that flows through the gateway | 100% (direct egress blocked by network policy) |
| KPI | Time from upstream definition change to calls blocked | ≤ `definition_ttl_seconds` (default 60 s) |
| KPI | Median time to decide an approval | < 15 min in business hours |
| Completion | A call is complete when its outcome is in the signed audit chain | Enforced: audit failure fails the call |

## Permissions

| Mechanism | Use |
|---|---|
| RBAC | Admin roles from the enterprise IdP: `gateway-admin`, `gateway-reviewer`, `gateway-approver`, `gateway-auditor`; separation of duties between discovery/registration and approval |
| ABAC | Gateway policy over subject (scopes, delegation, federation), resource (lifecycle, risk, classification, allow list, destructive hint) and environment (approval, purpose of use) |
| Agent identity | SPIFFE IDs issued by the identity fabric; partner SPIFFE IDs verified against partner JWKS |
| OAuth 2.0 / OIDC | RFC 7662 introspection, RFC 7523 jwt-bearer for the gateway's own credential, RFC 8693 token exchange per hop, RFC 9728 protected resource metadata, OIDC for administrators |
| Workload identity | Projected service-account token (audience `identity-fabric`) for the fabric; cloud workload identity (IRSA, Azure Workload ID, GKE WI) for the audit export job |

## Inputs and outputs

| Interface | Input schema | Output schema |
|---|---|---|
| Registry API | `schemas/register-server.request`, `approve-tool.request`, `deprecate.request`, `register-card.request`, `approve-card.request`, `decide-approval.request` | `upstream-server.response`, `tool-version.response`, `discovery-report.response`, `agent-card-version.response`, `approval.response` |
| MCP | Pinned upstream input schema per tool | Pinned output schema (validated) or text content |
| A2A | `schemas/a2a-jsonrpc.request`; cards validated against `schemas/a2a-agent-card` | A2A Task or Message |

Validation: unknown fields are rejected on every administrative input;
identifiers are pattern-checked; caller patterns must be SPIFFE IDs; upstream
URLs and card endpoints must be HTTPS on an allow list.

Provenance: every pinned definition and card carries its SHA-256 digest,
discoverer/registrant, reviewer and timestamps; card signatures record `kid`
and algorithm; delegated credentials carry the full `act` chain.

Audit metadata on every call: actor, delegation chain, authentication source,
target and version, definition hash or card digest, argument/message and
response digests, response size, redactions, approval id, gateway and fabric
decisions with their policy digests, correlation ID.
