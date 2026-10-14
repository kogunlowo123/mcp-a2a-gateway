# MCP and A2A Enterprise Gateway

A single, governed entry point for AI agents to reach enterprise tools (Model
Context Protocol) and other agents (Agent2Agent protocol), including agents in
partner trust domains. Every tool definition is reviewed and pinned by hash,
every call is authorized by the agent identity fabric and the gateway's own
policy, high-risk calls wait for a human, content crossing the boundary is
inspected, and every decision lands in a signed audit chain.

```
Agent ─▶ Gateway ─▶ Authentication ─▶ Authorization ─▶ Federation
          │             │                  │                │
          │      fabric introspection  gateway policy   RFC 8693 delegated
          │      or federated JWKS     + fabric PDP     credential per hop
          ▼
   pinned tool catalog · approval gate · content inspection · signed audit
```

## Capabilities

| Capability | Implementation |
|---|---|
| MCP gateway | Official MCP SDK `MCPServer` (the successor of FastMCP in mcp 2.x) over stateless Streamable HTTP at `/mcp`; upstream servers reached with the SDK `Client`, protocol revisions 2025-11-25 and 2026-07-28 |
| Tool registration and discovery | Upstream servers registered behind an egress allow list; `tools/list` discovery creates draft versions with a SHA-256 definition hash |
| Lifecycle | draft → approved → deprecated (with sunset) → revoked; approval by a reviewer who did not run discovery (separation of duties) |
| Rug-pull defense | Agents only ever see the pinned definition; a live definition that differs from its pin blocks calls until a reviewer approves the new version |
| Tool poisoning | Descriptions and schema text are scored for injection at discovery; flagged versions need a written override to approve |
| Per-tool allow lists | SPIFFE ID globs per tool version, plus credential scopes (`mcp:<server>:<tool>`) |
| Parameter validation | Arguments validated against the pinned JSON Schema (Draft 2020-12, formats checked) and size-capped |
| Response limits | Byte ceiling enforced on the wire before parsing, per tool or per server |
| Output inspection | agentic-core `ContentGuard`: prompt-injection indicators and credentials block the response; PII is redacted; structured output validated against the pinned output schema |
| Egress DLP | Credential material in tool arguments or A2A messages is blocked before it leaves |
| A2A gateway | Agent Card at `/.well-known/agent-card.json`, JSON-RPC `message/send`, `tasks/get`, `tasks/cancel`, authenticated extended card at `/a2a` |
| Agent card registry | Cards accepted only from configured trust domains and hosts, JWS-signed (RFC 8785 canonical form) by keys in the domain's JWKS, pinned by digest, same lifecycle as tools |
| Federation | Outbound: RFC 8693 token exchange at the identity fabric for every hop, delegation depth checked against the target domain. Inbound: partner tokens verified against the partner JWKS and confined to an inbound scope ceiling |
| Authorization | agentic-core `PolicyEngine` (`policies/gateway-authorization.yaml`) combined with the fabric's `/v1/authorize`; most restrictive wins |
| Human approval | `require_approval` decisions create an approval bound to caller, delegation chain, target and payload digest; single use; expires |
| Resilience | Per-agent token-bucket rate limits, per-upstream circuit breakers, timeouts everywhere, fail-closed on every dependency |
| Audit | agentic-core signed hash chain, one chain per replica stored in PostgreSQL, verifiable online (`/v1/audit/verify`) and exportable for WORM archival |
| Observability | Prometheus metrics, OpenTelemetry traces, JSON logs with correlation IDs, SLO and security alerts, Grafana dashboard |

## Quick start (local)

Requires Docker. No API keys or cloud credentials are needed.

```bash
docker compose up --build
curl -s localhost:8090/.well-known/agent-card.json | jq .name
curl -s localhost:8090/.well-known/oauth-protected-resource | jq
```

The stack runs the gateway, the [agent identity fabric](https://github.com/kogunlowo123/agent-identity-fabric),
PostgreSQL for each, an OIDC provider standing in for the workload issuer and
the enterprise IdP, and an OpenTelemetry collector. To use delegated upstream
credentials locally, register the gateway as an agent in the fabric and set
`GATEWAY_GATEWAY_AGENT_ID` and `GATEWAY_WORKLOAD_TOKEN_FILE`
([configuration](docs/operations/configuration.md)).

## Development

```bash
uv sync
make check        # ruff, black, mypy --strict, bandit, contract drift, tests (coverage >= 90%)
make integration  # PostgreSQL tests (needs GATEWAY_TEST_DATABASE_URL)
make helm terraform
```

Test suites: `tests/unit`, `tests/security` (one test per threat T1-T18 in the
threat model), `tests/chaos` (dependency failures), `tests/performance`
(latency budgets; `locustfile.py` for load), `tests/e2e` (full HTTP lifecycle
with the official MCP SDK client, both MCP protocol eras, A2A JSON-RPC,
interoperability with the real identity fabric, and a property-based OpenAPI
contract test), `tests/integration` (PostgreSQL). Upstream MCP servers in the
tests are real SDK servers served in-process; no network is used.

## API

| Endpoint | Caller | Purpose |
|---|---|---|
| `POST /mcp` | Agents (fabric credential) | MCP Streamable HTTP: `tools/list`, `tools/call` over the pinned catalog |
| `POST /a2a` | Agents | A2A JSON-RPC: `message/send`, `tasks/get`, `tasks/cancel`, `agent/getAuthenticatedExtendedCard` |
| `GET /.well-known/agent-card.json` | Anyone | The gateway's A2A Agent Card |
| `GET /.well-known/oauth-protected-resource` | MCP clients | RFC 9728 metadata naming the identity fabric |
| `POST /v1/servers`, `/discover`, `/enable`, `/disable` | `gateway-admin`, `gateway-reviewer` | Upstream MCP servers and discovery |
| `GET /v1/tools`, `POST /v1/tools/{server}/{tool}/versions/{v}/approve\|deprecate\|revoke` | `gateway-reviewer` | Tool lifecycle |
| `POST /v1/agent-cards`, `/refresh`, `/versions/{v}/approve\|deprecate\|revoke` | `gateway-admin`, `gateway-reviewer` | Agent card registry |
| `GET /v1/approvals`, `POST /v1/approvals/{id}/approve\|deny` | `gateway-approver` | Human approval of high-risk calls |
| `GET /v1/audit/verify` | `gateway-auditor` | Verify this replica's signed audit chain |

Full contract: [docs/api/openapi.json](docs/api/openapi.json); JSON Schemas in [schemas/](schemas/).
Operator tools: `python -m mcp_a2a_gateway.cardsign` (sign your own agent cards),
`python -m mcp_a2a_gateway.audit_export` (verified audit segments for WORM storage).

## Deployment

| Layer | Location |
|---|---|
| Container image | `Dockerfile` (non-root, read-only root filesystem compatible) |
| Helm chart | `deployments/helm/mcp-a2a-gateway` (Deployment, PDB, HPA, NetworkPolicy, ServiceMonitor, projected workload token) |
| Namespace and secret sync | `deployments/kubernetes` (restricted Pod Security, External Secrets) |
| Cloud infrastructure | `deployments/terraform/{aws,azure,gcp}`: managed PostgreSQL, KMS, secret store, WORM archive for audit segments, workload identity. AWS is the reference deployment |

See the [startup runbook](docs/runbooks/startup.md).

## Documentation

- [Architecture](docs/architecture/overview.md), [MCP gateway design](docs/architecture/mcp-gateway.md), [A2A federation design](docs/architecture/a2a-federation.md), [agent specification](docs/architecture/agent-specification.md)
- [ADRs](docs/architecture/adr/)
- [Threat model and risk register](docs/security/threat-model.md)
- [Compliance control mapping](docs/compliance/control-mapping.md)
- Runbooks: [startup](docs/runbooks/startup.md), [monitoring](docs/runbooks/monitoring.md), [incident response](docs/runbooks/incident-response.md), [rollback](docs/runbooks/rollback.md), [disaster recovery](docs/runbooks/disaster-recovery.md), [audit export](docs/runbooks/audit-export.md)
- [Configuration reference](docs/operations/configuration.md), [operations, cost and scalability](docs/operations/operations.md)

Shared controls (policy engine, audit chain, content guard, logging, telemetry)
come from [agentic-core](https://github.com/kogunlowo123/agentic-core).

## License

Apache-2.0
