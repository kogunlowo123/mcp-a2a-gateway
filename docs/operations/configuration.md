# Configuration reference

All settings are `GATEWAY_*` environment variables (see
`src/mcp_a2a_gateway/config.py`). The service refuses to start with incomplete
or unsafe configuration. List and object values are JSON.

| Variable | Required | Default | Description |
|---|---|---|---|
| `GATEWAY_ENVIRONMENT` | no | `production` | `production` refuses ephemeral keys and insecure upstreams |
| `GATEWAY_PUBLIC_URL` | yes | | Public base URL; used in the Agent Card and RFC 9728 metadata |
| `GATEWAY_TRUST_DOMAIN` | yes | | Trust domain of local agents; subjects must be `spiffe://<domain>/...` |
| `GATEWAY_DATABASE_URL` | yes | | SQLAlchemy async URL (`postgresql+asyncpg://...`) |
| `GATEWAY_FABRIC_URL` | yes* | | Identity fabric base URL (introspection, authorization, token exchange) |
| `GATEWAY_GATEWAY_AGENT_ID` | no | | The gateway's SPIFFE ID in the fabric; enables delegated credentials |
| `GATEWAY_WORKLOAD_TOKEN_FILE` | with agent id | | Projected service-account token used for the jwt-bearer grant |
| `GATEWAY_TOKEN_ISSUER` | yes* | | Issuer of agent credentials when no fabric is configured |
| `GATEWAY_TOKEN_JWKS_URL` | yes* | | JWKS for local verification when no fabric is configured |
| `GATEWAY_TOKEN_AUDIENCE` | no | `agent-platform` | Required `aud` of agent credentials |
| `GATEWAY_ADMIN_ISSUER` | yes | | Enterprise OIDC issuer for administrators |
| `GATEWAY_ADMIN_AUDIENCE` | yes | | Audience of administrator tokens |
| `GATEWAY_ADMIN_JWKS_URL` | yes | | Enterprise IdP JWKS |
| `GATEWAY_ADMIN_ROLES_CLAIM` | no | `roles` | Claim carrying the `gateway-*` roles |
| `GATEWAY_POLICY_FILE` | no | `policies/gateway-authorization.yaml` | Gateway authorization policy |
| `GATEWAY_AUDIT_KEY_FILE` | yes** | | Ed25519 PEM signing the audit chain; file stem is the key id |
| `GATEWAY_AUDIT_CHAIN_ID` | no | `gateway-0` | Chain id; the chart sets the pod name |
| `GATEWAY_DEV_EPHEMERAL_KEYS` | no | `false` | In-memory audit key, non-production only (replaces **) |
| `GATEWAY_UPSTREAM_ALLOWED_HOSTS` | no | `[]` | Host globs upstream MCP servers may use; empty refuses every registration |
| `GATEWAY_ALLOW_INSECURE_UPSTREAMS` | no | `false` | Permit `http://` upstreams (development only) |
| `GATEWAY_TRUST_DOMAINS` | no | `{}` | Federated trust domains, see below |
| `GATEWAY_REQUIRE_SIGNED_CARDS` | no | `true` | Refuse agent cards without a valid signature |
| `GATEWAY_MCP_ALLOWED_HOSTS` | no | `[]` | Host header values accepted on `/mcp`; empty disables DNS-rebinding checks |
| `GATEWAY_DEFINITION_TTL_SECONDS` | no | `60` | Cache of live upstream definitions for drift checks (0 = every call) |
| `GATEWAY_APPROVAL_TTL_SECONDS` | no | `3600` | Lifetime of an approval request |
| `GATEWAY_MAX_ARGUMENT_BYTES` | no | `262144` | Maximum canonical size of tool arguments |
| `GATEWAY_A2A_MAX_RESPONSE_BYTES` | no | `1048576` | Maximum remote-agent response size |
| `GATEWAY_A2A_TIMEOUT_SECONDS` | no | `60` | Remote-agent call timeout |
| `GATEWAY_RATE_LIMIT_PER_MINUTE` | no | `600` | Per-agent token bucket (per replica) |
| `GATEWAY_CIRCUIT_FAILURE_THRESHOLD` | no | `5` | Consecutive upstream failures that open a circuit |
| `GATEWAY_CIRCUIT_RESET_SECONDS` | no | `30` | Time before a half-open probe |
| `GATEWAY_LOG_LEVEL` | no | `INFO` | |
| `GATEWAY_OTLP_ENDPOINT` | no | | OTLP gRPC endpoint for traces |
| `GATEWAY_HOST` / `GATEWAY_PORT` | no | `127.0.0.1` / `8080` | The image sets host `0.0.0.0` |
| `GATEWAY_FORWARDED_ALLOW_IPS` | no | `127.0.0.1` | Proxies trusted for `X-Forwarded-*` |
| `GATEWAY_UPSTREAM_SECRET_*` | no | | Credentials for `static_bearer` upstreams, referenced by name in the server registration |

\* Either `GATEWAY_FABRIC_URL`, or `GATEWAY_TOKEN_ISSUER` with
`GATEWAY_TOKEN_JWKS_URL`. Without the fabric, credentials are verified locally
(no revocation check), only gateway policy applies, and delegated upstreams
and A2A federation are unavailable.

## Trust domains

```json
{
  "agents.partner.example": {
    "card_jwks_url": "https://keys.partner.example/agent-cards.json",
    "card_hosts": ["*.agents.partner.example"],
    "max_classification": 1,
    "max_delegation_depth": 2,
    "token_issuer": "https://identity.partner.example",
    "token_jwks_url": "https://identity.partner.example/.well-known/jwks.json",
    "token_audience": "partner-gateway",
    "inbound_scopes": ["mcp:catalog:search", "a2a:send:*"]
  }
}
```

The `.example` names are reserved documentation names (RFC 2606). `card_jwks` may replace
`card_jwks_url` with an inline JWKS. The four `token_*`/`inbound_scopes` keys
are optional and enable inbound federation; set all of them or none.
Classifications: 0 PUBLIC, 1 INTERNAL, 2 CONFIDENTIAL, 3 RESTRICTED.

## Registering upstream servers

`POST /v1/servers`:

```json
{
  "server_id": "crm",
  "display_name": "CRM tools",
  "url": "https://crm-mcp.mcp.svc.cluster.local/mcp",
  "owner": "sales-platform",
  "auth": {"mode": "delegated"},
  "max_response_bytes": 1048576,
  "timeout_seconds": 30
}
```

`auth.mode` is `delegated` (default), `static_bearer` (with
`"secret_env": "GATEWAY_UPSTREAM_SECRET_CRM"`) or `none`.

## Tool policy (approval body)

```json
{
  "policy": {
    "risk": 3,
    "classification": 2,
    "allowed_agents": ["spiffe://agents.corp.internal/agent/sales/*"],
    "max_response_bytes": 262144,
    "redact_pii": true,
    "requires_approval": false
  },
  "reason": "Reviewed with the CRM owner; writes need approval at risk 3"
}
```

Agents additionally need a credential scope covering `mcp:<server>:<tool>`
(lower-cased tool name), and A2A callers one covering `a2a:send:<card id>`.

## Call metadata

| Key | Where | Meaning |
|---|---|---|
| `mcp-a2a-gateway/approval-id` | MCP `_meta`, A2A `metadata` | Approval for exactly this call |
| `mcp-a2a-gateway/purpose-of-use` | MCP `_meta`, A2A `metadata` | Declared purpose; required for RESTRICTED targets |
| `mcp-a2a-gateway/target-agent` | A2A `metadata` | Agent card id to route to |
| `mcp-a2a-gateway/skill` | A2A `metadata` | Skill id on the target card |
