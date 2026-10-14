# Runbook: incident response

Severity follows the alert label (`page` = respond now, `ticket` = next
business day). Every administrative action below is recorded in the audit
chain.

## Definition drift

`GatewayToolDefinitionDrift`: an upstream advertises a tool definition that
differs from its pin. Calls to that tool are already blocked.

1. `POST /v1/servers/<id>/discover` and read the report (`changed` entries).
2. Compare the new draft with the approved version
   (`GET /v1/tools/<server>/<tool>`): description, schemas, annotations.
3. Expected release: review and approve the new version (the old one is
   superseded). Unexpected change: `POST /v1/servers/<id>/disable`, revoke the
   draft, contact the upstream owner and treat it as a supply-chain incident.

## Injected content

`GatewayOutputBlockedSpike`: an upstream or remote agent keeps returning
content that fails inspection.

1. Identify the upstream from the alert labels; correlate audit events
   (`mcp.tools.call` or `a2a.message/send` with outcome `content_blocked`).
2. If the upstream serves untrusted third-party data (tickets, web pages),
   the block is working as intended; inform the owning team.
3. If the upstream itself is compromised: disable the server or revoke the
   card version, rotate any `static_bearer` credential and notify security.

## Authentication failures

`GatewayAuthenticationFailures`: sustained invalid credentials.

1. Break down by endpoint and source (ingress logs).
2. Check fabric health first: a fabric outage shows as 502 at the gateway,
   not 401.
3. Suspected credential stuffing or replay: block the source at ingress and
   suspend the affected agent in the identity fabric. Suspension takes effect
   on the next call, because the gateway introspects every request.

## Deny spike

`GatewayDenySpike`: more than 20% of decisions are denials. Usually a policy
or allow-list change, or a new agent without scopes. Compare `local_rules`
and `fabric_rules` in recent audit events.

## Elevated 5xx

1. `kubectl -n mcp-gateway get pods`, `/readyz` (database) and fabric health.
2. Database unavailable: see disaster recovery. Audit writes fail closed, so
   calls fail until the database is back.

## Replicas down

`GatewayReplicasDown`: check events, OOM kills (raise memory if large
responses are allowed), image pull errors and failed readiness (database).

## Compromised partner domain

Revoke every card of the domain (`POST /v1/agent-cards/<id>/versions/<v>/revoke`),
remove the domain from `gateway.trustDomains` (this ends inbound federation)
and redeploy. Audit events with `authenticated_by: federation:<domain>` show
what the domain's agents did.
