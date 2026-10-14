# Runbook: monitoring

Dashboard: `configs/grafana/mcp-a2a-gateway.json`. Alerts:
`configs/prometheus/alerts.yaml`.

| Signal | Metric | Normal |
|---|---|---|
| Availability | `gateway:request_errors:ratio_5m` | < 0.1% |
| Tool call outcomes | `gateway_tool_calls_total{outcome}` | mostly `success`; `approval_required` tracks policy |
| Authorization | `gateway_authorization_decisions_total{protocol,decision}` | deny share stable week over week |
| Drift | `gateway_definition_drift_total{server}` | 0 outside planned upstream releases |
| Blocked output | `gateway_output_blocked_total{upstream,reason}` | near 0 |
| Upstream health | `gateway_upstream_errors_total{upstream,error}` | near 0 |
| Authentication | `gateway_authentication_failures_total{endpoint}` | low, flat |

## Latency

`GatewayToolCallLatencyHigh` measures end-to-end latency including the
upstream. Compare `gateway_tool_call_duration_seconds` with the upstream's own
metrics. Gateway-side contributors: fabric round trips (introspect, authorize,
exchange), the live definition refresh (one `tools/list` per server per
`definition_ttl_seconds`) and output inspection (about 3 ms per KB of text).
For large responses, lower `max_response_bytes` in the tool policy.

## Upstream failures

The per-upstream circuit opens after `circuit_failure_threshold` consecutive
failures and admits one probe after `circuit_reset_seconds`. Check the
upstream's health and network policy. Calls fail with `upstream_circuit_open`
while it is open; nothing is retried automatically, because tool calls are not
assumed to be idempotent.

## Approval backlog

`GatewayApprovalBacklog` fires when calls wait for approval and nobody
decides. List pending approvals with `GET /v1/approvals?status=pending` (role
`gateway-approver`). Pending approvals expire after `approval_ttl_seconds`.

## Audit

Daily: `GET /v1/audit/verify` (auditor role) on each replica, and check the
export job:
`kubectl -n mcp-gateway get jobs -l app.kubernetes.io/name=mcp-a2a-gateway-audit-export`.
