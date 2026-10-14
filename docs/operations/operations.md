# Operations: observability, deployment pattern, cost and scalability

## Observability

| Signal | Implementation |
|---|---|
| Metrics | Prometheus text at `/metrics` from a per-process registry: request latency by route and status, tool calls by server and outcome, tool latency, A2A operations, authorization decisions by protocol, definition drift, blocked output, upstream errors, lifecycle events, authentication failures |
| Traces | OpenTelemetry FastAPI instrumentation, exported over OTLP gRPC when `GATEWAY_OTLP_ENDPOINT` is set; `Authorization` headers are stripped by the collector config |
| Logs | JSON (structlog via agentic-core) with correlation IDs; sensitive keys scrubbed; no request bodies |
| Correlation | `X-Correlation-ID` accepted (≤ 64 printable characters) or generated, returned on every response and recorded in every audit event |
| Alerts | `configs/prometheus/alerts.yaml`: multi-window error-budget burn, latency, drift, blocked output, authentication failures, deny spikes, upstream failures, approval backlog, replica count |
| Dashboard | `configs/grafana/mcp-a2a-gateway.json` |
| Audit | Signed chains in PostgreSQL, `/v1/audit/verify`, hourly verified export to WORM |

## Deployment pattern

- Stateless Deployment, at least three replicas spread across zones, PDB
  `minAvailable: 2`, HPA on CPU (inspection and JSON processing are the
  CPU-bound parts).
- Restricted Pod Security; non-root UID 10001; read-only root filesystem;
  all capabilities dropped; no service-account token automount (only a
  projected token with audience `identity-fabric`).
- Default-deny namespace; the chart's NetworkPolicy admits only agent
  namespaces, ingress and monitoring, and egress only to DNS, PostgreSQL,
  OTLP and configured upstream ports. The application's host allow list is
  the finer-grained control.
- Agents' direct egress to MCP servers should be blocked by their own
  namespace policies so the gateway is the only path.
- Rollouts: `maxUnavailable: 0`, readiness on database connectivity.

## Cloud reference implementation

| Concern | AWS (reference) | Azure | GCP |
|---|---|---|---|
| Kubernetes | EKS | AKS | GKE |
| Database | RDS PostgreSQL 16 Multi-AZ, KMS, forced TLS, IAM auth, PITR 14 days | PostgreSQL Flexible Server zone-redundant HA, geo-redundant backups | Cloud SQL PostgreSQL 16 regional, CMEK, PITR |
| Secrets | Secrets Manager (KMS) + External Secrets | Key Vault (RBAC, private) + External Secrets | Secret Manager + External Secrets |
| Audit archive | S3 Object Lock (compliance mode, 7 years) | Immutable blob container (GZRS) | GCS retention policy (lockable) |
| Workload identity | IRSA for the audit export job | Workload ID (federated credential) | GKE Workload Identity |

## Cost

Costs scale with replicas and with the database; the gateway adds no
per-request third-party charges (no model calls).

| Item | Driver | Sizing guidance |
|---|---|---|
| Gateway pods | CPU for JSON handling and inspection | 0.5 vCPU / 512 MiB request per replica; inspection ≈ 3 ms of CPU per KB of model-visible text |
| PostgreSQL | Audit writes (one event per call plus registry changes) and approval rows | `db.r6g.large`-class handles thousands of calls per second; audit rows ≈ 1-2 KB each |
| Audit archive | Event volume × retention | ≈ 1.5 KB per call; 10 M calls/month ≈ 15 GB/month in WORM storage |
| Fabric | Three round trips per governed call (introspect, authorize, exchange) | Size the fabric for 3× the gateway's call rate |
| Upstream discovery | `tools/list` per server per `definition_ttl_seconds` per replica | Negligible at the default 60 s |

## Scalability

- Horizontal: replicas share nothing but the database; add replicas for CPU.
- Per-agent rate limits are per replica (effective limit = limit × replicas);
  enforce global quotas at the ingress if a hard cap is required.
- Circuit breakers are per replica; each replica probes independently.
- The database is the scaling limit: one audit insert per call. Partitioning
  `audit_events` by `chain_id` and archiving exported events keeps it small.
- Latency budget (gateway overhead, excluding upstream time): fabric round
  trips 3 × (1-10 ms in-cluster), policy evaluation < 2 ms, validation and
  inspection proportional to payload size, audit insert 1-5 ms.

## Risks and tradeoffs

| Tradeoff | Choice | Consequence |
|---|---|---|
| Latency vs revocation freshness | Introspect every request at the fabric | Suspension takes effect on the next call; one extra round trip |
| Upstream load vs drift window | 60 s definition cache | A changed upstream may receive calls for up to 60 s before blocking; set 0 for critical servers |
| False positives vs injection risk | Block on heuristic injection indicators | Some legitimate content is withheld; alerts and reviews tune the detectors |
| Sessions vs scale | Stateless transport | No server-to-client MCP features through the gateway |
| Vendor lock-in | Open protocols (MCP, A2A, OAuth, SPIFFE IDs, JWS), Terraform for three clouds | Swapping cloud or IdP is configuration, not code |
