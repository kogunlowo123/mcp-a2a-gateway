# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [0.1.0] - 2026-10-14

### Added

- MCP gateway on the official SDK (`MCPServer`, stateless Streamable HTTP),
  serving the pinned, entitled tool catalog to each agent; both protocol eras.
- Upstream server registration behind an egress allow list; discovery with
  SHA-256 definition pinning, injection scoring of tool text, and a
  draft/approved/deprecated/revoked lifecycle with separation of duties.
- Governed call pipeline: rate limits, schema and size validation, egress DLP,
  gateway policy combined with the identity fabric decision, payload-bound
  single-use human approvals, live drift checks, RFC 8693 delegated
  credentials, byte-limited upstream calls with circuit breakers, output
  inspection and output-schema validation.
- A2A gateway: Agent Card, JSON-RPC `message/send`, `tasks/get`,
  `tasks/cancel`, authenticated extended card; signed and pinned agent card
  registry per trust domain; per-hop delegation with depth limits; inbound
  federation with scope ceilings; task ownership.
- Signed per-replica audit chains in PostgreSQL, online verification and
  verified incremental export for WORM archival.
- Card signing CLI (`python -m mcp_a2a_gateway.cardsign`).
- Helm chart (Deployment, HPA, PDB, NetworkPolicy, ServiceMonitor, optional
  audit export CronJob), Kubernetes namespace and secret sync, Terraform for
  AWS, Azure and GCP.
- CI: lint, types, SAST, contract drift, unit/security/chaos/performance/e2e
  tests, PostgreSQL integration, Helm/kubeconform, Terraform validate, Trivy,
  Syft, Grype, Semgrep, container smoke test; release with provenance and SBOM.
