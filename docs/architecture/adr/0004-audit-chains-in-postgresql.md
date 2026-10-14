# ADR-0004: Per-replica signed audit chains stored in PostgreSQL

- Status: Accepted
- Date: 2026-10-14

## Context

The agentic-core audit chain is append-serialized per writer. The identity
fabric keeps one chain per replica on a per-pod volume (StatefulSet). The
gateway's transport is stateless and should scale as a Deployment.

## Decision

Implement the agentic-core `AuditSink` protocol over PostgreSQL
(`audit_events`, primary key `(chain_id, sequence)`), with the pod name as
chain id. A second writer on the same chain id fails on insert instead of
forking the chain. `GET /v1/audit/verify` verifies a chain online; the
`audit_export` job exports verified segments hourly and uploads them to WORM
storage (S3 Object Lock, immutable blobs, retention-locked GCS), committing
its position only after a successful upload.

## Consequences

- No per-replica volumes; replicas are interchangeable.
- Audit writes share the database's availability; an audit failure fails the
  call (fail closed), so the database SLO bounds the gateway SLO.
- Chains accumulate per pod name over time; auditors verify each chain
  independently and correlate across chains with correlation IDs.
- The database is not WORM; tamper evidence comes from signatures and hash
  links, and immutability from the export. Verification before export means a
  tampered chain is never archived as if it were genuine.
