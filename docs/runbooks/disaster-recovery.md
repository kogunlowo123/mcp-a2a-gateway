# Runbook: disaster recovery

| Component | RPO | RTO | Mechanism |
|---|---|---|---|
| PostgreSQL (registry, approvals, audit chains) | 5 min | 1 h | Multi-AZ / zone-redundant HA; point-in-time recovery (14 days) |
| Archived audit segments | 0 (immutable) | n/a | S3 Object Lock, immutable blobs, retention-locked GCS |
| Gateway pods | n/a | 10 min | Stateless Deployment across three zones |

## Database loss

1. Restore to a new instance with point-in-time recovery to the latest point.
2. Update the database URL secret; External Secrets syncs it; restart the
   Deployment.
3. Verify chains: `GET /v1/audit/verify` per replica, and
   `python -m mcp_a2a_gateway.audit_export export --out /tmp/check`, which
   verifies every chain. Events after the restore point that were already
   exported remain in WORM storage; record the gap in the incident report.

## Region loss

Apply the Terraform root in the recovery region, restore the latest
cross-region backup and deploy the chart with the same values. Register the
gateway in the recovery-region identity fabric if it is a separate instance.
Approvals pending at the time of the loss must be requested again.

## Audit key loss

Generate a new key (startup runbook, step 2) with a new key id. Archived
segments stay verifiable with the old public key (keep it in the auditors'
key set); new chains start under new pod names.
