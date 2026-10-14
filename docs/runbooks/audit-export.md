# Runbook: audit export to WORM storage

The chart's optional CronJob (`auditExport.enabled`) runs hourly:

1. **export** (gateway image):
   `python -m mcp_a2a_gateway.audit_export export --out /export` verifies every
   chain end to end and writes the events after the last archived sequence as
   `<chain>-<first>-<last>.jsonl` plus a manifest with the SHA-256, sequence
   range and head hash. A chain that fails verification is not written, and
   the job fails.
2. **upload** (uploader image): copies `/export` to the WORM bucket
   (`s3://<bucket>/audit-segments/` by default; Object Lock compliance mode
   applies the retention).
3. **commit** (gateway image): records each manifest's last sequence in
   `audit_exports`. It runs only if the upload succeeded, so a failed upload is
   retried in the next hour.

## Azure and GCP uploaders

```yaml
auditExport:
  uploader:
    image: mcr.microsoft.com/azure-cli:<pinned tag>
    command:
      - /bin/sh
      - -c
      - az login --federated-token "$(cat $AZURE_FEDERATED_TOKEN_FILE)" --service-principal -u "$AZURE_CLIENT_ID" -t "$AZURE_TENANT_ID" && az storage blob upload-batch --auth-mode login --account-name <account> -d audit-segments -s /export
```

```yaml
auditExport:
  uploader:
    image: gcr.io/google.com/cloudsdktool/google-cloud-cli:<pinned tag>-slim
    command:
      - /bin/sh
      - -c
      - gcloud storage cp /export/* "gs://${AUDIT_BUCKET}/audit-segments/"
```

## Verifying archived segments

1. `sha256sum <file>.jsonl` equals the manifest's `sha256`.
2. Segments link: the first event's `prev_hash` equals the previous segment's
   `head_hash`.
3. A complete chain (all segments of one chain id, in order) verifies with
   `agentic_core.audit.verify_chain(events, {key_id: audit_public_key})`.

## Manual run

```bash
kubectl -n mcp-gateway create job \
  --from=cronjob/gateway-mcp-a2a-gateway-audit-export audit-export-manual
```
