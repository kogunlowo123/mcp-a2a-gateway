# Runbook: rollback

## Application

```bash
helm -n mcp-gateway history gateway
helm -n mcp-gateway rollback gateway <revision> --wait
```

The schema is additive within a minor version, so the previous image runs on
the current database. Audit chains continue under new pod names.

## Registry changes

A wrong tool approval is rolled back by revoking that version
(`POST /v1/tools/<server>/<tool>/versions/<v>/revoke`); run discovery again to
create a new draft if the tool should return. A wrong card approval: revoke
the card version. Revocations take effect immediately on every replica,
because registry state lives in the database.

## Policy

`policies/gateway-authorization.yaml` ships in the image; roll back the image
(or the chart revision that set it). The policy digest in each audit event
shows which policy produced each decision.
