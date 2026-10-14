# Runbook: first deployment and startup

## Prerequisites

- Kubernetes ≥ 1.27 with a service-account OIDC issuer (EKS, AKS and GKE
  enable it), External Secrets Operator and a `ClusterSecretStore` named
  `platform-secrets` for the cloud secret manager.
- The [agent identity fabric](https://github.com/kogunlowo123/agent-identity-fabric)
  deployed and reachable from the gateway namespace.
- Enterprise IdP app registration exposing roles `gateway-admin`,
  `gateway-reviewer`, `gateway-approver`, `gateway-auditor`.

## 1. Provision cloud resources

```bash
cd deployments/terraform/aws        # or azure / gcp
terraform init                      # configure an encrypted remote backend first
terraform apply -var-file=<environment>.tfvars
```

Record the outputs: database URL secret name, KMS key, audit bucket and the
audit export workload identity.

## 2. Create the audit signing key

Generate an Ed25519 key outside Terraform (never in state) and store it as
`mcp-a2a-gateway-audit-key-<kid>`:

```bash
openssl genpkey -algorithm ed25519 \
  | aws secretsmanager create-secret --name mcp-a2a-gateway-audit-key-2026-10 \
      --kms-key-id <kms_key_arn> --secret-string file:///dev/stdin
```

Azure: `az keyvault secret set --vault-name <vault> --name mcp-a2a-gateway-audit-key-2026-10 --file /dev/stdin`.
GCP: `gcloud secrets create mcp-a2a-gateway-audit-key-2026-10 --data-file=-`.

Upstream service credentials (only for `static_bearer` upstreams) are stored
as `mcp-a2a-gateway-upstream-<SUFFIX>` and appear in the pod as
`GATEWAY_UPSTREAM_SECRET_<SUFFIX>`.

## 3. Register the gateway in the identity fabric

As a fabric registrar, register the gateway agent with the scopes it may
delegate, bound to its service account and the audience `identity-fabric`:

```json
{
  "namespace": "platform", "name": "mcp-a2a-gateway",
  "display_name": "MCP and A2A gateway",
  "mandate": {"mission": "Governed access to MCP tools and federated agents",
              "business_owner": "ai-platform", "technical_owner": "ai-platform",
              "escalation_contact": "ai-platform-oncall"},
  "scopes": ["mcp:crm:*", "a2a:send:partner-research"],
  "risk": 3, "max_classification": 2,
  "workload": {"issuer": "<cluster OIDC issuer>",
               "subject": "system:serviceaccount:mcp-gateway:mcp-a2a-gateway",
               "audience": "identity-fabric"}
}
```

The fabric intersects every token exchange with these scopes literally, so
list the exact scope strings agents hold for the tools and agents the gateway
fronts.

## 4. Namespace, secrets and chart

```bash
kubectl apply -k deployments/kubernetes
kubectl -n mcp-gateway get externalsecret        # all READY=True
helm upgrade --install gateway oci://ghcr.io/kogunlowo123/charts/mcp-a2a-gateway \
  --version 0.1.0 -n mcp-gateway -f <environment>.yaml --wait
```

`<environment>.yaml` sets every value marked REQUIRED in `values.yaml`
(public URL, trust domain, fabric URL, gateway SPIFFE ID, admin OIDC, egress
allow list, audit key file) plus federated `trustDomains` and, to archive
audit segments, `auditExport.enabled`, `auditExport.bucket` and the export
service account annotation from Terraform.

## 5. Verify

```bash
kubectl -n mcp-gateway rollout status deployment/gateway-mcp-a2a-gateway
kubectl -n mcp-gateway port-forward svc/gateway-mcp-a2a-gateway 8080:80
curl -sf localhost:8080/readyz
curl -s localhost:8080/.well-known/agent-card.json | jq .url
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8080/mcp   # 401
```

## 6. Onboard the first upstream

```bash
curl -X POST "$GW/v1/servers" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' -d @crm-server.json
curl -X POST "$GW/v1/servers/crm/discover" -H "Authorization: Bearer $ADMIN_TOKEN"
# A different person, holding gateway-reviewer:
curl -X POST "$GW/v1/tools/crm/lookup_customer/versions/1/approve" \
  -H "Authorization: Bearer $REVIEWER_TOKEN" -H 'content-type: application/json' \
  -d @lookup-customer-policy.json
```
