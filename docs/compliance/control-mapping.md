# Compliance control mapping

The evidence column names the artifact an auditor can inspect. HIPAA and GxP
columns apply when tools behind the gateway touch PHI or GxP records.

| Control objective | HIPAA Security Rule | SOC 2 (TSC 2017) | ISO/IEC 27001:2022 | NIST SP 800-53 r5 | NIST AI RMF 1.0 | 21 CFR Part 11 / GxP | Evidence |
|---|---|---|---|---|---|---|---|
| Unique, attested identity for every caller | 164.312(a)(2)(i), 164.312(d) | CC6.1 | 5.16, 5.17 | IA-2, IA-9 | GOVERN 1.4 | 11.10(d), 11.300 | Fabric introspection; `authenticated_by` and subject in every audit event |
| Least privilege for tool and agent access | 164.308(a)(4) | CC6.3 | 5.15, 8.2 | AC-6, AC-3 | MANAGE 2.4 | 11.10(g) | Tool policies (allow lists, risk, classification), scopes, `policies/gateway-authorization.yaml` |
| Bounded, attributable delegation | 164.308(a)(3) | CC6.2 | 5.18 | AC-6(9), AU-10 | GOVERN 2.1 | 11.10(g) | `act` chains in delegated tokens and audit events; depth rule in policy |
| Change control for tools and agents reachable by AI | 164.308(a)(8) | CC8.1 | 8.32 | CM-3, CM-5 | MAP 4.1, MANAGE 3.1 | 11.10(k) | Draft → approved lifecycle, discoverer ≠ reviewer, pinned hashes, discovery reports |
| Supply chain integrity of third-party tools and partner agents | — | CC9.2 | 5.19, 5.21 | SR-3, SR-11 | MAP 4.1 | — | Signed agent cards, trust-domain allow lists, definition drift alerts, SBOM |
| Human oversight of high-risk actions | — | CC5.2 | 5.2 | AC-3(2) | GOVERN 3.2, MANAGE 2.3 | 11.10(f), 11.200 | Approval records bound to payload digest, approver identity and reason |
| Protection of sensitive data in transit through agents | 164.312(e)(1) | C1.1 | 8.11, 8.12 | SC-8, SI-4 | MEASURE 2.10 | — | PII redaction, egress DLP, classification ceilings, HTTPS-only egress |
| Defense against adversarial inputs to AI | — | CC7.1 | 8.7 | SI-3, SI-10 | MEASURE 2.7 | — | Output inspection, definition scoring, schema validation, threat tests T1-T18 |
| Audit trail integrity and retention | 164.312(b) | CC7.2 | 8.15 | AU-9, AU-10, AU-11 | MEASURE 2.8 | 11.10(e) | Signed per-replica chains, `/v1/audit/verify`, WORM export manifests |
| Monitoring and incident response | 164.308(a)(6) | CC7.3, CC7.4 | 5.24, 5.26 | IR-4, SI-4 | MANAGE 4.1 | — | `configs/prometheus/alerts.yaml`, incident runbook |
| Availability and recovery | 164.308(a)(7) | A1.2 | 8.14 | CP-9, CP-10 | — | — | Multi-AZ database, PDB, HPA, DR runbook |
| Secure configuration and vulnerability management | 164.308(a)(1) | CC7.1 | 8.8, 8.9 | CM-6, RA-5 | — | — | CI: bandit, Semgrep, Trivy (config and image), Grype, pip-audit; restricted Pod Security |

GxP: for computerized-system validation, the CI run for the deployed tag is
OQ evidence for the acceptance criteria in `docs/architecture/overview.md`;
discovery reports and approval records document configuration changes to the
validated state (which tools and agents are reachable), and the signed audit
chain provides attributable, time-stamped records of every AI-initiated
action.
