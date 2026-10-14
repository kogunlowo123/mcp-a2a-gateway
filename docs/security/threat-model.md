# Threat model

## Assets

| Asset | Impact if compromised |
|---|---|
| Pinned tool and card registry | Agents call attacker-controlled tools or agents |
| Delegated credentials in flight | Replay against upstreams within scope and lifetime |
| Gateway fabric identity and its registered scopes | Delegation on behalf of any agent within those scopes |
| Upstream service credentials (`static_bearer`) | Direct access to upstream systems |
| Approval records | High-risk actions executed without a genuine human decision |
| Audit chains and audit key | Loss of accountability; forged evidence |
| Content flowing through (tool output, A2A responses) | Prompt injection of downstream agents; data leakage |

## Trust boundaries

1. Agents → gateway (`/mcp`, `/a2a`): authenticated but untrusted input.
2. Gateway → upstream MCP servers: untrusted output, possibly malicious definitions.
3. Gateway ↔ partner trust domains: foreign identities, foreign cards, foreign content.
4. Gateway → identity fabric, enterprise IdP, partner JWKS.
5. Gateway → PostgreSQL, secret store, WORM archive.
6. Administrators → registry, lifecycle and approval APIs.

## STRIDE (each threat has an adversarial test in `tests/security/test_gateway_attacks.py`)

| ID | Threat | STRIDE | Control | Test |
|---|---|---|---|---|
| T1 | Upstream replays the agent's token elsewhere (token passthrough) | Spoofing | RFC 8693 delegated token: sub=agent, act=gateway, one scope | `test_t1_agent_token_is_never_passed_through` |
| T2 | Upstream silently changes a tool after approval (rug pull) | Tampering | Pinned definitions served; live digest must match the pin | `test_t2_rug_pull_is_blocked` |
| T3 | Tool description carries instructions to the model (tool poisoning) | Tampering / elevation | Injection scoring at discovery; override with recorded reason | `test_t3_tool_poisoning_cannot_be_approved_silently` |
| T4 | Tool output carries indirect prompt injection | Tampering / elevation | ContentGuard on model-visible output; block | `test_t4_indirect_injection_in_tool_output` |
| T5 | Agent exfiltrates credentials through tool arguments | Information disclosure | Egress DLP (SecretScanner) on arguments and A2A messages | `test_t5_credential_exfiltration_through_arguments` |
| T6 | Registering an upstream that points at internal services (SSRF) | Elevation | HTTPS-only egress host allow list; no redirects | `test_t6_ssrf_targets_are_refused` |
| T7 | Forged or altered agent card; card nominating its own key (`jku`) | Spoofing / tampering | JWS over RFC 8785 canonical card; keys only from the domain JWKS | `test_t7_card_tampering_and_key_substitution` |
| T8 | Card endpoint redirecting traffic outside its domain | Spoofing | Card URL host must be on the domain's `card_hosts` | `test_t8_card_cannot_redirect_traffic_outside_its_domain` |
| T9 | Reading or continuing another agent's task by id (BOLA) | Information disclosure | Task routes bound to creating agent and card | `test_t9_task_ids_are_not_an_access_token` |
| T10 | Approval replay, payload swap, self-approval | Elevation / repudiation | Approval bound to caller, chain, target, payload digest; single use; requester cannot decide | `test_t10_approval_replay_swap_and_self_approval` |
| T11 | Unbounded transitive delegation, partner re-delegated onward | Elevation | Depth + 1 ≤ domain limit; federated callers never exchanged | `test_t11_transitive_delegation_is_bounded` |
| T12 | Partner token with broad scopes | Elevation | Inbound scope ceiling; broader scopes dropped | `test_t12_federated_scopes_cannot_exceed_the_inbound_ceiling` |
| T13 | Partner issuer minting identities in our trust domain | Spoofing | Federated subject must be in the issuing domain | `test_t13_partner_cannot_mint_identities_in_our_domain` |
| T14 | Forged, unsigned, revoked or wrong-audience agent credentials | Spoofing | Fabric introspection (signature, revocation, epochs); audience check | `test_t14_forged_and_unsigned_credentials` |
| T15 | Response flooding to exhaust memory | Denial of service | Byte ceiling on the wire before parsing | `test_t15_response_flooding` |
| T16 | Tampering with stored audit events | Repudiation | Signed hash chain; online verify; verified export to WORM | `test_t16_audit_tampering_is_detected` |
| T17 | Partner agent triggering destructive tools autonomously | Elevation | Approval required for federated callers on destructive tools | `test_t17_destructive_tools_are_not_auto_executed_for_partners` |
| T18 | Case-variant tool names shadowing a reviewed tool | Spoofing | Case-insensitive uniqueness at discovery | `test_t18_case_shadowing_tools_are_rejected` |
| T19 | Fabric, upstream or database outage used to bypass checks | Denial of service | Every dependency fails closed; circuit breakers; audit failure fails the call | `tests/chaos/test_dependency_failures.py` |
| T20 | Flooding the gateway from one agent | Denial of service | Per-agent token bucket, HPA, upstream circuit breakers | `tests/unit/test_mcp_gateway.py::test_rate_limit_per_agent` |

## MITRE ATT&CK (Enterprise)

| Technique | Mitigation |
|---|---|
| T1550.001 Use Alternate Authentication Material: Application Access Token | Delegated tokens bound to one scope and short lifetime; no passthrough |
| T1528 Steal Application Access Token | Agent tokens never leave the gateway; egress DLP on arguments |
| T1078.004 Valid Accounts: Cloud Accounts | Fabric introspection enforces suspension and revocation immediately |
| T1190 Exploit Public-Facing Application | Schema validation, size limits, property-based API fuzzing in CI |
| T1557 Adversary-in-the-Middle | HTTPS-only upstreams and cards; signed cards; pinned endpoints |
| T1565.001 Data Manipulation: Stored Data | Signed audit chain, WORM export |
| T1562.008 Impair Defenses: Disable Cloud Logs | Audit failure fails the call; drift and block alerts |
| T1090 Proxy (abuse of gateway as pivot) | Egress allow list; network policy; no redirects |

## MITRE ATLAS

| Technique | Mitigation |
|---|---|
| AML.T0051.001 LLM Prompt Injection: Indirect | Output inspection on tool results and A2A responses |
| AML.T0051.000 LLM Prompt Injection: Direct (via tool descriptions) | Discovery scoring, pinned definitions, review |
| AML.T0053 LLM Plugin Compromise | Rug-pull defense, allow lists, approval for high-risk tools |
| AML.T0057 LLM Data Leakage | PII redaction, classification ceilings, egress DLP |
| AML.T0010 ML Supply Chain Compromise | Upstream registration behind review; signed agent cards |

## OWASP Top 10 for LLM Applications (2025)

| Risk | Control |
|---|---|
| LLM01 Prompt Injection | Output inspection, definition scoring, pinned definitions |
| LLM02 Sensitive Information Disclosure | PII redaction, egress DLP, classification ceilings, digests instead of payloads in audit |
| LLM03 Supply Chain | Review-gated upstream onboarding, signed cards, SBOM and image scanning |
| LLM05 Improper Output Handling | Output schema validation, injection blocking, upstream error text never relayed |
| LLM06 Excessive Agency | Scoped delegation, allow lists, approval for high-risk and destructive actions, delegation depth caps |
| LLM10 Unbounded Consumption | Rate limits, byte ceilings, timeouts, circuit breakers |

## OWASP API Security Top 10 (2023)

| Risk | Control |
|---|---|
| API1 Broken Object Level Authorization | Task ownership; approvals visible only to their requester; tools invisible without scope |
| API2 Broken Authentication | Fabric introspection; issuer, audience and algorithm checks; RFC 9728 challenge |
| API3 Broken Object Property Level Authorization | `extra="forbid"` on admin inputs; argument schema validation |
| API4 Unrestricted Resource Consumption | Byte and argument limits, paging limits, rate limits, HPA |
| API5 Broken Function Level Authorization | Distinct admin roles; separation of duties for approvals |
| API6 Unrestricted Access to Sensitive Business Flows | Human approval for high-risk calls |
| API7 Server Side Request Forgery | Egress host allow lists for upstreams, cards and card endpoints |
| API8 Security Misconfiguration | Production refuses ephemeral keys and insecure upstreams; Helm `required` values; restricted Pod Security |
| API10 Unsafe Consumption of APIs | Upstream and remote responses size-capped, schema-validated, inspected |

## Risk register

| ID | Risk | Likelihood | Impact | Owner | Treatment | Residual |
|---|---|---|---|---|---|---|
| R1 | Heuristic injection detection misses a novel phrasing | Medium | High | AI Security | Layered with pinning, allow lists, approvals, delegation limits; detector extensible via agentic-core `extra_signals` | Medium |
| R2 | False positives block legitimate tool output | Medium | Medium | Platform | Alerts on block spikes; per-tool PII setting; review of detector rules | Low |
| R3 | Gateway fabric identity compromised | Low | High | Security Ops | Workload-attested credential, 10-minute TTL, registration scopes as ceiling, fabric suspension | Low |
| R4 | Upstream changes within the drift-cache window | Medium | Medium | Platform | `definition_ttl_seconds` (0 for critical servers), drift alert | Low |
| R5 | PostgreSQL outage stops all calls (audit fail-closed) | Low | High | Platform | Multi-AZ, PITR, readiness probe, DR runbook | Low |
| R6 | Delegated tokens use the platform audience (fabric v0.1.0 lacks RFC 8707 resource) | Medium | Medium | Identity team | Single scope, short TTL, upstreams introspect; adopt resource indicators when the fabric supports them | Medium |
| R7 | Approver fatigue rubber-stamps requests | Medium | High | Business owners | Redacted payload preview, reasons recorded, approval metrics | Medium |
| R8 | Inspection CPU cost on large responses | Medium | Low | Platform | Byte ceilings (default 1 MiB), HPA on CPU | Low |
