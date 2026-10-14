"""Authorization: the gateway's own policy combined with the identity fabric's decision.

Both are evaluated for every call by a local agent; the most restrictive
outcome wins (deny > require_approval > allow). A human approval recorded at
the gateway satisfies ``require_approval`` from either source, never a deny.
Federated callers are decided by local policy only: the fabric cannot vouch
for a subject from another trust domain.
"""

from __future__ import annotations

from typing import Any

from agentic_core.domain.classification import DataClassification, Decision, RiskLevel
from agentic_core.policy import PolicyEngine, PolicyRequest, Resource, Subject
from pydantic import BaseModel, ConfigDict, Field

from mcp_a2a_gateway.domain.models import Principal
from mcp_a2a_gateway.domain.ports import IdentityFabricPort


class Target(BaseModel):
    """What a call reaches, with the attributes policy rules may test."""

    model_config = ConfigDict(frozen=True)

    resource_type: str
    resource_id: str
    action: str
    risk: RiskLevel
    classification: DataClassification
    attributes: dict[str, Any] = Field(default_factory=dict)


class AuthorizationOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision: Decision
    reasons: tuple[str, ...]
    local_rules: tuple[str, ...]
    local_policy_digest: str
    fabric_decision: str | None = None
    fabric_rules: tuple[str, ...] = ()
    fabric_policy_digest: str | None = None

    def evidence(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "local_rules": list(self.local_rules),
            "local_policy_digest": self.local_policy_digest,
            "fabric_decision": self.fabric_decision,
            "fabric_rules": list(self.fabric_rules),
            "fabric_policy_digest": self.fabric_policy_digest,
        }


_RANK = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.DENY: 2}


class Authorizer:
    def __init__(self, policy: PolicyEngine, fabric: IdentityFabricPort | None) -> None:
        self._policy = policy
        self._fabric = fabric

    @property
    def policy_digest(self) -> str:
        return self._policy.policy.digest

    async def decide(
        self,
        principal: Principal,
        target: Target,
        *,
        approval_granted: bool,
        environment: dict[str, Any] | None = None,
    ) -> AuthorizationOutcome:
        env = {**(environment or {}), "approval_granted": approval_granted}
        local = self._policy.evaluate(
            PolicyRequest(
                subject=Subject(
                    id=principal.subject,
                    kind="agent",
                    attributes={
                        "scopes": sorted(principal.scopes),
                        "action_in_scope": principal.holds(target.action),
                        "delegated": principal.delegation_depth > 0,
                        "delegation_depth": principal.delegation_depth,
                        "federated": principal.federated,
                        "trust_domain": principal.trust_domain,
                    },
                ),
                action=target.action,
                resource=Resource(
                    type=target.resource_type,
                    id=target.resource_id,
                    classification=target.classification,
                    attributes=target.attributes,
                ),
                risk=target.risk,
                environment=env,
            )
        )
        decision = local.decision
        reasons = [f"gateway policy: {local.reason}"]
        fabric_decision: str | None = None
        fabric_rules: tuple[str, ...] = ()
        fabric_digest: str | None = None

        if self._fabric is not None and principal.authenticated_by == "fabric":
            remote = await self._fabric.authorize(
                principal.token,
                action=target.action,
                resource_type=target.resource_type,
                resource_id=target.resource_id,
                classification=int(target.classification),
                attributes={k: v for k, v in target.attributes.items() if _plain(v)},
                environment=env,
            )
            fabric_decision, fabric_rules = remote.decision, remote.matched_rules
            fabric_digest = remote.policy_digest
            try:
                remote_decision = Decision(remote.decision)
            except ValueError:
                remote_decision = Decision.DENY
            reasons.append(f"identity fabric: {remote.reason or remote.decision}")
            if _RANK[remote_decision] > _RANK[decision]:
                decision = remote_decision

        if decision is Decision.REQUIRE_APPROVAL and approval_granted:
            decision = Decision.ALLOW
            reasons.append("human approval presented")
        return AuthorizationOutcome(
            decision=decision,
            reasons=tuple(reasons),
            local_rules=local.matched_rules,
            local_policy_digest=local.policy_digest,
            fabric_decision=fabric_decision,
            fabric_rules=fabric_rules,
            fabric_policy_digest=fabric_digest,
        )


def _plain(value: Any) -> bool:
    return value is None or isinstance(value, str | int | float | bool)
