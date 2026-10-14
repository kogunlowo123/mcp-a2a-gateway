"""Human approval of individual high-risk calls.

An approval is bound to the requesting agent, its delegation chain, the
target, the action and the SHA-256 digest of the exact payload. It expires,
can be used once, and cannot be decided by the agent that requested it.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import Any

from agentic_core.domain.identifiers import new_id
from agentic_core.domain.provenance import canonical_json, content_digest
from agentic_core.security import PiiDetector, SecretScanner

from mcp_a2a_gateway.application.audit import AuditRecorder
from mcp_a2a_gateway.domain.errors import (
    ApprovalRequiredError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
)
from mcp_a2a_gateway.domain.models import (
    ApprovalKind,
    ApprovalRequest,
    ApprovalStatus,
    Principal,
)
from mcp_a2a_gateway.domain.ports import ApprovalRepository, Clock

PREVIEW_CHARS = 2000


def payload_digest(payload: Any) -> str:
    return content_digest(canonical_json(payload))


class ApprovalService:
    def __init__(
        self,
        *,
        repository: ApprovalRepository,
        audit: AuditRecorder,
        clock: Clock,
        ttl: timedelta,
    ) -> None:
        self._repo = repository
        self._audit = audit
        self._clock = clock
        self._ttl = ttl
        self._pii = PiiDetector()
        self._secrets = SecretScanner()

    def _preview(self, payload: Any) -> str:
        text = canonical_json(payload).decode()
        text, _ = self._secrets.redact(text)
        text, _ = self._pii.redact(text)
        return text if len(text) <= PREVIEW_CHARS else text[:PREVIEW_CHARS] + "...[truncated]"

    async def request(
        self,
        *,
        kind: ApprovalKind,
        principal: Principal,
        target: str,
        action: str,
        payload: Any,
        reasons: tuple[str, ...],
    ) -> ApprovalRequiredError:
        now = self._clock.now()
        approval = ApprovalRequest(
            approval_id=new_id(),
            kind=kind,
            requester=principal.subject,
            delegation_chain=principal.delegation_chain,
            target=target,
            action=action,
            payload_digest=payload_digest(payload),
            payload_preview=self._preview(payload),
            reasons=reasons,
            requested_at=now,
            expires_at=now + self._ttl,
        )
        await self._repo.add(approval)
        await self._audit.record(
            principal.subject,
            "approval.request",
            approval.approval_id,
            "pending",
            {"target": target, "action": action, "payload_digest": approval.payload_digest},
        )
        return ApprovalRequiredError(
            f"{action} requires human approval",
            approval_id=approval.approval_id,
            expires_at=approval.expires_at.isoformat(),
        )

    async def verify(
        self, approval_id: str, *, principal: Principal, target: str, payload: Any
    ) -> ApprovalRequest:
        """Check that ``approval_id`` authorizes exactly this call. Does not consume it."""
        approval = await self._repo.get(approval_id)
        if approval is None or approval.requester != principal.subject:
            raise ForbiddenError("approval not found for this caller")
        if approval.delegation_chain != principal.delegation_chain:
            raise ForbiddenError("approval was granted to a different delegation chain")
        if approval.target != target or approval.payload_digest != payload_digest(payload):
            raise ForbiddenError("approval does not match this call's target or payload")
        if self._clock.now() >= approval.expires_at:
            raise ForbiddenError("approval has expired")
        if approval.status is ApprovalStatus.PENDING:
            raise ApprovalRequiredError(
                "approval is still pending",
                approval_id=approval.approval_id,
                expires_at=approval.expires_at.isoformat(),
            )
        if approval.status is not ApprovalStatus.APPROVED:
            raise ForbiddenError(f"approval is {approval.status}")
        return approval

    async def consume(self, approval: ApprovalRequest) -> None:
        if not await self._repo.consume(approval.approval_id, at=self._clock.now()):
            raise ForbiddenError("approval has already been used")

    async def decide(
        self, approval_id: str, *, approve: bool, actor: str, reason: str
    ) -> ApprovalRequest:
        approval = await self.get(approval_id)
        if approval.status is not ApprovalStatus.PENDING:
            raise InvalidStateError(f"approval is already {approval.status}")
        now = self._clock.now()
        if now >= approval.expires_at:
            raise InvalidStateError("approval request has expired")
        if actor == approval.requester or actor in approval.delegation_chain:
            raise ForbiddenError("the requesting agent cannot decide its own approval")
        decided = approval.model_copy(
            update={
                "status": ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED,
                "decided_by": actor,
                "decided_at": now,
                "decision_reason": reason,
            }
        )
        await self._repo.update(decided)
        await self._audit.record(
            actor,
            "approval.decide",
            approval_id,
            decided.status.value,
            {"target": approval.target, "action": approval.action, "reason": reason},
        )
        return decided

    async def status_for(self, approval_id: str, *, principal: Principal) -> ApprovalRequest:
        """An agent may read the status of approvals it requested, and nothing else."""
        approval = await self._repo.get(approval_id)
        if approval is None or approval.requester != principal.subject:
            raise NotFoundError("approval not found")
        await self._audit.record(
            principal.subject, "approval.status", approval_id, approval.status.value, {}
        )
        return approval

    async def get(self, approval_id: str) -> ApprovalRequest:
        approval = await self._repo.get(approval_id)
        if approval is None:
            raise NotFoundError(f"approval {approval_id} not found")
        return approval

    async def list(self, *, status: ApprovalStatus | None, limit: int) -> Sequence[ApprovalRequest]:
        return await self._repo.list(status=status, limit=limit)
