"""Audit recording with correlation IDs. A failed write fails the operation."""

from __future__ import annotations

from typing import Any

from agentic_core.audit import AuditLog
from agentic_core.observability import correlation_id


class AuditRecorder:
    def __init__(self, log: AuditLog) -> None:
        self._log = log

    async def record(
        self, actor: str, action: str, resource: str, outcome: str, details: dict[str, Any]
    ) -> None:
        await self._log.record(
            actor=actor,
            action=action,
            resource=resource,
            outcome=outcome,
            correlation_id=correlation_id(),
            details=details,
        )
