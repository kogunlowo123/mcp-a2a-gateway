"""A2A federation: route ``message/send`` and task operations to approved remote agents.

The caller's credential never leaves the trust domain. For each hop the
gateway asks the identity fabric for an RFC 8693 delegated credential
(subject = calling agent, actor = gateway) narrowed to the one scope that
authorizes the target agent, after checking the caller's delegation depth
against the remote trust domain's limit. Federated callers cannot be routed
onward to another trust domain. Remote responses are inspected as untrusted
content before they reach the calling agent.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable
from typing import Any

from agentic_core.domain.classification import Decision
from agentic_core.domain.provenance import canonical_json, content_digest

from mcp_a2a_gateway.application.approvals import ApprovalService
from mcp_a2a_gateway.application.audit import AuditRecorder
from mcp_a2a_gateway.application.authorization import Authorizer, Target
from mcp_a2a_gateway.application.credentials import UpstreamCredentials
from mcp_a2a_gateway.application.directory import AgentDirectory
from mcp_a2a_gateway.application.mcp_gateway import APPROVAL_META_KEY, PURPOSE_META_KEY
from mcp_a2a_gateway.domain.errors import (
    RPC_TASK_NOT_FOUND,
    ContentBlockedError,
    ForbiddenError,
    GatewayError,
    NotFoundError,
    UpstreamError,
    ValidationFailedError,
)
from mcp_a2a_gateway.domain.models import AgentCardVersion, ApprovalKind, Principal, matches_any
from mcp_a2a_gateway.domain.ports import Clock, RemoteAgentPort, TaskRouteRepository
from mcp_a2a_gateway.observability.metrics import GatewayMetrics
from mcp_a2a_gateway.security.inspection import ContentInspector, a2a_text_fields
from mcp_a2a_gateway.security.resilience import CircuitBreaker, RateLimiter

TARGET_KEY = "mcp-a2a-gateway/target-agent"
SKILL_KEY = "mcp-a2a-gateway/skill"
GATEWAY_KEYS = frozenset({TARGET_KEY, SKILL_KEY, APPROVAL_META_KEY, PURPOSE_META_KEY})


class TaskNotFoundError(NotFoundError):
    code = "task_not_found"
    rpc_code = RPC_TASK_NOT_FOUND


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _strip(metadata: Any) -> dict[str, Any] | None:
    kept = {k: v for k, v in _dict(metadata).items() if k not in GATEWAY_KEYS}
    return kept or None


def _without_none(value: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in value.items() if v is not None}


class A2AFederation:
    def __init__(
        self,
        *,
        directory: AgentDirectory,
        remote: RemoteAgentPort,
        authorizer: Authorizer,
        approvals: ApprovalService,
        credentials: UpstreamCredentials,
        inspector: ContentInspector,
        tasks: TaskRouteRepository,
        audit: AuditRecorder,
        metrics: GatewayMetrics,
        limiter: RateLimiter,
        breaker: CircuitBreaker,
        clock: Clock,
        max_response_bytes: int,
    ) -> None:
        self._directory = directory
        self._remote = remote
        self._authorizer = authorizer
        self._approvals = approvals
        self._credentials = credentials
        self._inspector = inspector
        self._tasks = tasks
        self._audit = audit
        self._metrics = metrics
        self._limiter = limiter
        self._breaker = breaker
        self._clock = clock
        self._max_response_bytes = max_response_bytes

    async def _card(self, principal: Principal, card_id: str) -> AgentCardVersion:
        record = await self._directory.servable(card_id)
        if record is None or record.policy is None or not principal.holds(record.action):
            raise NotFoundError(f"unknown agent {card_id}")
        return record

    def _target(self, principal: Principal, record: AgentCardVersion, skill: str | None) -> Target:
        policy = record.policy
        if policy is None:  # pragma: no cover - servable cards always carry a policy
            raise ForbiddenError("agent card has no approval policy")
        domain = self._directory.domain(record.trust_domain).config
        ceiling = domain.max_classification
        if principal.federated:
            caller_domain = self._directory.domain(principal.trust_domain).config
            ceiling = min(ceiling, caller_domain.max_classification)
        past_sunset = record.sunset_at is not None and record.sunset_at <= self._clock.now()
        return Target(
            resource_type="a2a_agent",
            resource_id=record.card_id,
            action=record.action,
            risk=policy.risk,
            classification=policy.classification,
            attributes={
                "trust_domain": record.trust_domain,
                "lifecycle": record.status.value,
                "version": record.version,
                "skill": skill,
                "allow_listed": matches_any(principal.subject, policy.allowed_callers),
                "past_sunset": past_sunset,
                "destructive": False,
                "requires_approval": policy.requires_approval,
                "within_caller_ceiling": policy.classification <= ceiling,
                # The hop adds the gateway to the chain.
                "delegation_within_limit": principal.delegation_depth + 1
                <= domain.max_delegation_depth,
            },
        )

    async def _authorize(
        self,
        principal: Principal,
        record: AgentCardVersion,
        skill: str | None,
        payload: Any,
        metadata: dict[str, Any],
    ) -> tuple[str | None, dict[str, Any]]:
        approval_id = metadata.get(APPROVAL_META_KEY)
        approval = None
        if isinstance(approval_id, str) and approval_id:
            approval = await self._approvals.verify(
                approval_id, principal=principal, target=record.card_id, payload=payload
            )
        purpose = metadata.get(PURPOSE_META_KEY)
        environment = {"purpose_of_use": purpose} if isinstance(purpose, str) and purpose else {}
        outcome = await self._authorizer.decide(
            principal,
            self._target(principal, record, skill),
            approval_granted=approval is not None,
            environment=environment,
        )
        self._metrics.authorization.labels("a2a", outcome.decision.value).inc()
        if outcome.decision is Decision.DENY:
            raise ForbiddenError(
                "; ".join(outcome.reasons), data={"rule": ",".join(outcome.local_rules)}
            )
        if outcome.decision is Decision.REQUIRE_APPROVAL:
            raise await self._approvals.request(
                kind=ApprovalKind.A2A_MESSAGE,
                principal=principal,
                target=record.card_id,
                action=record.action,
                payload=payload,
                reasons=outcome.reasons,
            )
        if approval is not None:
            await self._approvals.consume(approval)
        return (approval.approval_id if approval else None), outcome.evidence()

    async def _forward(
        self, principal: Principal, record: AgentCardVersion, method: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        token = await self._credentials.delegate(principal, record.action)
        key = f"a2a:{record.card_id}"
        self._breaker.before(key)
        try:
            result = await self._remote.call(
                str(record.card.url),
                method,
                params,
                token=token,
                max_response_bytes=self._max_response_bytes,
            )
        except UpstreamError as exc:
            self._breaker.failure(key)
            self._metrics.upstream_errors.labels(key, exc.code).inc()
            raise
        except BaseException:
            self._breaker.release(key)
            raise
        self._breaker.success(key)
        policy = record.policy
        verdict, cleaned = self._inspector.inspect_projected(
            result, a2a_text_fields, redact_pii=policy.redact_pii if policy else True
        )
        if verdict.blocked:
            self._metrics.output_blocked.labels(key, "inspection").inc()
            raise ContentBlockedError(
                "remote agent response blocked by content inspection",
                data={"kinds": list(verdict.kinds)},
            )
        if not isinstance(cleaned, dict):  # pragma: no cover - projection preserves shape
            raise UpstreamError("remote agent response changed shape")
        return cleaned

    async def _audited(
        self,
        principal: Principal,
        method: str,
        resource: str,
        run: Awaitable[tuple[dict[str, Any], dict[str, Any]]],
    ) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            result, details = await run
        except GatewayError as exc:
            self._metrics.a2a_messages.labels(method, exc.code).inc()
            await self._audit.record(
                principal.subject,
                f"a2a.{method}",
                resource,
                exc.code,
                {
                    "chain": list(principal.delegation_chain),
                    "authenticated_by": principal.authenticated_by,
                    "error": exc.message,
                    **{k: v for k, v in exc.data.items() if k in {"approval_id", "rule"}},
                },
            )
            raise
        self._metrics.a2a_messages.labels(method, "success").inc()
        self._metrics.a2a_latency.observe(time.perf_counter() - started)
        await self._audit.record(
            principal.subject,
            f"a2a.{method}",
            resource,
            "success",
            {
                "chain": list(principal.delegation_chain),
                "authenticated_by": principal.authenticated_by,
                **details,
            },
        )
        return result

    # ---------------------------------------------------------------- operations

    async def send_message(self, principal: Principal, params: dict[str, Any]) -> dict[str, Any]:
        message = params.get("message")
        if not isinstance(message, dict):
            raise ValidationFailedError("params.message is required")
        metadata = {**_dict(message.get("metadata")), **_dict(params.get("metadata"))}
        card_id = metadata.get(TARGET_KEY)
        if not isinstance(card_id, str):
            raise ValidationFailedError(f"metadata[{TARGET_KEY!r}] must name the target agent")
        return await self._audited(
            principal, "message/send", card_id, self._send(principal, params, message, metadata)
        )

    async def _send(
        self,
        principal: Principal,
        params: dict[str, Any],
        message: dict[str, Any],
        metadata: dict[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        self._limiter.acquire(principal.subject)
        card_id = str(metadata[TARGET_KEY])
        record = await self._card(principal, card_id)
        policy = record.policy
        skill = metadata.get(SKILL_KEY)
        skills = {s.id for s in record.card.skills}
        if skill is not None:
            if not isinstance(skill, str) or skill not in skills:
                raise ValidationFailedError(f"agent {card_id} has no skill {skill!r}")
            if policy and policy.allowed_skills and skill not in policy.allowed_skills:
                raise ForbiddenError(f"skill {skill} is not approved for federation")
        elif policy and policy.allowed_skills:
            raise ValidationFailedError(f"metadata[{SKILL_KEY!r}] is required for {card_id}")

        task_id = message.get("taskId")
        if task_id is not None:
            route = await self._tasks.lookup(str(task_id))
            if route != (card_id, principal.subject):
                raise TaskNotFoundError(f"task {task_id} not found")

        forwarded_message = _without_none({**message, "metadata": _strip(message.get("metadata"))})
        forwarded = _without_none(
            {**params, "message": forwarded_message, "metadata": _strip(params.get("metadata"))}
        )
        egress = self._inspector.scan_egress(forwarded["message"])
        if egress.blocked:
            raise ContentBlockedError(
                "message contains credential material", data={"kinds": list(egress.kinds)}
            )
        approval_id, evidence = await self._authorize(
            principal, record, skill if isinstance(skill, str) else None, forwarded, metadata
        )
        result = await self._forward(principal, record, "message/send", forwarded)
        kind = result.get("kind")
        if kind not in {"task", "message"}:
            raise UpstreamError("remote agent returned neither a task nor a message")
        if kind == "task" and isinstance(result.get("id"), str):
            await self._tasks.remember(
                result["id"], card_id=card_id, owner=principal.subject, at=self._clock.now()
            )
        return result, {
            "card_version": record.version,
            "card_digest": record.card_digest,
            "skill": skill,
            "message_digest": content_digest(canonical_json(forwarded["message"])),
            "result_kind": kind,
            "approval_id": approval_id,
            **evidence,
        }

    async def task_operation(
        self, principal: Principal, method: str, params: dict[str, Any]
    ) -> dict[str, Any]:
        """``tasks/get`` and ``tasks/cancel``: only the agent that created a task may reach it."""
        task_id = params.get("id")
        if not isinstance(task_id, str) or not task_id:
            raise ValidationFailedError("params.id is required")
        return await self._audited(
            principal, method, task_id, self._task(principal, method, task_id, params)
        )

    async def _task(
        self, principal: Principal, method: str, task_id: str, params: dict[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        self._limiter.acquire(principal.subject)
        route = await self._tasks.lookup(task_id)
        if route is None or route[1] != principal.subject:
            raise TaskNotFoundError(f"task {task_id} not found")
        record = await self._card(principal, route[0])
        forwarded = {k: v for k, v in params.items() if k != "metadata"}
        _, evidence = await self._authorize(principal, record, None, forwarded, {})
        result = await self._forward(principal, record, method, forwarded)
        return result, {"card_id": record.card_id, "card_version": record.version, **evidence}

    async def extended_skills(self, principal: Principal) -> list[dict[str, Any]]:
        skills: list[dict[str, Any]] = []
        for record in await self._directory.catalog(principal):
            allowed = set(record.policy.allowed_skills) if record.policy else set()
            for skill in record.card.skills:
                if allowed and skill.id not in allowed:
                    continue
                skills.append(
                    {
                        "id": f"{record.card_id}/{skill.id}",
                        "name": f"{record.card.name}: {skill.name}",
                        "description": skill.description,
                        "tags": [*skill.tags, f"trust-domain:{record.trust_domain}"],
                    }
                )
        return skills
