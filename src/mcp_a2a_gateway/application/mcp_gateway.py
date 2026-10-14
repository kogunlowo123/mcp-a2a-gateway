"""Governed MCP tool calls.

For every ``tools/call`` the gateway, in order: rate-limits the caller,
resolves the pinned tool version, bounds and validates the arguments against
the pinned input schema, blocks credential material leaving in arguments,
authorizes (gateway policy + identity fabric, with human approval for
high-risk calls), confirms the upstream still serves the pinned definition,
obtains a narrowly scoped delegated credential, calls the upstream with a
byte ceiling behind a circuit breaker, inspects the output (prompt injection,
credentials, PII, pinned output schema) and records the outcome in the
signed audit chain. Any failure stops the call.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agentic_core.domain.classification import DataClassification, Decision
from agentic_core.domain.provenance import canonical_json, content_digest
from jsonschema import Draft202012Validator, FormatChecker
from pydantic import BaseModel, ConfigDict

from mcp_a2a_gateway.application.approvals import ApprovalService
from mcp_a2a_gateway.application.audit import AuditRecorder
from mcp_a2a_gateway.application.authorization import Authorizer, Target
from mcp_a2a_gateway.application.credentials import UpstreamCredentials
from mcp_a2a_gateway.application.registry import ToolRegistry
from mcp_a2a_gateway.domain.errors import (
    ContentBlockedError,
    DefinitionDriftError,
    ForbiddenError,
    GatewayError,
    NotFoundError,
    UpstreamError,
    ValidationFailedError,
)
from mcp_a2a_gateway.domain.models import (
    ApprovalKind,
    Lifecycle,
    Principal,
    ToolVersion,
    UpstreamServer,
    matches_any,
    split_exposed_name,
)
from mcp_a2a_gateway.domain.ports import Clock, UpstreamMcpPort, UpstreamToolCall
from mcp_a2a_gateway.observability.metrics import GatewayMetrics
from mcp_a2a_gateway.security.inspection import ContentInspector, mcp_text_fields
from mcp_a2a_gateway.security.resilience import CircuitBreaker, RateLimiter

APPROVAL_META_KEY = "mcp-a2a-gateway/approval-id"
PURPOSE_META_KEY = "mcp-a2a-gateway/purpose-of-use"


class ToolCallResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    content: list[dict[str, Any]]
    structured_content: dict[str, Any] | None = None
    is_error: bool = False
    tool: str
    version: int
    definition_hash: str
    redactions: int = 0


@dataclass
class _Snapshot:
    digests: dict[str, str]
    fetched_at: float


class LiveDefinitions:
    """Cached digests of what each upstream currently advertises, for drift checks."""

    def __init__(
        self,
        *,
        upstream: UpstreamMcpPort,
        credentials: UpstreamCredentials,
        ttl_s: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._upstream = upstream
        self._credentials = credentials
        self._ttl = ttl_s
        self._clock = clock
        self._cache: dict[str, _Snapshot] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    def invalidate(self, server_id: str) -> None:
        self._cache.pop(server_id, None)

    async def digest(self, server: UpstreamServer, name: str) -> str | None:
        lock = self._locks.setdefault(server.server_id, asyncio.Lock())
        async with lock:
            snapshot = self._cache.get(server.server_id)
            if snapshot is None or self._clock() - snapshot.fetched_at >= self._ttl:
                token = await self._credentials.for_gateway(server)
                live = await self._upstream.list_tools(server, token=token)
                snapshot = _Snapshot({d.name: d.digest() for d in live}, self._clock())
                self._cache[server.server_id] = snapshot
            return snapshot.digests.get(name)


class McpGateway:
    def __init__(
        self,
        *,
        registry: ToolRegistry,
        upstream: UpstreamMcpPort,
        live: LiveDefinitions,
        credentials: UpstreamCredentials,
        authorizer: Authorizer,
        approvals: ApprovalService,
        inspector: ContentInspector,
        audit: AuditRecorder,
        metrics: GatewayMetrics,
        limiter: RateLimiter,
        breaker: CircuitBreaker,
        clock: Clock,
        max_argument_bytes: int,
        federation_ceilings: dict[str, DataClassification] | None = None,
    ) -> None:
        self._registry = registry
        self._upstream = upstream
        self._live = live
        self._credentials = credentials
        self._authorizer = authorizer
        self._approvals = approvals
        self._inspector = inspector
        self._audit = audit
        self._metrics = metrics
        self._limiter = limiter
        self._breaker = breaker
        self._clock = clock
        self._max_argument_bytes = max_argument_bytes
        self._federation_ceilings = federation_ceilings or {}

    # ------------------------------------------------------------------ catalog

    def _visible(self, tool: ToolVersion, principal: Principal) -> bool:
        if tool.policy is None or not principal.holds(tool.action):
            return False
        if tool.sunset_at is not None and tool.sunset_at <= self._clock.now():
            return False
        return matches_any(principal.subject, tool.policy.allowed_agents)

    async def catalog(self, principal: Principal) -> list[ToolVersion]:
        """Tools this caller may see: servable, enabled server, allow-listed, in scope."""
        enabled = {s.server_id for s in await self._registry.servers() if s.enabled}
        visible = [
            tool
            for status in (Lifecycle.APPROVED, Lifecycle.DEPRECATED)
            for tool in await self._registry.tools(status=status)
            if tool.server_id in enabled and self._visible(tool, principal)
        ]
        return sorted(visible, key=lambda t: t.exposed_name)

    # --------------------------------------------------------------------- call

    def _target(self, tool: ToolVersion, principal: Principal) -> Target:
        policy = tool.policy
        if policy is None:  # pragma: no cover - servable versions always carry a policy
            raise ForbiddenError("tool has no approval policy")
        ceiling = (
            self._federation_ceilings.get(principal.trust_domain, DataClassification.PUBLIC)
            if principal.federated
            else DataClassification.RESTRICTED
        )
        past_sunset = tool.sunset_at is not None and tool.sunset_at <= self._clock.now()
        return Target(
            resource_type="mcp_tool",
            resource_id=tool.exposed_name,
            action=tool.action,
            risk=policy.risk,
            classification=policy.classification,
            attributes={
                "server": tool.server_id,
                "lifecycle": tool.status.value,
                "version": tool.version,
                "allow_listed": matches_any(principal.subject, policy.allowed_agents),
                "past_sunset": past_sunset,
                "destructive": tool.definition.destructive,
                "requires_approval": policy.requires_approval,
                "within_caller_ceiling": policy.classification <= ceiling,
                "delegation_within_limit": True,
            },
        )

    def _validate_arguments(self, tool: ToolVersion, arguments: dict[str, Any]) -> None:
        size = len(canonical_json(arguments))
        if size > self._max_argument_bytes:
            raise ValidationFailedError(
                f"arguments are {size} bytes; the limit is {self._max_argument_bytes}"
            )
        validator = Draft202012Validator(
            tool.definition.input_schema, format_checker=FormatChecker()
        )
        errors = sorted(validator.iter_errors(arguments), key=lambda e: list(e.absolute_path))
        if errors:
            # Paths and validator names only: the rejected values are the caller's data.
            raise ValidationFailedError(
                "arguments do not match the pinned input schema",
                data={
                    "violations": [
                        {"path": "/".join(str(p) for p in e.absolute_path), "rule": e.validator}
                        for e in errors[:20]
                    ]
                },
            )

    async def call(
        self,
        principal: Principal,
        exposed_name: str,
        arguments: dict[str, Any],
        *,
        meta: dict[str, Any] | None = None,
    ) -> ToolCallResult:
        started = time.perf_counter()
        meta = meta or {}
        parsed = split_exposed_name(exposed_name)
        server_id = parsed[0] if parsed else "unknown"
        try:
            result = await self._call(principal, exposed_name, arguments, meta)
        except GatewayError as exc:
            self._metrics.tool_calls.labels(server_id, exc.code).inc()
            await self._audit.record(
                principal.subject,
                "mcp.tools.call",
                exposed_name,
                exc.code,
                {
                    "chain": list(principal.delegation_chain),
                    "authenticated_by": principal.authenticated_by,
                    "arguments_digest": content_digest(canonical_json(arguments)),
                    "error": exc.message,
                    **{k: v for k, v in exc.data.items() if k in {"approval_id", "rule"}},
                },
            )
            raise
        self._metrics.tool_calls.labels(server_id, "success").inc()
        self._metrics.tool_latency.labels(server_id).observe(time.perf_counter() - started)
        return result

    async def _call(
        self,
        principal: Principal,
        exposed_name: str,
        arguments: dict[str, Any],
        meta: dict[str, Any],
    ) -> ToolCallResult:
        self._limiter.acquire(principal.subject)
        parsed = split_exposed_name(exposed_name)
        if parsed is None:
            raise NotFoundError(f"unknown tool {exposed_name}")
        server_id, name = parsed
        tool = await self._registry.servable(server_id, name)
        server = await self._registry.server(server_id) if tool is not None else None
        if tool is None or server is None or not self._visible_or_known(tool, principal):
            raise NotFoundError(f"unknown tool {exposed_name}")
        if not server.enabled:
            raise ForbiddenError(f"upstream server {server_id} is disabled")
        self._validate_arguments(tool, arguments)

        egress = self._inspector.scan_egress(arguments)
        if egress.blocked:
            raise ContentBlockedError(
                "arguments contain credential material", data={"kinds": list(egress.kinds)}
            )

        approval_id = meta.get(APPROVAL_META_KEY)
        approval = None
        if isinstance(approval_id, str) and approval_id:
            approval = await self._approvals.verify(
                approval_id, principal=principal, target=exposed_name, payload=arguments
            )
        purpose = meta.get(PURPOSE_META_KEY)
        environment = {"purpose_of_use": purpose} if isinstance(purpose, str) and purpose else {}
        target = self._target(tool, principal)
        outcome = await self._authorizer.decide(
            principal, target, approval_granted=approval is not None, environment=environment
        )
        self._metrics.authorization.labels("mcp", outcome.decision.value).inc()
        if outcome.decision is Decision.DENY:
            raise ForbiddenError(
                "; ".join(outcome.reasons), data={"rule": ",".join(outcome.local_rules)}
            )
        if outcome.decision is Decision.REQUIRE_APPROVAL:
            raise await self._approvals.request(
                kind=ApprovalKind.TOOL_CALL,
                principal=principal,
                target=exposed_name,
                action=tool.action,
                payload=arguments,
                reasons=outcome.reasons,
            )
        if approval is not None:
            await self._approvals.consume(approval)

        upstream_result = await self._guarded(server, tool, principal, arguments)
        inspected = await self._inspect(tool, upstream_result)
        await self._audit.record(
            principal.subject,
            "mcp.tools.call",
            exposed_name,
            "success",
            {
                "chain": list(principal.delegation_chain),
                "authenticated_by": principal.authenticated_by,
                "version": tool.version,
                "definition_hash": tool.definition_hash,
                "arguments_digest": content_digest(canonical_json(arguments)),
                "response_digest": content_digest(
                    canonical_json([inspected.content, inspected.structured_content])
                ),
                "response_bytes": upstream_result.size_bytes,
                "upstream_is_error": upstream_result.is_error,
                "redactions": inspected.redactions,
                "approval_id": approval.approval_id if approval else None,
                **outcome.evidence(),
            },
        )
        return inspected

    def _visible_or_known(self, tool: ToolVersion, principal: Principal) -> bool:
        """Callers learn nothing about tools outside their scopes (no existence oracle)."""
        return principal.holds(tool.action)

    async def _guarded(
        self,
        server: UpstreamServer,
        tool: ToolVersion,
        principal: Principal,
        arguments: dict[str, Any],
    ) -> UpstreamToolCall:
        # Fabric failures while minting the credential must not trip the upstream's breaker.
        token = await self._credentials.for_call(server, principal, tool.action)
        limit = (
            tool.policy.max_response_bytes
            if tool.policy and tool.policy.max_response_bytes
            else server.max_response_bytes
        )
        self._breaker.before(server.server_id)
        try:
            live = await self._live.digest(server, tool.name)
            if live != tool.definition_hash:
                self._live.invalidate(server.server_id)
                self._metrics.definition_drift.labels(server.server_id).inc()
                await self._audit.record(
                    "gateway",
                    "tool.definition_drift",
                    tool.exposed_name,
                    "blocked",
                    {"pinned_hash": tool.definition_hash, "live_hash": live},
                )
                raise DefinitionDriftError(
                    f"{tool.exposed_name} changed upstream since version {tool.version} was "
                    "approved; calls are blocked until the new definition is reviewed"
                )
            result = await self._upstream.call_tool(
                server, tool.name, arguments, token=token, max_response_bytes=limit
            )
        except UpstreamError as exc:
            self._breaker.failure(server.server_id)
            self._metrics.upstream_errors.labels(server.server_id, exc.code).inc()
            raise
        except BaseException:
            self._breaker.release(server.server_id)
            raise
        self._breaker.success(server.server_id)
        return result

    async def _inspect(self, tool: ToolVersion, result: UpstreamToolCall) -> ToolCallResult:
        redact = tool.policy.redact_pii if tool.policy else True
        verdict, cleaned = self._inspector.inspect_projected(
            {"content": result.content, "structured": result.structured_content},
            mcp_text_fields,
            redact_pii=redact,
        )
        if verdict.blocked:
            self._metrics.output_blocked.labels(tool.server_id, "inspection").inc()
            raise ContentBlockedError(
                "tool output blocked by content inspection", data={"kinds": list(verdict.kinds)}
            )
        structured = cleaned["structured"]
        schema = tool.definition.output_schema
        if schema is not None and not result.is_error:
            # Validated before redaction rewrote any string, against the pinned schema.
            errors = list(Draft202012Validator(schema).iter_errors(result.structured_content or {}))
            if result.structured_content is None or errors:
                self._metrics.output_blocked.labels(tool.server_id, "output_schema").inc()
                raise ContentBlockedError("tool output does not match the pinned output schema")
        return ToolCallResult(
            content=cleaned["content"],
            structured_content=structured,
            is_error=result.is_error,
            tool=tool.exposed_name,
            version=tool.version,
            definition_hash=tool.definition_hash,
            redactions=verdict.redactions,
        )
