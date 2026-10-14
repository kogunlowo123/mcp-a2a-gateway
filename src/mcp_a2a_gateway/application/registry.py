"""Upstream MCP server registration, tool discovery and the pinned tool lifecycle.

Discovery never changes what agents can call. Every new or changed tool
definition becomes a *draft* version with its SHA-256 definition hash; only a
reviewer (not the person who ran discovery) can approve it, which pins that
exact definition. Agents are always shown the pinned definition, never the
live one, so an upstream that silently rewrites a tool description or schema
(a "rug pull") cannot reach the model until a human approves the change.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Literal

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from mcp_a2a_gateway.application.audit import AuditRecorder
from mcp_a2a_gateway.application.credentials import UpstreamCredentials
from mcp_a2a_gateway.domain.errors import (
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    ValidationFailedError,
)
from mcp_a2a_gateway.domain.models import (
    EXPOSED_SEPARATOR,
    MAX_EXPOSED_NAME,
    SERVABLE,
    TOOL_NAME,
    Lifecycle,
    ToolDefinition,
    ToolPolicy,
    ToolVersion,
    UpstreamAuth,
    UpstreamServer,
)
from mcp_a2a_gateway.domain.ports import Clock, ServerRepository, ToolRepository, UpstreamMcpPort
from mcp_a2a_gateway.security.egress import check_url
from mcp_a2a_gateway.security.inspection import ContentInspector

INJECTION_REVIEW_THRESHOLD = 0.5


class RegisterServer(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    server_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,23}$")
    display_name: str = Field(min_length=3, max_length=120)
    url: HttpUrl
    owner: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=2000)
    auth: UpstreamAuth = UpstreamAuth()
    max_response_bytes: int = Field(default=1_048_576, ge=1024, le=16_777_216)
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)


class ToolChange(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    change: Literal["new", "changed", "unchanged", "removed", "rejected"]
    version: int | None = None
    definition_hash: str | None = None
    status: Lifecycle | None = None
    detail: str = ""


class DiscoveryReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    server_id: str
    discovered_at: datetime
    changes: tuple[ToolChange, ...]

    def count(self, change: str) -> int:
        return sum(1 for c in self.changes if c.change == change)


class ApproveTool(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy: ToolPolicy
    reason: str = Field(min_length=5, max_length=1000)
    override_findings_reason: str | None = Field(
        default=None,
        min_length=20,
        max_length=1000,
        description="Required to approve a definition flagged for instruction-like text",
    )


class DeprecateTool(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    sunset_at: datetime
    reason: str = Field(min_length=5, max_length=1000)


class LifecycleReason(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    reason: str = Field(min_length=5, max_length=1000)


def definition_problems(definition: ToolDefinition, server_id: str) -> str | None:
    if not TOOL_NAME.fullmatch(definition.name):
        return "tool name does not match ^[A-Za-z0-9_.-]{1,64}$"
    if len(server_id) + len(EXPOSED_SEPARATOR) + len(definition.name) > MAX_EXPOSED_NAME:
        return f"exposed name {server_id}{EXPOSED_SEPARATOR}{definition.name} exceeds 64 characters"
    for label, schema in (("input", definition.input_schema), ("output", definition.output_schema)):
        if schema is None:
            continue
        if schema.get("type") != "object":
            return f"{label} schema must have type object"
        try:
            Draft202012Validator.check_schema(schema)
        except SchemaError as exc:
            return f"{label} schema is not valid JSON Schema: {exc.message}"
    return None


class ToolRegistry:
    def __init__(
        self,
        *,
        servers: ServerRepository,
        tools: ToolRepository,
        upstream: UpstreamMcpPort,
        credentials: UpstreamCredentials,
        inspector: ContentInspector,
        audit: AuditRecorder,
        clock: Clock,
        allowed_hosts: tuple[str, ...],
        allow_http: bool,
    ) -> None:
        self._servers = servers
        self._tools = tools
        self._upstream = upstream
        self._credentials = credentials
        self._inspector = inspector
        self._audit = audit
        self._clock = clock
        self._allowed_hosts = allowed_hosts
        self._allow_http = allow_http

    # ------------------------------------------------------------------ servers

    async def register_server(self, command: RegisterServer, *, actor: str) -> UpstreamServer:
        check_url(str(command.url), allowed_hosts=self._allowed_hosts, allow_http=self._allow_http)
        now = self._clock.now()
        server = UpstreamServer(
            **command.model_dump(), registered_by=actor, created_at=now, updated_at=now
        )
        await self._servers.add(server)
        await self._audit.record(
            actor,
            "server.register",
            server.server_id,
            "success",
            {"url": str(server.url), "auth": server.auth.mode.value},
        )
        return server

    async def server(self, server_id: str) -> UpstreamServer:
        server = await self._servers.get(server_id)
        if server is None:
            raise NotFoundError(f"upstream server {server_id} not found")
        return server

    async def servers(self) -> Sequence[UpstreamServer]:
        return await self._servers.list()

    async def set_enabled(
        self, server_id: str, *, enabled: bool, actor: str, reason: str
    ) -> UpstreamServer:
        server = await self.server(server_id)
        updated = server.model_copy(update={"enabled": enabled, "updated_at": self._clock.now()})
        await self._servers.update(updated)
        await self._audit.record(
            actor,
            "server.enable" if enabled else "server.disable",
            server_id,
            "success",
            {"reason": reason},
        )
        return updated

    # ---------------------------------------------------------------- discovery

    async def discover(self, server_id: str, *, actor: str) -> DiscoveryReport:
        server = await self.server(server_id)
        token = await self._credentials.for_gateway(server)
        live = await self._upstream.list_tools(server, token=token)
        current = {t.name: t for t in await self._tools.latest_by_server(server_id)}
        now = self._clock.now()
        changes: list[ToolChange] = []
        seen: set[str] = set()
        seen_lower: set[str] = set()

        for definition in live:
            problem = definition_problems(definition, server_id)
            if problem is None and definition.name.lower() in seen_lower:
                problem = "duplicate tool name (names are compared case-insensitively)"
            if problem is not None:
                changes.append(
                    ToolChange(name=definition.name[:64], change="rejected", detail=problem)
                )
                continue
            seen.add(definition.name)
            seen_lower.add(definition.name.lower())
            digest = definition.digest()
            existing = current.get(definition.name)
            revoked = existing is not None and existing.status is Lifecycle.REVOKED
            if existing is not None and existing.definition_hash == digest and not revoked:
                changes.append(
                    ToolChange(
                        name=definition.name,
                        change="unchanged",
                        version=existing.version,
                        definition_hash=digest,
                        status=existing.status,
                    )
                )
                continue
            score, kinds = self._inspector.score_definition(definition)
            draft = ToolVersion(
                server_id=server_id,
                name=definition.name,
                version=1 if existing is None else existing.version + 1,
                definition=definition,
                definition_hash=digest,
                injection_score=score,
                injection_kinds=kinds,
                discovered_by=actor,
                discovered_at=now,
                updated_at=now,
            )
            await self._tools.add(draft)
            change: Literal["new", "changed"] = "new" if existing is None else "changed"
            if existing is not None and existing.status in SERVABLE:
                await self._audit.record(
                    actor,
                    "tool.definition_drift",
                    draft.exposed_name,
                    "detected",
                    {
                        "pinned_version": existing.version,
                        "pinned_hash": existing.definition_hash,
                        "live_hash": digest,
                    },
                )
            changes.append(
                ToolChange(
                    name=definition.name,
                    change=change,
                    version=draft.version,
                    definition_hash=digest,
                    status=Lifecycle.DRAFT,
                    detail=f"injection indicators: {', '.join(kinds)}" if kinds else "",
                )
            )

        for name, existing in current.items():
            if name not in seen and existing.status in SERVABLE:
                changes.append(
                    ToolChange(
                        name=name,
                        change="removed",
                        version=existing.version,
                        definition_hash=existing.definition_hash,
                        status=existing.status,
                        detail="no longer advertised upstream; calls will fail the drift check",
                    )
                )
        report = DiscoveryReport(server_id=server_id, discovered_at=now, changes=tuple(changes))
        await self._audit.record(
            actor,
            "server.discover",
            server_id,
            "success",
            {kind: report.count(kind) for kind in ("new", "changed", "removed", "rejected")},
        )
        return report

    # ---------------------------------------------------------------- lifecycle

    async def version(self, server_id: str, name: str, version: int) -> ToolVersion:
        tool = await self._tools.get(server_id, name, version)
        if tool is None:
            raise NotFoundError(f"tool {server_id}/{name} v{version} not found")
        return tool

    async def versions(self, server_id: str, name: str) -> Sequence[ToolVersion]:
        found = await self._tools.versions(server_id, name)
        if not found:
            raise NotFoundError(f"tool {server_id}/{name} not found")
        return found

    async def tools(
        self, *, status: Lifecycle | None = None, server_id: str | None = None
    ) -> Sequence[ToolVersion]:
        return await self._tools.list(status=status, server_id=server_id)

    async def servable(self, server_id: str, name: str) -> ToolVersion | None:
        for tool in reversed(await self._tools.versions(server_id, name)):
            if tool.status in SERVABLE:
                return tool
        return None

    async def approve(
        self, server_id: str, name: str, version: int, command: ApproveTool, *, actor: str
    ) -> ToolVersion:
        tool = await self.version(server_id, name, version)
        await self.server(server_id)
        if tool.status is not Lifecycle.DRAFT:
            raise InvalidStateError(
                f"only draft versions can be approved; this one is {tool.status}"
            )
        if actor == tool.discovered_by:
            raise ForbiddenError("separation of duties: discoverer cannot approve the same version")
        if (
            tool.injection_score >= INJECTION_REVIEW_THRESHOLD
            and not command.override_findings_reason
        ):
            raise ValidationFailedError(
                "tool definition contains instruction-like text "
                f"({', '.join(tool.injection_kinds)}); fix it upstream or set "
                "override_findings_reason",
                data={"injection_score": tool.injection_score},
            )
        now = self._clock.now()
        for previous in await self._tools.versions(server_id, name):
            if previous.status in SERVABLE and previous.version != version:
                await self._tools.update(
                    previous.transition(
                        Lifecycle.REVOKED, at=now, reason=f"superseded by version {version}"
                    )
                )
        approved = tool.transition(
            Lifecycle.APPROVED,
            at=now,
            reason=command.reason,
            policy=command.policy,
            approved_by=actor,
            approved_at=now,
        )
        await self._tools.update(approved)
        await self._audit.record(
            actor,
            "tool.approve",
            f"{approved.exposed_name}@{version}",
            "success",
            {
                "definition_hash": approved.definition_hash,
                "risk": int(command.policy.risk),
                "classification": int(command.policy.classification),
                "allowed_agents": list(command.policy.allowed_agents),
                "override_findings_reason": command.override_findings_reason,
            },
        )
        return approved

    async def deprecate(
        self, server_id: str, name: str, version: int, command: DeprecateTool, *, actor: str
    ) -> ToolVersion:
        tool = await self.version(server_id, name, version)
        if command.sunset_at <= self._clock.now():
            raise ValidationFailedError("sunset_at must be in the future")
        updated = tool.transition(
            Lifecycle.DEPRECATED,
            at=self._clock.now(),
            reason=command.reason,
            sunset_at=command.sunset_at,
        )
        await self._tools.update(updated)
        await self._audit.record(
            actor,
            "tool.deprecate",
            f"{updated.exposed_name}@{version}",
            "success",
            {"sunset_at": command.sunset_at.isoformat(), "reason": command.reason},
        )
        return updated

    async def revoke(
        self, server_id: str, name: str, version: int, reason: str, *, actor: str
    ) -> ToolVersion:
        tool = await self.version(server_id, name, version)
        if tool.status is Lifecycle.REVOKED:
            raise ConflictError("tool version is already revoked")
        updated = tool.transition(Lifecycle.REVOKED, at=self._clock.now(), reason=reason)
        await self._tools.update(updated)
        await self._audit.record(
            actor, "tool.revoke", f"{updated.exposed_name}@{version}", "success", {"reason": reason}
        )
        return updated
