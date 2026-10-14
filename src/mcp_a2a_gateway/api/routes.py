"""Administrative and operational HTTP routes.

Administrative endpoints require an enterprise OIDC token with a gateway
role. Agents never call these; they use ``/mcp`` and ``/a2a``.
"""

from __future__ import annotations

from typing import Annotated

from agentic_core.audit import verify_chain
from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from mcp_a2a_gateway.api.schemas import (
    ApprovalList,
    AuditVerification,
    CardList,
    DecideApproval,
    ServerList,
    ToolList,
)
from mcp_a2a_gateway.application.directory import ApproveCard, RefreshResult, RegisterCard
from mcp_a2a_gateway.application.registry import (
    ApproveTool,
    DeprecateTool,
    DiscoveryReport,
    LifecycleReason,
    RegisterServer,
)
from mcp_a2a_gateway.domain.models import (
    AgentCardVersion,
    ApprovalRequest,
    ApprovalStatus,
    Lifecycle,
    ToolVersion,
    UpstreamServer,
)
from mcp_a2a_gateway.runtime.container import Container
from mcp_a2a_gateway.security.admin import READERS, AdminPrincipal, AdminRole, require_role

router = APIRouter()


def container(request: Request) -> Container:
    value: Container = request.app.state.container
    return value


async def admin(
    request: Request, authorization: Annotated[str | None, Header()] = None
) -> AdminPrincipal:
    return await container(request).admin.authenticate(authorization)


Deps = Annotated[Container, Depends(container)]
Admin = Annotated[AdminPrincipal, Depends(admin)]
ServerId = Annotated[str, Path(pattern=r"^[a-z][a-z0-9-]{1,23}$")]
ToolName = Annotated[str, Path(pattern=r"^[A-Za-z0-9_.\-]{1,64}$")]
CardId = Annotated[str, Path(pattern=r"^[a-z][a-z0-9-]{1,47}$")]
Version = Annotated[int, Path(ge=1, le=1_000_000)]


# ------------------------------------------------------------- upstream servers


@router.post("/v1/servers", status_code=201, tags=["mcp registry"])
async def register_server(body: RegisterServer, c: Deps, who: Admin) -> UpstreamServer:
    require_role(who, AdminRole.ADMIN)
    server = await c.registry.register_server(body, actor=who.subject)
    c.metrics.lifecycle.labels("server.register").inc()
    return server


@router.get("/v1/servers", tags=["mcp registry"])
async def list_servers(c: Deps, who: Admin) -> ServerList:
    require_role(who, *READERS)
    return ServerList(items=list(await c.registry.servers()))


@router.get("/v1/servers/{server_id}", tags=["mcp registry"])
async def get_server(server_id: ServerId, c: Deps, who: Admin) -> UpstreamServer:
    require_role(who, *READERS)
    return await c.registry.server(server_id)


@router.post("/v1/servers/{server_id}/discover", tags=["mcp registry"])
async def discover(server_id: ServerId, c: Deps, who: Admin) -> DiscoveryReport:
    require_role(who, AdminRole.ADMIN)
    report = await c.registry.discover(server_id, actor=who.subject)
    c.metrics.lifecycle.labels("server.discover").inc()
    for change in report.changes:
        if change.change == "changed":
            c.metrics.definition_drift.labels(server_id).inc()
    return report


@router.post("/v1/servers/{server_id}/disable", tags=["mcp registry"])
async def disable_server(
    server_id: ServerId, body: LifecycleReason, c: Deps, who: Admin
) -> UpstreamServer:
    require_role(who, AdminRole.ADMIN, AdminRole.REVIEWER)
    return await c.registry.set_enabled(
        server_id, enabled=False, actor=who.subject, reason=body.reason
    )


@router.post("/v1/servers/{server_id}/enable", tags=["mcp registry"])
async def enable_server(
    server_id: ServerId, body: LifecycleReason, c: Deps, who: Admin
) -> UpstreamServer:
    require_role(who, AdminRole.REVIEWER)
    return await c.registry.set_enabled(
        server_id, enabled=True, actor=who.subject, reason=body.reason
    )


# ------------------------------------------------------------------------ tools


@router.get("/v1/tools", tags=["mcp registry"])
async def list_tools(
    c: Deps,
    who: Admin,
    status: Lifecycle | None = None,
    server_id: Annotated[str | None, Query(pattern=r"^[a-z][a-z0-9-]{1,23}$")] = None,
) -> ToolList:
    require_role(who, *READERS)
    return ToolList(items=list(await c.registry.tools(status=status, server_id=server_id)))


@router.get("/v1/tools/{server_id}/{name}", tags=["mcp registry"])
async def tool_versions(server_id: ServerId, name: ToolName, c: Deps, who: Admin) -> ToolList:
    require_role(who, *READERS)
    return ToolList(items=list(await c.registry.versions(server_id, name)))


@router.post("/v1/tools/{server_id}/{name}/versions/{version}/approve", tags=["mcp registry"])
async def approve_tool(
    *, server_id: ServerId, name: ToolName, version: Version, body: ApproveTool, c: Deps, who: Admin
) -> ToolVersion:
    require_role(who, AdminRole.REVIEWER)
    tool = await c.registry.approve(server_id, name, version, body, actor=who.subject)
    c.metrics.lifecycle.labels("tool.approve").inc()
    return tool


@router.post("/v1/tools/{server_id}/{name}/versions/{version}/deprecate", tags=["mcp registry"])
async def deprecate_tool(
    *,
    server_id: ServerId,
    name: ToolName,
    version: Version,
    body: DeprecateTool,
    c: Deps,
    who: Admin,
) -> ToolVersion:
    require_role(who, AdminRole.REVIEWER)
    tool = await c.registry.deprecate(server_id, name, version, body, actor=who.subject)
    c.metrics.lifecycle.labels("tool.deprecate").inc()
    return tool


@router.post("/v1/tools/{server_id}/{name}/versions/{version}/revoke", tags=["mcp registry"])
async def revoke_tool(
    *,
    server_id: ServerId,
    name: ToolName,
    version: Version,
    body: LifecycleReason,
    c: Deps,
    who: Admin,
) -> ToolVersion:
    require_role(who, AdminRole.REVIEWER)
    tool = await c.registry.revoke(server_id, name, version, body.reason, actor=who.subject)
    c.metrics.lifecycle.labels("tool.revoke").inc()
    return tool


# ------------------------------------------------------------------ agent cards


@router.post("/v1/agent-cards", status_code=201, tags=["a2a directory"])
async def register_card(body: RegisterCard, c: Deps, who: Admin) -> AgentCardVersion:
    require_role(who, AdminRole.ADMIN)
    record = await c.directory.register(body, actor=who.subject)
    c.metrics.lifecycle.labels("card.register").inc()
    return record


@router.get("/v1/agent-cards", tags=["a2a directory"])
async def list_cards(c: Deps, who: Admin, status: Lifecycle | None = None) -> CardList:
    require_role(who, *READERS)
    return CardList(items=list(await c.directory.cards(status=status)))


@router.get("/v1/agent-cards/{card_id}", tags=["a2a directory"])
async def card_versions(card_id: CardId, c: Deps, who: Admin) -> CardList:
    require_role(who, *READERS)
    return CardList(items=list(await c.directory.versions(card_id)))


@router.post("/v1/agent-cards/{card_id}/refresh", tags=["a2a directory"])
async def refresh_card(card_id: CardId, c: Deps, who: Admin) -> RefreshResult:
    require_role(who, AdminRole.ADMIN)
    result = await c.directory.refresh(card_id, actor=who.subject)
    c.metrics.lifecycle.labels("card.refresh").inc()
    return result


@router.post("/v1/agent-cards/{card_id}/versions/{version}/approve", tags=["a2a directory"])
async def approve_card(
    card_id: CardId, version: Version, body: ApproveCard, c: Deps, who: Admin
) -> AgentCardVersion:
    require_role(who, AdminRole.REVIEWER)
    record = await c.directory.approve(card_id, version, body, actor=who.subject)
    c.metrics.lifecycle.labels("card.approve").inc()
    return record


@router.post("/v1/agent-cards/{card_id}/versions/{version}/deprecate", tags=["a2a directory"])
async def deprecate_card(
    card_id: CardId, version: Version, body: DeprecateTool, c: Deps, who: Admin
) -> AgentCardVersion:
    require_role(who, AdminRole.REVIEWER)
    return await c.directory.deprecate(card_id, version, body, actor=who.subject)


@router.post("/v1/agent-cards/{card_id}/versions/{version}/revoke", tags=["a2a directory"])
async def revoke_card(
    card_id: CardId, version: Version, body: LifecycleReason, c: Deps, who: Admin
) -> AgentCardVersion:
    require_role(who, AdminRole.REVIEWER)
    record = await c.directory.revoke(card_id, version, body.reason, actor=who.subject)
    c.metrics.lifecycle.labels("card.revoke").inc()
    return record


# -------------------------------------------------------------------- approvals


@router.get("/v1/approvals", tags=["approvals"])
async def list_approvals(
    c: Deps,
    who: Admin,
    status: ApprovalStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> ApprovalList:
    require_role(who, AdminRole.APPROVER, AdminRole.AUDITOR)
    return ApprovalList(items=list(await c.approvals.list(status=status, limit=limit)))


@router.get("/v1/approvals/{approval_id}", tags=["approvals"])
async def get_approval(
    approval_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")], c: Deps, who: Admin
) -> ApprovalRequest:
    require_role(who, AdminRole.APPROVER, AdminRole.AUDITOR)
    return await c.approvals.get(approval_id)


async def _decide(
    c: Container, who: AdminPrincipal, approval_id: str, approve: bool, reason: str
) -> ApprovalRequest:
    require_role(who, AdminRole.APPROVER)
    decided = await c.approvals.decide(
        approval_id, approve=approve, actor=who.subject, reason=reason
    )
    c.metrics.lifecycle.labels("approval.approve" if approve else "approval.deny").inc()
    return decided


@router.post("/v1/approvals/{approval_id}/approve", tags=["approvals"])
async def approve_call(
    approval_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    body: DecideApproval,
    c: Deps,
    who: Admin,
) -> ApprovalRequest:
    return await _decide(c, who, approval_id, True, body.reason)


@router.post("/v1/approvals/{approval_id}/deny", tags=["approvals"])
async def deny_call(
    approval_id: Annotated[str, Path(pattern=r"^[0-9a-f]{32}$")],
    body: DecideApproval,
    c: Deps,
    who: Admin,
) -> ApprovalRequest:
    return await _decide(c, who, approval_id, False, body.reason)


# ------------------------------------------------------------------------ audit


@router.get("/v1/audit/verify", tags=["audit"])
async def verify_audit(c: Deps, who: Admin) -> AuditVerification:
    """Verify this replica's signed audit chain end to end."""
    require_role(who, AdminRole.AUDITOR)
    events = [event async for event in c.audit_sink.read()]
    count = verify_chain(events, {c.audit_key_id: c.audit_public_key})
    return AuditVerification(
        chain_id=c.audit_sink.chain_id,
        key_id=c.audit_key_id,
        events_verified=count,
        head_hash=events[-1].hash if events else None,
    )


# ------------------------------------------------------------------- discovery


@router.get("/.well-known/oauth-protected-resource", tags=["discovery"])
async def protected_resource(c: Deps) -> dict[str, object]:
    """RFC 9728 metadata for the MCP endpoint (MCP authorization specification)."""
    settings = c.settings
    issuer = settings.fabric_url or settings.token_issuer or ""
    return {
        "resource": f"{settings.public_base}/mcp",
        "authorization_servers": [issuer.rstrip("/")],
        "bearer_methods_supported": ["header"],
        "resource_name": "Enterprise MCP and A2A gateway",
    }


# ------------------------------------------------------------------ operations


@router.get("/healthz", tags=["operations"], include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["operations"], include_in_schema=False)
async def readyz(c: Deps, response: Response) -> dict[str, str]:
    try:
        async with c.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        response.status_code = 503
        return {"status": "database unavailable"}
    return {"status": "ready"}


@router.get("/metrics", tags=["operations"], include_in_schema=False)
async def metrics(c: Deps) -> Response:
    return Response(generate_latest(c.metrics.registry), media_type=CONTENT_TYPE_LATEST)
