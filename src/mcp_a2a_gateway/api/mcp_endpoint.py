"""The gateway's MCP endpoint: the official SDK ``MCPServer`` over stateless Streamable HTTP.

Agents see one MCP server whose catalog is the set of approved, pinned
upstream tools they are entitled to (``<server>__<tool>``), plus gateway
tools. Authentication happens at the HTTP layer (401 with RFC 9728
``resource_metadata`` per the MCP authorization specification); the
authenticated principal reaches tool handlers through SDK middleware.

The transport is stateless with JSON responses, so any replica can serve any
request and no sticky sessions are needed.
"""

from __future__ import annotations

import json
from contextvars import ContextVar
from typing import Any

from mcp.server import MCPServer
from mcp.server.context import CallNext, HandlerResult, ServerRequestContext
from mcp.server.mcpserver.context import Context
from mcp.server.streamable_http_manager import StreamableHTTPASGIApp
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp_types import INVALID_PARAMS, CallToolResult, InputRequiredResult, TextContent, Tool
from pydantic import BaseModel, ConfigDict, Field
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import Receive, Scope, Send

from mcp_a2a_gateway import __version__
from mcp_a2a_gateway.application.mcp_gateway import ToolCallResult
from mcp_a2a_gateway.domain.errors import (
    RPC_UNAUTHORIZED,
    GatewayError,
    NotFoundError,
    UnauthorizedError,
)
from mcp_a2a_gateway.domain.models import Lifecycle, Principal, ToolVersion
from mcp_a2a_gateway.runtime.container import Container

PRINCIPAL_STATE = "gateway_principal"
_principal: ContextVar[Principal | None] = ContextVar("gateway_principal", default=None)

INSTRUCTIONS = (
    "Enterprise MCP gateway. Tools are named <server>__<tool> and are pinned, reviewed versions "
    "of upstream tools. Calls are authorized per agent and audited. A call may return "
    "error=approval_required with an approval_id: after a human approves it, repeat the "
    "identical call with _meta['mcp-a2a-gateway/approval-id'] set to that id."
)


def current_principal() -> Principal:
    principal = _principal.get()
    if principal is None:
        raise MCPError(code=RPC_UNAUTHORIZED, message="request is not authenticated")
    return principal


class PrincipalBinding:
    """SDK middleware: expose the principal the HTTP gate authenticated to every handler."""

    async def __call__(
        self, ctx: ServerRequestContext[Any, Any], call_next: CallNext
    ) -> HandlerResult:
        request = ctx.request
        state = getattr(request, "state", None)
        principal = getattr(state, PRINCIPAL_STATE, None)
        if not isinstance(principal, Principal):
            raise MCPError(code=RPC_UNAUTHORIZED, message="request is not authenticated")
        token = _principal.set(principal)
        try:
            return await call_next(ctx)
        finally:
            _principal.reset(token)


class ApprovalStatusView(BaseModel):
    model_config = ConfigDict(frozen=True)

    approval_id: str
    status: str
    target: str
    expires_at: str
    decided_at: str | None = None
    decision_reason: str | None = None


class FederatedAgentView(BaseModel):
    model_config = ConfigDict(frozen=True)

    agent: str = Field(description="Value for metadata['mcp-a2a-gateway/target-agent']")
    name: str
    description: str
    trust_domain: str
    skills: list[str]


class FederatedAgents(BaseModel):
    model_config = ConfigDict(frozen=True)

    agents: list[FederatedAgentView]


def _tool_view(tool: ToolVersion) -> Tool:
    definition = tool.definition
    description = definition.description
    if tool.status is Lifecycle.DEPRECATED and tool.sunset_at is not None:
        description = f"[Deprecated; removed after {tool.sunset_at.isoformat()}] {description}"
    return Tool.model_validate(
        {
            "name": tool.exposed_name,
            "title": definition.title,
            "description": description,
            "inputSchema": definition.input_schema,
            "outputSchema": definition.output_schema,
            "annotations": definition.annotations,
            "_meta": {
                "mcp-a2a-gateway/version": tool.version,
                "mcp-a2a-gateway/definition-hash": tool.definition_hash,
            },
        }
    )


def _error_result(exc: GatewayError) -> CallToolResult:
    body = {"error": exc.code, "error_description": exc.message, **exc.data}
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(body, sort_keys=True))],
        is_error=True,
    )


def _success_result(result: ToolCallResult) -> CallToolResult:
    return CallToolResult.model_validate(
        {
            "content": result.content,
            "structuredContent": result.structured_content,
            "isError": result.is_error,
        }
    )


class GatewayMcpServer(MCPServer):
    def __init__(self, container: Container) -> None:
        super().__init__(
            name="mcp-a2a-gateway",
            title="Enterprise MCP and A2A gateway",
            version=__version__,
            instructions=INSTRUCTIONS,
            middleware=[PrincipalBinding()],
            warn_on_duplicate_tools=False,
        )
        self._container = container
        self.add_tool(
            self.approval_status,
            name="gateway__approval_status",
            title="Approval status",
            description="Status of an approval this agent requested for a high-risk call.",
            structured_output=True,
        )
        self.add_tool(
            self.federated_agents,
            name="gateway__federated_agents",
            title="Federated agents",
            description="Remote A2A agents this agent may message through the gateway's /a2a.",
            structured_output=True,
        )

    async def approval_status(self, approval_id: str) -> ApprovalStatusView:
        principal = current_principal()
        try:
            approval = await self._container.approvals.status_for(approval_id, principal=principal)
        except NotFoundError as exc:
            raise MCPError(code=INVALID_PARAMS, message=exc.message) from exc
        return ApprovalStatusView(
            approval_id=approval.approval_id,
            status=approval.status.value,
            target=approval.target,
            expires_at=approval.expires_at.isoformat(),
            decided_at=approval.decided_at.isoformat() if approval.decided_at else None,
            decision_reason=approval.decision_reason,
        )

    async def federated_agents(self) -> FederatedAgents:
        principal = current_principal()
        records = await self._container.directory.catalog(principal)
        return FederatedAgents(
            agents=[
                FederatedAgentView(
                    agent=r.card_id,
                    name=r.card.name,
                    description=r.card.description,
                    trust_domain=r.trust_domain,
                    skills=[
                        s.id
                        for s in r.card.skills
                        if not (r.policy and r.policy.allowed_skills)
                        or s.id in r.policy.allowed_skills
                    ],
                )
                for r in records
            ]
        )

    async def list_tools(self) -> list[Tool]:
        principal = current_principal()
        native = await super().list_tools()
        upstream = [_tool_view(t) for t in await self._container.mcp.catalog(principal)]
        return [*native, *upstream]

    async def call_tool(
        self, name: str, arguments: dict[str, Any], context: Context[Any, Any] | None = None
    ) -> CallToolResult | InputRequiredResult:
        if self._tool_manager.get_tool(name) is not None:
            return await super().call_tool(name, arguments, context)
        principal = current_principal()
        meta: dict[str, Any] = {}
        if context is not None and context.request_context.meta:
            meta = dict(context.request_context.meta)
        try:
            result = await self._container.mcp.call(principal, name, arguments, meta=meta)
        except NotFoundError as exc:
            raise MCPError(code=INVALID_PARAMS, message=exc.message) from exc
        except GatewayError as exc:
            return _error_result(exc)
        return _success_result(result)


def transport_security(container: Container) -> TransportSecuritySettings:
    hosts = list(container.settings.mcp_allowed_hosts)
    if not hosts:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=[]
    )


def build_mcp(container: Container) -> tuple[GatewayMcpServer, StreamableHTTPASGIApp]:
    server = GatewayMcpServer(container)
    server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        transport_security=transport_security(container),
        max_request_body_size=container.settings.max_argument_bytes + 65_536,
        # Not a bind address: tells the SDK this app is not localhost-only, so the
        # transport security settings above apply instead of its loopback defaults.
        host="0.0.0.0",  # noqa: S104  # nosec B104
    )
    return server, StreamableHTTPASGIApp(server.session_manager)


class McpHttpGate:
    """ASGI endpoint for /mcp: authenticate, then hand the request to the SDK transport."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        app = scope["app"]
        container: Container = app.state.container
        transport: StreamableHTTPASGIApp = app.state.mcp_transport
        request = Request(scope, receive)
        try:
            principal = await container.authenticator.authenticate(
                request.headers.get("authorization")
            )
        except GatewayError as exc:
            container.metrics.authentication_failures.labels("mcp").inc()
            status = 401 if isinstance(exc, UnauthorizedError) else exc.status
            metadata = f"{container.settings.public_base}/.well-known/oauth-protected-resource"
            challenge = f'Bearer error="invalid_token", resource_metadata="{metadata}"'
            headers = {"WWW-Authenticate": challenge} if status == 401 else None
            response = JSONResponse(
                {"error": exc.code, "error_description": exc.message},
                status_code=status,
                headers=headers,
            )
            await response(scope, receive, send)
            return
        scope.setdefault("state", {})[PRINCIPAL_STATE] = principal
        await transport(scope, receive, send)
