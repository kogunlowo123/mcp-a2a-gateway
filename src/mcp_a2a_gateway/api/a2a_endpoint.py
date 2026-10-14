"""The gateway's A2A surface: its Agent Card and the JSON-RPC endpoint at POST /a2a."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header
from fastapi.responses import JSONResponse

from mcp_a2a_gateway import __version__
from mcp_a2a_gateway.api.routes import Deps, container
from mcp_a2a_gateway.api.schemas import JsonRpcRequest, JsonRpcResponse
from mcp_a2a_gateway.application.federation import SKILL_KEY, TARGET_KEY
from mcp_a2a_gateway.config import Settings
from mcp_a2a_gateway.domain.errors import (
    RPC_METHOD_NOT_FOUND,
    RPC_UNSUPPORTED_OPERATION,
    GatewayError,
    UnauthorizedError,
)
from mcp_a2a_gateway.domain.models import Principal
from mcp_a2a_gateway.runtime.container import Container

RPC_PUSH_NOT_SUPPORTED = -32003

router = APIRouter()

ROUTING_SKILL = {
    "id": "federated-agent-routing",
    "name": "Federated agent routing",
    "description": (
        "Delivers a message to an approved agent in this or a federated trust domain under a "
        f"delegated credential. Set metadata['{TARGET_KEY}'] to the agent id and optionally "
        f"metadata['{SKILL_KEY}'] to the skill id."
    ),
    "tags": ["a2a", "federation", "gateway"],
    "examples": ["Ask the partner research agent for the latest assay summary"],
    "inputModes": ["text/plain", "application/json"],
    "outputModes": ["text/plain", "application/json"],
}


def gateway_card(
    settings: Settings, extra_skills: list[dict[str, Any]] | None = None
) -> dict[str, Any]:
    if settings.fabric_url is not None:
        scheme: dict[str, Any] = {
            "type": "oauth2",
            "description": "Agent credential from the enterprise agent identity fabric",
            "flows": {
                "clientCredentials": {
                    "tokenUrl": f"{settings.fabric_url.rstrip('/')}/oauth2/token",
                    "scopes": {},
                }
            },
        }
    else:
        scheme = {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    return {
        "protocolVersion": "0.3.0",
        "name": "Enterprise MCP and A2A gateway",
        "description": (
            "Routes agent-to-agent messages to approved agents across trust domains with "
            "delegated authority, policy enforcement, content inspection and signed audit."
        ),
        "url": f"{settings.public_base}/a2a",
        "preferredTransport": "JSONRPC",
        "version": __version__,
        "capabilities": {
            "streaming": False,
            "pushNotifications": False,
            "stateTransitionHistory": False,
        },
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [ROUTING_SKILL, *(extra_skills or [])],
        "securitySchemes": {"agentIdentity": scheme},
        "security": [{"agentIdentity": []}],
        "supportsAuthenticatedExtendedCard": True,
    }


@router.get("/.well-known/agent-card.json", tags=["a2a"])
async def agent_card(c: Deps) -> dict[str, Any]:
    return gateway_card(c.settings)


def _rpc_error(request_id: str | int | None, exc: GatewayError) -> JsonRpcResponse:
    return JsonRpcResponse(
        id=request_id,
        error={
            "code": exc.rpc_code,
            "message": exc.message,
            "data": {"error": exc.code, **exc.data},
        },
    )


async def _dispatch(c: Container, principal: Principal, call: JsonRpcRequest) -> dict[str, Any]:
    method = call.method
    if method == "message/send":
        return await c.federation.send_message(principal, call.params)
    if method in {"tasks/get", "tasks/cancel"}:
        return await c.federation.task_operation(principal, method, call.params)
    if method == "agent/getAuthenticatedExtendedCard":
        return gateway_card(c.settings, await c.federation.extended_skills(principal))
    if method in {"message/stream", "tasks/resubscribe"}:
        raise UnsupportedMethodError(
            "streaming is not supported by this gateway", RPC_UNSUPPORTED_OPERATION
        )
    if method.startswith("tasks/pushNotificationConfig/"):
        raise UnsupportedMethodError("push notifications are not supported", RPC_PUSH_NOT_SUPPORTED)
    raise UnsupportedMethodError(f"method {method} not found", RPC_METHOD_NOT_FOUND)


class UnsupportedMethodError(GatewayError):
    code = "unsupported_operation"

    def __init__(self, message: str, rpc_code: int) -> None:
        super().__init__(message)
        self.rpc_code = rpc_code


class HttpRpcError(Exception):
    """A JSON-RPC error that must also carry an HTTP status (authentication failures)."""

    def __init__(self, status: int, body: JsonRpcResponse) -> None:
        super().__init__(body.error)
        self.status = status
        self.body = body

    def response(self) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if self.status == 401 else None
        return JSONResponse(
            self.body.model_dump(exclude_none=True), status_code=self.status, headers=headers
        )


@router.post("/a2a", tags=["a2a"], response_model_exclude_none=True)
async def a2a_rpc(
    call: JsonRpcRequest,
    c: Annotated[Container, Depends(container)],
    authorization: Annotated[str | None, Header()] = None,
) -> JsonRpcResponse:
    """A2A JSON-RPC 2.0: message/send, tasks/get, tasks/cancel and the extended card."""
    try:
        principal = await c.authenticator.authenticate(authorization)
    except GatewayError as exc:
        c.metrics.authentication_failures.labels("a2a").inc()
        status = 401 if isinstance(exc, UnauthorizedError) else exc.status
        raise HttpRpcError(status, _rpc_error(call.id, exc)) from exc
    try:
        result = await _dispatch(c, principal, call)
    except GatewayError as exc:
        return _rpc_error(call.id, exc)
    return JsonRpcResponse(id=call.id, result=result)
