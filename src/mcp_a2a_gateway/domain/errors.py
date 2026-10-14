"""Domain errors.

Each error carries an OAuth-style ``code`` and HTTP ``status`` for the REST
API, and a JSON-RPC ``rpc_code`` for the MCP and A2A endpoints.
"""

from __future__ import annotations

from typing import Any

# JSON-RPC 2.0 reserved codes and the A2A-specific range (A2A spec section 8).
RPC_INVALID_REQUEST = -32600
RPC_METHOD_NOT_FOUND = -32601
RPC_INVALID_PARAMS = -32602
RPC_INTERNAL_ERROR = -32603
RPC_TASK_NOT_FOUND = -32001
RPC_TASK_NOT_CANCELABLE = -32002
RPC_UNSUPPORTED_OPERATION = -32004
RPC_INVALID_AGENT_RESPONSE = -32006
# Implementation-defined server errors (-32000 to -32099) used by the gateway.
RPC_UNAUTHORIZED = -32040
RPC_FORBIDDEN = -32041
RPC_APPROVAL_REQUIRED = -32042
RPC_RATE_LIMITED = -32043
RPC_UPSTREAM_UNAVAILABLE = -32044


class GatewayError(Exception):
    code = "gateway_error"
    status = 400
    rpc_code = RPC_INVALID_PARAMS

    def __init__(self, message: str, *, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.data = data or {}


class NotFoundError(GatewayError):
    code = "not_found"
    status = 404
    rpc_code = RPC_INVALID_PARAMS


class ConflictError(GatewayError):
    code = "conflict"
    status = 409


class InvalidStateError(GatewayError):
    code = "invalid_state"
    status = 409


class ValidationFailedError(GatewayError):
    code = "invalid_request"
    status = 422


class UnauthorizedError(GatewayError):
    code = "unauthorized"
    status = 401
    rpc_code = RPC_UNAUTHORIZED


class ForbiddenError(GatewayError):
    code = "forbidden"
    status = 403
    rpc_code = RPC_FORBIDDEN


class ApprovalRequiredError(GatewayError):
    """A human must approve this exact call before it can run."""

    code = "approval_required"
    status = 403
    rpc_code = RPC_APPROVAL_REQUIRED

    def __init__(self, message: str, *, approval_id: str, expires_at: str) -> None:
        super().__init__(message, data={"approval_id": approval_id, "expires_at": expires_at})
        self.approval_id = approval_id


class RateLimitedError(GatewayError):
    code = "rate_limited"
    status = 429
    rpc_code = RPC_RATE_LIMITED


class DefinitionDriftError(GatewayError):
    """The upstream tool definition no longer matches the pinned, approved one."""

    code = "tool_definition_changed"
    status = 409
    rpc_code = RPC_FORBIDDEN


class ContentBlockedError(GatewayError):
    """Content failed inspection (injection, credentials, schema)."""

    code = "content_blocked"
    status = 422
    rpc_code = RPC_INVALID_AGENT_RESPONSE


class UpstreamError(GatewayError):
    code = "upstream_error"
    status = 502
    rpc_code = RPC_UPSTREAM_UNAVAILABLE


class UpstreamTimeoutError(UpstreamError):
    code = "upstream_timeout"
    status = 504


class ResponseTooLargeError(UpstreamError):
    code = "response_too_large"
    status = 502


class CircuitOpenError(UpstreamError):
    code = "upstream_circuit_open"
    status = 503


class SignatureError(GatewayError):
    code = "invalid_signature"
    status = 422


class EgressDeniedError(GatewayError):
    """A configured URL points outside the egress allow list."""

    code = "egress_denied"
    status = 422
