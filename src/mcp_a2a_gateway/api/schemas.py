"""HTTP request and response bodies that are not domain models."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from mcp_a2a_gateway.domain.models import (
    AgentCardVersion,
    ApprovalRequest,
    ToolVersion,
    UpstreamServer,
)


class ServerList(BaseModel):
    items: list[UpstreamServer]


class ToolList(BaseModel):
    items: list[ToolVersion]


class CardList(BaseModel):
    items: list[AgentCardVersion]


class ApprovalList(BaseModel):
    items: list[ApprovalRequest]


class DecideApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=5, max_length=1000)


class AuditVerification(BaseModel):
    chain_id: str
    key_id: str
    events_verified: int
    head_hash: str | None


class OAuthError(BaseModel):
    error: str
    error_description: str


class JsonRpcRequest(BaseModel):
    """JSON-RPC 2.0 request envelope accepted at POST /a2a."""

    model_config = ConfigDict(extra="forbid")

    jsonrpc: str = Field(pattern=r"^2\.0$")
    id: str | int | None = None
    method: str = Field(min_length=1, max_length=100)
    params: dict[str, Any] = Field(default_factory=dict)


class JsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: str | int | None = None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
