"""Ports the application layer depends on. Adapters live in infrastructure and integrations."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict

from mcp_a2a_gateway.domain.models import (
    AgentCardVersion,
    ApprovalRequest,
    ApprovalStatus,
    Lifecycle,
    ToolDefinition,
    ToolVersion,
    UpstreamServer,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class ServerRepository(Protocol):
    async def add(self, server: UpstreamServer) -> None: ...

    async def get(self, server_id: str) -> UpstreamServer | None: ...

    async def update(self, server: UpstreamServer) -> None: ...

    async def list(self) -> Sequence[UpstreamServer]: ...


class ToolRepository(Protocol):
    async def add(self, tool: ToolVersion) -> None: ...

    async def update(self, tool: ToolVersion) -> None: ...

    async def get(self, server_id: str, name: str, version: int) -> ToolVersion | None: ...

    async def versions(self, server_id: str, name: str) -> Sequence[ToolVersion]: ...

    async def latest_by_server(self, server_id: str) -> Sequence[ToolVersion]: ...

    async def list(
        self, *, status: Lifecycle | None = None, server_id: str | None = None
    ) -> Sequence[ToolVersion]: ...


class CardRepository(Protocol):
    async def add(self, card: AgentCardVersion) -> None: ...

    async def update(self, card: AgentCardVersion) -> None: ...

    async def get(self, card_id: str, version: int) -> AgentCardVersion | None: ...

    async def versions(self, card_id: str) -> Sequence[AgentCardVersion]: ...

    async def list(self, *, status: Lifecycle | None = None) -> Sequence[AgentCardVersion]: ...


class ApprovalRepository(Protocol):
    async def add(self, approval: ApprovalRequest) -> None: ...

    async def get(self, approval_id: str) -> ApprovalRequest | None: ...

    async def update(self, approval: ApprovalRequest) -> None: ...

    async def consume(self, approval_id: str, *, at: datetime) -> bool:
        """Atomically move an approved request to used; False if it was not approved/unused."""
        ...

    async def list(
        self, *, status: ApprovalStatus | None = None, limit: int = 100
    ) -> Sequence[ApprovalRequest]: ...


class TaskRouteRepository(Protocol):
    """Which federated agent owns a remote A2A task, and which caller created it."""

    async def remember(self, task_id: str, *, card_id: str, owner: str, at: datetime) -> None: ...

    async def lookup(self, task_id: str) -> tuple[str, str] | None: ...


class FabricAuthorization(BaseModel):
    """The identity fabric's decision (POST /v1/authorize)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    decision: str
    agent: str
    action: str
    resource: str
    matched_rules: tuple[str, ...] = ()
    policy_version: str = ""
    policy_digest: str = ""
    reason: str = ""
    delegation_chain: tuple[str, ...] = ()


class FabricIntrospection(BaseModel):
    """RFC 7662 introspection response from the identity fabric."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    active: bool
    sub: str | None = None
    scope: str | None = None
    exp: int | None = None
    iss: str | None = None
    aud: str | None = None
    jti: str | None = None
    act: dict[str, Any] | None = None


class IdentityFabricPort(Protocol):
    async def introspect(self, token: str) -> FabricIntrospection: ...

    async def authorize(
        self,
        token: str,
        *,
        action: str,
        resource_type: str,
        resource_id: str,
        classification: int,
        attributes: dict[str, Any],
        environment: dict[str, Any],
    ) -> FabricAuthorization: ...

    async def exchange(self, subject_token: str, *, scope: str) -> str:
        """RFC 8693: a credential for the subject with the gateway as actor, narrowed to scope."""
        ...


class UpstreamToolCall(BaseModel):
    model_config = ConfigDict(frozen=True)

    content: list[dict[str, Any]]
    structured_content: dict[str, Any] | None = None
    is_error: bool = False
    size_bytes: int = 0


class UpstreamMcpPort(Protocol):
    async def list_tools(
        self, server: UpstreamServer, *, token: str | None
    ) -> list[ToolDefinition]: ...

    async def call_tool(
        self,
        server: UpstreamServer,
        name: str,
        arguments: dict[str, Any],
        *,
        token: str | None,
        max_response_bytes: int,
    ) -> UpstreamToolCall: ...


class RemoteAgentPort(Protocol):
    async def fetch_card(self, url: str) -> dict[str, Any]: ...

    async def call(
        self, url: str, method: str, params: dict[str, Any], *, token: str, max_response_bytes: int
    ) -> dict[str, Any]: ...
