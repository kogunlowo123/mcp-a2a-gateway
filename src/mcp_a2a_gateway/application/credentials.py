"""Which credential the gateway presents to an upstream MCP server or a federated agent.

The caller's own token is never forwarded (MCP forbids token passthrough).
Delegated access uses RFC 8693 token exchange at the identity fabric: the
result names the calling agent as subject and the gateway as actor, and is
narrowed to the single scope that authorizes the call.
"""

from __future__ import annotations

from collections.abc import Mapping

from mcp_a2a_gateway.domain.errors import ForbiddenError, UpstreamError
from mcp_a2a_gateway.domain.models import Principal, UpstreamAuthMode, UpstreamServer
from mcp_a2a_gateway.integrations.identity_fabric import FabricClient


class UpstreamCredentials:
    def __init__(self, *, fabric: FabricClient | None, env: Mapping[str, str]) -> None:
        self._fabric = fabric
        self._env = env

    def _static(self, server: UpstreamServer) -> str:
        name = server.auth.secret_env or ""
        value = self._env.get(name, "").strip()
        if not value:
            raise UpstreamError(f"credential {name} for upstream {server.server_id} is not mounted")
        return value

    async def gateway_token(self) -> str:
        if self._fabric is None or self._fabric.credential is None:
            raise ForbiddenError(
                "this gateway has no fabric identity (GATEWAY_GATEWAY_AGENT_ID not configured)"
            )
        return await self._fabric.credential.token()

    async def for_gateway(self, server: UpstreamServer) -> str | None:
        """Credential for gateway-initiated requests (discovery, drift checks)."""
        match server.auth.mode:
            case UpstreamAuthMode.NONE:
                return None
            case UpstreamAuthMode.STATIC_BEARER:
                return self._static(server)
            case UpstreamAuthMode.DELEGATED:
                return await self.gateway_token()

    async def for_call(
        self, server: UpstreamServer, principal: Principal, action: str
    ) -> str | None:
        match server.auth.mode:
            case UpstreamAuthMode.NONE:
                return None
            case UpstreamAuthMode.STATIC_BEARER:
                return self._static(server)
            case UpstreamAuthMode.DELEGATED:
                return await self.delegate(principal, action)

    async def delegate(self, principal: Principal, action: str) -> str:
        if self._fabric is None:
            raise ForbiddenError("delegated credentials require the identity fabric")
        if principal.federated:
            # A foreign credential cannot be re-delegated into another hop.
            raise ForbiddenError("federated callers cannot be delegated onward")
        scope = principal.matching_scope(action)
        if scope is None:
            raise ForbiddenError(f"no held scope covers {action}")
        return await self._fabric.exchange(principal.token, scope=scope)
