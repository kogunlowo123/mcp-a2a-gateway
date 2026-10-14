"""Administrator authentication via the enterprise OIDC provider."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from mcp_a2a_gateway.domain.errors import ForbiddenError, UnauthorizedError
from mcp_a2a_gateway.domain.ports import Clock
from mcp_a2a_gateway.security.jwks import KeyResolver, verify_jwt


class AdminPrincipal(BaseModel):
    model_config = ConfigDict(frozen=True)

    subject: str
    roles: frozenset[str]


class AdminRole:
    ADMIN = "gateway-admin"  # register upstream servers and agent cards, run discovery
    REVIEWER = "gateway-reviewer"  # approve, deprecate and revoke tools and agent cards
    APPROVER = "gateway-approver"  # approve or deny individual high-risk calls
    AUDITOR = "gateway-auditor"  # read-only inventory and audit verification


READERS = (AdminRole.ADMIN, AdminRole.REVIEWER, AdminRole.APPROVER, AdminRole.AUDITOR)


class AdminAuthenticator:
    def __init__(
        self,
        resolver: KeyResolver,
        *,
        issuer: str,
        audience: str,
        clock: Clock,
        roles_claim: str = "roles",
    ) -> None:
        self._resolver = resolver
        self._issuer = issuer
        self._audience = audience
        self._clock = clock
        self._roles_claim = roles_claim

    async def authenticate(self, authorization: str | None) -> AdminPrincipal:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise UnauthorizedError("bearer token required")
        claims = await verify_jwt(
            authorization[7:].strip(),
            self._resolver,
            issuer=self._issuer,
            audience=self._audience,
            now=self._clock.now(),
        )
        raw = claims.get(self._roles_claim, [])
        roles = (
            frozenset(r for r in raw if isinstance(r, str))
            if isinstance(raw, list)
            else frozenset()
        )
        return AdminPrincipal(subject=str(claims["sub"]), roles=roles)


def require_role(principal: AdminPrincipal, *allowed: str) -> None:
    if not principal.roles.intersection(allowed):
        raise ForbiddenError(f"requires one of roles {sorted(allowed)}")
