"""Authentication of agents calling the MCP and A2A endpoints.

Three credential sources, tried by the token's issuer:

* **Federated trust domains** - tokens from a configured partner issuer are
  verified against that domain's JWKS and confined to the domain's inbound
  scope ceiling.
* **Identity fabric** (preferred for local agents) - RFC 7662 introspection,
  which also enforces revocation, suspension epochs and the delegation chain.
* **Local JWKS** - signature verification when no fabric is configured.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

from mcp_a2a_gateway.domain.errors import UnauthorizedError
from mcp_a2a_gateway.domain.models import Principal, matches_any
from mcp_a2a_gateway.domain.ports import Clock, IdentityFabricPort
from mcp_a2a_gateway.security.jwks import KeyResolver, verify_jwt

MAX_CHAIN = 10


@dataclass(frozen=True)
class TokenSource:
    issuer: str
    audience: str
    resolver: KeyResolver


@dataclass(frozen=True)
class FederatedSource(TokenSource):
    trust_domain: str
    inbound_scopes: tuple[str, ...]


def flatten_actors(act: Any) -> tuple[str, ...]:
    """RFC 8693 nested ``act`` claim to an ordered chain, nearest actor first."""
    chain: list[str] = []
    current = act
    while isinstance(current, dict) and len(chain) < MAX_CHAIN:
        sub = current.get("sub")
        if not isinstance(sub, str) or not sub:
            raise UnauthorizedError("malformed act claim")
        chain.append(sub)
        current = current.get("act")
    if current is not None:
        raise UnauthorizedError("delegation chain too deep or malformed")
    return tuple(chain)


def peek_issuer(token: str) -> str | None:
    """Read ``iss`` without verification, only to choose which verifier applies.

    Nothing read here is trusted: the selected verifier checks the signature,
    issuer and audience before any claim is used.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise UnauthorizedError("malformed token")
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (binascii.Error, ValueError) as exc:
        raise UnauthorizedError("malformed token") from exc
    if not isinstance(payload, dict):
        raise UnauthorizedError("malformed token")
    issuer = payload.get("iss")
    return issuer if isinstance(issuer, str) else None


def bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise UnauthorizedError("agent bearer token required")
    token = authorization[7:].strip()
    if not token:
        raise UnauthorizedError("agent bearer token required")
    return token


class AgentAuthenticator:
    def __init__(
        self,
        *,
        trust_domain: str,
        audience: str,
        clock: Clock,
        fabric: IdentityFabricPort | None = None,
        local: TokenSource | None = None,
        federated: tuple[FederatedSource, ...] = (),
    ) -> None:
        if fabric is None and local is None:
            raise ValueError("an identity fabric or a local token source is required")
        self._trust_domain = trust_domain
        self._audience = audience
        self._clock = clock
        self._fabric = fabric
        self._local = local
        self._federated = {f.issuer: f for f in federated}

    async def authenticate(self, authorization: str | None) -> Principal:
        token = bearer_token(authorization)
        issuer = peek_issuer(token)
        if issuer is not None and issuer in self._federated:
            return await self._federation(token, self._federated[issuer])
        if self._fabric is not None:
            return await self._introspect(token)
        if self._local is None:  # pragma: no cover - guarded in __init__
            raise UnauthorizedError("no credential source configured")
        claims = await verify_jwt(
            token,
            self._local.resolver,
            issuer=self._local.issuer,
            audience=self._local.audience,
            now=self._clock.now(),
        )
        return self._principal(token, claims, "jwks")

    async def _introspect(self, token: str) -> Principal:
        if self._fabric is None:  # pragma: no cover - caller checks
            raise UnauthorizedError("identity fabric not configured")
        result = await self._fabric.introspect(token)
        if not result.active or result.sub is None:
            raise UnauthorizedError("credential is not active")
        if result.aud != self._audience:
            raise UnauthorizedError("credential audience not accepted")
        claims = {"sub": result.sub, "scope": result.scope or "", "act": result.act}
        return self._principal(token, claims, "fabric")

    def _principal(self, token: str, claims: dict[str, Any], source: str) -> Principal:
        subject = str(claims["sub"])
        if not subject.startswith(f"spiffe://{self._trust_domain}/"):
            raise UnauthorizedError("credential subject is outside this trust domain")
        scope = claims.get("scope", "")
        return Principal(
            subject=subject,
            scopes=frozenset(scope.split()) if isinstance(scope, str) else frozenset(),
            delegation_chain=flatten_actors(claims.get("act")),
            trust_domain=self._trust_domain,
            authenticated_by=source,
            token=token,
        )

    async def _federation(self, token: str, source: FederatedSource) -> Principal:
        claims = await verify_jwt(
            token,
            source.resolver,
            issuer=source.issuer,
            audience=source.audience,
            now=self._clock.now(),
        )
        subject = str(claims["sub"])
        if not subject.startswith(f"spiffe://{source.trust_domain}/"):
            raise UnauthorizedError("federated subject does not belong to its trust domain")
        raw = claims.get("scope", "")
        granted = frozenset(raw.split()) if isinstance(raw, str) else frozenset()
        # Scopes outside the domain's inbound ceiling are dropped, never widened.
        scopes = frozenset(s for s in granted if matches_any(s, source.inbound_scopes))
        return Principal(
            subject=subject,
            scopes=scopes,
            delegation_chain=flatten_actors(claims.get("act")),
            trust_domain=source.trust_domain,
            federated=True,
            authenticated_by=f"federation:{source.trust_domain}",
            token=token,
        )
