"""JWKS retrieval with caching, and JWT verification against the injected clock."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import datetime
from typing import Any, Protocol

import httpx
import jwt

from mcp_a2a_gateway.domain.errors import UnauthorizedError

ACCEPTED_ALGORITHMS: tuple[str, ...] = ("EdDSA", "ES256", "RS256")


class KeyResolver(Protocol):
    async def key_for(self, kid: str) -> Any: ...


def _parse(document: dict[str, Any]) -> dict[str, Any]:
    keys: dict[str, Any] = {}
    for jwk in document.get("keys", []):
        if isinstance(jwk, dict) and isinstance(jwk.get("kid"), str):
            keys[jwk["kid"]] = jwt.PyJWK(jwk).key
    return keys


class StaticJwks:
    """Resolver backed by a JWKS document supplied in configuration."""

    def __init__(self, jwks: dict[str, Any]) -> None:
        self._keys = _parse(jwks)

    async def key_for(self, kid: str) -> Any:
        key = self._keys.get(kid)
        if key is None:
            raise UnauthorizedError(f"unknown signing key {kid!r}")
        return key


class RemoteJwks:
    """Fetches a JWKS URL, caches it, and refreshes once on an unknown ``kid``.

    Refreshes are rate limited so a stream of tokens with random ``kid``
    values cannot be used to hammer the issuer. Redirects are not followed.
    """

    def __init__(
        self,
        url: str,
        *,
        client: httpx.AsyncClient,
        ttl_s: float = 300.0,
        min_refresh_interval_s: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url
        self._client = client
        self._ttl = ttl_s
        self._min_refresh = min_refresh_interval_s
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None

    async def _refresh(self) -> None:
        response = await self._client.get(self._url, follow_redirects=False)
        response.raise_for_status()
        document = response.json()
        if not isinstance(document, dict):
            raise ValueError("JWKS document must be an object")
        self._keys = _parse(document)
        self._fetched_at = self._clock()

    async def key_for(self, kid: str) -> Any:
        now = self._clock()
        stale = self._fetched_at is None or now - self._fetched_at > self._ttl
        may_refresh = self._fetched_at is None or now - self._fetched_at >= self._min_refresh
        if stale or (kid not in self._keys and may_refresh):
            try:
                await self._refresh()
            except (httpx.HTTPError, ValueError, jwt.PyJWTError) as exc:
                if kid not in self._keys:
                    raise UnauthorizedError(f"cannot fetch signing keys from {self._url}") from exc
        key = self._keys.get(kid)
        if key is None:
            raise UnauthorizedError(f"unknown signing key {kid!r}")
        return key


async def verify_jwt(
    token: str,
    resolver: KeyResolver,
    *,
    issuer: str,
    audience: str,
    now: datetime,
    algorithms: tuple[str, ...] = ACCEPTED_ALGORITHMS,
    leeway_s: int = 30,
) -> dict[str, Any]:
    """Verify signature, issuer and audience; check time claims against ``now``.

    Rejects ``alg: none`` and any algorithm outside ``algorithms``; the
    algorithm is pinned to the header value so key-type confusion fails.
    """
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise UnauthorizedError("malformed token") from exc
    alg = header.get("alg")
    kid = header.get("kid")
    if alg not in algorithms or not isinstance(kid, str):
        raise UnauthorizedError("token algorithm or key id not accepted")
    key = await resolver.key_for(kid)
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            key=key,
            algorithms=[alg],
            issuer=issuer,
            audience=audience,
            options={
                "require": ["exp", "iat", "iss", "sub", "aud"],
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise UnauthorizedError(f"token rejected: {type(exc).__name__}") from exc
    instant = now.timestamp()
    exp, iat, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf")
    if not isinstance(exp, int | float) or not isinstance(iat, int | float):
        raise UnauthorizedError("token time claims are not numeric")
    if exp + leeway_s <= instant:
        raise UnauthorizedError("token expired")
    if iat - leeway_s > instant:
        raise UnauthorizedError("token issued in the future")
    if isinstance(nbf, int | float) and nbf - leeway_s > instant:
        raise UnauthorizedError("token not yet valid")
    return claims
