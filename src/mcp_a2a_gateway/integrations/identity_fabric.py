"""Typed client for the agent identity fabric.

Wire formats: RFC 7662 introspection, RFC 7523 jwt-bearer and RFC 8693
token exchange at ``/oauth2/*``, and the fabric's ``/v1/authorize`` policy
decision point. Every failure is fail-closed.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
from pydantic import ValidationError

from mcp_a2a_gateway.domain.errors import ForbiddenError, UnauthorizedError, UpstreamError
from mcp_a2a_gateway.domain.ports import Clock, FabricAuthorization, FabricIntrospection

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
# RFC 8693 identifiers, not credentials.
TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105  # nosec B105
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"  # noqa: S105  # nosec B105
REFRESH_MARGIN = timedelta(seconds=60)


class GatewayCredential:
    """The gateway's own fabric credential, obtained with its workload token and cached."""

    def __init__(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        agent_id: str,
        workload_token_file: Path,
        clock: Clock,
    ) -> None:
        self._client = client
        self._base = base_url.rstrip("/")
        self._agent_id = agent_id
        self._token_file = workload_token_file
        self._clock = clock
        self._token: str | None = None
        self._expires_at = clock.now()
        self._lock = asyncio.Lock()

    @property
    def agent_id(self) -> str:
        return self._agent_id

    async def token(self) -> str:
        async with self._lock:
            if self._token is None or self._clock.now() >= self._expires_at - REFRESH_MARGIN:
                await self._obtain()
            if self._token is None:  # pragma: no cover - _obtain sets or raises
                raise UpstreamError("gateway credential unavailable")
            return self._token

    async def _obtain(self) -> None:
        # Projected service-account tokens rotate on disk; read on every refresh.
        workload_token = (await asyncio.to_thread(self._token_file.read_text, "utf-8")).strip()
        body = await _post_form(
            self._client,
            f"{self._base}/oauth2/token",
            {"grant_type": JWT_BEARER, "client_id": self._agent_id, "assertion": workload_token},
        )
        token, expires_in = body.get("access_token"), body.get("expires_in")
        if not isinstance(token, str) or not isinstance(expires_in, int):
            raise UpstreamError("identity fabric returned a malformed token response")
        self._token = token
        self._expires_at = self._clock.now() + timedelta(seconds=expires_in)


async def _post_form(client: httpx.AsyncClient, url: str, data: dict[str, str]) -> dict[str, Any]:
    try:
        response = await client.post(url, data=data, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise UpstreamError(f"identity fabric unreachable: {type(exc).__name__}") from exc
    if response.status_code == 400:
        error = _error(response)
        raise ForbiddenError(f"identity fabric refused the grant: {error}")
    if response.status_code != 200:
        raise UpstreamError(f"identity fabric returned HTTP {response.status_code}")
    return _json_object(response)


def _error(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return "invalid_request"
    if isinstance(body, dict):
        return str(body.get("error_description") or body.get("error") or "invalid_request")
    return "invalid_request"


def _json_object(response: httpx.Response) -> dict[str, Any]:
    try:
        body = response.json()
    except ValueError as exc:
        raise UpstreamError("identity fabric returned invalid JSON") from exc
    if not isinstance(body, dict):
        raise UpstreamError("identity fabric returned a non-object body")
    return body


class FabricClient:
    def __init__(
        self,
        *,
        client: httpx.AsyncClient,
        base_url: str,
        credential: GatewayCredential | None = None,
    ) -> None:
        self._client = client
        self._base = base_url.rstrip("/")
        self._credential = credential

    @property
    def credential(self) -> GatewayCredential | None:
        return self._credential

    async def introspect(self, token: str) -> FabricIntrospection:
        body = await _post_form(self._client, f"{self._base}/oauth2/introspect", {"token": token})
        try:
            return FabricIntrospection.model_validate(body)
        except ValidationError as exc:
            raise UpstreamError("identity fabric returned a malformed introspection") from exc

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
    ) -> FabricAuthorization:
        try:
            response = await self._client.post(
                f"{self._base}/v1/authorize",
                json={
                    "action": action,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "resource_classification": classification,
                    "resource_attributes": attributes,
                    "environment": environment,
                },
                headers={"Authorization": f"Bearer {token}"},
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise UpstreamError(f"identity fabric unreachable: {type(exc).__name__}") from exc
        if response.status_code == 401:
            raise UnauthorizedError("identity fabric rejected the credential")
        if response.status_code != 200:
            raise UpstreamError(f"identity fabric returned HTTP {response.status_code}")
        try:
            return FabricAuthorization.model_validate(_json_object(response))
        except ValidationError as exc:
            raise UpstreamError("identity fabric returned a malformed decision") from exc

    async def exchange(self, subject_token: str, *, scope: str) -> str:
        if self._credential is None:
            raise ForbiddenError("delegated credentials need GATEWAY_GATEWAY_AGENT_ID configured")
        actor = await self._credential.token()
        body = await _post_form(
            self._client,
            f"{self._base}/oauth2/token",
            {
                "grant_type": TOKEN_EXCHANGE,
                "subject_token": subject_token,
                "subject_token_type": JWT_TOKEN_TYPE,
                "actor_token": actor,
                "actor_token_type": JWT_TOKEN_TYPE,
                "scope": scope,
            },
        )
        token = body.get("access_token")
        if not isinstance(token, str):
            raise UpstreamError("identity fabric returned a malformed token response")
        return token
