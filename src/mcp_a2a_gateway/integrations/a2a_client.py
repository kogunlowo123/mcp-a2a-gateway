"""Outbound A2A: agent card retrieval and JSON-RPC calls to federated agents."""

from __future__ import annotations

import json
from typing import Any

import httpx
from agentic_core.domain.identifiers import new_id

from mcp_a2a_gateway import __version__
from mcp_a2a_gateway.domain.errors import (
    GatewayError,
    ResponseTooLargeError,
    UpstreamError,
    UpstreamTimeoutError,
)

CARD_MAX_BYTES = 262_144


class RemoteAgentError(GatewayError):
    """The remote agent answered with a JSON-RPC error object."""

    code = "remote_agent_error"
    status = 502

    def __init__(self, remote_code: int) -> None:
        super().__init__(
            f"remote agent returned JSON-RPC error {remote_code}",
            data={"remote_code": remote_code},
        )
        self.rpc_code = remote_code if -32099 <= remote_code <= -32000 else -32603


async def _read_limited(response: httpx.Response, limit: int) -> bytes:
    declared = response.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise ResponseTooLargeError(f"response declares {declared} bytes, limit {limit}")
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) > limit:
            raise ResponseTooLargeError(f"response exceeded {limit} bytes")
    return bytes(body)


def _object(raw: bytes, what: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise UpstreamError(f"{what} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise UpstreamError(f"{what} is not a JSON object")
    return value


class HttpRemoteAgentClient:
    def __init__(self, client: httpx.AsyncClient, *, timeout_s: float) -> None:
        self._client = client
        self._timeout = httpx.Timeout(timeout_s)
        self._headers = {"User-Agent": f"mcp-a2a-gateway/{__version__}"}

    async def fetch_card(self, url: str) -> dict[str, Any]:
        try:
            async with self._client.stream(
                "GET", url, headers=self._headers, timeout=self._timeout, follow_redirects=False
            ) as response:
                if response.status_code != 200:
                    raise UpstreamError(f"agent card fetch returned HTTP {response.status_code}")
                raw = await _read_limited(response, CARD_MAX_BYTES)
        except httpx.TimeoutException as exc:
            raise UpstreamTimeoutError(f"agent card fetch from {url} timed out") from exc
        except httpx.HTTPError as exc:
            raise UpstreamError(f"agent card fetch failed: {type(exc).__name__}") from exc
        return _object(raw, "agent card")

    async def call(
        self, url: str, method: str, params: dict[str, Any], *, token: str, max_response_bytes: int
    ) -> dict[str, Any]:
        request_id = new_id()
        envelope = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        headers = {**self._headers, "Authorization": f"Bearer {token}"}
        try:
            async with self._client.stream(
                "POST",
                url,
                json=envelope,
                headers=headers,
                timeout=self._timeout,
                follow_redirects=False,
            ) as response:
                if response.status_code != 200:
                    raise UpstreamError(f"remote agent returned HTTP {response.status_code}")
                raw = await _read_limited(response, max_response_bytes)
        except httpx.TimeoutException as exc:
            raise UpstreamTimeoutError(f"remote agent at {url} timed out") from exc
        except httpx.HTTPError as exc:
            raise UpstreamError(f"remote agent call failed: {type(exc).__name__}") from exc
        reply = _object(raw, "remote agent response")
        if reply.get("jsonrpc") != "2.0" or reply.get("id") != request_id:
            raise UpstreamError("remote agent response does not match the request")
        error = reply.get("error")
        if isinstance(error, dict):
            code = error.get("code")
            raise RemoteAgentError(code if isinstance(code, int) else -32603)
        result = reply.get("result")
        if not isinstance(result, dict):
            raise UpstreamError("remote agent response has no result object")
        return result
