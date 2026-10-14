"""Upstream MCP client built on the official SDK ``Client`` over Streamable HTTP.

Each operation opens its own short-lived connection, so no upstream session
is ever shared between agents. The HTTP transport counts response bytes and
aborts as soon as the configured limit is crossed, before the body is
parsed. Protocol negotiation (``server/discover`` with fallback to the
``initialize`` handshake) is left to the SDK.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any, TypeVar

import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp_types import Implementation, Tool

from mcp_a2a_gateway import __version__
from mcp_a2a_gateway.domain.errors import (
    ResponseTooLargeError,
    UpstreamError,
    UpstreamTimeoutError,
)
from mcp_a2a_gateway.domain.models import ToolDefinition, UpstreamServer
from mcp_a2a_gateway.domain.ports import UpstreamToolCall

MAX_LIST_PAGES = 50
_T = TypeVar("_T")


class _CountingStream(httpx2.AsyncByteStream):
    def __init__(self, inner: httpx2.AsyncByteStream, guard: LimitedTransport) -> None:
        self._inner = inner
        self._guard = guard

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for chunk in self._inner:
            self._guard.received += len(chunk)
            if self._guard.received > self._guard.limit:
                self._guard.exceeded = True
                raise ResponseTooLargeError(f"upstream response exceeded {self._guard.limit} bytes")
            yield chunk

    async def aclose(self) -> None:
        await self._inner.aclose()


class LimitedTransport(httpx2.AsyncBaseTransport):
    """Enforces a byte ceiling on every response body passing through it."""

    def __init__(self, inner: httpx2.AsyncBaseTransport, limit: int) -> None:
        self._inner = inner
        self.limit = limit
        self.received = 0
        self.exceeded = False

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        self.received = 0
        response = await self._inner.handle_async_request(request)
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self.limit:
            await response.aclose()
            self.exceeded = True
            raise ResponseTooLargeError(f"upstream response declares {declared} bytes")
        if not isinstance(response.stream, httpx2.AsyncByteStream):  # pragma: no cover
            raise UpstreamError("upstream transport returned a synchronous stream")
        return httpx2.Response(
            status_code=response.status_code,
            headers=response.headers,
            stream=_CountingStream(response.stream, self),
            request=request,
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


TransportFactory = Callable[[], httpx2.AsyncBaseTransport]


def _definition(tool: Tool) -> ToolDefinition:
    annotations = (
        tool.annotations.model_dump(mode="json", by_alias=True, exclude_none=True)
        if tool.annotations is not None
        else None
    )
    return ToolDefinition(
        name=tool.name,
        title=tool.title,
        description=tool.description or "",
        input_schema=dict(tool.input_schema),
        output_schema=dict(tool.output_schema) if tool.output_schema is not None else None,
        annotations=annotations or None,
    )


def _translate(
    exc: Exception, server: UpstreamServer, transport: LimitedTransport, limit: int
) -> UpstreamError:
    if transport.exceeded:
        return ResponseTooLargeError(f"upstream response exceeded {limit} bytes")
    if isinstance(exc, UpstreamError):
        return exc
    if isinstance(exc, TimeoutError):
        return UpstreamTimeoutError(f"upstream {server.server_id} timed out")
    if isinstance(exc, MCPError):
        # Upstream error text is untrusted; only the code is relayed.
        return UpstreamError(
            f"upstream {server.server_id} returned JSON-RPC error {exc.code}",
            data={"upstream_code": exc.code},
        )
    return UpstreamError(f"upstream {server.server_id} failed: {type(exc).__name__}")


class SdkUpstreamClient:
    def __init__(self, transport_factory: TransportFactory | None = None) -> None:
        self._transport_factory = transport_factory or (
            lambda: httpx2.AsyncHTTPTransport(retries=0)
        )

    async def _run(
        self,
        server: UpstreamServer,
        token: str | None,
        limit: int,
        operation: Callable[[Client], Awaitable[_T]],
    ) -> tuple[_T, int]:
        transport = LimitedTransport(self._transport_factory(), limit)
        headers = {"User-Agent": f"mcp-a2a-gateway/{__version__}"}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        http = httpx2.AsyncClient(
            transport=transport,
            headers=headers,
            timeout=httpx2.Timeout(server.timeout_seconds),
            follow_redirects=False,
        )
        try:
            async with asyncio.timeout(server.timeout_seconds), http:
                connection = streamable_http_client(str(server.url), http_client=http)
                async with Client(
                    connection,
                    mode="auto",
                    cache=None,
                    read_timeout_seconds=server.timeout_seconds,
                    client_info=Implementation(name="mcp-a2a-gateway", version=__version__),
                ) as client:
                    result = await operation(client)
            return result, transport.received
        except Exception as exc:
            raise _translate(exc, server, transport, limit) from exc

    async def list_tools(
        self, server: UpstreamServer, *, token: str | None
    ) -> list[ToolDefinition]:
        async def walk(client: Client) -> list[ToolDefinition]:
            tools: list[ToolDefinition] = []
            cursor: str | None = None
            for _ in range(MAX_LIST_PAGES):
                page = await client.list_tools(cursor=cursor)
                tools.extend(_definition(tool) for tool in page.tools)
                cursor = page.next_cursor
                if cursor is None:
                    return tools
            raise UpstreamError(f"upstream {server.server_id} tools/list did not terminate")

        tools, _ = await self._run(server, token, server.max_response_bytes, walk)
        return tools

    async def call_tool(
        self,
        server: UpstreamServer,
        name: str,
        arguments: dict[str, Any],
        *,
        token: str | None,
        max_response_bytes: int,
    ) -> UpstreamToolCall:
        async def call(client: Client) -> UpstreamToolCall:
            result = await client.call_tool(name, arguments)
            return UpstreamToolCall(
                content=[
                    block.model_dump(mode="json", by_alias=True, exclude_none=True)
                    for block in result.content
                ],
                structured_content=result.structured_content,
                is_error=bool(result.is_error),
            )

        outcome, size = await self._run(server, token, max_response_bytes, call)
        return outcome.model_copy(update={"size_bytes": size})
