"""FastAPI application factory."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from agentic_core.observability import bind_correlation_id, get_logger
from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.routing import Route

from mcp_a2a_gateway import __version__
from mcp_a2a_gateway.api import a2a_endpoint
from mcp_a2a_gateway.api.a2a_endpoint import HttpRpcError
from mcp_a2a_gateway.api.mcp_endpoint import McpHttpGate, build_mcp
from mcp_a2a_gateway.api.routes import router
from mcp_a2a_gateway.domain.errors import RPC_INVALID_REQUEST, GatewayError
from mcp_a2a_gateway.runtime.container import Container

ContainerFactory = Callable[[], Awaitable[Container]]

log = get_logger("mcp_a2a_gateway.api")


def create_app(factory: ContainerFactory) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        container = await factory()
        server, transport = build_mcp(container)
        app.state.container = container
        app.state.mcp_transport = transport
        log.info("startup", version=__version__, chain=container.audit_sink.chain_id)
        try:
            async with server.session_manager.run():
                yield
        finally:
            await container.aclose()

    app = FastAPI(
        title="MCP and A2A Enterprise Gateway",
        version=__version__,
        description=(
            "Governed federation of MCP tools and A2A agents: registration, schema pinning, "
            "approval lifecycle, delegated authority, content inspection and signed audit."
        ),
        lifespan=lifespan,
    )
    app.include_router(router)
    app.include_router(a2a_endpoint.router)
    app.router.routes.append(Route("/mcp", endpoint=McpHttpGate()))

    @app.middleware("http")
    async def correlation_and_metrics(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        incoming = request.headers.get("x-correlation-id")
        cid = incoming if incoming and len(incoming) <= 64 and incoming.isprintable() else None
        started = time.perf_counter()
        with bind_correlation_id(cid) as bound:
            response = await call_next(request)
        response.headers["X-Correlation-ID"] = bound
        response.headers["X-Content-Type-Options"] = "nosniff"
        route = request.scope.get("route")
        path = getattr(route, "path", "unmatched")
        container: Container | None = getattr(request.app.state, "container", None)
        if container is not None:
            container.metrics.requests.labels(
                request.method, path, str(response.status_code)
            ).observe(time.perf_counter() - started)
        return response

    @app.exception_handler(GatewayError)
    async def gateway_error(_: Request, exc: GatewayError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else None
        return JSONResponse(
            status_code=exc.status,
            content={"error": exc.code, "error_description": exc.message, **exc.data},
            headers=headers,
        )

    @app.exception_handler(HttpRpcError)
    async def rpc_http_error(_: Request, exc: HttpRpcError) -> JSONResponse:
        return exc.response()

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            {"loc": [str(p) for p in e.get("loc", ())], "msg": str(e.get("msg", ""))}
            for e in exc.errors()
        ]
        if request.url.path == "/a2a":
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": RPC_INVALID_REQUEST,
                        "message": "invalid JSON-RPC request",
                        "data": {"details": details},
                    },
                },
            )
        return JSONResponse(
            status_code=422,
            content={
                "error": "invalid_request",
                "error_description": "request failed validation",
                "details": details,
            },
        )

    return app
