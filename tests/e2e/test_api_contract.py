"""Property-based API contract test: no generated input may cause a 5xx."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import schemathesis
from fastapi.testclient import TestClient
from hypothesis import HealthCheck, assume, settings

from mcp_a2a_gateway.api.app import create_app
from mcp_a2a_gateway.runtime.container import Container
from tests.conftest import (
    FakeClock,
    FakeIdp,
    FakeMonotonic,
    Network,
    Upstreams,
    make_container,
    make_settings,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def client(tmp_path: Path, network: Network, admin_idp: FakeIdp) -> Iterator[TestClient]:
    """App whose container is built inside the TestClient's own event loop by its lifespan."""
    settings = make_settings(tmp_path, network)

    async def factory() -> Container:
        return await make_container(
            settings,
            network=network,
            upstreams=Upstreams(),
            admin_idp=admin_idp,
            clock=FakeClock(),
            monotonic=FakeMonotonic(),
        )

    with TestClient(create_app(factory), base_url="https://gateway.corp.test") as test_client:
        yield test_client


@pytest.fixture
def api_schema(client: TestClient) -> Any:
    return schemathesis.openapi.from_dict(client.get("/openapi.json").json())


schema = schemathesis.pytest.from_fixture("api_schema")


@schema.parametrize()
@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
def test_no_server_errors(case: Any, client: TestClient) -> None:
    # Header values must be transmittable over HTTP/1.1 at all.
    assume(all(str(v).isascii() for v in (case.headers or {}).values()))
    kwargs = case.as_transport_kwargs(base_url="")
    response = client.request(
        kwargs["method"],
        kwargs["url"],
        params=kwargs.get("params"),
        headers=kwargs.get("headers"),
        json=kwargs.get("json"),
        data=kwargs.get("data"),
        content=kwargs.get("content"),
    )
    assert response.status_code < 500, (case.method, case.path, response.text)
