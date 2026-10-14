"""Fault injection: every dependency failure fails closed and is observable."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from mcp_a2a_gateway.application.federation import TARGET_KEY
from mcp_a2a_gateway.domain.errors import (
    CircuitOpenError,
    UnauthorizedError,
    UpstreamError,
    UpstreamTimeoutError,
)
from mcp_a2a_gateway.infrastructure.database import make_engine
from mcp_a2a_gateway.runtime.container import Container
from tests.conftest import (
    PARTNER,
    FakeFabric,
    FakeMonotonic,
    Gateway,
    Network,
    Upstreams,
    onboard_crm,
    onboard_partner,
    principal_for,
)

pytestmark = pytest.mark.chaos

LOOKUP = {"customer_id": "C-1"}


async def test_identity_fabric_outage_fails_closed(
    container: Container, fabric: FakeFabric
) -> None:
    token = fabric.mint("spiffe://agents.corp.test/agent/sales/planner", {"mcp:crm:*"})
    fabric.down = True
    with pytest.raises(UpstreamError, match="503"):
        await container.authenticator.authenticate(f"Bearer {token}")


async def test_fabric_outage_mid_call_blocks_the_call(
    container: Container, fabric: FakeFabric, upstreams: Upstreams
) -> None:
    await onboard_crm(container, tools=("lookup_customer",))
    principal = await principal_for(container, fabric, {"mcp:crm:*"})
    fabric.down = True
    with pytest.raises(UpstreamError):
        await container.mcp.call(principal, "crm__lookup_customer", LOOKUP)
    assert upstreams.crm.calls == []


async def test_upstream_outage_opens_the_circuit_then_recovers(
    container: Container, fabric: FakeFabric, upstreams: Upstreams, monotonic: FakeMonotonic
) -> None:
    await onboard_crm(container, tools=("lookup_customer",))
    principal = await principal_for(container, fabric, {"mcp:crm:*"})
    healthy = upstreams.apps.pop("crm.corp.test")
    monotonic.advance(120)  # force a live definition refresh against the dead upstream
    for _ in range(5):
        with pytest.raises(UpstreamError):
            await container.mcp.call(principal, "crm__lookup_customer", LOOKUP)
    with pytest.raises(CircuitOpenError):
        await container.mcp.call(principal, "crm__lookup_customer", LOOKUP)
    upstreams.apps["crm.corp.test"] = healthy
    monotonic.advance(31)
    result = await container.mcp.call(principal, "crm__lookup_customer", LOOKUP)
    assert not result.is_error
    metrics = container.metrics.registry.get_sample_value(
        "gateway_upstream_errors_total", {"upstream": "crm", "error": "upstream_error"}
    )
    assert metrics == 5


async def test_audit_failure_blocks_the_call(
    container: Container, fabric: FakeFabric, upstreams: Upstreams
) -> None:
    """If evidence cannot be written, the action must not report success."""
    await onboard_crm(container, tools=("lookup_customer",))
    principal = await principal_for(container, fabric, {"mcp:crm:*"})

    async def broken_append(_: Any) -> None:
        raise OSError("audit store unavailable")

    container.audit_sink.append = broken_append  # type: ignore[method-assign]
    with pytest.raises(OSError, match="audit store unavailable"):
        await container.mcp.call(principal, "crm__lookup_customer", LOOKUP)


async def test_remote_agent_timeout(
    container: Container, fabric: FakeFabric, network: Network
) -> None:
    await onboard_partner(container)
    principal = await principal_for(container, fabric, {"a2a:send:partner-research"})
    original = network.partner_agent.handler

    def slow(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/a2a":
            raise httpx.ReadTimeout("remote stalled", request=request)
        return original(request)

    network.partner_agent.handler = slow  # type: ignore[method-assign]
    message = {
        "message": {
            "role": "user",
            "messageId": "m",
            "parts": [{"kind": "text", "text": "hello"}],
            "metadata": {TARGET_KEY: "partner-research"},
        }
    }
    with pytest.raises(UpstreamTimeoutError):
        await container.federation.send_message(principal, message)


async def test_partner_jwks_outage_rejects_federated_callers(
    container: Container, network: Network
) -> None:
    from mcp_a2a_gateway.security.jwks import RemoteJwks

    token = network.partner_idp.mint(sub=f"spiffe://{PARTNER}/agent/r/a", aud="mcp-a2a-gateway")
    authenticator = container.authenticator
    dead = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(503)))
    source = authenticator._federated["https://identity.partner.test"]
    authenticator._federated["https://identity.partner.test"] = type(source)(
        issuer=source.issuer,
        audience=source.audience,
        resolver=RemoteJwks("https://identity.partner.test/jwks", client=dead),
        trust_domain=source.trust_domain,
        inbound_scopes=source.inbound_scopes,
    )
    with pytest.raises(UnauthorizedError, match="cannot fetch"):
        await authenticator.authenticate(f"Bearer {token}")
    await dead.aclose()


async def test_database_outage_flips_readiness_only(gateway: Gateway) -> None:
    container = gateway.container
    assert (await gateway.http.get("/readyz")).status_code == 200
    healthy = container.engine
    container.engine = make_engine("sqlite+aiosqlite:////nonexistent/dir/db.sqlite")
    try:
        assert (await gateway.http.get("/readyz")).status_code == 503
        assert (await gateway.http.get("/healthz")).status_code == 200
    finally:
        await container.engine.dispose()
        container.engine = healthy
