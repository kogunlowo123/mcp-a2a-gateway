"""Interoperability with the real agent-identity-fabric service (in-process, no network).

The fabric issues real workload-attested EdDSA credentials, evaluates its own
authorization policy and performs RFC 8693 token exchange; the gateway uses
it exactly as in production.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
from agentic_core.domain.classification import DataClassification, RiskLevel
from identity_fabric.api.app import create_app as create_fabric_app
from identity_fabric.application.service import IdentityFabric, RegisterAgent
from identity_fabric.config import Settings as FabricSettings
from identity_fabric.domain.models import AgentMandate, AgentStatus, WorkloadBinding
from identity_fabric.runtime.container import build_container as build_fabric

from mcp_a2a_gateway.domain.errors import ForbiddenError, UnauthorizedError
from mcp_a2a_gateway.integrations.mcp_upstream import SdkUpstreamClient
from mcp_a2a_gateway.runtime.container import Container, build_container
from mcp_a2a_gateway.security.jwks import StaticJwks
from tests.conftest import (
    GATEWAY_ID,
    ROOT,
    TRUST_DOMAIN,
    FakeClock,
    FakeIdp,
    FakeMonotonic,
    Network,
    Upstreams,
    agent_uri,
    make_settings,
    onboard_crm,
)

pytestmark = pytest.mark.e2e

WORKLOAD_ISSUER = "https://oidc.eks.us-east-1.amazonaws.com/id/TESTCLUSTER"


def registration(namespace: str, name: str, scopes: set[str]) -> RegisterAgent:
    return RegisterAgent(
        namespace=namespace,
        name=name,
        display_name=f"{name} agent",
        mandate=AgentMandate(
            mission="Serve account managers with customer context and follow-ups.",
            business_owner="sales-operations",
            technical_owner="sales-platform",
            escalation_contact="sales-platform-oncall",
        ),
        scopes=frozenset(scopes),
        risk=RiskLevel.MODERATE,
        max_classification=DataClassification.CONFIDENTIAL,
        workload=WorkloadBinding(
            issuer=WORKLOAD_ISSUER,
            subject=f"system:serviceaccount:{namespace}:{name}",
            audience="identity-fabric",
        ),
    )


@dataclass
class Federation:
    fabric: IdentityFabric
    gateway: Container
    workload: FakeIdp

    async def credential(self, namespace: str, name: str) -> str:
        uri = f"spiffe://{TRUST_DOMAIN}/agent/{namespace}/{name}"
        workload = self.workload.mint(
            sub=f"system:serviceaccount:{namespace}:{name}", aud="identity-fabric"
        )
        issued = await self.fabric.issue_for_workload(uri, workload, scopes=None)
        return issued.access_token


@pytest.fixture
async def federation(
    tmp_path: Path,
    network: Network,
    upstreams: Upstreams,
    admin_idp: FakeIdp,
    clock: FakeClock,
    monotonic: FakeMonotonic,
) -> AsyncIterator[Federation]:
    workload_idp = FakeIdp(WORKLOAD_ISSUER, kid="cluster-1")
    fabric_settings = FabricSettings(
        environment="test",
        trust_domain=TRUST_DOMAIN,
        issuer="https://identity.corp.test",
        audience="agent-platform",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'fabric.db'}",
        dev_ephemeral_keys=True,
        audit_log_path=tmp_path / "fabric-audit.jsonl",
        workload_issuers={WORKLOAD_ISSUER: "https://unused.invalid/jwks"},
        admin_issuer="https://login.corp.test/tenant",
        admin_audience="identity-fabric-admin",
        admin_jwks_url="https://unused.invalid/admin-jwks",
        policy_file=ROOT / "tests" / "fixtures" / "identity-fabric-policy.yaml",
    )
    fabric_container = await build_fabric(
        fabric_settings,
        workload_resolvers={WORKLOAD_ISSUER: StaticJwks(workload_idp.jwks())},  # type: ignore[dict-item]
        admin_resolver=StaticJwks(admin_idp.jwks()),  # type: ignore[arg-type]
    )
    fabric_app = create_fabric_app(lambda: _ready(fabric_container))
    fabric_app.state.container = fabric_container
    service = fabric_container.fabric

    for namespace, name, scopes in (
        ("platform", "mcp-a2a-gateway", {"mcp:crm:*", "a2a:send:partner-research"}),
        ("sales", "planner", {"mcp:crm:*", "a2a:send:partner-research"}),
    ):
        await service.register(registration(namespace, name, scopes), actor="registrar")
        token = workload_idp.mint(
            sub=f"system:serviceaccount:{namespace}:{name}", aud="identity-fabric"
        )
        await service.attest(f"spiffe://{TRUST_DOMAIN}/agent/{namespace}/{name}", token)

    fabric_transport = httpx.ASGITransport(app=fabric_app)
    other = httpx.MockTransport(network.handler)

    class Router(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            if request.url.host == "identity.corp.test":
                return await fabric_transport.handle_async_request(request)
            return await other.handle_async_request(request)

    settings = make_settings(tmp_path, network)
    settings.workload_token_file.write_text(  # type: ignore[union-attr]
        workload_idp.mint(
            sub="system:serviceaccount:platform:mcp-a2a-gateway", aud="identity-fabric", ttl=3600
        ),
        encoding="utf-8",
    )
    gateway = await build_container(
        settings.model_copy(
            update={"policy_file": ROOT / "policies" / "gateway-authorization.yaml"}
        ),
        clock=clock,
        monotonic=monotonic,
        http=httpx.AsyncClient(transport=Router()),
        upstream=SdkUpstreamClient(transport_factory=upstreams.transport),
        admin_resolver=StaticJwks(admin_idp.jwks()),
        federation_resolvers={},
    )
    yield Federation(fabric=service, gateway=gateway, workload=workload_idp)
    await gateway.aclose()
    await fabric_container.aclose()


async def _ready(container: Any) -> Any:
    return container


async def test_governed_call_with_real_fabric(federation: Federation, upstreams: Upstreams) -> None:
    gateway = federation.gateway
    await onboard_crm(gateway, tools=("lookup_customer",))
    credential = await federation.credential("sales", "planner")
    principal = await gateway.authenticator.authenticate(f"Bearer {credential}")
    assert principal.subject == agent_uri("planner")
    assert principal.authenticated_by == "fabric"

    result = await gateway.mcp.call(principal, "crm__lookup_customer", {"customer_id": "C-42"})
    assert result.structured_content is not None
    assert result.structured_content["customer_id"] == "C-42"

    delegated = jwt.decode(
        upstreams.crm.headers[-1].removeprefix("Bearer "), options={"verify_signature": False}
    )
    assert delegated["sub"] == agent_uri("planner")
    assert delegated["act"] == {"sub": GATEWAY_ID}
    assert delegated["scope"] == "mcp:crm:*"

    # Suspension in the fabric takes effect on the very next call.
    await federation.fabric.set_status(
        agent_uri("planner"), AgentStatus.SUSPENDED, actor="secops", reason="investigation 31"
    )
    with pytest.raises(UnauthorizedError):
        await gateway.authenticator.authenticate(f"Bearer {credential}")


async def test_fabric_refuses_delegation_beyond_the_gateways_registration(
    federation: Federation,
) -> None:
    gateway = federation.gateway
    await onboard_crm(gateway, tools=("lookup_customer",))
    credential = await federation.credential("sales", "planner")
    principal = await gateway.authenticator.authenticate(f"Bearer {credential}")
    narrowed = principal.model_copy(update={"scopes": frozenset({"mcp:crm:lookup_customer"})})
    with pytest.raises(ForbiddenError, match="refused the grant"):
        await gateway.mcp.call(narrowed, "crm__lookup_customer", {"customer_id": "C-1"})
