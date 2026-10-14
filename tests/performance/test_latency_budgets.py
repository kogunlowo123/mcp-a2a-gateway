"""Latency budgets for hot paths. Loose enough for shared CI runners."""

from __future__ import annotations

import time

import pytest
from agentic_core.domain.classification import DataClassification, RiskLevel
from agentic_core.policy import PolicyEngine, PolicySet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_a2a_gateway.application.authorization import Authorizer, Target
from mcp_a2a_gateway.domain.models import Principal
from mcp_a2a_gateway.runtime.container import Container
from mcp_a2a_gateway.security.card_signatures import sign_card, verify_card
from mcp_a2a_gateway.security.inspection import ContentInspector, mcp_text_fields
from mcp_a2a_gateway.security.jwks import StaticJwks
from tests.conftest import ROOT, FakeFabric, card_jwks, onboard_crm, partner_card, principal_for

pytestmark = pytest.mark.performance


async def test_local_authorization_budget() -> None:
    authorizer = Authorizer(
        PolicyEngine(PolicySet.from_file(ROOT / "policies" / "gateway-authorization.yaml")), None
    )
    principal = Principal(
        subject="spiffe://agents.corp.test/agent/sales/planner",
        scopes=frozenset({"mcp:crm:*"}),
        trust_domain="agents.corp.test",
        authenticated_by="jwks",
        token="t",
    )
    target = Target(
        resource_type="mcp_tool",
        resource_id="crm__lookup_customer",
        action="mcp:crm:lookup_customer",
        risk=RiskLevel.LOW,
        classification=DataClassification.CONFIDENTIAL,
        attributes={
            "lifecycle": "approved",
            "allow_listed": True,
            "past_sunset": False,
            "destructive": False,
            "requires_approval": False,
            "within_caller_ceiling": True,
            "delegation_within_limit": True,
        },
    )
    started = time.perf_counter()
    for _ in range(1000):
        outcome = await authorizer.decide(principal, target, approval_granted=False)
    per_call_ms = (time.perf_counter() - started) * 1000 / 1000
    assert outcome.decision.value == "allow"
    assert per_call_ms < 2


def test_output_inspection_budget() -> None:
    inspector = ContentInspector()
    text = ("Quarterly usage for account 4471 rose 12 percent; contact the owner. " * 900)[:64_000]
    payload = {"content": [{"type": "text", "text": text}], "structured": None}
    started = time.perf_counter()
    for _ in range(20):
        verdict, _ = inspector.inspect_projected(payload, mcp_text_fields, redact_pii=True)
    per_call_ms = (time.perf_counter() - started) * 1000 / 20
    assert not verdict.blocked
    # ~3 ms per KB on a developer workstation (agentic-core regex detectors); 2x headroom.
    assert per_call_ms < 500


async def test_card_verification_budget() -> None:
    key = Ed25519PrivateKey.generate()
    signed = sign_card(partner_card(), key, kid="partner-cards-1")
    resolver = StaticJwks(card_jwks(key))
    started = time.perf_counter()
    for _ in range(200):
        await verify_card(signed, resolver)
    # About 1 ms on a workstation; the suite runs under branch-coverage tracing in CI.
    assert (time.perf_counter() - started) * 1000 / 200 < 20


async def test_governed_call_budget(container: Container, fabric: FakeFabric) -> None:
    """Full path through fabric checks, drift cache, SDK upstream and inspection."""
    await onboard_crm(container, tools=("lookup_customer",))
    principal = await principal_for(container, fabric, {"mcp:crm:*"})
    await container.mcp.call(principal, "crm__lookup_customer", {"customer_id": "C-0"})
    started = time.perf_counter()
    for i in range(10):
        await container.mcp.call(principal, "crm__lookup_customer", {"customer_id": f"C-{i}"})
    per_call_ms = (time.perf_counter() - started) * 1000 / 10
    assert per_call_ms < 1500
