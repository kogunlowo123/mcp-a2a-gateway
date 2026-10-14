"""The whole gateway over HTTP, as platform teams and agents use it.

Administrators use the REST API with enterprise OIDC tokens. Agents use the
official MCP SDK client against /mcp and A2A JSON-RPC against /a2a.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError

from mcp_a2a_gateway.application.federation import SKILL_KEY, TARGET_KEY
from mcp_a2a_gateway.application.mcp_gateway import APPROVAL_META_KEY
from mcp_a2a_gateway.security.admin import AdminRole
from tests.conftest import (
    CRM_URL,
    PARTNER,
    PARTNER_CARD_URL,
    FakeFabric,
    FakeIdp,
    Gateway,
    Network,
    admin_headers,
    agent_uri,
)

pytestmark = pytest.mark.e2e

ADMIN = AdminRole.ADMIN
REVIEWER = AdminRole.REVIEWER
APPROVER = AdminRole.APPROVER
AUDITOR = AdminRole.AUDITOR


def policy(risk: int = 1, **extra: Any) -> dict[str, Any]:
    return {
        "risk": risk,
        "classification": 2,
        "allowed_agents": ["spiffe://agents.corp.test/agent/sales/*"],
        **extra,
    }


async def onboard_over_http(gateway: Gateway, admin_idp: FakeIdp) -> None:
    http = gateway.http
    alice = admin_headers(admin_idp, ADMIN, sub="alice@corp.test")
    bob = admin_headers(admin_idp, REVIEWER, sub="bob@corp.test")
    created = await http.post(
        "/v1/servers",
        json={
            "server_id": "crm",
            "display_name": "CRM tools",
            "url": CRM_URL,
            "owner": "sales-platform",
        },
        headers=alice,
    )
    assert created.status_code == 201, created.text
    report = await http.post("/v1/servers/crm/discover", headers=alice)
    assert report.status_code == 200
    assert {c["change"] for c in report.json()["changes"]} == {"new"}
    for name, risk in (("lookup_customer", 1), ("create_ticket", 3)):
        approved = await http.post(
            f"/v1/tools/crm/{name}/versions/1/approve",
            json={"policy": policy(risk), "reason": "reviewed by sales security"},
            headers=bob,
        )
        assert approved.status_code == 200, approved.text


async def test_admin_api_authorization(gateway: Gateway, admin_idp: FakeIdp) -> None:
    http = gateway.http
    body = {"server_id": "crm", "display_name": "CRM", "url": CRM_URL, "owner": "sales"}
    assert (await http.post("/v1/servers", json=body)).status_code == 401
    auditor = admin_headers(admin_idp, AUDITOR)
    denied = await http.post("/v1/servers", json=body, headers=auditor)
    assert denied.status_code == 403
    assert denied.json()["error"] == "forbidden"
    assert (await http.get("/v1/servers", headers=auditor)).json() == {"items": []}
    invalid = await http.post(
        "/v1/servers", json={**body, "extra": 1}, headers=admin_headers(admin_idp, ADMIN)
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"] == "invalid_request"
    missing = await http.get("/v1/servers/nope", headers=auditor)
    assert missing.status_code == 404


async def test_mcp_tools_over_the_official_sdk(
    gateway: Gateway, admin_idp: FakeIdp, fabric: FakeFabric
) -> None:
    await onboard_over_http(gateway, admin_idp)
    token = fabric.mint(agent_uri(), {"mcp:crm:*"})
    async with (
        gateway.mcp_http(token) as http,
        Client(
            streamable_http_client("https://gateway.corp.test/mcp", http_client=http), cache=None
        ) as client,
    ):
        listed = await client.list_tools()
        names = sorted(t.name for t in listed.tools)
        assert names == [
            "crm__create_ticket",
            "crm__lookup_customer",
            "gateway__approval_status",
            "gateway__federated_agents",
        ]
        lookup = next(t for t in listed.tools if t.name == "crm__lookup_customer")
        assert lookup.meta is not None
        assert lookup.meta["mcp-a2a-gateway/version"] == 1

        result = await client.call_tool("crm__lookup_customer", {"customer_id": "C-7"})
        assert not result.is_error
        assert result.structured_content is not None
        assert result.structured_content["email"] == "[REDACTED:email]"

        args = {"customer_id": "C-7", "summary": "Replace damaged unit"}
        pending = await client.call_tool("crm__create_ticket", args)
        assert pending.is_error
        body = json.loads(pending.content[0].text)  # type: ignore[union-attr]
        assert body["error"] == "approval_required"
        approval_id = body["approval_id"]

        status = await client.call_tool("gateway__approval_status", {"approval_id": approval_id})
        assert status.structured_content is not None
        assert status.structured_content["status"] == "pending"

        decided = await gateway.http.post(
            f"/v1/approvals/{approval_id}/approve",
            json={"reason": "warranty claim verified"},
            headers=admin_headers(admin_idp, APPROVER, sub="carol@corp.test"),
        )
        assert decided.status_code == 200, decided.text

        created = await client.call_tool(
            "crm__create_ticket", args, meta={APPROVAL_META_KEY: approval_id}
        )
        assert not created.is_error
        assert created.structured_content == {
            "ticket_id": "T-1001",
            "customer_id": "C-7",
            "summary": "Replace damaged unit",
        }
        with pytest.raises(MCPError):
            await client.call_tool("crm__does_not_exist", {})
        with pytest.raises(MCPError):
            await client.call_tool("gateway__approval_status", {"approval_id": "0" * 32})
        agents = await client.call_tool("gateway__federated_agents", {})
        assert agents.structured_content == {"agents": []}

    listing = await gateway.http.get(
        "/v1/approvals", params={"status": "used"}, headers=admin_headers(admin_idp, AUDITOR)
    )
    assert [a["approval_id"] for a in listing.json()["items"]] == [approval_id]
    one = await gateway.http.get(
        f"/v1/approvals/{approval_id}", headers=admin_headers(admin_idp, AUDITOR)
    )
    assert one.json()["decided_by"] == "carol@corp.test"


async def test_mcp_endpoint_requires_authentication(gateway: Gateway, fabric: FakeFabric) -> None:
    response = await gateway.http.post(
        "/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    )
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert (
        'resource_metadata="https://gateway.corp.test/.well-known/oauth-protected-resource"'
        in challenge
    )
    metadata = (await gateway.http.get("/.well-known/oauth-protected-resource")).json()
    assert metadata["resource"] == "https://gateway.corp.test/mcp"
    assert metadata["authorization_servers"] == ["https://identity.corp.test"]
    fabric.down = True
    unavailable = await gateway.http.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers={"Authorization": f"Bearer {fabric.mint(agent_uri(), {'mcp:crm:*'})}"},
    )
    assert unavailable.status_code == 502


async def test_a2a_federation_over_json_rpc(
    gateway: Gateway, admin_idp: FakeIdp, fabric: FakeFabric, network: Network
) -> None:
    http = gateway.http
    card = (await http.get("/.well-known/agent-card.json")).json()
    assert card["url"] == "https://gateway.corp.test/a2a"
    assert card["securitySchemes"]["agentIdentity"]["type"] == "oauth2"
    assert card["supportsAuthenticatedExtendedCard"] is True

    registered = await http.post(
        "/v1/agent-cards",
        json={"card_id": "partner-research", "trust_domain": PARTNER, "card_url": PARTNER_CARD_URL},
        headers=admin_headers(admin_idp, ADMIN, sub="alice@corp.test"),
    )
    assert registered.status_code == 201, registered.text
    approved = await http.post(
        "/v1/agent-cards/partner-research/versions/1/approve",
        json={
            "policy": {
                "risk": 2,
                "classification": 1,
                "allowed_callers": ["spiffe://agents.corp.test/agent/sales/*"],
                "allowed_skills": ["assay-summary"],
            },
            "reason": "partner MSA 2026",
        },
        headers=admin_headers(admin_idp, REVIEWER, sub="bob@corp.test"),
    )
    assert approved.status_code == 200, approved.text

    token = fabric.mint(agent_uri(), {"a2a:send:partner-research"})
    auth = {"Authorization": f"Bearer {token}"}

    def rpc(method: str, params: dict[str, Any], rid: int = 1) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}

    sent = await http.post(
        "/a2a",
        json=rpc(
            "message/send",
            {
                "message": {
                    "role": "user",
                    "messageId": "m-1",
                    "parts": [{"kind": "text", "text": "Summarize assay 7781"}],
                },
                "metadata": {TARGET_KEY: "partner-research", SKILL_KEY: "assay-summary"},
            },
        ),
        headers=auth,
    )
    assert sent.status_code == 200
    task = sent.json()["result"]
    assert task["kind"] == "task"
    fetched = await http.post("/a2a", json=rpc("tasks/get", {"id": task["id"]}, 2), headers=auth)
    assert fetched.json()["result"]["id"] == task["id"]

    extended = await http.post(
        "/a2a", json=rpc("agent/getAuthenticatedExtendedCard", {}), headers=auth
    )
    skills = [s["id"] for s in extended.json()["result"]["skills"]]
    assert skills == ["federated-agent-routing", "partner-research/assay-summary"]

    errors = {
        "message/stream": -32004,
        "tasks/resubscribe": -32004,
        "tasks/pushNotificationConfig/set": -32003,
        "agent/unknown": -32601,
    }
    for method, code in errors.items():
        reply = await http.post("/a2a", json=rpc(method, {}), headers=auth)
        assert reply.json()["error"]["code"] == code, method
    missing_task = await http.post("/a2a", json=rpc("tasks/get", {"id": "nope"}), headers=auth)
    assert missing_task.json()["error"]["code"] == -32001

    bad = await http.post("/a2a", json={"jsonrpc": "1.0", "method": "x"}, headers=auth)
    assert bad.status_code == 400
    assert bad.json()["error"]["code"] == -32600
    anonymous = await http.post("/a2a", json=rpc("message/send", {}))
    assert anonymous.status_code == 401
    assert anonymous.json()["error"]["code"] == -32040

    refreshed = await http.post(
        "/v1/agent-cards/partner-research/refresh", headers=admin_headers(admin_idp, ADMIN)
    )
    assert refreshed.json()["changed"] is False
    listing = await http.get("/v1/agent-cards", headers=admin_headers(admin_idp, AUDITOR))
    assert len(listing.json()["items"]) == 1
    versions = await http.get(
        "/v1/agent-cards/partner-research", headers=admin_headers(admin_idp, AUDITOR)
    )
    assert versions.json()["items"][0]["status"] == "approved"


async def test_lifecycle_endpoints_and_audit(
    gateway: Gateway, admin_idp: FakeIdp, fabric: FakeFabric
) -> None:
    await onboard_over_http(gateway, admin_idp)
    http = gateway.http
    reviewer = admin_headers(admin_idp, REVIEWER, sub="bob@corp.test")
    auditor = admin_headers(admin_idp, AUDITOR)
    versions = await http.get("/v1/tools/crm/lookup_customer", headers=auditor)
    assert versions.json()["items"][0]["status"] == "approved"
    tools = await http.get(
        "/v1/tools", params={"status": "approved", "server_id": "crm"}, headers=auditor
    )
    assert len(tools.json()["items"]) == 2
    deprecated = await http.post(
        "/v1/tools/crm/lookup_customer/versions/1/deprecate",
        json={"sunset_at": "2099-01-01T00:00:00Z", "reason": "moving to crm-v2"},
        headers=reviewer,
    )
    assert deprecated.json()["status"] == "deprecated"
    revoked = await http.post(
        "/v1/tools/crm/create_ticket/versions/1/revoke",
        json={"reason": "incident 4411"},
        headers=reviewer,
    )
    assert revoked.json()["status"] == "revoked"
    disabled = await http.post(
        "/v1/servers/crm/disable", json={"reason": "maintenance"}, headers=reviewer
    )
    assert disabled.json()["enabled"] is False
    enabled = await http.post(
        "/v1/servers/crm/enable", json={"reason": "maintenance done"}, headers=reviewer
    )
    assert enabled.json()["enabled"] is True
    assert (await http.get("/v1/servers/crm", headers=auditor)).json()["server_id"] == "crm"

    verification = await http.get("/v1/audit/verify", headers=auditor)
    assert verification.status_code == 200
    assert verification.json()["events_verified"] >= 6
    assert (await http.get("/v1/audit/verify", headers=reviewer)).status_code == 403

    deny = await http.post(
        "/v1/approvals/" + "a" * 32 + "/deny",
        json={"reason": "not needed"},
        headers=admin_headers(admin_idp, APPROVER),
    )
    assert deny.status_code == 404


async def test_operational_endpoints(gateway: Gateway) -> None:
    http = gateway.http
    assert (await http.get("/healthz")).json() == {"status": "ok"}
    ready = await http.get("/readyz", headers={"X-Correlation-ID": "trace-123"})
    assert ready.json() == {"status": "ready"}
    assert ready.headers["x-correlation-id"] == "trace-123"
    assert ready.headers["x-content-type-options"] == "nosniff"
    generated = await http.get("/healthz", headers={"X-Correlation-ID": "x" * 100})
    assert generated.headers["x-correlation-id"] != "x" * 100
    metrics = await http.get("/metrics")
    assert "gateway_http_request_duration_seconds" in metrics.text


@pytest.mark.parametrize("mode", ["legacy", "2026-07-28"])
async def test_both_protocol_eras_are_served(
    gateway: Gateway, admin_idp: FakeIdp, fabric: FakeFabric, mode: str
) -> None:
    await onboard_over_http(gateway, admin_idp)
    token = fabric.mint(agent_uri(), {"mcp:crm:lookup_customer"})
    async with (
        gateway.mcp_http(token) as http,
        Client(
            streamable_http_client("https://gateway.corp.test/mcp", http_client=http),
            mode=mode,
            cache=None,
        ) as client,
    ):
        names = sorted(t.name for t in (await client.list_tools()).tools)
        assert "crm__lookup_customer" in names
        assert "crm__create_ticket" not in names
        result = await client.call_tool("crm__lookup_customer", {"customer_id": "C-9"})
        assert result.structured_content is not None
        assert result.structured_content["customer_id"] == "C-9"
