"""Shared fixtures.

Everything runs in-process with zero credentials:

* ``FakeFabric`` speaks the identity fabric's wire protocol (RFC 7662
  introspection, RFC 7523/8693 token endpoint, /v1/authorize) over
  ``httpx.MockTransport`` and mints real EdDSA credentials.
* Upstream MCP servers are real SDK ``MCPServer`` apps reached through
  ``httpx2.ASGITransport``.
* Remote A2A agents are JSON-RPC handlers behind the same mock transport.
"""

from __future__ import annotations

import asyncio
import base64
import fnmatch
import json
import os
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import httpx2
import jwt
import pytest
from agentic_core.domain.classification import DataClassification, RiskLevel
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp_types import ToolAnnotations
from pydantic import BaseModel

from mcp_a2a_gateway.application.directory import ApproveCard, RegisterCard
from mcp_a2a_gateway.application.registry import ApproveTool, RegisterServer
from mcp_a2a_gateway.config import Settings, TrustDomainConfig
from mcp_a2a_gateway.domain.models import (
    AgentCardVersion,
    CardPolicy,
    Principal,
    ToolPolicy,
    ToolVersion,
)
from mcp_a2a_gateway.integrations.mcp_upstream import SdkUpstreamClient
from mcp_a2a_gateway.runtime.container import Container, build_container
from mcp_a2a_gateway.security.card_signatures import sign_card
from mcp_a2a_gateway.security.jwks import StaticJwks

ROOT = Path(__file__).resolve().parents[1]
TRUST_DOMAIN = "agents.corp.test"
PARTNER = "agents.partner.test"
FABRIC_URL = "https://identity.corp.test"
FABRIC_ISSUER = FABRIC_URL
AUDIENCE = "agent-platform"
ADMIN_ISSUER = "https://login.corp.test/tenant"
PARTNER_ISSUER = "https://identity.partner.test"
GATEWAY_ID = f"spiffe://{TRUST_DOMAIN}/agent/platform/mcp-a2a-gateway"
CRM_URL = "https://crm.corp.test/mcp"
PARTNER_AGENT_URL = "https://research.partner.test/a2a"
PARTNER_CARD_URL = "https://research.partner.test/.well-known/agent-card.json"


def agent_uri(name: str = "planner", domain: str = TRUST_DOMAIN) -> str:
    return f"spiffe://{domain}/agent/sales/{name}"


# ------------------------------------------------------------------- clocks


@dataclass
class FakeClock:
    current: datetime = field(default_factory=lambda: datetime.now(UTC).replace(microsecond=0))

    def now(self) -> datetime:
        return self.current

    def advance(self, seconds: float) -> None:
        self.current += timedelta(seconds=seconds)


@dataclass
class FakeMonotonic:
    value: float = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


# -------------------------------------------------------------- identity


@dataclass
class FakeIdp:
    """Minimal OIDC issuer: ES256 keypair plus JWKS."""

    issuer: str
    kid: str = "k1"
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "alg": "ES256", "use": "sig"})
        return {"keys": [jwk]}

    def mint(self, *, sub: str, aud: str, ttl: int = 300, **extra: Any) -> str:
        now = int(time.time())
        claims = {"iss": self.issuer, "sub": sub, "aud": aud, "iat": now, "exp": now + ttl}
        claims.update(extra)
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": self.kid})


def admin_headers(idp: FakeIdp, *roles: str, sub: str = "alice@corp.test") -> dict[str, str]:
    token = idp.mint(sub=sub, aud="mcp-a2a-gateway-admin", roles=list(roles))
    return {"Authorization": f"Bearer {token}"}


@dataclass
class FakeFabric:
    """The identity fabric's HTTP contract, in memory."""

    key: Ed25519PrivateKey = field(default_factory=Ed25519PrivateKey.generate)
    registered: dict[str, frozenset[str]] = field(default_factory=dict)
    revoked: set[str] = field(default_factory=set)
    overrides: dict[str, str] = field(default_factory=dict)
    authorize_calls: list[dict[str, Any]] = field(default_factory=list)
    exchanges: list[dict[str, str]] = field(default_factory=list)
    workload_token: str = "workload-token-of-the-gateway"
    down: bool = False
    counter: int = 0

    def mint(
        self,
        sub: str,
        scopes: set[str] | frozenset[str],
        *,
        act: dict[str, Any] | None = None,
        ttl: int = 600,
        aud: str = AUDIENCE,
    ) -> str:
        self.counter += 1
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": FABRIC_ISSUER,
            "sub": sub,
            "aud": aud,
            "iat": now,
            "exp": now + ttl,
            "jti": f"jti-{self.counter}",
            "scope": " ".join(sorted(scopes)),
        }
        if act is not None:
            claims["act"] = act
        return jwt.encode(claims, self.key, algorithm="EdDSA", headers={"kid": "fabric-1"})

    def _claims(self, token: str) -> dict[str, Any] | None:
        try:
            claims: dict[str, Any] = jwt.decode(
                token, self.key.public_key(), algorithms=["EdDSA"], audience=AUDIENCE
            )
        except jwt.PyJWTError:
            return None
        return None if claims["jti"] in self.revoked else claims

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            return httpx.Response(503, json={"error": "unavailable"})
        routes = {
            "/oauth2/introspect": self._introspect,
            "/v1/authorize": self._authorize,
            "/oauth2/token": lambda r: self._token(dict(httpx.QueryParams(r.content.decode()))),
        }
        route = routes.get(request.url.path)
        return route(request) if route else httpx.Response(404)

    def _introspect(self, request: httpx.Request) -> httpx.Response:
        form = dict(httpx.QueryParams(request.content.decode()))
        claims = self._claims(form.get("token", ""))
        if claims is None:
            return httpx.Response(200, json={"active": False})
        return httpx.Response(200, json={"active": True, **claims})

    def _authorize(self, request: httpx.Request) -> httpx.Response:
        claims = self._claims(request.headers.get("authorization", "")[7:])
        if claims is None:
            return httpx.Response(401, json={"error": "unauthorized"})
        body = json.loads(request.content)
        self.authorize_calls.append(body)
        action = body["action"]
        in_scope = any(fnmatch.fnmatchcase(action, s) for s in claims["scope"].split())
        decision = self.overrides.get(action, "allow" if in_scope else "deny")
        return httpx.Response(
            200,
            json={
                "decision": decision,
                "agent": claims["sub"],
                "action": action,
                "resource": f"{body['resource_type']}:{body['resource_id']}",
                "matched_rules": ["fabric-rule"],
                "policy_version": "2026.10.0",
                "policy_digest": "sha256:" + "f" * 64,
                "reason": f"fabric {decision}",
                "delegation_chain": [],
            },
        )

    def _token(self, form: dict[str, str]) -> httpx.Response:
        grant = form.get("grant_type", "")
        if grant.endswith("jwt-bearer"):
            if form.get("client_id") != GATEWAY_ID or form.get("assertion") != self.workload_token:
                return httpx.Response(400, json={"error": "invalid_grant"})
            token = self.mint(GATEWAY_ID, self.registered.get(GATEWAY_ID, frozenset()))
            return httpx.Response(200, json={"access_token": token, "expires_in": 600})
        subject = self._claims(form.get("subject_token", ""))
        actor = self._claims(form.get("actor_token", ""))
        if subject is None or actor is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        requested = set(form.get("scope", "").split())
        allowed = set(subject["scope"].split()) & self.registered.get(actor["sub"], frozenset())
        if not requested or not requested <= allowed:
            return httpx.Response(
                400, json={"error": "invalid_grant", "error_description": "scope not delegable"}
            )
        self.exchanges.append({"subject": subject["sub"], "actor": actor["sub"], **form})
        chain: dict[str, Any] = {"sub": actor["sub"]}
        if "act" in subject:
            chain["act"] = subject["act"]
        token = self.mint(subject["sub"], requested, act=chain, ttl=300)
        return httpx.Response(200, json={"access_token": token, "expires_in": 300})


# ------------------------------------------------------------- remote agents


@dataclass
class FakeRemoteAgent:
    """An A2A agent in the partner trust domain."""

    reply_text: str = "Assay summary: 3 batches released, 1 under investigation."
    error_code: int | None = None
    status: int = 200
    pad_bytes: int = 0
    calls: list[dict[str, Any]] = field(default_factory=list)
    authorizations: list[str] = field(default_factory=list)
    tasks: dict[str, dict[str, Any]] = field(default_factory=dict)

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.calls.append(body)
        self.authorizations.append(request.headers.get("authorization", ""))
        if self.status != 200:
            return httpx.Response(self.status)
        if self.error_code is not None:
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": self.error_code, "message": "remote refused"},
                },
            )
        method = body["method"]
        if method == "message/send":
            task_id = f"task-{len(self.tasks) + 1}"
            task = {
                "kind": "task",
                "id": task_id,
                "contextId": "ctx-1",
                "status": {"state": "completed"},
                "artifacts": [
                    {
                        "artifactId": "a1",
                        "parts": [{"kind": "text", "text": self.reply_text + " " * self.pad_bytes}],
                    }
                ],
            }
            self.tasks[task_id] = task
            result: dict[str, Any] = task
        elif method == "tasks/get":
            result = self.tasks[body["params"]["id"]]
        elif method == "tasks/cancel":
            result = {**self.tasks[body["params"]["id"]], "status": {"state": "canceled"}}
        else:
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": body["id"],
                    "error": {"code": -32601, "message": "x"},
                },
            )
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": result})


def partner_card(url: str = PARTNER_AGENT_URL, **changes: Any) -> dict[str, Any]:
    card: dict[str, Any] = {
        "protocolVersion": "0.3.0",
        "name": "Partner research agent",
        "description": "Summarizes assay and batch release status for partner programs.",
        "url": url,
        "version": "1.4.0",
        "preferredTransport": "JSONRPC",
        "capabilities": {"streaming": False, "pushNotifications": False},
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            {"id": "assay-summary", "name": "Assay summary", "description": "Summarize assays"},
            {"id": "batch-status", "name": "Batch status", "description": "Batch release state"},
        ],
        "securitySchemes": {"fabric": {"type": "http", "scheme": "bearer"}},
        "security": [{"fabric": []}],
    }
    card.update(changes)
    return card


@dataclass
class Network:
    """Routes every outbound HTTP request of the gateway by host."""

    fabric: FakeFabric
    partner_agent: FakeRemoteAgent
    partner_signer: Ed25519PrivateKey
    partner_idp: FakeIdp
    card_overrides: dict[str, Any] = field(default_factory=dict)
    requests: list[httpx.Request] = field(default_factory=list)

    def signed_card(self, **changes: Any) -> dict[str, Any]:
        return sign_card(partner_card(**changes), self.partner_signer, kid="partner-cards-1")

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host = request.url.host
        if host == "identity.corp.test":
            return self.fabric.handler(request)
        if host == "research.partner.test":
            if request.url.path.endswith("agent-card.json"):
                card = self.card_overrides.get("card") or self.signed_card()
                return httpx.Response(200, json=card)
            return self.partner_agent.handler(request)
        return httpx.Response(404, json={"error": "no route"})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


def card_jwks(key: Ed25519PrivateKey) -> dict[str, Any]:
    jwk = json.loads(jwt.algorithms.OKPAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "partner-cards-1", "use": "sig", "alg": "EdDSA"})
    return {"keys": [jwk]}


# ----------------------------------------------------------- upstream MCP


class Customer(BaseModel):
    customer_id: str
    name: str
    email: str
    tier: str


class Ticket(BaseModel):
    ticket_id: str
    customer_id: str
    summary: str


@dataclass
class CrmBehaviour:
    """Knobs a test can turn to make the upstream misbehave."""

    note: str = "Customer prefers email contact."
    report_bytes: int = 10
    description: str = "Look up a customer record by id."
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    headers: list[str] = field(default_factory=list)


def build_crm(behaviour: CrmBehaviour) -> MCPServer:
    server = MCPServer("crm", version="3.1.0")

    @server.tool(
        description=behaviour.description,
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    def lookup_customer(customer_id: str) -> Customer:
        behaviour.calls.append(("lookup_customer", {"customer_id": customer_id}))
        return Customer(
            customer_id=customer_id,
            name="Dana Whitfield",
            email="dana.whitfield@customers.test",
            tier="gold",
        )

    @server.tool(description="Open a support ticket for a customer.")
    def create_ticket(customer_id: str, summary: str) -> Ticket:
        behaviour.calls.append(("create_ticket", {"customer_id": customer_id}))
        return Ticket(ticket_id="T-1001", customer_id=customer_id, summary=summary)

    @server.tool(
        description="Fetch the latest account note.",
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    def account_note(customer_id: str) -> str:
        behaviour.calls.append(("account_note", {"customer_id": customer_id}))
        return behaviour.note

    @server.tool(
        description="Export a usage report.",
        annotations=ToolAnnotations(readOnlyHint=True),
    )
    def usage_report(customer_id: str) -> str:
        behaviour.calls.append(("usage_report", {"customer_id": customer_id}))
        return "x" * behaviour.report_bytes

    return server


class HostRouter(httpx2.AsyncBaseTransport):
    def __init__(self, apps: dict[str, Any]) -> None:
        self._apps = apps

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        app = self._apps.get(request.url.host)
        if app is None:
            return httpx2.Response(502, request=request)
        return await httpx2.ASGITransport(app=app).handle_async_request(request)


async def _hold(manager: Any, ready: asyncio.Event, stop: asyncio.Event) -> None:
    """Enter and exit a session manager's task group inside one task (anyio requirement)."""
    async with manager.run():
        ready.set()
        await stop.wait()


@dataclass
class Upstreams:
    """Real MCP servers served in-process, swappable to simulate upstream changes."""

    crm: CrmBehaviour = field(default_factory=CrmBehaviour)
    apps: dict[str, Any] = field(default_factory=dict)
    servers: dict[str, MCPServer] = field(default_factory=dict)
    tasks: list[asyncio.Task[None]] = field(default_factory=list)
    stop: asyncio.Event = field(default_factory=asyncio.Event)

    async def serve(self, host: str, server: MCPServer) -> None:
        app = server.streamable_http_app(
            json_response=True,
            stateless_http=True,
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        ready = asyncio.Event()
        self.tasks.append(asyncio.create_task(_hold(server.session_manager, ready, self.stop)))
        await ready.wait()
        self.apps[host] = _HeaderSpy(app, self.crm.headers)
        self.servers[host] = server

    async def aclose(self) -> None:
        self.stop.set()
        await asyncio.gather(*self.tasks)

    def transport(self) -> httpx2.AsyncBaseTransport:
        return HostRouter(self.apps)


class _HeaderSpy:
    def __init__(self, app: Any, sink: list[str]) -> None:
        self._app = app
        self._sink = sink

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        headers = dict(scope.get("headers") or [])
        self._sink.append(headers.get(b"authorization", b"").decode())
        await self._app(scope, receive, send)


# --------------------------------------------------------------- fixtures


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def monotonic() -> FakeMonotonic:
    return FakeMonotonic()


@pytest.fixture
def admin_idp() -> FakeIdp:
    return FakeIdp(ADMIN_ISSUER, kid="admin-1")


@pytest.fixture
def fabric() -> FakeFabric:
    fake = FakeFabric()
    fake.registered[GATEWAY_ID] = frozenset(
        {"mcp:crm:*", "mcp:crm:lookup_customer", "a2a:send:*", "a2a:send:partner-research"}
    )
    return fake


@pytest.fixture
def network(fabric: FakeFabric) -> Network:
    return Network(
        fabric=fabric,
        partner_agent=FakeRemoteAgent(),
        partner_signer=Ed25519PrivateKey.generate(),
        partner_idp=FakeIdp(PARTNER_ISSUER, kid="partner-1"),
    )


def make_settings(tmp_path: Path, network: Network, **overrides: Any) -> Settings:
    workload = tmp_path / "workload-token"
    workload.write_text(network.fabric.workload_token, encoding="utf-8")
    db = os.environ.get("GATEWAY_TEST_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'g.db'}")
    values: dict[str, Any] = {
        "environment": "test",
        "public_url": "https://gateway.corp.test",
        "trust_domain": TRUST_DOMAIN,
        "database_url": db,
        "fabric_url": FABRIC_URL,
        "gateway_agent_id": GATEWAY_ID,
        "workload_token_file": workload,
        "admin_issuer": ADMIN_ISSUER,
        "admin_audience": "mcp-a2a-gateway-admin",
        "admin_jwks_url": "https://login.corp.test/jwks",
        "dev_ephemeral_keys": True,
        "audit_chain_id": f"test-{tmp_path.name}",
        "policy_file": ROOT / "policies" / "gateway-authorization.yaml",
        "upstream_allowed_hosts": ("*.corp.test",),
        "trust_domains": {
            PARTNER: TrustDomainConfig(
                card_jwks=card_jwks(network.partner_signer),
                card_hosts=("*.partner.test",),
                max_classification=DataClassification.CONFIDENTIAL,
                max_delegation_depth=2,
                token_issuer=PARTNER_ISSUER,
                token_jwks_url="https://identity.partner.test/jwks",
                token_audience="mcp-a2a-gateway",
                inbound_scopes=("mcp:crm:lookup_customer", "a2a:send:*"),
            )
        },
    }
    values.update(overrides)
    return Settings(**values)


@pytest.fixture
def settings(tmp_path: Path, network: Network) -> Settings:
    return make_settings(tmp_path, network)


@pytest.fixture
async def upstreams() -> AsyncIterator[Upstreams]:
    servers = Upstreams()
    await servers.serve("crm.corp.test", build_crm(servers.crm))
    yield servers
    await servers.aclose()


async def reset_database(url: str) -> None:
    """Scenario tests share one PostgreSQL database in CI; start each from an empty schema."""
    from mcp_a2a_gateway.infrastructure.database import make_engine, metadata

    engine = make_engine(url)
    try:
        async with engine.begin() as conn:
            await conn.run_sync(metadata.drop_all)
    finally:
        await engine.dispose()


async def make_container(
    settings: Settings,
    *,
    network: Network,
    upstreams: Upstreams,
    admin_idp: FakeIdp,
    clock: FakeClock,
    monotonic: FakeMonotonic,
    env: dict[str, str] | None = None,
) -> Container:
    if settings.database_url.startswith("postgresql"):
        await reset_database(settings.database_url)
    return await build_container(
        settings,
        clock=clock,
        monotonic=monotonic,
        http=network.client(),
        upstream=SdkUpstreamClient(transport_factory=upstreams.transport),
        admin_resolver=StaticJwks(admin_idp.jwks()),
        federation_resolvers={PARTNER: StaticJwks(network.partner_idp.jwks())},
        env=env or {"GATEWAY_UPSTREAM_SECRET_CRM": "crm-service-credential"},
    )


@pytest.fixture
async def container(
    settings: Settings,
    network: Network,
    upstreams: Upstreams,
    admin_idp: FakeIdp,
    clock: FakeClock,
    monotonic: FakeMonotonic,
) -> AsyncIterator[Container]:
    built = await make_container(
        settings,
        network=network,
        upstreams=upstreams,
        admin_idp=admin_idp,
        clock=clock,
        monotonic=monotonic,
    )
    yield built
    await built.aclose()


# --------------------------------------------------------------- scenarios

ALL_CRM_TOOLS = ("lookup_customer", "create_ticket", "account_note", "usage_report")


def crm_registration(**changes: Any) -> RegisterServer:
    values: dict[str, Any] = {
        "server_id": "crm",
        "display_name": "CRM tools",
        "url": CRM_URL,
        "owner": "sales-platform",
        "description": "Customer records and support tickets",
    }
    values.update(changes)
    return RegisterServer(**values)


def tool_policy(**changes: Any) -> ToolPolicy:
    values: dict[str, Any] = {
        "risk": RiskLevel.LOW,
        "classification": DataClassification.CONFIDENTIAL,
        "allowed_agents": (f"spiffe://{TRUST_DOMAIN}/agent/sales/*", f"spiffe://{PARTNER}/agent/*"),
    }
    values.update(changes)
    return ToolPolicy(**values)


async def onboard_crm(
    container: Container,
    *,
    tools: tuple[str, ...] = ALL_CRM_TOOLS,
    policies: dict[str, ToolPolicy] | None = None,
    **server_changes: Any,
) -> dict[str, ToolVersion]:
    """Register the CRM upstream, discover it as alice and approve as bob."""
    await container.registry.register_server(crm_registration(**server_changes), actor="alice")
    await container.registry.discover("crm", actor="alice")
    approved: dict[str, ToolVersion] = {}
    for name in tools:
        policy = (policies or {}).get(name) or tool_policy()
        approved[name] = await container.registry.approve(
            "crm", name, 1, ApproveTool(policy=policy, reason="reviewed for sales"), actor="bob"
        )
    return approved


def card_policy(**changes: Any) -> CardPolicy:
    values: dict[str, Any] = {
        "risk": RiskLevel.MODERATE,
        "classification": DataClassification.INTERNAL,
        "allowed_callers": (f"spiffe://{TRUST_DOMAIN}/agent/sales/*",),
    }
    values.update(changes)
    return CardPolicy(**values)


async def onboard_partner(
    container: Container, *, policy: CardPolicy | None = None, card_id: str = "partner-research"
) -> AgentCardVersion:
    await container.directory.register(
        RegisterCard(card_id=card_id, trust_domain=PARTNER, card_url=PARTNER_CARD_URL),
        actor="alice",
    )
    return await container.directory.approve(
        card_id, 1, ApproveCard(policy=policy or card_policy(), reason="partner MSA"), actor="bob"
    )


async def principal_for(
    container: Container, fabric: FakeFabric, scopes: set[str], name: str = "planner", **kw: Any
) -> Principal:
    token = fabric.mint(agent_uri(name), scopes, **kw)
    return await container.authenticator.authenticate(f"Bearer {token}")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


Factory = Callable[[], Any]


# ------------------------------------------------------------- HTTP harness


@dataclass
class Gateway:
    """The full ASGI app with its lifespan running, plus an HTTP client bound to it."""

    app: Any
    http: httpx.AsyncClient

    @property
    def container(self) -> Container:
        value: Container = self.app.state.container
        return value

    def mcp_http(self, token: str | None) -> httpx2.AsyncClient:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=self.app),
            base_url="https://gateway.corp.test",
            headers=headers,
        )


async def _lifespan(app: Any, ready: asyncio.Event, stop: asyncio.Event) -> None:
    async with app.router.lifespan_context(app):
        ready.set()
        await stop.wait()


@pytest.fixture
async def gateway(
    settings: Settings,
    network: Network,
    upstreams: Upstreams,
    admin_idp: FakeIdp,
    clock: FakeClock,
    monotonic: FakeMonotonic,
) -> AsyncIterator[Gateway]:
    from mcp_a2a_gateway.api.app import create_app

    async def factory() -> Container:
        return await make_container(
            settings,
            network=network,
            upstreams=upstreams,
            admin_idp=admin_idp,
            clock=clock,
            monotonic=monotonic,
        )

    app = create_app(factory)
    ready, stop = asyncio.Event(), asyncio.Event()
    task = asyncio.create_task(_lifespan(app, ready, stop))
    started = asyncio.create_task(ready.wait())
    await asyncio.wait({task, started}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        started.cancel()
        task.result()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://gateway.corp.test"
    ) as http:
        yield Gateway(app=app, http=http)
    stop.set()
    await task
