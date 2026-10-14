"""Composition root: builds every service once per process from Settings."""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import timedelta

import httpx
from agentic_core.audit import AuditLog
from agentic_core.policy import PolicyEngine, PolicySet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from sqlalchemy.ext.asyncio import AsyncEngine

from mcp_a2a_gateway.application.approvals import ApprovalService
from mcp_a2a_gateway.application.audit import AuditRecorder
from mcp_a2a_gateway.application.authorization import Authorizer
from mcp_a2a_gateway.application.credentials import UpstreamCredentials
from mcp_a2a_gateway.application.directory import AgentDirectory, TrustDomain
from mcp_a2a_gateway.application.federation import A2AFederation
from mcp_a2a_gateway.application.mcp_gateway import LiveDefinitions, McpGateway
from mcp_a2a_gateway.application.registry import ToolRegistry
from mcp_a2a_gateway.config import Settings
from mcp_a2a_gateway.domain.ports import Clock, RemoteAgentPort, UpstreamMcpPort
from mcp_a2a_gateway.infrastructure.database import (
    SqlApprovalRepository,
    SqlAuditSink,
    SqlCardRepository,
    SqlServerRepository,
    SqlTaskRouteRepository,
    SqlToolRepository,
    SystemClock,
    create_schema,
    make_engine,
)
from mcp_a2a_gateway.integrations.a2a_client import HttpRemoteAgentClient
from mcp_a2a_gateway.integrations.identity_fabric import FabricClient, GatewayCredential
from mcp_a2a_gateway.integrations.mcp_upstream import SdkUpstreamClient
from mcp_a2a_gateway.observability.metrics import GatewayMetrics
from mcp_a2a_gateway.security.admin import AdminAuthenticator
from mcp_a2a_gateway.security.authn import AgentAuthenticator, FederatedSource, TokenSource
from mcp_a2a_gateway.security.inspection import ContentInspector
from mcp_a2a_gateway.security.jwks import KeyResolver, RemoteJwks, StaticJwks
from mcp_a2a_gateway.security.resilience import CircuitBreaker, RateLimiter


@dataclass
class Container:
    settings: Settings
    registry: ToolRegistry
    directory: AgentDirectory
    mcp: McpGateway
    federation: A2AFederation
    approvals: ApprovalService
    authenticator: AgentAuthenticator
    admin: AdminAuthenticator
    metrics: GatewayMetrics
    engine: AsyncEngine
    http: httpx.AsyncClient
    audit_sink: SqlAuditSink
    audit_key_id: str
    audit_public_key: Ed25519PublicKey
    clock: Clock

    async def aclose(self) -> None:
        await self.http.aclose()
        await self.engine.dispose()


def audit_signer(settings: Settings) -> tuple[Ed25519PrivateKey, str]:
    if settings.audit_key_file is None:
        return Ed25519PrivateKey.generate(), "audit-ephemeral"
    key = serialization.load_pem_private_key(settings.audit_key_file.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("audit key must be Ed25519")
    return key, settings.audit_key_file.stem


async def build_container(
    settings: Settings,
    *,
    clock: Clock | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    http: httpx.AsyncClient | None = None,
    upstream: UpstreamMcpPort | None = None,
    remote: RemoteAgentPort | None = None,
    admin_resolver: KeyResolver | None = None,
    token_resolver: KeyResolver | None = None,
    card_resolvers: Mapping[str, KeyResolver] | None = None,
    federation_resolvers: Mapping[str, KeyResolver] | None = None,
    env: Mapping[str, str] | None = None,
) -> Container:
    clock = clock or SystemClock()
    http = http or httpx.AsyncClient(timeout=httpx.Timeout(5.0))
    metrics = GatewayMetrics()

    engine = make_engine(settings.database_url)
    await create_schema(engine)
    signer, key_id = audit_signer(settings)
    sink = SqlAuditSink(engine, settings.audit_chain_id)
    audit = AuditRecorder(AuditLog(sink, signer, key_id=key_id))

    fabric: FabricClient | None = None
    if settings.fabric_url is not None:
        credential = None
        if settings.gateway_agent_id is not None and settings.workload_token_file is not None:
            credential = GatewayCredential(
                client=http,
                base_url=settings.fabric_url,
                agent_id=settings.gateway_agent_id,
                workload_token_file=settings.workload_token_file,
                clock=clock,
            )
        fabric = FabricClient(client=http, base_url=settings.fabric_url, credential=credential)

    local: TokenSource | None = None
    if fabric is None and settings.token_issuer and settings.token_jwks_url:
        local = TokenSource(
            issuer=settings.token_issuer,
            audience=settings.token_audience,
            resolver=token_resolver or RemoteJwks(settings.token_jwks_url, client=http),
        )
    federated = tuple(
        FederatedSource(
            issuer=cfg.token_issuer,
            audience=cfg.token_audience,
            resolver=(federation_resolvers or {}).get(name)
            or RemoteJwks(cfg.token_jwks_url, client=http),
            trust_domain=name,
            inbound_scopes=cfg.inbound_scopes,
        )
        for name, cfg in settings.trust_domains.items()
        if cfg.token_issuer is not None
        and cfg.token_audience is not None
        and cfg.token_jwks_url is not None
    )
    authenticator = AgentAuthenticator(
        trust_domain=settings.trust_domain,
        audience=settings.token_audience,
        clock=clock,
        fabric=fabric,
        local=local,
        federated=federated,
    )

    domains: dict[str, TrustDomain] = {}
    for name, cfg in settings.trust_domains.items():
        resolver = (card_resolvers or {}).get(name)
        if resolver is None:
            resolver = (
                StaticJwks(cfg.card_jwks)
                if cfg.card_jwks is not None
                else RemoteJwks(str(cfg.card_jwks_url), client=http)
            )
        domains[name] = TrustDomain(name=name, config=cfg, card_keys=resolver)

    upstream = upstream or SdkUpstreamClient()
    remote = remote or HttpRemoteAgentClient(http, timeout_s=settings.a2a_timeout_seconds)
    credentials = UpstreamCredentials(fabric=fabric, env=env if env is not None else os.environ)
    inspector = ContentInspector()
    authorizer = Authorizer(PolicyEngine(PolicySet.from_file(settings.policy_file)), fabric)
    approvals = ApprovalService(
        repository=SqlApprovalRepository(engine),
        audit=audit,
        clock=clock,
        ttl=timedelta(seconds=settings.approval_ttl_seconds),
    )
    limiter = RateLimiter(settings.rate_limit_per_minute, clock=monotonic)
    breaker = CircuitBreaker(
        threshold=settings.circuit_failure_threshold,
        reset_s=settings.circuit_reset_seconds,
        clock=monotonic,
    )
    registry = ToolRegistry(
        servers=SqlServerRepository(engine),
        tools=SqlToolRepository(engine),
        upstream=upstream,
        credentials=credentials,
        inspector=inspector,
        audit=audit,
        clock=clock,
        allowed_hosts=settings.upstream_allowed_hosts,
        allow_http=settings.allow_insecure_upstreams,
    )
    directory = AgentDirectory(
        cards=SqlCardRepository(engine),
        remote=remote,
        trust_domains=domains,
        require_signed=settings.require_signed_cards,
        audit=audit,
        clock=clock,
    )
    mcp = McpGateway(
        registry=registry,
        upstream=upstream,
        live=LiveDefinitions(
            upstream=upstream,
            credentials=credentials,
            ttl_s=settings.definition_ttl_seconds,
            clock=monotonic,
        ),
        credentials=credentials,
        authorizer=authorizer,
        approvals=approvals,
        inspector=inspector,
        audit=audit,
        metrics=metrics,
        limiter=limiter,
        breaker=breaker,
        clock=clock,
        max_argument_bytes=settings.max_argument_bytes,
        federation_ceilings={n: c.max_classification for n, c in settings.trust_domains.items()},
    )
    federation = A2AFederation(
        directory=directory,
        remote=remote,
        authorizer=authorizer,
        approvals=approvals,
        credentials=credentials,
        inspector=inspector,
        tasks=SqlTaskRouteRepository(engine),
        audit=audit,
        metrics=metrics,
        limiter=limiter,
        breaker=breaker,
        clock=clock,
        max_response_bytes=settings.a2a_max_response_bytes,
    )
    admin = AdminAuthenticator(
        admin_resolver or RemoteJwks(settings.admin_jwks_url, client=http),
        issuer=settings.admin_issuer,
        audience=settings.admin_audience,
        clock=clock,
        roles_claim=settings.admin_roles_claim,
    )
    return Container(
        settings=settings,
        registry=registry,
        directory=directory,
        mcp=mcp,
        federation=federation,
        approvals=approvals,
        authenticator=authenticator,
        admin=admin,
        metrics=metrics,
        engine=engine,
        http=http,
        audit_sink=sink,
        audit_key_id=key_id,
        audit_public_key=signer.public_key(),
        clock=clock,
    )
