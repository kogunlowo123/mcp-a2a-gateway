"""Repositories, approval consumption and the audit chain against a real PostgreSQL.

Runs when GATEWAY_TEST_DATABASE_URL points at PostgreSQL, e.g.
postgresql+asyncpg://gateway:gateway@localhost:5432/gateway (CI service container).
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta

import pytest
from agentic_core.audit import AuditLog, verify_chain
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_a2a_gateway.domain.models import (
    ApprovalKind,
    ApprovalRequest,
    ApprovalStatus,
    Lifecycle,
)
from mcp_a2a_gateway.infrastructure.database import (
    SqlApprovalRepository,
    SqlAuditSink,
    SqlTaskRouteRepository,
    SqlToolRepository,
    create_schema,
    make_engine,
)
from tests.unit.test_domain import version

URL = os.environ.get("GATEWAY_TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not URL.startswith("postgresql"), reason="PostgreSQL not configured"),
]


async def test_repositories_round_trip() -> None:
    engine = make_engine(URL)
    await create_schema(engine)
    await create_schema(engine)  # idempotent
    suffix = f"{datetime.now(UTC).timestamp():.0f}"
    try:
        tools = SqlToolRepository(engine)
        tool = version(server_id=f"pg{suffix[-8:]}")
        await tools.add(tool)
        assert await tools.get(tool.server_id, tool.name, 1) == tool
        approved = tool.transition(Lifecycle.APPROVED, at=datetime.now(UTC), reason="ok")
        await tools.update(approved)
        assert any(
            t.server_id == tool.server_id for t in await tools.list(status=Lifecycle.APPROVED)
        )

        routes = SqlTaskRouteRepository(engine)
        await routes.remember(f"task-{suffix}", card_id="c", owner="o", at=datetime.now(UTC))
        assert await routes.lookup(f"task-{suffix}") == ("c", "o")
    finally:
        await engine.dispose()


async def test_concurrent_approval_consumption_is_single_use() -> None:
    engine = make_engine(URL)
    await create_schema(engine)
    try:
        repo = SqlApprovalRepository(engine)
        now = datetime.now(UTC)
        approval = ApprovalRequest(
            approval_id=os.urandom(16).hex(),
            kind=ApprovalKind.TOOL_CALL,
            requester="spiffe://agents.corp.test/agent/sales/planner",
            target="crm__create_ticket",
            action="mcp:crm:create_ticket",
            payload_digest="sha256:" + "0" * 64,
            payload_preview="{}",
            reasons=("test",),
            status=ApprovalStatus.APPROVED,
            requested_at=now,
            expires_at=now + timedelta(hours=1),
        )
        await repo.add(approval)
        results = await asyncio.gather(
            *(repo.consume(approval.approval_id, at=now) for _ in range(8))
        )
        assert results.count(True) == 1
        stored = await repo.get(approval.approval_id)
        assert stored is not None
        assert stored.status is ApprovalStatus.USED
    finally:
        await engine.dispose()


async def test_audit_chain_in_postgres() -> None:
    engine = make_engine(URL)
    await create_schema(engine)
    try:
        key = Ed25519PrivateKey.generate()
        chain = f"pg-{os.urandom(4).hex()}"
        log = AuditLog(SqlAuditSink(engine, chain), key, key_id="audit-pg")
        for i in range(5):
            await log.record(actor="a", action="x", resource=str(i), outcome="success")
        events = [e async for e in SqlAuditSink(engine, chain).read()]
        assert verify_chain(events, {"audit-pg": key.public_key()}) == 5
    finally:
        await engine.dispose()
