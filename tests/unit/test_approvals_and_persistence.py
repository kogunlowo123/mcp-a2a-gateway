"""Approval rules and SQL repositories (SQLite here; PostgreSQL in tests/integration)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from agentic_core.audit import AuditLog, verify_chain
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.exc import IntegrityError

from mcp_a2a_gateway.application.approvals import ApprovalService, payload_digest
from mcp_a2a_gateway.application.audit import AuditRecorder
from mcp_a2a_gateway.domain.errors import (
    ApprovalRequiredError,
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
)
from mcp_a2a_gateway.domain.models import ApprovalKind, ApprovalStatus, Principal
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
from tests.conftest import FakeClock
from tests.unit.test_domain import NOW, version


def principal(subject: str = "spiffe://agents.corp.test/agent/sales/planner") -> Principal:
    return Principal(
        subject=subject,
        scopes=frozenset({"mcp:crm:*"}),
        trust_domain="agents.corp.test",
        authenticated_by="fabric",
        token="t",
    )


@pytest.fixture
async def engine(tmp_path: Path):  # type: ignore[no-untyped-def]
    built = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'r.db'}")
    await create_schema(built)
    await create_schema(built)  # idempotent
    yield built
    await built.dispose()


@pytest.fixture
async def service(engine, clock: FakeClock) -> ApprovalService:  # type: ignore[no-untyped-def]
    sink = SqlAuditSink(engine, "approvals-test")
    return ApprovalService(
        repository=SqlApprovalRepository(engine),
        audit=AuditRecorder(AuditLog(sink, Ed25519PrivateKey.generate(), key_id="k")),
        clock=clock,
        ttl=timedelta(minutes=30),
    )


async def request(service: ApprovalService, payload: dict[str, str]) -> str:
    error = await service.request(
        kind=ApprovalKind.TOOL_CALL,
        principal=principal(),
        target="crm__create_ticket",
        action="mcp:crm:create_ticket",
        payload=payload,
        reasons=("gateway policy: human approval required",),
    )
    assert isinstance(error, ApprovalRequiredError)
    return error.approval_id


class TestApprovals:
    async def test_preview_is_redacted_and_bounded(self, service: ApprovalService) -> None:
        approval_id = await request(
            service,
            {"email": "dana@customers.test", "note": "x" * 5000, "k": "AKIAABCDEFGHIJKLMNOP"},
        )
        stored = await service.get(approval_id)
        assert "dana@customers.test" not in stored.payload_preview
        assert "AKIA" not in stored.payload_preview
        assert stored.payload_preview.endswith("...[truncated]")
        assert stored.payload_digest == payload_digest(
            {"email": "dana@customers.test", "note": "x" * 5000, "k": "AKIAABCDEFGHIJKLMNOP"}
        )

    async def test_decision_rules(self, service: ApprovalService, clock: FakeClock) -> None:
        approval_id = await request(service, {"a": "1"})
        with pytest.raises(ForbiddenError, match="own approval"):
            await service.decide(
                approval_id, approve=True, actor=principal().subject, reason="self approve"
            )
        denied = await service.decide(approval_id, approve=False, actor="carol", reason="no need")
        assert denied.status is ApprovalStatus.DENIED
        with pytest.raises(InvalidStateError, match="already"):
            await service.decide(approval_id, approve=True, actor="carol", reason="changed mind")
        with pytest.raises(ForbiddenError, match="denied"):
            await service.verify(
                approval_id, principal=principal(), target="crm__create_ticket", payload={"a": "1"}
            )

        late = await request(service, {"a": "2"})
        clock.advance(3600)
        with pytest.raises(InvalidStateError, match="expired"):
            await service.decide(late, approve=True, actor="carol", reason="too late")
        with pytest.raises(NotFoundError):
            await service.get("0" * 32)

    async def test_verify_binds_caller_chain_target_payload_and_time(
        self, service: ApprovalService, clock: FakeClock
    ) -> None:
        approval_id = await request(service, {"a": "1"})
        await service.decide(approval_id, approve=True, actor="carol", reason="verified")
        ok = await service.verify(
            approval_id, principal=principal(), target="crm__create_ticket", payload={"a": "1"}
        )
        assert ok.status is ApprovalStatus.APPROVED
        other = principal("spiffe://agents.corp.test/agent/sales/other")
        with pytest.raises(ForbiddenError, match="not found"):
            await service.verify(
                approval_id, principal=other, target="crm__create_ticket", payload={"a": "1"}
            )
        chained = principal().model_copy(update={"delegation_chain": ("spiffe://x/agent/a/b",)})
        with pytest.raises(ForbiddenError, match="delegation chain"):
            await service.verify(
                approval_id, principal=chained, target="crm__create_ticket", payload={"a": "1"}
            )
        with pytest.raises(ForbiddenError, match="target or payload"):
            await service.verify(
                approval_id, principal=principal(), target="crm__x", payload={"a": "1"}
            )
        clock.advance(3600)
        with pytest.raises(ForbiddenError, match="expired"):
            await service.verify(
                approval_id, principal=principal(), target="crm__create_ticket", payload={"a": "1"}
            )

    async def test_consumption_is_atomic(self, service: ApprovalService) -> None:
        approval_id = await request(service, {"a": "1"})
        approval = await service.decide(approval_id, approve=True, actor="carol", reason="ok then")
        results = await asyncio.gather(
            service.consume(approval), service.consume(approval), return_exceptions=True
        )
        assert sum(1 for r in results if r is None) == 1
        assert sum(1 for r in results if isinstance(r, ForbiddenError)) == 1
        listed = await service.list(status=ApprovalStatus.USED, limit=10)
        assert [a.approval_id for a in listed] == [approval_id]
        assert listed[0].used_at is not None

    async def test_status_visible_only_to_requester(self, service: ApprovalService) -> None:
        approval_id = await request(service, {"a": "1"})
        assert (
            await service.status_for(approval_id, principal=principal())
        ).approval_id == approval_id
        with pytest.raises(NotFoundError):
            await service.status_for(approval_id, principal=principal("spiffe://a/agent/b/c"))


class TestRepositories:
    async def test_tool_and_server_repositories(self, engine) -> None:  # type: ignore[no-untyped-def]
        tools = SqlToolRepository(engine)
        tool = version()
        await tools.add(tool)
        with pytest.raises(ConflictError):
            await tools.add(tool)
        assert await tools.get("crm", "lookup", 1) == tool
        assert await tools.get("crm", "lookup", 2) is None
        await tools.add(version(version=2))
        latest = await tools.latest_by_server("crm")
        assert [t.version for t in latest] == [2]
        with pytest.raises(NotFoundError):
            await tools.update(version(version=9))
        servers = SqlServerRepository(engine)
        assert await servers.get("crm") is None
        assert await servers.list() == []
        from mcp_a2a_gateway.domain.models import UpstreamServer
        from tests.conftest import crm_registration

        server = UpstreamServer(
            **crm_registration().model_dump(), registered_by="a", created_at=NOW, updated_at=NOW
        )
        with pytest.raises(NotFoundError):
            await servers.update(server)

    async def test_card_and_approval_repositories_missing_rows(self, engine) -> None:  # type: ignore[no-untyped-def]
        cards = SqlCardRepository(engine)
        assert await cards.get("x", 1) is None
        approvals = SqlApprovalRepository(engine)
        assert not await approvals.consume("missing", at=NOW)
        from mcp_a2a_gateway.domain.models import ApprovalRequest

        ghost = ApprovalRequest(
            approval_id="f" * 32,
            kind=ApprovalKind.TOOL_CALL,
            requester="r",
            target="t",
            action="a",
            payload_digest="d",
            payload_preview="p",
            reasons=(),
            requested_at=NOW,
            expires_at=NOW,
        )
        with pytest.raises(NotFoundError):
            await approvals.update(ghost)
        from mcp_a2a_gateway.domain.models import AgentCard, AgentCardVersion
        from tests.unit.test_a2a import partner_card

        record = AgentCardVersion(
            card_id="partner",
            version=1,
            trust_domain="agents.partner.test",
            card=AgentCard.model_validate(partner_card()),
            card_digest="d",
            registered_by="a",
            registered_at=NOW,
            updated_at=NOW,
        )
        await cards.add(record)
        with pytest.raises(ConflictError):
            await cards.add(record)
        with pytest.raises(NotFoundError):
            await cards.update(record.model_copy(update={"version": 5}))

    async def test_task_routes(self, engine) -> None:  # type: ignore[no-untyped-def]
        routes = SqlTaskRouteRepository(engine)
        at = datetime.now(UTC)
        await routes.remember("t1", card_id="c", owner="o", at=at)
        await routes.remember("t1", card_id="c", owner="o", at=at)  # idempotent
        with pytest.raises(ConflictError):
            await routes.remember("t1", card_id="c", owner="someone-else", at=at)
        assert await routes.lookup("t1") == ("c", "o")
        assert await routes.lookup("t2") is None

    async def test_audit_sink_chains_per_replica(self, engine) -> None:  # type: ignore[no-untyped-def]
        key = Ed25519PrivateKey.generate()
        first = AuditLog(SqlAuditSink(engine, "gateway-0"), key, key_id="audit-1")
        second = AuditLog(SqlAuditSink(engine, "gateway-1"), key, key_id="audit-1")
        for i in range(3):
            await first.record(actor="a", action="x", resource=str(i), outcome="success")
            await second.record(actor="b", action="y", resource=str(i), outcome="success")
        sink = SqlAuditSink(engine, "gateway-0")
        events = [e async for e in sink.read()]
        assert verify_chain(events, {"audit-1": key.public_key()}) == 3
        assert (await sink.tail()) == events[-1]
        assert await SqlAuditSink(engine, "empty").tail() is None

        # A second writer on the same chain id cannot fork it: the insert fails.
        forked = AuditLog(SqlAuditSink(engine, "gateway-0"), key, key_id="audit-1")
        await forked.record(actor="c", action="z", resource="r", outcome="success")
        with pytest.raises(IntegrityError):
            await first.record(actor="a", action="x", resource="late", outcome="success")

    def test_system_clock_is_aware(self) -> None:
        assert SystemClock().now().tzinfo is not None
