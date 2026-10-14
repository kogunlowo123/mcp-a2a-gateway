"""SQLAlchemy Core persistence. PostgreSQL in production; SQLite in tests.

Aggregates are stored as validated JSON documents next to the columns that
queries filter on. The signed audit chain lives here too: one chain per
replica (``chain_id``), with ``(chain_id, sequence)`` as the primary key so a
forked or replayed chain fails on insert instead of silently diverging.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime

from agentic_core.audit import AuditEvent
from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    insert,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from mcp_a2a_gateway.domain.errors import ConflictError, NotFoundError
from mcp_a2a_gateway.domain.models import (
    AgentCardVersion,
    ApprovalRequest,
    ApprovalStatus,
    Lifecycle,
    ToolVersion,
    UpstreamServer,
)

metadata = MetaData()

servers = Table(
    "upstream_servers",
    metadata,
    Column("server_id", String(32), primary_key=True),
    Column("document", Text, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

tool_versions = Table(
    "tool_versions",
    metadata,
    Column("server_id", String(32), primary_key=True),
    Column("name", String(64), primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("status", String(16), nullable=False),
    Column("document", Text, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Index("ix_tool_versions_status", "status"),
)

agent_cards = Table(
    "agent_cards",
    metadata,
    Column("card_id", String(48), primary_key=True),
    Column("version", Integer, primary_key=True),
    Column("status", String(16), nullable=False),
    Column("document", Text, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Index("ix_agent_cards_status", "status"),
)

approvals = Table(
    "approvals",
    metadata,
    Column("approval_id", String(64), primary_key=True),
    Column("status", String(16), nullable=False),
    Column("requester", String(512), nullable=False),
    Column("document", Text, nullable=False),
    Column("requested_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Index("ix_approvals_status", "status"),
)

task_routes = Table(
    "task_routes",
    metadata,
    Column("task_id", String(256), primary_key=True),
    Column("card_id", String(48), nullable=False),
    Column("owner", String(512), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

audit_events = Table(
    "audit_events",
    metadata,
    Column("chain_id", String(128), primary_key=True),
    Column("sequence", Integer, primary_key=True),
    Column("event_id", String(64), nullable=False, unique=True),
    Column("document", Text, nullable=False),
)

audit_exports = Table(
    "audit_exports",
    metadata,
    Column("chain_id", String(128), primary_key=True),
    Column("last_sequence", Integer, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

schema_version = Table(
    "schema_version",
    metadata,
    Column("version", Integer, primary_key=True),
)

SCHEMA_VERSION = 1


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


async def create_schema(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
        current = (await conn.execute(select(schema_version.c.version))).scalar()
        if current is None:
            await conn.execute(insert(schema_version).values(version=SCHEMA_VERSION))


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class SqlServerRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, server: UpstreamServer) -> None:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    insert(servers).values(
                        server_id=server.server_id,
                        document=server.model_dump_json(),
                        created_at=server.created_at,
                        updated_at=server.updated_at,
                    )
                )
        except IntegrityError as exc:
            raise ConflictError(f"upstream server {server.server_id} already registered") from exc

    async def get(self, server_id: str) -> UpstreamServer | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(servers.c.document).where(servers.c.server_id == server_id)
                )
            ).first()
        return UpstreamServer.model_validate_json(row[0]) if row else None

    async def update(self, server: UpstreamServer) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(servers)
                .where(servers.c.server_id == server.server_id)
                .values(document=server.model_dump_json(), updated_at=server.updated_at)
            )
        if result.rowcount == 0:
            raise NotFoundError(f"upstream server {server.server_id} not found")

    async def list(self) -> Sequence[UpstreamServer]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(select(servers.c.document).order_by(servers.c.server_id))
            ).all()
        return [UpstreamServer.model_validate_json(r[0]) for r in rows]


class SqlToolRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, tool: ToolVersion) -> None:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    insert(tool_versions).values(
                        server_id=tool.server_id,
                        name=tool.name,
                        version=tool.version,
                        status=tool.status.value,
                        document=tool.model_dump_json(),
                        updated_at=tool.updated_at,
                    )
                )
        except IntegrityError as exc:
            raise ConflictError(f"tool {tool.exposed_name} v{tool.version} already exists") from exc

    async def update(self, tool: ToolVersion) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(tool_versions)
                .where(
                    (tool_versions.c.server_id == tool.server_id)
                    & (tool_versions.c.name == tool.name)
                    & (tool_versions.c.version == tool.version)
                )
                .values(
                    status=tool.status.value,
                    document=tool.model_dump_json(),
                    updated_at=tool.updated_at,
                )
            )
        if result.rowcount == 0:
            raise NotFoundError(f"tool {tool.exposed_name} v{tool.version} not found")

    async def get(self, server_id: str, name: str, version: int) -> ToolVersion | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(tool_versions.c.document).where(
                        (tool_versions.c.server_id == server_id)
                        & (tool_versions.c.name == name)
                        & (tool_versions.c.version == version)
                    )
                )
            ).first()
        return ToolVersion.model_validate_json(row[0]) if row else None

    async def versions(self, server_id: str, name: str) -> Sequence[ToolVersion]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(tool_versions.c.document)
                    .where(
                        (tool_versions.c.server_id == server_id) & (tool_versions.c.name == name)
                    )
                    .order_by(tool_versions.c.version)
                )
            ).all()
        return [ToolVersion.model_validate_json(r[0]) for r in rows]

    async def latest_by_server(self, server_id: str) -> Sequence[ToolVersion]:
        latest: dict[str, ToolVersion] = {}
        for tool in await self.list(server_id=server_id):
            if tool.name not in latest or tool.version > latest[tool.name].version:
                latest[tool.name] = tool
        return sorted(latest.values(), key=lambda t: t.name)

    async def list(
        self, *, status: Lifecycle | None = None, server_id: str | None = None
    ) -> Sequence[ToolVersion]:
        query = select(tool_versions.c.document).order_by(
            tool_versions.c.server_id, tool_versions.c.name, tool_versions.c.version
        )
        if status is not None:
            query = query.where(tool_versions.c.status == status.value)
        if server_id is not None:
            query = query.where(tool_versions.c.server_id == server_id)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [ToolVersion.model_validate_json(r[0]) for r in rows]


class SqlCardRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, card: AgentCardVersion) -> None:
        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    insert(agent_cards).values(
                        card_id=card.card_id,
                        version=card.version,
                        status=card.status.value,
                        document=card.model_dump_json(),
                        updated_at=card.updated_at,
                    )
                )
        except IntegrityError as exc:
            raise ConflictError(f"agent card {card.card_id} v{card.version} exists") from exc

    async def update(self, card: AgentCardVersion) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(agent_cards)
                .where(
                    (agent_cards.c.card_id == card.card_id)
                    & (agent_cards.c.version == card.version)
                )
                .values(
                    status=card.status.value,
                    document=card.model_dump_json(),
                    updated_at=card.updated_at,
                )
            )
        if result.rowcount == 0:
            raise NotFoundError(f"agent card {card.card_id} v{card.version} not found")

    async def get(self, card_id: str, version: int) -> AgentCardVersion | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(agent_cards.c.document).where(
                        (agent_cards.c.card_id == card_id) & (agent_cards.c.version == version)
                    )
                )
            ).first()
        return AgentCardVersion.model_validate_json(row[0]) if row else None

    async def versions(self, card_id: str) -> Sequence[AgentCardVersion]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(agent_cards.c.document)
                    .where(agent_cards.c.card_id == card_id)
                    .order_by(agent_cards.c.version)
                )
            ).all()
        return [AgentCardVersion.model_validate_json(r[0]) for r in rows]

    async def list(self, *, status: Lifecycle | None = None) -> Sequence[AgentCardVersion]:
        query = select(agent_cards.c.document).order_by(
            agent_cards.c.card_id, agent_cards.c.version
        )
        if status is not None:
            query = query.where(agent_cards.c.status == status.value)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [AgentCardVersion.model_validate_json(r[0]) for r in rows]


class SqlApprovalRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def add(self, approval: ApprovalRequest) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(approvals).values(
                    approval_id=approval.approval_id,
                    status=approval.status.value,
                    requester=approval.requester,
                    document=approval.model_dump_json(),
                    requested_at=approval.requested_at,
                    expires_at=approval.expires_at,
                )
            )

    async def get(self, approval_id: str) -> ApprovalRequest | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(approvals.c.document).where(approvals.c.approval_id == approval_id)
                )
            ).first()
        return ApprovalRequest.model_validate_json(row[0]) if row else None

    async def update(self, approval: ApprovalRequest) -> None:
        async with self._engine.begin() as conn:
            result = await conn.execute(
                update(approvals)
                .where(approvals.c.approval_id == approval.approval_id)
                .values(status=approval.status.value, document=approval.model_dump_json())
            )
        if result.rowcount == 0:
            raise NotFoundError(f"approval {approval.approval_id} not found")

    async def consume(self, approval_id: str, *, at: datetime) -> bool:
        async with self._engine.begin() as conn:
            claimed = await conn.execute(
                update(approvals)
                .where(
                    (approvals.c.approval_id == approval_id)
                    & (approvals.c.status == ApprovalStatus.APPROVED.value)
                )
                .values(status=ApprovalStatus.USED.value)
            )
            if claimed.rowcount != 1:
                return False
            row = (
                await conn.execute(
                    select(approvals.c.document).where(approvals.c.approval_id == approval_id)
                )
            ).one()
            used = ApprovalRequest.model_validate_json(row[0]).model_copy(
                update={"status": ApprovalStatus.USED, "used_at": _aware(at)}
            )
            await conn.execute(
                update(approvals)
                .where(approvals.c.approval_id == approval_id)
                .values(document=used.model_dump_json())
            )
        return True

    async def list(
        self, *, status: ApprovalStatus | None = None, limit: int = 100
    ) -> Sequence[ApprovalRequest]:
        query = select(approvals.c.document).order_by(approvals.c.requested_at.desc()).limit(limit)
        if status is not None:
            query = query.where(approvals.c.status == status.value)
        async with self._engine.connect() as conn:
            rows = (await conn.execute(query)).all()
        return [ApprovalRequest.model_validate_json(r[0]) for r in rows]


class SqlTaskRouteRepository:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine

    async def remember(self, task_id: str, *, card_id: str, owner: str, at: datetime) -> None:
        async with self._engine.begin() as conn:
            existing = (
                await conn.execute(
                    select(task_routes.c.card_id, task_routes.c.owner).where(
                        task_routes.c.task_id == task_id
                    )
                )
            ).first()
            if existing is None:
                await conn.execute(
                    insert(task_routes).values(
                        task_id=task_id, card_id=card_id, owner=owner, created_at=at
                    )
                )
            elif (existing[0], existing[1]) != (card_id, owner):
                raise ConflictError("task id is already bound to another agent or caller")

    async def lookup(self, task_id: str) -> tuple[str, str] | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(task_routes.c.card_id, task_routes.c.owner).where(
                        task_routes.c.task_id == task_id
                    )
                )
            ).first()
        return (str(row[0]), str(row[1])) if row else None


class SqlAuditSink:
    """agentic-core ``AuditSink`` storing one replica's chain in the database."""

    def __init__(self, engine: AsyncEngine, chain_id: str) -> None:
        self._engine = engine
        self.chain_id = chain_id

    async def append(self, event: AuditEvent) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                insert(audit_events).values(
                    chain_id=self.chain_id,
                    sequence=event.sequence,
                    event_id=event.event_id,
                    document=event.model_dump_json(),
                )
            )

    async def read(self) -> AsyncIterator[AuditEvent]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(audit_events.c.document)
                    .where(audit_events.c.chain_id == self.chain_id)
                    .order_by(audit_events.c.sequence)
                )
            ).all()
        for row in rows:
            yield AuditEvent.model_validate_json(row[0])

    async def tail(self) -> AuditEvent | None:
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(audit_events.c.document)
                    .where(audit_events.c.chain_id == self.chain_id)
                    .order_by(audit_events.c.sequence.desc())
                    .limit(1)
                )
            ).first()
        return AuditEvent.model_validate_json(row[0]) if row else None


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)
