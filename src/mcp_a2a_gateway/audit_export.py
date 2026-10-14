"""Export signed audit chains for WORM archival and offline verification.

    python -m mcp_a2a_gateway.audit_export export --out /export [--chain gateway-0] [--after N]
    python -m mcp_a2a_gateway.audit_export commit --out /export

``export`` verifies every chain end to end against the audit public key and
writes the events after the last archived sequence (recorded in the
``audit_exports`` table, or ``--after``) as one JSON Lines file per chain plus
a manifest with the file's SHA-256, the sequence range and the head hash.
Nothing is written for a chain that fails verification.

``commit`` records the manifests' last sequences as archived. Run it only
after the files are safely in WORM storage (the CronJob in
deployments/kubernetes/audit-export-cronjob.yaml runs export, upload, commit
in that order), so a failed upload is retried on the next run.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from agentic_core.audit import AuditEvent, verify_chain
from agentic_core.domain.errors import AuditIntegrityError
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncEngine

from mcp_a2a_gateway.config import Settings
from mcp_a2a_gateway.infrastructure.database import (
    SqlAuditSink,
    audit_events,
    audit_exports,
    create_schema,
    make_engine,
)
from mcp_a2a_gateway.runtime.container import audit_signer


class SegmentManifest(BaseModel):
    model_config = ConfigDict(frozen=True)

    chain_id: str
    key_id: str
    first_sequence: int
    last_sequence: int
    events: int
    head_hash: str
    file: str
    sha256: str


async def chain_ids(engine: AsyncEngine) -> list[str]:
    async with engine.connect() as conn:
        rows = (await conn.execute(select(audit_events.c.chain_id).distinct())).all()
    return sorted(str(r[0]) for r in rows)


async def archived_through(engine: AsyncEngine, chain_id: str) -> int:
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                select(audit_exports.c.last_sequence).where(audit_exports.c.chain_id == chain_id)
            )
        ).first()
    return int(row[0]) if row else -1


def export_segment(
    chain_id: str,
    events: Sequence[AuditEvent],
    *,
    after: int,
    key_id: str,
    public_key: Ed25519PublicKey,
    out: Path,
) -> SegmentManifest | None:
    """Verify the whole chain, then write the events with sequence > ``after``."""
    verify_chain(events, {key_id: public_key})
    segment = [e for e in events if e.sequence > after]
    if not segment:
        return None
    name = f"{chain_id}-{segment[0].sequence:010d}-{segment[-1].sequence:010d}.jsonl"
    body = "".join(e.model_dump_json() + "\n" for e in segment).encode()
    (out / name).write_bytes(body)
    manifest = SegmentManifest(
        chain_id=chain_id,
        key_id=key_id,
        first_sequence=segment[0].sequence,
        last_sequence=segment[-1].sequence,
        events=len(segment),
        head_hash=segment[-1].hash,
        file=name,
        sha256=hashlib.sha256(body).hexdigest(),
    )
    (out / f"{name}.manifest.json").write_text(
        manifest.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    return manifest


async def export(settings: Settings, out: Path, *, chain: str | None, after: int | None) -> int:
    signer, key_id = audit_signer(settings)
    engine = make_engine(settings.database_url)
    failures = 0
    try:
        await create_schema(engine)  # idempotent; an empty database exports nothing
        await asyncio.to_thread(out.mkdir, parents=True, exist_ok=True)
        for chain_id in [chain] if chain else await chain_ids(engine):
            events = [e async for e in SqlAuditSink(engine, chain_id).read()]
            start = after if after is not None else await archived_through(engine, chain_id)
            try:
                manifest = await asyncio.to_thread(
                    export_segment,
                    chain_id,
                    events,
                    after=start,
                    key_id=key_id,
                    public_key=signer.public_key(),
                    out=out,
                )
            except AuditIntegrityError as exc:
                failures += 1
                sys.stderr.write(f"{chain_id}: verification failed at {exc.sequence}: {exc}\n")
                continue
            summary = manifest.model_dump() if manifest else {"chain_id": chain_id, "events": 0}
            sys.stdout.write(json.dumps(summary) + "\n")
    finally:
        await engine.dispose()
    return 1 if failures else 0


def read_manifests(out: Path) -> list[SegmentManifest]:
    return [
        SegmentManifest.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(out.glob("*.manifest.json"))
    ]


async def commit(settings: Settings, out: Path) -> int:
    """Record the archived position of every manifest in ``out`` (never moves backwards)."""
    engine = make_engine(settings.database_url)
    try:
        await create_schema(engine)
        for manifest in await asyncio.to_thread(read_manifests, out):
            current = await archived_through(engine, manifest.chain_id)
            if manifest.last_sequence <= current:
                continue
            now = datetime.now(UTC)
            async with engine.begin() as conn:
                if current < 0:
                    await conn.execute(
                        insert(audit_exports).values(
                            chain_id=manifest.chain_id,
                            last_sequence=manifest.last_sequence,
                            updated_at=now,
                        )
                    )
                else:
                    await conn.execute(
                        update(audit_exports)
                        .where(audit_exports.c.chain_id == manifest.chain_id)
                        .values(last_sequence=manifest.last_sequence, updated_at=now)
                    )
            sys.stdout.write(f"{manifest.chain_id}: archived through {manifest.last_sequence}\n")
    finally:
        await engine.dispose()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mcp_a2a_gateway.audit_export")
    commands = parser.add_subparsers(dest="command", required=True)
    exporting = commands.add_parser("export", help="write verified segments to --out")
    exporting.add_argument("--out", type=Path, required=True)
    exporting.add_argument("--chain", help="one chain id (default: every chain)")
    exporting.add_argument("--after", type=int, help="override the recorded archive position")
    committing = commands.add_parser("commit", help="record segments in --out as archived")
    committing.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    settings = Settings()  # populated from GATEWAY_* environment variables
    if args.command == "export":
        return asyncio.run(export(settings, args.out, chain=args.chain, after=args.after))
    return asyncio.run(commit(settings, args.out))


if __name__ == "__main__":
    raise SystemExit(main())
