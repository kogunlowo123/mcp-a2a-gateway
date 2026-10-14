"""Agent card directory: registration, signature verification, pinning and lifecycle.

A card is accepted only from a configured trust domain, only from hosts that
domain is allowed to use, and (by default) only with a valid JWS signature
from a key in that domain's JWKS. The verified card is pinned by digest; the
gateway always routes to the pinned card's endpoint, so a remote change to a
card (new endpoint, new skills) takes effect only after review.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from agentic_core.domain.provenance import content_digest
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, ValidationError, model_validator

from mcp_a2a_gateway.application.audit import AuditRecorder
from mcp_a2a_gateway.application.registry import DeprecateTool
from mcp_a2a_gateway.config import TrustDomainConfig
from mcp_a2a_gateway.domain.errors import (
    ConflictError,
    ForbiddenError,
    InvalidStateError,
    NotFoundError,
    ValidationFailedError,
)
from mcp_a2a_gateway.domain.models import (
    SERVABLE,
    AgentCard,
    AgentCardVersion,
    CardPolicy,
    Lifecycle,
    Principal,
    matches_any,
)
from mcp_a2a_gateway.domain.ports import CardRepository, Clock, RemoteAgentPort
from mcp_a2a_gateway.security.card_signatures import signing_payload, verify_card
from mcp_a2a_gateway.security.egress import check_url
from mcp_a2a_gateway.security.jwks import KeyResolver


@dataclass(frozen=True)
class TrustDomain:
    name: str
    config: TrustDomainConfig
    card_keys: KeyResolver


class RegisterCard(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    card_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,47}$")
    trust_domain: str = Field(min_length=1, max_length=253)
    card_url: HttpUrl | None = Field(
        default=None,
        description="Where to fetch the card, e.g. https://host/.well-known/agent-card.json",
    )
    card: dict[str, Any] | None = Field(default=None, description="Inline card document")

    @model_validator(mode="after")
    def _one_source(self) -> RegisterCard:
        if (self.card_url is None) == (self.card is None):
            raise ValueError("provide exactly one of card_url or card")
        return self


class ApproveCard(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    policy: CardPolicy
    reason: str = Field(min_length=5, max_length=1000)


class RefreshResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    card_id: str
    changed: bool
    version: int
    card_digest: str


class AgentDirectory:
    def __init__(
        self,
        *,
        cards: CardRepository,
        remote: RemoteAgentPort,
        trust_domains: dict[str, TrustDomain],
        require_signed: bool,
        audit: AuditRecorder,
        clock: Clock,
    ) -> None:
        self._cards = cards
        self._remote = remote
        self._domains = trust_domains
        self._require_signed = require_signed
        self._audit = audit
        self._clock = clock

    def domain(self, name: str) -> TrustDomain:
        domain = self._domains.get(name)
        if domain is None:
            raise ValidationFailedError(f"trust domain {name} is not federated with this gateway")
        return domain

    async def _verified(
        self, domain: TrustDomain, raw: dict[str, Any]
    ) -> tuple[AgentCard, str, str | None, str | None]:
        try:
            card = AgentCard.model_validate(raw)
        except ValidationError as exc:
            raise ValidationFailedError(
                "agent card is not a valid A2A card",
                data={"fields": sorted({".".join(map(str, e["loc"])) for e in exc.errors()})},
            ) from exc
        check_url(str(card.url), allowed_hosts=domain.config.card_hosts)
        kid = alg = None
        if self._require_signed or raw.get("signatures"):
            verified = await verify_card(raw, domain.card_keys)
            kid, alg = verified.kid, verified.alg
        return card, content_digest(signing_payload(raw)), kid, alg

    async def _fetch(self, domain: TrustDomain, url: str) -> dict[str, Any]:
        check_url(url, allowed_hosts=domain.config.card_hosts)
        return await self._remote.fetch_card(url)

    async def register(self, command: RegisterCard, *, actor: str) -> AgentCardVersion:
        domain = self.domain(command.trust_domain)
        if await self._cards.versions(command.card_id):
            raise ConflictError(f"agent card {command.card_id} exists; use refresh")
        source = str(command.card_url) if command.card_url is not None else None
        raw = command.card if command.card is not None else await self._fetch(domain, source or "")
        card, digest, kid, alg = await self._verified(domain, raw)
        now = self._clock.now()
        record = AgentCardVersion(
            card_id=command.card_id,
            version=1,
            trust_domain=domain.name,
            card=card,
            card_digest=digest,
            signature_kid=kid,
            signature_alg=alg,
            source_url=source,
            registered_by=actor,
            registered_at=now,
            updated_at=now,
        )
        await self._cards.add(record)
        await self._audit.record(
            actor,
            "card.register",
            record.card_id,
            "success",
            {"trust_domain": domain.name, "card_digest": digest, "kid": kid, "url": str(card.url)},
        )
        return record

    async def refresh(self, card_id: str, *, actor: str) -> RefreshResult:
        latest = (await self.versions(card_id))[-1]
        if latest.source_url is None:
            raise InvalidStateError("inline cards cannot be refreshed; register a new card id")
        domain = self.domain(latest.trust_domain)
        raw = await self._fetch(domain, latest.source_url)
        card, digest, kid, alg = await self._verified(domain, raw)
        if digest == latest.card_digest and latest.status is not Lifecycle.REVOKED:
            return RefreshResult(
                card_id=card_id, changed=False, version=latest.version, card_digest=digest
            )
        now = self._clock.now()
        draft = latest.model_copy(
            update={
                "version": latest.version + 1,
                "card": card,
                "card_digest": digest,
                "signature_kid": kid,
                "signature_alg": alg,
                "status": Lifecycle.DRAFT,
                "policy": None,
                "registered_by": actor,
                "registered_at": now,
                "updated_at": now,
                "approved_by": None,
                "approved_at": None,
                "status_reason": None,
                "sunset_at": None,
            }
        )
        await self._cards.add(draft)
        await self._audit.record(
            actor,
            "card.drift",
            card_id,
            "detected",
            {
                "previous_digest": latest.card_digest,
                "card_digest": digest,
                "version": draft.version,
            },
        )
        return RefreshResult(
            card_id=card_id, changed=True, version=draft.version, card_digest=digest
        )

    async def versions(self, card_id: str) -> Sequence[AgentCardVersion]:
        found = await self._cards.versions(card_id)
        if not found:
            raise NotFoundError(f"agent card {card_id} not found")
        return found

    async def version(self, card_id: str, version: int) -> AgentCardVersion:
        found = await self._cards.get(card_id, version)
        if found is None:
            raise NotFoundError(f"agent card {card_id} v{version} not found")
        return found

    async def cards(self, *, status: Lifecycle | None = None) -> Sequence[AgentCardVersion]:
        return await self._cards.list(status=status)

    async def servable(self, card_id: str) -> AgentCardVersion | None:
        for record in reversed(await self._cards.versions(card_id)):
            if record.status in SERVABLE:
                return record
        return None

    async def approve(
        self, card_id: str, version: int, command: ApproveCard, *, actor: str
    ) -> AgentCardVersion:
        record = await self.version(card_id, version)
        if record.status is not Lifecycle.DRAFT:
            raise InvalidStateError(
                f"only draft versions can be approved; this one is {record.status}"
            )
        if actor == record.registered_by:
            raise ForbiddenError("separation of duties: registrant cannot approve the same version")
        domain = self.domain(record.trust_domain)
        if command.policy.classification > domain.config.max_classification:
            raise ValidationFailedError(
                f"classification exceeds trust domain {domain.name} ceiling "
                f"{domain.config.max_classification.name}"
            )
        skills = {s.id for s in record.card.skills}
        unknown = sorted(set(command.policy.allowed_skills) - skills)
        if unknown:
            raise ValidationFailedError(f"allowed_skills not on the card: {unknown}")
        now = self._clock.now()
        for previous in await self._cards.versions(card_id):
            if previous.status in SERVABLE and previous.version != version:
                await self._cards.update(
                    previous.transition(
                        Lifecycle.REVOKED, at=now, reason=f"superseded by version {version}"
                    )
                )
        approved = record.transition(
            Lifecycle.APPROVED,
            at=now,
            reason=command.reason,
            policy=command.policy,
            approved_by=actor,
            approved_at=now,
        )
        await self._cards.update(approved)
        await self._audit.record(
            actor,
            "card.approve",
            f"{card_id}@{version}",
            "success",
            {
                "card_digest": approved.card_digest,
                "risk": int(command.policy.risk),
                "classification": int(command.policy.classification),
                "allowed_callers": list(command.policy.allowed_callers),
            },
        )
        return approved

    async def deprecate(
        self, card_id: str, version: int, command: DeprecateTool, *, actor: str
    ) -> AgentCardVersion:
        record = await self.version(card_id, version)
        now = self._clock.now()
        if command.sunset_at <= now:
            raise ValidationFailedError("sunset_at must be in the future")
        updated = record.transition(
            Lifecycle.DEPRECATED, at=now, reason=command.reason, sunset_at=command.sunset_at
        )
        await self._cards.update(updated)
        await self._audit.record(
            actor, "card.deprecate", f"{card_id}@{version}", "success", {"reason": command.reason}
        )
        return updated

    async def revoke(
        self, card_id: str, version: int, reason: str, *, actor: str
    ) -> AgentCardVersion:
        record = await self.version(card_id, version)
        if record.status is Lifecycle.REVOKED:
            raise ConflictError("agent card version is already revoked")
        updated = record.transition(Lifecycle.REVOKED, at=self._clock.now(), reason=reason)
        await self._cards.update(updated)
        await self._audit.record(
            actor, "card.revoke", f"{card_id}@{version}", "success", {"reason": reason}
        )
        return updated

    async def catalog(self, principal: Principal) -> list[AgentCardVersion]:
        now = self._clock.now()
        visible: list[AgentCardVersion] = []
        for status in (Lifecycle.APPROVED, Lifecycle.DEPRECATED):
            for record in await self._cards.list(status=status):
                if (
                    record.policy is not None
                    and principal.holds(record.action)
                    and matches_any(principal.subject, record.policy.allowed_callers)
                    and (record.sunset_at is None or record.sunset_at > now)
                ):
                    visible.append(record)
        return sorted(visible, key=lambda r: r.card_id)
