"""Gateway domain model: upstream servers, pinned tool versions, agent cards, approvals."""

from __future__ import annotations

import fnmatch
import re
from datetime import datetime
from enum import StrEnum
from typing import Any

from agentic_core.domain.classification import DataClassification, RiskLevel
from agentic_core.domain.provenance import canonical_json, content_digest
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from mcp_a2a_gateway.domain.errors import InvalidStateError

SERVER_ID = re.compile(r"^[a-z][a-z0-9-]{1,23}$")
CARD_ID = re.compile(r"^[a-z][a-z0-9-]{1,47}$")
# MCP tool names (SEP-986): 1-64 characters from [A-Za-z0-9_.-].
TOOL_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
SECRET_ENV = re.compile(r"^GATEWAY_UPSTREAM_SECRET_[A-Z0-9_]{1,40}$")
SPIFFE_PATTERN = re.compile(r"^spiffe://[a-z0-9.\-_*]+(/[A-Za-z0-9.\-_*]+)*$")
EXPOSED_SEPARATOR = "__"
MAX_EXPOSED_NAME = 64


class Lifecycle(StrEnum):
    DRAFT = "draft"  # discovered or registered, not callable
    APPROVED = "approved"  # reviewed and pinned, callable
    DEPRECATED = "deprecated"  # callable until its sunset, hidden from new catalogs after
    REVOKED = "revoked"  # terminal


_TRANSITIONS: dict[Lifecycle, frozenset[Lifecycle]] = {
    Lifecycle.DRAFT: frozenset({Lifecycle.APPROVED, Lifecycle.REVOKED}),
    Lifecycle.APPROVED: frozenset({Lifecycle.DEPRECATED, Lifecycle.REVOKED}),
    Lifecycle.DEPRECATED: frozenset({Lifecycle.REVOKED}),
    Lifecycle.REVOKED: frozenset(),
}

SERVABLE = frozenset({Lifecycle.APPROVED, Lifecycle.DEPRECATED})


def check_transition(current: Lifecycle, target: Lifecycle, *, what: str) -> None:
    if target not in _TRANSITIONS[current]:
        raise InvalidStateError(f"cannot move {what} from {current} to {target}")


def matches_any(value: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


def _patterns(values: tuple[str, ...]) -> tuple[str, ...]:
    bad = [v for v in values if not SPIFFE_PATTERN.fullmatch(v)]
    if bad:
        raise ValueError(f"caller patterns must be SPIFFE IDs (globs allowed): {bad}")
    return values


# --------------------------------------------------------------------------- MCP


class UpstreamAuthMode(StrEnum):
    NONE = "none"  # upstream is protected by network policy / mTLS only
    STATIC_BEARER = "static_bearer"  # gateway's own credential from a mounted secret
    DELEGATED = "delegated"  # RFC 8693 token minted per call by the identity fabric


class UpstreamAuth(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: UpstreamAuthMode = UpstreamAuthMode.DELEGATED
    secret_env: str | None = Field(
        default=None,
        description="Environment variable holding the bearer token (static_bearer only); "
        "must start with GATEWAY_UPSTREAM_SECRET_",
    )

    @model_validator(mode="after")
    def _secret(self) -> UpstreamAuth:
        if self.mode is UpstreamAuthMode.STATIC_BEARER:
            if self.secret_env is None or not SECRET_ENV.fullmatch(self.secret_env):
                raise ValueError(
                    "static_bearer needs secret_env matching GATEWAY_UPSTREAM_SECRET_*"
                )
        elif self.secret_env is not None:
            raise ValueError("secret_env is only valid with static_bearer")
        return self


class UpstreamServer(BaseModel):
    model_config = ConfigDict(frozen=True)

    server_id: str
    display_name: str = Field(min_length=3, max_length=120)
    url: HttpUrl
    owner: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=2000)
    auth: UpstreamAuth = UpstreamAuth()
    max_response_bytes: int = Field(default=1_048_576, ge=1024, le=16_777_216)
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    enabled: bool = True
    registered_by: str
    created_at: datetime
    updated_at: datetime

    @field_validator("server_id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not SERVER_ID.fullmatch(value) or EXPOSED_SEPARATOR in value:
            raise ValueError("server_id must match ^[a-z][a-z0-9-]{1,23}$")
        return value


class ToolDefinition(BaseModel):
    """The parts of an MCP tool definition that are pinned and hashed."""

    model_config = ConfigDict(frozen=True)

    name: str
    title: str | None = None
    description: str = ""
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] | None = None

    def digest(self) -> str:
        """Hash over the canonical JSON of every field an agent or model can observe."""
        return content_digest(canonical_json(self.model_dump(mode="json")))

    @property
    def destructive(self) -> bool:
        """MCP ``destructiveHint`` defaults to true when ``readOnlyHint`` is not set."""
        hints = self.annotations or {}
        if hints.get("readOnlyHint") is True:
            return False
        return bool(hints.get("destructiveHint", True))


class ToolPolicy(BaseModel):
    """Set by a reviewer when a tool version is approved."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    risk: RiskLevel
    classification: DataClassification
    allowed_agents: tuple[str, ...] = Field(
        min_length=1, description="SPIFFE IDs (globs allowed) of agents that may call the tool"
    )
    max_response_bytes: int | None = Field(default=None, ge=1024, le=16_777_216)
    redact_pii: bool = True
    requires_approval: bool = Field(
        default=False, description="Every call needs human approval regardless of risk"
    )

    @field_validator("allowed_agents")
    @classmethod
    def _agents(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _patterns(value)


class ToolVersion(BaseModel):
    model_config = ConfigDict(frozen=True)

    server_id: str
    name: str
    version: int = Field(ge=1)
    definition: ToolDefinition
    definition_hash: str
    status: Lifecycle = Lifecycle.DRAFT
    policy: ToolPolicy | None = None
    injection_score: float = Field(
        default=0.0, description="Prompt-injection score of the description and schema text"
    )
    injection_kinds: tuple[str, ...] = ()
    discovered_by: str
    discovered_at: datetime
    updated_at: datetime
    approved_by: str | None = None
    approved_at: datetime | None = None
    status_reason: str | None = None
    sunset_at: datetime | None = None

    @property
    def exposed_name(self) -> str:
        return f"{self.server_id}{EXPOSED_SEPARATOR}{self.name}"

    @property
    def action(self) -> str:
        return tool_action(self.server_id, self.name)

    def transition(
        self, target: Lifecycle, *, at: datetime, reason: str | None, **changes: Any
    ) -> ToolVersion:
        check_transition(self.status, target, what=f"tool {self.exposed_name} v{self.version}")
        return self.model_copy(
            update={"status": target, "updated_at": at, "status_reason": reason, **changes}
        )


def tool_action(server_id: str, tool_name: str) -> str:
    """Scope-shaped action string evaluated by the identity fabric and local policy."""
    return f"mcp:{server_id}:{tool_name.lower()}"


def split_exposed_name(exposed: str) -> tuple[str, str] | None:
    server_id, sep, name = exposed.partition(EXPOSED_SEPARATOR)
    if not sep or not SERVER_ID.fullmatch(server_id) or not TOOL_NAME.fullmatch(name):
        return None
    return server_id, name


# --------------------------------------------------------------------------- A2A


class AgentSkill(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow", populate_by_name=True)

    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    tags: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()
    input_modes: tuple[str, ...] | None = Field(default=None, alias="inputModes")
    output_modes: tuple[str, ...] | None = Field(default=None, alias="outputModes")


class AgentCapabilities(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow", populate_by_name=True)

    streaming: bool = False
    push_notifications: bool = Field(default=False, alias="pushNotifications")
    state_transition_history: bool = Field(default=False, alias="stateTransitionHistory")


class AgentCardSignature(BaseModel):
    """JWS over the canonical card (A2A ``AgentCardSignature``)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    protected: str = Field(min_length=4, description="base64url JWS protected header")
    signature: str = Field(min_length=4, description="base64url signature")
    header: dict[str, Any] | None = None


class AgentCard(BaseModel):
    """A2A Agent Card. Unknown fields are preserved so signatures stay verifiable."""

    model_config = ConfigDict(frozen=True, extra="allow", populate_by_name=True)

    protocol_version: str = Field(default="0.3.0", alias="protocolVersion")
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    url: HttpUrl
    version: str = Field(min_length=1, max_length=64)
    capabilities: AgentCapabilities = AgentCapabilities()
    skills: tuple[AgentSkill, ...] = Field(min_length=1)
    default_input_modes: tuple[str, ...] = Field(default=("text/plain",), alias="defaultInputModes")
    default_output_modes: tuple[str, ...] = Field(
        default=("text/plain",), alias="defaultOutputModes"
    )
    security_schemes: dict[str, Any] | None = Field(default=None, alias="securitySchemes")
    security: tuple[dict[str, Any], ...] | None = None
    preferred_transport: str = Field(default="JSONRPC", alias="preferredTransport")
    signatures: tuple[AgentCardSignature, ...] | None = None

    def wire(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude_none=True)


class CardPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    risk: RiskLevel
    classification: DataClassification
    allowed_callers: tuple[str, ...] = Field(min_length=1)
    allowed_skills: tuple[str, ...] = Field(
        default=(), description="Skill ids callers may target; empty allows every card skill"
    )
    redact_pii: bool = True
    requires_approval: bool = False

    @field_validator("allowed_callers")
    @classmethod
    def _callers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _patterns(value)


class AgentCardVersion(BaseModel):
    model_config = ConfigDict(frozen=True)

    card_id: str
    version: int = Field(ge=1)
    trust_domain: str
    card: AgentCard
    card_digest: str
    signature_kid: str | None = None
    signature_alg: str | None = None
    source_url: str | None = None
    status: Lifecycle = Lifecycle.DRAFT
    policy: CardPolicy | None = None
    registered_by: str
    registered_at: datetime
    updated_at: datetime
    approved_by: str | None = None
    approved_at: datetime | None = None
    status_reason: str | None = None
    sunset_at: datetime | None = None

    @field_validator("card_id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not CARD_ID.fullmatch(value):
            raise ValueError("card_id must match ^[a-z][a-z0-9-]{1,47}$")
        return value

    @property
    def action(self) -> str:
        return f"a2a:send:{self.card_id}"

    def transition(
        self, target: Lifecycle, *, at: datetime, reason: str | None, **changes: Any
    ) -> AgentCardVersion:
        check_transition(self.status, target, what=f"agent card {self.card_id} v{self.version}")
        return self.model_copy(
            update={"status": target, "updated_at": at, "status_reason": reason, **changes}
        )


# ----------------------------------------------------------------------- approvals


class ApprovalKind(StrEnum):
    TOOL_CALL = "tool_call"
    A2A_MESSAGE = "a2a_message"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    USED = "used"


class ApprovalRequest(BaseModel):
    """A pending high-risk call, bound to the exact caller, target and payload digest."""

    model_config = ConfigDict(frozen=True)

    approval_id: str
    kind: ApprovalKind
    requester: str
    delegation_chain: tuple[str, ...] = ()
    target: str = Field(description="exposed tool name or agent card id")
    action: str
    payload_digest: str
    payload_preview: str = Field(description="Redacted, truncated payload shown to the approver")
    reasons: tuple[str, ...]
    status: ApprovalStatus = ApprovalStatus.PENDING
    requested_at: datetime
    expires_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_reason: str | None = None
    used_at: datetime | None = None


# ---------------------------------------------------------------------- principals


class Principal(BaseModel):
    """An authenticated caller of the MCP or A2A endpoints."""

    model_config = ConfigDict(frozen=True)

    subject: str
    scopes: frozenset[str]
    delegation_chain: tuple[str, ...] = ()
    trust_domain: str
    federated: bool = False
    authenticated_by: str = Field(description="fabric, jwks or federation:<trust domain>")
    token: str = Field(repr=False, exclude=True)

    @property
    def delegation_depth(self) -> int:
        return len(self.delegation_chain)

    def holds(self, action: str) -> bool:
        return any(fnmatch.fnmatchcase(action, scope) for scope in self.scopes)

    def matching_scope(self, action: str) -> str | None:
        """The most specific held scope that covers ``action`` (exact before wildcard)."""
        if action in self.scopes:
            return action
        covering = sorted(
            (s for s in self.scopes if fnmatch.fnmatchcase(action, s)), key=lambda s: -len(s)
        )
        return covering[0] if covering else None
