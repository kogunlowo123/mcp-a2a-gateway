"""Runtime settings, read from GATEWAY_* environment variables."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from agentic_core.domain.classification import DataClassification
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_TRUST_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9.\-_]{0,253}[a-z0-9])?$")


class TrustDomainConfig(BaseModel):
    """A federated trust domain whose agent cards (and optionally tokens) the gateway accepts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    card_jwks_url: str | None = Field(
        default=None, description="JWKS of the keys that sign this domain's agent cards"
    )
    card_jwks: dict[str, Any] | None = Field(
        default=None, description="Inline JWKS alternative to card_jwks_url"
    )
    card_hosts: tuple[str, ...] = Field(
        min_length=1, description="Host globs agent cards and agent endpoints may live on"
    )
    max_classification: DataClassification = DataClassification.INTERNAL
    max_delegation_depth: int = Field(default=2, ge=0, le=5)
    token_issuer: str | None = Field(
        default=None, description="Issuer of this domain's agent credentials (inbound federation)"
    )
    token_jwks_url: str | None = None
    token_audience: str | None = None
    inbound_scopes: tuple[str, ...] = Field(
        default=(), description="Ceiling (globs) on scopes a federated caller may exercise here"
    )

    @model_validator(mode="after")
    def _complete(self) -> TrustDomainConfig:
        if (self.card_jwks_url is None) == (self.card_jwks is None):
            raise ValueError("exactly one of card_jwks_url or card_jwks is required")
        inbound = (self.token_issuer, self.token_jwks_url, self.token_audience)
        if any(v is not None for v in inbound) and not all(v is not None for v in inbound):
            raise ValueError(
                "inbound federation needs token_issuer, token_jwks_url, token_audience"
            )
        if self.token_issuer is not None and not self.inbound_scopes:
            raise ValueError("inbound federation needs a non-empty inbound_scopes ceiling")
        return self

    @property
    def accepts_inbound(self) -> bool:
        return self.token_issuer is not None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="GATEWAY_", env_nested_delimiter="__")

    environment: str = "production"
    public_url: HttpUrl = Field(description="Public base URL of this gateway")
    trust_domain: str = Field(description="Trust domain of the agents this gateway serves")
    database_url: str = Field(description="SQLAlchemy async URL, e.g. postgresql+asyncpg://...")

    # Identity fabric (preferred) or a local JWKS for agent credentials.
    fabric_url: str | None = Field(default=None, description="Agent identity fabric base URL")
    gateway_agent_id: str | None = Field(
        default=None, description="This gateway's SPIFFE ID as registered in the fabric"
    )
    workload_token_file: Path | None = Field(
        default=None, description="Projected service-account token used to obtain credentials"
    )
    token_issuer: str | None = Field(default=None, description="iss of agent credentials")
    token_audience: str = Field(default="agent-platform", description="aud of agent credentials")
    token_jwks_url: str | None = Field(
        default=None, description="JWKS for local verification when fabric_url is not set"
    )

    admin_issuer: str = Field(description="Enterprise OIDC issuer for administrators")
    admin_audience: str = Field(description="Audience administrators' tokens must carry")
    admin_jwks_url: str
    admin_roles_claim: str = "roles"

    policy_file: Path = Path("policies/gateway-authorization.yaml")
    audit_key_file: Path | None = None
    audit_chain_id: str = Field(
        default="gateway-0", description="One signed chain per replica; set to the pod name"
    )
    dev_ephemeral_keys: bool = Field(
        default=False, description="In-memory audit key. Refused when environment=production."
    )

    upstream_allowed_hosts: tuple[str, ...] = Field(
        default=(), description="Host globs upstream MCP servers may be registered on"
    )
    allow_insecure_upstreams: bool = Field(
        default=False, description="Permit http:// upstreams. Refused in production."
    )
    trust_domains: dict[str, TrustDomainConfig] = Field(default_factory=dict)
    require_signed_cards: bool = True
    mcp_allowed_hosts: tuple[str, ...] = Field(
        default=(), description="Host header values accepted on /mcp (DNS rebinding protection)"
    )

    definition_ttl_seconds: int = Field(default=60, ge=0, le=3600)
    approval_ttl_seconds: int = Field(default=3600, ge=60, le=86_400)
    max_argument_bytes: int = Field(default=262_144, ge=1024, le=4_194_304)
    a2a_max_response_bytes: int = Field(default=1_048_576, ge=1024, le=16_777_216)
    a2a_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    rate_limit_per_minute: int = Field(default=600, ge=1, le=100_000)
    circuit_failure_threshold: int = Field(default=5, ge=1, le=100)
    circuit_reset_seconds: float = Field(default=30.0, gt=0, le=600)

    log_level: str = "INFO"
    otlp_endpoint: str | None = None

    @field_validator("trust_domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        if not _TRUST_DOMAIN.fullmatch(value):
            raise ValueError(f"invalid trust domain {value!r}")
        return value

    @field_validator("trust_domains")
    @classmethod
    def _domains(cls, value: dict[str, TrustDomainConfig]) -> dict[str, TrustDomainConfig]:
        bad = [name for name in value if not _TRUST_DOMAIN.fullmatch(name)]
        if bad:
            raise ValueError(f"invalid trust domain names {bad}")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> Settings:
        production = self.environment == "production"
        if self.dev_ephemeral_keys:
            if production:
                raise ValueError("dev_ephemeral_keys cannot be used in production")
        elif self.audit_key_file is None:
            raise ValueError("GATEWAY_AUDIT_KEY_FILE is required")
        if self.allow_insecure_upstreams and production:
            raise ValueError("allow_insecure_upstreams cannot be used in production")
        if self.fabric_url is None:
            if self.token_issuer is None or self.token_jwks_url is None:
                raise ValueError(
                    "without GATEWAY_FABRIC_URL, GATEWAY_TOKEN_ISSUER and GATEWAY_TOKEN_JWKS_URL "
                    "are required for local credential verification"
                )
        elif (self.gateway_agent_id is None) != (self.workload_token_file is None):
            raise ValueError("gateway_agent_id and workload_token_file must be set together")
        return self

    @property
    def public_base(self) -> str:
        return str(self.public_url).rstrip("/")

    @property
    def delegation_enabled(self) -> bool:
        return self.fabric_url is not None and self.gateway_agent_id is not None
