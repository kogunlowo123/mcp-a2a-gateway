"""Domain model invariants and settings validation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from agentic_core.domain.classification import DataClassification, RiskLevel
from pydantic import ValidationError

from mcp_a2a_gateway.config import Settings, TrustDomainConfig
from mcp_a2a_gateway.domain.errors import InvalidStateError
from mcp_a2a_gateway.domain.models import (
    AgentCard,
    CardPolicy,
    Lifecycle,
    Principal,
    ToolDefinition,
    ToolPolicy,
    ToolVersion,
    UpstreamAuth,
    UpstreamAuthMode,
    UpstreamServer,
    check_transition,
    split_exposed_name,
    tool_action,
)
from tests.conftest import Network, make_settings, partner_card

NOW = datetime(2026, 10, 14, tzinfo=UTC)


def definition(**changes: Any) -> ToolDefinition:
    values: dict[str, Any] = {
        "name": "lookup",
        "description": "Look up a record",
        "input_schema": {"type": "object", "properties": {"id": {"type": "string"}}},
    }
    values.update(changes)
    return ToolDefinition(**values)


def version(**changes: Any) -> ToolVersion:
    values: dict[str, Any] = {
        "server_id": "crm",
        "name": "lookup",
        "version": 1,
        "definition": definition(),
        "definition_hash": definition().digest(),
        "discovered_by": "alice",
        "discovered_at": NOW,
        "updated_at": NOW,
    }
    values.update(changes)
    return ToolVersion(**values)


class TestLifecycle:
    @pytest.mark.parametrize(
        ("current", "target"),
        [
            (Lifecycle.DRAFT, Lifecycle.APPROVED),
            (Lifecycle.DRAFT, Lifecycle.REVOKED),
            (Lifecycle.APPROVED, Lifecycle.DEPRECATED),
            (Lifecycle.APPROVED, Lifecycle.REVOKED),
            (Lifecycle.DEPRECATED, Lifecycle.REVOKED),
        ],
    )
    def test_allowed(self, current: Lifecycle, target: Lifecycle) -> None:
        check_transition(current, target, what="x")

    @pytest.mark.parametrize(
        ("current", "target"),
        [
            (Lifecycle.DRAFT, Lifecycle.DEPRECATED),
            (Lifecycle.DEPRECATED, Lifecycle.APPROVED),
            (Lifecycle.REVOKED, Lifecycle.APPROVED),
            (Lifecycle.REVOKED, Lifecycle.DRAFT),
            (Lifecycle.APPROVED, Lifecycle.DRAFT),
        ],
    )
    def test_refused(self, current: Lifecycle, target: Lifecycle) -> None:
        with pytest.raises(InvalidStateError):
            check_transition(current, target, what="x")

    def test_transition_updates_fields(self) -> None:
        approved = version().transition(
            Lifecycle.APPROVED, at=NOW, reason="ok", approved_by="bob", approved_at=NOW
        )
        assert approved.status is Lifecycle.APPROVED
        assert approved.approved_by == "bob"
        assert approved.status_reason == "ok"


class TestToolDefinition:
    def test_digest_ignores_key_order_but_not_content(self) -> None:
        a = definition(input_schema={"type": "object", "properties": {"id": {"type": "string"}}})
        b = definition(input_schema={"properties": {"id": {"type": "string"}}, "type": "object"})
        assert a.digest() == b.digest()
        assert definition(description="Look up a record!").digest() != a.digest()
        assert a.digest().startswith("sha256:")

    @pytest.mark.parametrize(
        ("annotations", "destructive"),
        [
            (None, True),
            ({"readOnlyHint": True}, False),
            ({"destructiveHint": False}, False),
            ({"readOnlyHint": False, "destructiveHint": True}, True),
        ],
    )
    def test_destructive_hint_defaults(
        self, annotations: dict[str, Any] | None, destructive: bool
    ) -> None:
        assert definition(annotations=annotations).destructive is destructive

    def test_exposed_names_and_actions(self) -> None:
        tool = version(name="Create_Ticket")
        assert tool.exposed_name == "crm__Create_Ticket"
        assert tool.action == "mcp:crm:create_ticket"
        assert tool_action("crm", "X") == "mcp:crm:x"
        assert split_exposed_name("crm__lookup") == ("crm", "lookup")
        for bad in ("crm", "crm__", "__lookup", "Crm__lookup", "crm__bad name"):
            assert split_exposed_name(bad) is None


class TestModels:
    def test_upstream_auth_rules(self) -> None:
        UpstreamAuth(mode=UpstreamAuthMode.STATIC_BEARER, secret_env="GATEWAY_UPSTREAM_SECRET_CRM")
        with pytest.raises(ValidationError):
            UpstreamAuth(mode=UpstreamAuthMode.STATIC_BEARER, secret_env="DATABASE_URL")
        with pytest.raises(ValidationError):
            UpstreamAuth(mode=UpstreamAuthMode.STATIC_BEARER)
        with pytest.raises(ValidationError):
            UpstreamAuth(mode=UpstreamAuthMode.NONE, secret_env="GATEWAY_UPSTREAM_SECRET_CRM")

    def test_server_id_rules(self) -> None:
        common = {
            "display_name": "CRM",
            "url": "https://crm.corp.test/mcp",
            "owner": "sales",
            "registered_by": "alice",
            "created_at": NOW,
            "updated_at": NOW,
        }
        UpstreamServer(server_id="crm-eu", **common)
        for bad in ("CRM", "a", "crm__x", "x" * 30, "9crm"):
            with pytest.raises(ValidationError):
                UpstreamServer(server_id=bad, **common)

    def test_caller_patterns_must_be_spiffe(self) -> None:
        with pytest.raises(ValidationError):
            ToolPolicy(
                risk=RiskLevel.LOW,
                classification=DataClassification.PUBLIC,
                allowed_agents=("*",),
            )
        with pytest.raises(ValidationError):
            CardPolicy(
                risk=RiskLevel.LOW,
                classification=DataClassification.PUBLIC,
                allowed_callers=("https://evil.test",),
            )

    def test_agent_card_preserves_unknown_fields(self) -> None:
        card = AgentCard.model_validate({**partner_card(), "provider": {"organization": "P"}})
        wire = card.wire()
        assert wire["provider"] == {"organization": "P"}
        assert wire["defaultInputModes"] == ["text/plain"]
        assert card.skills[0].id == "assay-summary"

    def test_principal_scopes(self) -> None:
        principal = Principal(
            subject="spiffe://agents.corp.test/agent/sales/planner",
            scopes=frozenset({"mcp:crm:*", "mcp:crm:lookup_customer", "a2a:send:x"}),
            delegation_chain=("spiffe://agents.corp.test/agent/a/b",),
            trust_domain="agents.corp.test",
            authenticated_by="fabric",
            token="secret-bearer-value",
        )
        assert principal.holds("mcp:crm:create_ticket")
        assert not principal.holds("mcp:erp:create_order")
        assert principal.matching_scope("mcp:crm:lookup_customer") == "mcp:crm:lookup_customer"
        assert principal.matching_scope("mcp:crm:create_ticket") == "mcp:crm:*"
        assert principal.matching_scope("a2a:send:y") is None
        assert principal.delegation_depth == 1
        assert "secret-bearer-value" not in repr(principal)
        assert "token" not in principal.model_dump()


class TestSettings:
    def test_valid_test_settings(self, tmp_path: Path, network: Network) -> None:
        settings = make_settings(tmp_path, network)
        assert settings.public_base == "https://gateway.corp.test"
        assert settings.delegation_enabled

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"environment": "production"}, "dev_ephemeral_keys"),
            ({"dev_ephemeral_keys": False}, "AUDIT_KEY_FILE"),
            (
                {
                    "allow_insecure_upstreams": True,
                    "environment": "production",
                    "dev_ephemeral_keys": False,
                    "audit_key_file": "k.pem",
                },
                "allow_insecure",
            ),
            ({"fabric_url": None}, "TOKEN_ISSUER"),
            ({"gateway_agent_id": None}, "set together"),
            ({"trust_domain": "Bad Domain"}, "invalid trust domain"),
        ],
    )
    def test_invalid(
        self, tmp_path: Path, network: Network, overrides: dict[str, Any], message: str
    ) -> None:
        with pytest.raises(ValidationError, match=message):
            make_settings(tmp_path, network, **overrides)

    def test_trust_domain_config_rules(self) -> None:
        jwks = {"keys": []}
        TrustDomainConfig(card_jwks=jwks, card_hosts=("*.p.test",))
        with pytest.raises(ValidationError, match="exactly one"):
            TrustDomainConfig(card_hosts=("*.p.test",))
        with pytest.raises(ValidationError, match="inbound federation needs token"):
            TrustDomainConfig(card_jwks=jwks, card_hosts=("*.p.test",), token_issuer="https://i")
        with pytest.raises(ValidationError, match="inbound_scopes"):
            TrustDomainConfig(
                card_jwks=jwks,
                card_hosts=("*.p.test",),
                token_issuer="https://i",
                token_jwks_url="https://i/jwks",
                token_audience="gw",
            )
        assert not TrustDomainConfig(card_jwks=jwks, card_hosts=("h",)).accepts_inbound

    def test_settings_reject_bad_federated_domain_names(
        self, tmp_path: Path, network: Network
    ) -> None:
        cfg = TrustDomainConfig(card_jwks={"keys": []}, card_hosts=("h",))
        with pytest.raises(ValidationError, match="invalid trust domain names"):
            make_settings(tmp_path, network, trust_domains={"Not Valid": cfg})

    def test_settings_from_environment(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env = {
            "GATEWAY_ENVIRONMENT": "staging",
            "GATEWAY_PUBLIC_URL": "https://gateway.corp.test",
            "GATEWAY_TRUST_DOMAIN": "agents.corp.test",
            "GATEWAY_DATABASE_URL": "sqlite+aiosqlite:///x.db",
            "GATEWAY_TOKEN_ISSUER": "https://identity.corp.test",
            "GATEWAY_TOKEN_JWKS_URL": "https://identity.corp.test/.well-known/jwks.json",
            "GATEWAY_ADMIN_ISSUER": "https://login.corp.test",
            "GATEWAY_ADMIN_AUDIENCE": "gw",
            "GATEWAY_ADMIN_JWKS_URL": "https://login.corp.test/jwks",
            "GATEWAY_DEV_EPHEMERAL_KEYS": "true",
            "GATEWAY_UPSTREAM_ALLOWED_HOSTS": '["*.svc.cluster.local"]',
        }
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        settings = Settings()  # type: ignore[call-arg]
        assert settings.upstream_allowed_hosts == ("*.svc.cluster.local",)
        assert not settings.delegation_enabled
