"""JWKS, JWT verification, admin and agent authentication, card signatures, egress, resilience."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_a2a_gateway.domain.errors import (
    CircuitOpenError,
    EgressDeniedError,
    ForbiddenError,
    RateLimitedError,
    SignatureError,
    UnauthorizedError,
)
from mcp_a2a_gateway.security.admin import AdminAuthenticator, AdminPrincipal, require_role
from mcp_a2a_gateway.security.authn import (
    AgentAuthenticator,
    FederatedSource,
    TokenSource,
    bearer_token,
    flatten_actors,
    peek_issuer,
)
from mcp_a2a_gateway.security.card_signatures import (
    canonicalize,
    sign_card,
    signing_payload,
    verify_card,
)
from mcp_a2a_gateway.security.egress import check_url
from mcp_a2a_gateway.security.jwks import RemoteJwks, StaticJwks, verify_jwt
from mcp_a2a_gateway.security.resilience import CircuitBreaker, RateLimiter
from tests.conftest import (
    ADMIN_ISSUER,
    PARTNER,
    PARTNER_ISSUER,
    TRUST_DOMAIN,
    FakeClock,
    FakeIdp,
    FakeMonotonic,
    b64,
    card_jwks,
    partner_card,
)


class TestJwks:
    async def test_static_resolver(self, admin_idp: FakeIdp) -> None:
        resolver = StaticJwks(admin_idp.jwks())
        assert await resolver.key_for("admin-1") is not None
        with pytest.raises(UnauthorizedError, match="unknown signing key"):
            await resolver.key_for("other")

    async def test_remote_caches_and_rate_limits_refresh(self, admin_idp: FakeIdp) -> None:
        fetches: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            fetches.append(str(request.url))
            return httpx.Response(200, json=admin_idp.jwks())

        mono = FakeMonotonic()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            jwks = RemoteJwks("https://login.corp.test/jwks", client=http, clock=mono)
            await jwks.key_for("admin-1")
            await jwks.key_for("admin-1")
            assert len(fetches) == 1
            with pytest.raises(UnauthorizedError):
                await jwks.key_for("rotated")  # within min refresh interval: no fetch
            assert len(fetches) == 1
            mono.advance(31)
            with pytest.raises(UnauthorizedError):
                await jwks.key_for("rotated")
            assert len(fetches) == 2
            mono.advance(400)
            await jwks.key_for("admin-1")
            assert len(fetches) == 3

    async def test_remote_serves_stale_keys_when_issuer_down(self, admin_idp: FakeIdp) -> None:
        state = {"up": True}

        def handler(_: httpx.Request) -> httpx.Response:
            return (
                httpx.Response(200, json=admin_idp.jwks()) if state["up"] else httpx.Response(500)
            )

        mono = FakeMonotonic()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            jwks = RemoteJwks("https://login.corp.test/jwks", client=http, clock=mono)
            await jwks.key_for("admin-1")
            state["up"] = False
            mono.advance(400)
            assert await jwks.key_for("admin-1") is not None
            with pytest.raises(UnauthorizedError, match="cannot fetch"):
                await jwks.key_for("new-key")

    async def test_non_object_document_rejected(self) -> None:
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json=[1]))
        ) as http:
            with pytest.raises(UnauthorizedError, match="cannot fetch"):
                await RemoteJwks("https://x.test/jwks", client=http).key_for("k")

    async def test_verify_jwt_checks(self, admin_idp: FakeIdp) -> None:
        resolver = StaticJwks(admin_idp.jwks())
        now = datetime.now(UTC)
        good = admin_idp.mint(sub="a", aud="aud")
        claims = await verify_jwt(good, resolver, issuer=ADMIN_ISSUER, audience="aud", now=now)
        assert claims["sub"] == "a"

        cases: list[tuple[str, datetime, str]] = [
            ("not-a-jwt", now, "malformed"),
            (admin_idp.mint(sub="a", aud="other"), now, "InvalidAudience"),
            (good, now + timedelta(hours=1), "expired"),
            (good, now - timedelta(hours=1), "future"),
            (admin_idp.mint(sub="a", aud="aud", nbf=int(time.time()) + 3600), now, "not yet"),
        ]
        for token, at, message in cases:
            with pytest.raises(UnauthorizedError, match=message):
                await verify_jwt(token, resolver, issuer=ADMIN_ISSUER, audience="aud", now=at)

    async def test_alg_none_and_hmac_rejected(self, admin_idp: FakeIdp) -> None:
        resolver = StaticJwks(admin_idp.jwks())
        claims = {"iss": ADMIN_ISSUER, "sub": "a", "aud": "x", "iat": 1, "exp": 2**31}
        unsigned = f"{b64(json.dumps({'alg': 'none', 'kid': 'admin-1'}).encode())}."
        unsigned += f"{b64(json.dumps(claims).encode())}."
        hmac = jwt.encode(claims, "k" * 32, algorithm="HS256", headers={"kid": "admin-1"})
        for token in (unsigned, hmac):
            with pytest.raises(UnauthorizedError, match="not accepted"):
                await verify_jwt(
                    token, resolver, issuer=ADMIN_ISSUER, audience="x", now=datetime.now(UTC)
                )

    async def test_non_numeric_time_claims(self, admin_idp: FakeIdp) -> None:
        token = jwt.encode(
            {"iss": ADMIN_ISSUER, "sub": "a", "aud": "x", "iat": "now", "exp": "later"},
            admin_idp.key,
            algorithm="ES256",
            headers={"kid": "admin-1"},
        )
        with pytest.raises(UnauthorizedError):
            await verify_jwt(
                token,
                StaticJwks(admin_idp.jwks()),
                issuer=ADMIN_ISSUER,
                audience="x",
                now=datetime.now(UTC),
            )


class TestAdmin:
    async def test_roles(self, admin_idp: FakeIdp, clock: FakeClock) -> None:
        auth = AdminAuthenticator(
            StaticJwks(admin_idp.jwks()), issuer=ADMIN_ISSUER, audience="adm", clock=clock
        )
        token = admin_idp.mint(sub="alice", aud="adm", roles=["gateway-admin", 7])
        principal = await auth.authenticate(f"Bearer {token}")
        assert principal.roles == frozenset({"gateway-admin"})
        odd = admin_idp.mint(sub="bob", aud="adm", roles="gateway-admin")
        assert (await auth.authenticate(f"Bearer {odd}")).roles == frozenset()
        with pytest.raises(UnauthorizedError):
            await auth.authenticate(None)
        with pytest.raises(UnauthorizedError):
            await auth.authenticate("Basic abc")

    def test_require_role(self) -> None:
        who = AdminPrincipal(subject="a", roles=frozenset({"gateway-auditor"}))
        require_role(who, "gateway-auditor", "gateway-admin")
        with pytest.raises(ForbiddenError):
            require_role(who, "gateway-admin")


class TestAgentAuthentication:
    def test_helpers(self) -> None:
        assert flatten_actors(None) == ()
        assert flatten_actors({"sub": "a", "act": {"sub": "b"}}) == ("a", "b")
        for bad in ({"sub": 1}, {"sub": "a", "act": "b"}):
            with pytest.raises(UnauthorizedError):
                flatten_actors(bad)
        deep: dict[str, Any] = {"sub": "z"}
        for i in range(12):
            deep = {"sub": f"a{i}", "act": deep}
        with pytest.raises(UnauthorizedError, match="too deep"):
            flatten_actors(deep)
        for bad_header in (None, "", "Bearer ", "Token x"):
            with pytest.raises(UnauthorizedError):
                bearer_token(bad_header)
        for bad_token in ("a.b", "a.!!!.c", f"a.{b64(b'[1]')}.c"):
            with pytest.raises(UnauthorizedError, match="malformed"):
                peek_issuer(bad_token)
        assert peek_issuer(f"a.{b64(json.dumps({'iss': 5}).encode())}.c") is None

    def test_requires_a_source(self, clock: FakeClock) -> None:
        with pytest.raises(ValueError, match="required"):
            AgentAuthenticator(trust_domain=TRUST_DOMAIN, audience="a", clock=clock)

    async def test_local_jwks_mode(self, clock: FakeClock) -> None:
        issuer = FakeIdp("https://identity.corp.test", kid="fabric-1")
        auth = AgentAuthenticator(
            trust_domain=TRUST_DOMAIN,
            audience="agent-platform",
            clock=clock,
            local=TokenSource(
                issuer=issuer.issuer, audience="agent-platform", resolver=StaticJwks(issuer.jwks())
            ),
        )
        sub = f"spiffe://{TRUST_DOMAIN}/agent/sales/planner"
        token = issuer.mint(sub=sub, aud="agent-platform", scope="mcp:crm:*", act={"sub": "x"})
        principal = await auth.authenticate(f"Bearer {token}")
        assert principal.authenticated_by == "jwks"
        assert principal.delegation_chain == ("x",)
        outsider = issuer.mint(sub="spiffe://other.test/agent/a/b", aud="agent-platform")
        with pytest.raises(UnauthorizedError, match="outside this trust domain"):
            await auth.authenticate(f"Bearer {outsider}")
        no_scope = issuer.mint(sub=sub, aud="agent-platform", scope=7)
        assert (await auth.authenticate(f"Bearer {no_scope}")).scopes == frozenset()

    async def test_federation_ceiling(self, clock: FakeClock) -> None:
        partner = FakeIdp(PARTNER_ISSUER, kid="p1")
        local = FakeIdp("https://identity.corp.test")
        auth = AgentAuthenticator(
            trust_domain=TRUST_DOMAIN,
            audience="agent-platform",
            clock=clock,
            local=TokenSource(local.issuer, "agent-platform", StaticJwks(local.jwks())),
            federated=(
                FederatedSource(
                    issuer=PARTNER_ISSUER,
                    audience="gw",
                    resolver=StaticJwks(partner.jwks()),
                    trust_domain=PARTNER,
                    inbound_scopes=("mcp:crm:lookup_customer", "a2a:send:*"),
                ),
            ),
        )
        token = partner.mint(
            sub=f"spiffe://{PARTNER}/agent/r/analyst",
            aud="gw",
            scope="mcp:crm:lookup_customer mcp:crm:* a2a:send:research mcp:erp:delete",
        )
        principal = await auth.authenticate(f"Bearer {token}")
        assert principal.federated
        assert principal.trust_domain == PARTNER
        assert principal.scopes == frozenset({"mcp:crm:lookup_customer", "a2a:send:research"})
        spoof = partner.mint(sub=f"spiffe://{TRUST_DOMAIN}/agent/sales/planner", aud="gw")
        with pytest.raises(UnauthorizedError, match="does not belong"):
            await auth.authenticate(f"Bearer {spoof}")
        no_scope = partner.mint(sub=f"spiffe://{PARTNER}/agent/r/a", aud="gw", scope=["x"])
        assert (await auth.authenticate(f"Bearer {no_scope}")).scopes == frozenset()


class TestCardSignatures:
    def test_canonical_form(self) -> None:
        assert (
            canonicalize({"b": 1.0, "a": [True, None, "é"]})
            == '{"a":[true,null,"é"],"b":1}'.encode()
        )
        assert canonicalize({"x": 1.5}) == b'{"x":1.5}'
        for bad in ({"x": float("nan")}, {"x": object()}):
            with pytest.raises(SignatureError):
                canonicalize(bad)
        signed = {"a": 1, "signatures": [{"protected": "x", "signature": "y"}]}
        assert signing_payload(signed) == b'{"a":1}'

    async def test_round_trip_and_tampering(self) -> None:
        key = Ed25519PrivateKey.generate()
        resolver = StaticJwks(card_jwks(key))
        signed = sign_card(partner_card(), key, kid="partner-cards-1")
        verified = await verify_card(signed, resolver)
        assert (verified.kid, verified.alg) == ("partner-cards-1", "EdDSA")
        tampered = {**signed, "url": "https://evil.partner.test/a2a"}
        with pytest.raises(SignatureError, match="no valid"):
            await verify_card(tampered, resolver)
        resigned = sign_card(signed, key, kid="partner-cards-1")
        assert len(resigned["signatures"]) == 2

    async def test_es256_signature(self) -> None:
        key = ec.generate_private_key(ec.SECP256R1())
        jwk = jwt.algorithms.ECAlgorithm.to_jwk(key.public_key(), as_dict=True)
        jwk["kid"] = "ec-1"
        signed = sign_card(partner_card(), key, kid="ec-1", alg="ES256")
        assert (await verify_card(signed, StaticJwks({"keys": [jwk]}))).alg == "ES256"
        with pytest.raises(SignatureError):
            sign_card(partner_card(), key, kid="ec-1", alg="HS256")

    async def test_rejections(self) -> None:
        key = Ed25519PrivateKey.generate()
        resolver = StaticJwks(card_jwks(key))
        attacker = Ed25519PrivateKey.generate()
        forged = sign_card(partner_card(), attacker, kid="partner-cards-1")
        unknown_kid = sign_card(partner_card(), key, kid="not-published")

        def header(h: dict[str, Any]) -> dict[str, Any]:
            return {
                **partner_card(),
                "signatures": [{"protected": b64(json.dumps(h).encode()), "signature": "AAAA"}],
            }

        cases = [
            (partner_card(), "not signed"),
            ({**partner_card(), "signatures": []}, "not signed"),
            ({**partner_card(), "signatures": ["x"]}, "malformed"),
            ({**partner_card(), "signatures": [{"protected": 1}]}, "lacks"),
            ({**partner_card(), "signatures": [{"protected": "!!", "signature": "x"}]}, "base64"),
            (
                {**partner_card(), "signatures": [{"protected": b64(b"[]"), "signature": "x"}]},
                "object",
            ),
            (header({"alg": "none", "kid": "partner-cards-1"}), "not accepted"),
            (header({"alg": "EdDSA", "kid": "partner-cards-1", "b64": False}), "unsupported"),
            (header({"alg": "EdDSA", "kid": "partner-cards-1", "crit": ["x"]}), "unsupported"),
            (forged, "InvalidSignature"),
            (unknown_kid, "UnauthorizedError"),
        ]
        for card, message in cases:
            with pytest.raises(SignatureError, match=message):
                await verify_card(card, resolver)

    async def test_jku_header_is_ignored(self) -> None:
        key = Ed25519PrivateKey.generate()
        attacker = Ed25519PrivateKey.generate()
        signed = sign_card(partner_card(), attacker, kid="partner-cards-1")
        protected = json.loads(
            __import__("base64").urlsafe_b64decode(signed["signatures"][0]["protected"] + "==")
        )
        assert "jku" not in protected
        signed["signatures"][0]["header"] = {"jku": "https://evil.test/jwks"}
        with pytest.raises(SignatureError):
            await verify_card(signed, StaticJwks(card_jwks(key)))


class TestEgress:
    def test_allow_list(self) -> None:
        hosts = ("*.corp.test", "mcp.svc.cluster.local")
        assert check_url("https://CRM.corp.test/mcp", allowed_hosts=hosts) == "crm.corp.test"
        assert check_url("https://mcp.svc.cluster.local", allowed_hosts=hosts)
        assert check_url("http://crm.corp.test", allowed_hosts=hosts, allow_http=True)
        for url, message in [
            ("http://crm.corp.test", "scheme"),
            ("ftp://crm.corp.test", "scheme"),
            ("https://user:pw@crm.corp.test", "credentials"),
            ("https:///path", "no host"),
            ("https://169.254.169.254/latest", "allow list"),
            ("https://corp.test.evil.test", "allow list"),
        ]:
            with pytest.raises(EgressDeniedError, match=message):
                check_url(url, allowed_hosts=hosts)


class TestResilience:
    def test_rate_limiter_refills(self) -> None:
        mono = FakeMonotonic()
        limiter = RateLimiter(2, clock=mono)
        limiter.acquire("a")
        limiter.acquire("a")
        with pytest.raises(RateLimitedError) as caught:
            limiter.acquire("a")
        assert caught.value.data["retry_after_seconds"] > 0
        limiter.acquire("b")
        mono.advance(30)
        limiter.acquire("a")

    def test_rate_limiter_bounds_memory(self) -> None:
        mono = FakeMonotonic()
        limiter = RateLimiter(10, clock=mono, max_keys=4)
        for i in range(4):
            limiter.acquire(f"k{i}")
        limiter.acquire("k4")  # evicts half of the live keys
        mono.advance(120)
        for i in range(5, 9):
            limiter.acquire(f"k{i}")
        limiter.acquire("k9")  # evicts idle keys
        assert len(limiter._buckets) <= 5

    def test_circuit_breaker(self) -> None:
        mono = FakeMonotonic()
        breaker = CircuitBreaker(threshold=2, reset_s=10, clock=mono)
        assert breaker.state("u") == "closed"
        breaker.before("u")
        breaker.failure("u")
        breaker.failure("u")
        assert breaker.state("u") == "open"
        with pytest.raises(CircuitOpenError):
            breaker.before("u")
        mono.advance(11)
        breaker.before("u")  # half-open probe
        assert breaker.state("u") == "half_open"
        with pytest.raises(CircuitOpenError):
            breaker.before("u")  # only one probe at a time
        breaker.release("u")
        breaker.before("u")
        breaker.failure("u")
        assert breaker.state("u") == "open"
        mono.advance(11)
        breaker.before("u")
        breaker.success("u")
        assert breaker.state("u") == "closed"
        breaker.release("unknown")
