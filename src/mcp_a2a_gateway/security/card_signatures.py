"""Agent Card signatures (A2A ``AgentCardSignature``): JWS over the RFC 8785 canonical card.

The signed payload is the card without its ``signatures`` member, serialized
with JSON Canonicalization Scheme rules. The JWS payload is detached: the
card carries only the protected header and the signature. Keys come from the
trust domain's configured JWKS; ``jku``/``x5u`` header hints are ignored so a
card can never nominate its own verification key.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
from typing import Any

import jwt
from pydantic import BaseModel, ConfigDict

from mcp_a2a_gateway.domain.errors import SignatureError, UnauthorizedError
from mcp_a2a_gateway.security.jwks import ACCEPTED_ALGORITHMS, KeyResolver


class VerifiedSignature(BaseModel):
    model_config = ConfigDict(frozen=True)

    kid: str
    alg: str


def _normalize(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, int | str):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise SignatureError("agent card contains a non-finite number")
        return int(value) if value.is_integer() else value
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_normalize(v) for v in value]
    raise SignatureError(f"agent card contains a non-JSON value of type {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """RFC 8785 serialization for the JSON subset used by agent cards."""
    return json.dumps(
        _normalize(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def signing_payload(card: dict[str, Any]) -> bytes:
    return canonicalize({k: v for k, v in card.items() if k != "signatures"})


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_json(segment: str) -> dict[str, Any]:
    try:
        decoded = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (binascii.Error, ValueError) as exc:
        raise SignatureError("signature header is not base64url JSON") from exc
    if not isinstance(decoded, dict):
        raise SignatureError("signature header is not a JSON object")
    return decoded


def sign_card(card: dict[str, Any], key: Any, *, kid: str, alg: str = "EdDSA") -> dict[str, Any]:
    """Return a copy of ``card`` with one more signature appended."""
    if alg not in ACCEPTED_ALGORITHMS:
        raise SignatureError(f"algorithm {alg} not accepted")
    # Standard (base64url-encoded) payload, then detached per RFC 7515 Appendix F:
    # the middle segment is dropped and recomputed from the card on verification.
    compact = jwt.PyJWS().encode(
        signing_payload(card), key, algorithm=alg, headers={"kid": kid, "typ": "JOSE"}
    )
    protected, _, signature = compact.split(".")
    signed = dict(card)
    signed["signatures"] = [
        *card.get("signatures", []),
        {"protected": protected, "signature": signature},
    ]
    return signed


async def verify_card(card: dict[str, Any], resolver: KeyResolver) -> VerifiedSignature:
    """Verify that at least one signature on ``card`` is valid under ``resolver``'s keys."""
    signatures = card.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise SignatureError("agent card is not signed")
    payload = _b64url(signing_payload(card))
    failures: list[str] = []
    for entry in signatures:
        if not isinstance(entry, dict):
            failures.append("malformed signature entry")
            continue
        protected, signature = entry.get("protected"), entry.get("signature")
        if not isinstance(protected, str) or not isinstance(signature, str):
            failures.append("signature entry lacks protected header or signature")
            continue
        header = _b64url_json(protected)
        alg, kid = header.get("alg"), header.get("kid")
        if alg not in ACCEPTED_ALGORITHMS or not isinstance(kid, str):
            failures.append("algorithm or key id not accepted")
            continue
        if header.get("b64") is False or "crit" in header:
            failures.append("unsupported JWS header parameters")
            continue
        try:
            key = await resolver.key_for(kid)
            jwt.PyJWS().decode_complete(
                f"{protected}.{payload}.{signature}", key=key, algorithms=[alg]
            )
        except (UnauthorizedError, jwt.PyJWTError) as exc:
            failures.append(f"{kid}: {type(exc).__name__}")
            continue
        return VerifiedSignature(kid=kid, alg=alg)
    raise SignatureError("no valid agent card signature: " + "; ".join(failures))
