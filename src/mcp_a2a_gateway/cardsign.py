"""Sign an A2A agent card for publication.

    python -m mcp_a2a_gateway.cardsign --key card-signing.pem --kid 2026-10 \
        < agent-card.json > agent-card.signed.json

The algorithm follows the key type (Ed25519 -> EdDSA, P-256 -> ES256,
RSA -> RS256). The public half belongs in the trust domain's card JWKS that
federated gateways are configured with.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from mcp_a2a_gateway.security.card_signatures import sign_card


def algorithm_for(key: Any) -> str:
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "EdDSA"
    if isinstance(key, ec.EllipticCurvePrivateKey) and isinstance(key.curve, ec.SECP256R1):
        return "ES256"
    if isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048:
        return "RS256"
    raise ValueError("signing key must be Ed25519, P-256 or RSA >= 2048 bits")


def run(key_file: Path, kid: str, source: TextIO, sink: TextIO) -> None:
    key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    card = json.load(source)
    if not isinstance(card, dict):
        raise ValueError("agent card must be a JSON object")
    signed = sign_card(card, key, kid=kid, alg=algorithm_for(key))
    json.dump(signed, sink, indent=2, ensure_ascii=False)
    sink.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mcp_a2a_gateway.cardsign")
    parser.add_argument("--key", type=Path, required=True, help="PEM private key")
    parser.add_argument("--kid", required=True, help="key id published in the card JWKS")
    args = parser.parse_args(argv)
    try:
        run(args.key, args.kid, sys.stdin, sys.stdout)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"cardsign: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
