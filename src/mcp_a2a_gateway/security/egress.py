"""Egress control: the gateway only connects to hosts an operator has allow-listed.

Applied when an upstream MCP server or agent card is registered, and again
to every agent endpoint a card advertises, so neither an administrator typo
nor a malicious card can point the gateway at internal services (SSRF).
"""

from __future__ import annotations

import fnmatch
from urllib.parse import urlsplit

from mcp_a2a_gateway.domain.errors import EgressDeniedError


def check_url(url: str, *, allowed_hosts: tuple[str, ...], allow_http: bool = False) -> str:
    """Return the lower-cased host of ``url`` if it may be contacted, else raise."""
    parts = urlsplit(url)
    if parts.scheme not in ({"https", "http"} if allow_http else {"https"}):
        raise EgressDeniedError(f"scheme {parts.scheme or '(none)'} is not allowed for {url}")
    if parts.username or parts.password:
        raise EgressDeniedError("URLs with embedded credentials are not allowed")
    host = (parts.hostname or "").lower()
    if not host:
        raise EgressDeniedError(f"URL {url} has no host")
    if not any(fnmatch.fnmatchcase(host, pattern.lower()) for pattern in allowed_hosts):
        raise EgressDeniedError(f"host {host} is not on the egress allow list")
    return host
