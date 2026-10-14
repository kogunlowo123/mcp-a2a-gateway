"""Content inspection for everything crossing the gateway, built on agentic-core ContentGuard.

* Tool output and remote-agent responses are EXTERNAL content: prompt-injection
  indicators or credential material block the response; PII is redacted when
  the tool policy asks for it.
* Tool arguments are scanned for credential material before they leave the
  enterprise (egress DLP).
* Tool descriptions and schema text are scored at discovery so reviewers see
  tool-poisoning attempts before approval.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentic_core.domain.classification import TrustLevel
from agentic_core.domain.provenance import canonical_json
from agentic_core.models.types import Message, ModelRequest, Role
from agentic_core.security import ContentGuard, GuardConfig, PromptInjectionDetector, SecretScanner
from pydantic import BaseModel, ConfigDict

from mcp_a2a_gateway.domain.models import ToolDefinition


class InspectionResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    blocked: bool
    reasons: tuple[str, ...] = ()
    kinds: tuple[str, ...] = ()
    redactions: int = 0


def collect_strings(value: Any) -> list[str]:
    """Every string leaf of a JSON value, depth first."""
    found: list[str] = []

    def keep(text: str) -> str:
        found.append(text)
        return text

    transform_strings(value, keep)
    return found


def transform_strings(value: Any, fn: Callable[[str], str]) -> Any:
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, dict):
        return {k: transform_strings(v, fn) for k, v in value.items()}
    if isinstance(value, list):
        return [transform_strings(v, fn) for v in value]
    return value


Projection = Callable[[Any, Callable[[str], str]], Any]


def mcp_text_fields(value: Any, fn: Callable[[str], str]) -> Any:
    """Apply ``fn`` to the model-visible text of an MCP tool result.

    ``value`` is ``{"content": [content blocks], "structured": object | None}``.
    Binary blocks (image, audio, blob resources) are left untouched.
    """
    blocks: list[dict[str, Any]] = []
    for block in value.get("content") or []:
        updated = dict(block)
        kind = updated.get("type")
        if kind == "text" and isinstance(updated.get("text"), str):
            updated["text"] = fn(updated["text"])
        elif kind == "resource" and isinstance(updated.get("resource"), dict):
            resource = dict(updated["resource"])
            if isinstance(resource.get("text"), str):
                resource["text"] = fn(resource["text"])
            updated["resource"] = resource
        elif kind == "resource_link":
            for key in ("name", "title", "description"):
                if isinstance(updated.get(key), str):
                    updated[key] = fn(updated[key])
        blocks.append(updated)
    structured = value.get("structured")
    return {
        "content": blocks,
        "structured": transform_strings(structured, fn) if structured is not None else None,
    }


def a2a_text_fields(value: Any, fn: Callable[[str], str]) -> Any:
    """Apply ``fn`` to text and data parts anywhere in an A2A Task or Message."""
    if isinstance(value, list):
        return [a2a_text_fields(v, fn) for v in value]
    if not isinstance(value, dict):
        return value
    updated: dict[str, Any] = {}
    for key, item in value.items():
        if key == "parts" and isinstance(item, list):
            updated[key] = [_a2a_part(part, fn) for part in item]
        else:
            updated[key] = a2a_text_fields(item, fn)
    return updated


def _a2a_part(part: Any, fn: Callable[[str], str]) -> Any:
    if not isinstance(part, dict):
        return part
    updated = dict(part)
    if updated.get("kind") == "text" and isinstance(updated.get("text"), str):
        updated["text"] = fn(updated["text"])
    elif updated.get("kind") == "data" and "data" in updated:
        updated["data"] = transform_strings(updated["data"], fn)
    return updated


def _definition_text(definition: ToolDefinition) -> str:
    parts = [definition.title or "", definition.description]
    parts.extend(collect_strings(definition.input_schema))
    if definition.output_schema:
        parts.extend(collect_strings(definition.output_schema))
    return "\n".join(p for p in parts if p)


class ContentInspector:
    def __init__(self) -> None:
        common = {"isolate_external": False, "block_secrets_in_input": True}
        self._redacting = ContentGuard(GuardConfig(redact_pii_in_input=True, **common))
        self._plain = ContentGuard(GuardConfig(redact_pii_in_input=False, **common))
        self._injection = PromptInjectionDetector()
        self._secrets = SecretScanner()

    def inspect_external(self, value: Any, *, redact_pii: bool) -> tuple[InspectionResult, Any]:
        """Inspect every string in ``value`` as untrusted external content.

        Returns the verdict and ``value`` with PII redacted (when requested and
        not blocked). A blocked verdict returns the original value unchanged;
        callers must not forward it.
        """
        texts = [s for s in collect_strings(value) if s.strip()]
        if not texts:
            return InspectionResult(blocked=False), value
        guard = self._redacting if redact_pii else self._plain
        request = ModelRequest(
            messages=tuple(
                Message(role=Role.USER, content=t, trust=TrustLevel.EXTERNAL) for t in texts
            )
        )
        verdict = guard.inspect_request(request)
        kinds = tuple(sorted({f.kind for f in verdict.findings}))
        if verdict.blocked or verdict.request is None:
            return InspectionResult(blocked=True, reasons=verdict.reasons, kinds=kinds), value
        sanitized = iter(m.content for m in verdict.request.messages)
        redactions = sum(1 for f in verdict.findings if f.category == "pii")

        def replace(text: str) -> str:
            return next(sanitized) if text.strip() else text

        cleaned = transform_strings(value, replace) if redact_pii and redactions else value
        return InspectionResult(blocked=False, kinds=kinds, redactions=redactions), cleaned

    def inspect_projected(
        self, value: Any, projection: Projection, *, redact_pii: bool
    ) -> tuple[InspectionResult, Any]:
        """Inspect only the text-bearing fields ``projection`` selects, and write them back."""
        texts: list[str] = []

        def keep(text: str) -> str:
            texts.append(text)
            return text

        projection(value, keep)
        verdict, cleaned = self.inspect_external(texts, redact_pii=redact_pii)
        if verdict.blocked or cleaned is texts:
            return verdict, projection(value, lambda s: s)
        replacements = iter(cleaned)
        return verdict, projection(value, lambda _s: next(replacements))

    def scan_egress(self, payload: Any) -> InspectionResult:
        """Credential material in data leaving the enterprise (tool arguments, A2A messages)."""
        findings = self._secrets.detect(canonical_json(payload).decode())
        if not findings:
            return InspectionResult(blocked=False)
        kinds = tuple(sorted({f.kind for f in findings}))
        return InspectionResult(
            blocked=True, reasons=("credential material in outbound payload",), kinds=kinds
        )

    def score_definition(self, definition: ToolDefinition) -> tuple[float, tuple[str, ...]]:
        assessment = self._injection.assess(_definition_text(definition))
        return assessment.score, tuple(assessment.kinds)
