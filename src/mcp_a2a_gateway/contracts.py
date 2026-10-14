"""Export published contracts: JSON Schemas for inputs/outputs and the OpenAPI document.

python -m mcp_a2a_gateway.contracts            # rewrite schemas/ and docs/api/
python -m mcp_a2a_gateway.contracts --check    # exit 1 if committed files are stale
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel

from mcp_a2a_gateway.api.app import create_app
from mcp_a2a_gateway.api.schemas import DecideApproval, JsonRpcRequest
from mcp_a2a_gateway.application.directory import ApproveCard, RegisterCard
from mcp_a2a_gateway.application.registry import (
    ApproveTool,
    DeprecateTool,
    DiscoveryReport,
    RegisterServer,
)
from mcp_a2a_gateway.domain.models import (
    AgentCard,
    AgentCardVersion,
    ApprovalRequest,
    ToolVersion,
    UpstreamServer,
)

MODELS: dict[str, type[BaseModel]] = {
    "register-server.request": RegisterServer,
    "upstream-server.response": UpstreamServer,
    "discovery-report.response": DiscoveryReport,
    "tool-version.response": ToolVersion,
    "approve-tool.request": ApproveTool,
    "deprecate.request": DeprecateTool,
    "register-card.request": RegisterCard,
    "approve-card.request": ApproveCard,
    "agent-card-version.response": AgentCardVersion,
    "a2a-agent-card": AgentCard,
    "approval.response": ApprovalRequest,
    "decide-approval.request": DecideApproval,
    "a2a-jsonrpc.request": JsonRpcRequest,
}


async def _no_container() -> Any:  # pragma: no cover - never started
    raise RuntimeError("contract export does not start the application")


def documents() -> dict[str, dict[str, Any]]:
    docs: dict[str, dict[str, Any]] = {
        f"schemas/{name}.schema.json": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"https://github.com/kogunlowo123/mcp-a2a-gateway/schemas/{name}.schema.json",
            **model.model_json_schema(mode="validation", by_alias=True),
        }
        for name, model in MODELS.items()
    }
    app: FastAPI = create_app(_no_container)
    docs["docs/api/openapi.json"] = app.openapi()
    return docs


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None, root: Path | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    base = root or Path.cwd()
    stale: list[str] = []
    for relative, document in documents().items():
        path = base / relative
        content = render(document)
        if "--check" in args:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                stale.append(relative)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
    if stale:
        sys.stderr.write(
            "stale contracts (run python -m mcp_a2a_gateway.contracts): " + ", ".join(stale) + "\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
