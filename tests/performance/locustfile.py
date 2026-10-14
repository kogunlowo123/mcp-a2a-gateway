"""Load profile for a deployed gateway.

Run against a staging deployment, never production, with a credential for a
load-test agent registered in the identity fabric and entitled to the tool:

    GATEWAY_LOAD_AGENT_TOKEN=<agent credential> GATEWAY_LOAD_TOOL=<server>__<tool> \
    GATEWAY_LOAD_ARGUMENTS='{"customer_id": "LOAD-1"}' \
    locust -f tests/performance/locustfile.py --host <staging gateway URL> \
           --users 200 --spawn-rate 20 --run-time 10m --headless

Agents list tools once per session and call them many times, so the mix
weights tools/call over tools/list. The stateless transport means any
replica can serve any request.
"""

from __future__ import annotations

import json
import os

from locust import HttpUser, between, task

TOKEN = os.environ.get("GATEWAY_LOAD_AGENT_TOKEN", "")
TOOL = os.environ.get("GATEWAY_LOAD_TOOL", "")
ARGUMENTS = json.loads(os.environ.get("GATEWAY_LOAD_ARGUMENTS", "{}"))
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
    "MCP-Protocol-Version": "2025-11-25",
}


class AgentTraffic(HttpUser):
    wait_time = between(0.05, 0.25)

    def _rpc(self, method: str, params: dict[str, object], name: str) -> None:
        self.client.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            headers=HEADERS,
            name=name,
        )

    @task(10)
    def call_tool(self) -> None:
        self._rpc("tools/call", {"name": TOOL, "arguments": ARGUMENTS}, "tools/call")

    @task(1)
    def list_tools(self) -> None:
        self._rpc("tools/list", {}, "tools/list")

    @task(1)
    def agent_card(self) -> None:
        self.client.get("/.well-known/agent-card.json", name="agent-card")
