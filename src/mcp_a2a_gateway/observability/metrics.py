"""Service metrics exposed on /metrics in Prometheus text format (own registry)."""

from __future__ import annotations

from prometheus_client import CollectorRegistry, Counter, Histogram

_LATENCY = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)


class GatewayMetrics:
    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.requests = Histogram(
            "gateway_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route", "status"],
            registry=self.registry,
            buckets=_LATENCY,
        )
        self.tool_calls = Counter(
            "gateway_tool_calls_total",
            "MCP tool calls by upstream server and outcome",
            ["server", "outcome"],
            registry=self.registry,
        )
        self.tool_latency = Histogram(
            "gateway_tool_call_duration_seconds",
            "End-to-end latency of successful tool calls",
            ["server"],
            registry=self.registry,
            buckets=_LATENCY,
        )
        self.a2a_messages = Counter(
            "gateway_a2a_requests_total",
            "A2A operations routed to federated agents by outcome",
            ["method", "outcome"],
            registry=self.registry,
        )
        self.a2a_latency = Histogram(
            "gateway_a2a_request_duration_seconds",
            "End-to-end latency of successful A2A operations",
            registry=self.registry,
            buckets=_LATENCY,
        )
        self.authorization = Counter(
            "gateway_authorization_decisions_total",
            "Combined authorization decisions",
            ["protocol", "decision"],
            registry=self.registry,
        )
        self.definition_drift = Counter(
            "gateway_definition_drift_total",
            "Pinned tool definitions found changed upstream (at discovery or at call time)",
            ["server"],
            registry=self.registry,
        )
        self.output_blocked = Counter(
            "gateway_output_blocked_total",
            "Responses withheld by content inspection or output schema validation",
            ["upstream", "reason"],
            registry=self.registry,
        )
        self.upstream_errors = Counter(
            "gateway_upstream_errors_total",
            "Failed upstream MCP or A2A calls",
            ["upstream", "error"],
            registry=self.registry,
        )
        self.lifecycle = Counter(
            "gateway_lifecycle_events_total",
            "Registry lifecycle events (tools, agent cards, approvals)",
            ["event"],
            registry=self.registry,
        )
        self.authentication_failures = Counter(
            "gateway_authentication_failures_total",
            "Rejected agent credentials",
            ["endpoint"],
            registry=self.registry,
        )
