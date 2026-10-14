"""Per-caller rate limiting and per-upstream circuit breaking (in-process, per replica)."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from mcp_a2a_gateway.domain.errors import CircuitOpenError, RateLimitedError


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """Token bucket per key: ``per_minute`` sustained, bursts up to the same amount."""

    def __init__(
        self,
        per_minute: int,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 50_000,
    ) -> None:
        self._capacity = float(per_minute)
        self._rate = per_minute / 60.0
        self._clock = clock
        self._max_keys = max_keys
        self._buckets: dict[str, _Bucket] = {}

    def acquire(self, key: str) -> None:
        now = self._clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self._max_keys:
                self._evict(now)
            bucket = self._buckets[key] = _Bucket(tokens=self._capacity, updated=now)
        bucket.tokens = min(self._capacity, bucket.tokens + (now - bucket.updated) * self._rate)
        bucket.updated = now
        if bucket.tokens < 1.0:
            retry = (1.0 - bucket.tokens) / self._rate
            raise RateLimitedError(
                f"rate limit exceeded for {key}", data={"retry_after_seconds": round(retry, 2)}
            )
        bucket.tokens -= 1.0

    def _evict(self, now: float) -> None:
        full = [k for k, b in self._buckets.items() if now - b.updated > 60.0]
        for key in full or list(self._buckets)[: len(self._buckets) // 2]:
            del self._buckets[key]


@dataclass
class _Circuit:
    failures: int = 0
    opened_at: float | None = None
    half_open_probe: bool = False


@dataclass
class CircuitBreaker:
    """Opens after ``threshold`` consecutive failures; one probe allowed after ``reset_s``."""

    threshold: int
    reset_s: float
    clock: Callable[[], float] = time.monotonic
    _circuits: dict[str, _Circuit] = field(default_factory=dict)

    def before(self, key: str) -> None:
        circuit = self._circuits.setdefault(key, _Circuit())
        if circuit.opened_at is None:
            return
        if self.clock() - circuit.opened_at < self.reset_s or circuit.half_open_probe:
            raise CircuitOpenError(f"upstream {key} is unavailable (circuit open)")
        circuit.half_open_probe = True

    def release(self, key: str) -> None:
        """End a call that said nothing about upstream health (e.g. a policy refusal)."""
        circuit = self._circuits.get(key)
        if circuit is not None:
            circuit.half_open_probe = False

    def success(self, key: str) -> None:
        self._circuits[key] = _Circuit()

    def failure(self, key: str) -> None:
        circuit = self._circuits.setdefault(key, _Circuit())
        circuit.failures += 1
        circuit.half_open_probe = False
        if circuit.failures >= self.threshold:
            circuit.opened_at = self.clock()

    def state(self, key: str) -> str:
        circuit = self._circuits.get(key)
        if circuit is None or circuit.opened_at is None:
            return "closed"
        return "half_open" if circuit.half_open_probe else "open"
