import time
from enum import Enum
from typing import Optional

import httpx


class HostStatus(str, Enum):
    UNKNOWN = "unknown"
    ALIVE = "alive"
    SUSPECT = "suspect"
    DEAD = "dead"


class HostMonitor:
    """Lightweight reachability probe for the scan target.

    Probes the target base URL with a plain HEAD/GET request (no scanner
    payloads or special headers) to determine actual host reachability
    independently of scanner traffic.

    State machine:
        UNKNOWN → (first probe success) → ALIVE
        UNKNOWN → (first probe fail) → SUSPECT
        ALIVE → (probe fail) → SUSPECT
        SUSPECT → (probe success) → ALIVE
        SUSPECT → (timeout exceeded) → DEAD
        DEAD → (never recovers without manual reset)
    """

    def __init__(
        self,
        target_url: str,
        unreachable_timeout: int = 120,
        probe_interval: int = 30,
        http_timeout: int = 5,
    ):
        self.target_url = target_url
        self.unreachable_timeout = unreachable_timeout
        self.probe_interval = probe_interval
        self.http_timeout = http_timeout

        self.status = HostStatus.UNKNOWN
        self._consecutive_failures = 0
        self._first_failure_at: Optional[float] = None
        self._last_probe_at: float = 0.0
        self._last_success_at: float = time.monotonic()

    async def probe(self) -> HostStatus:
        """Send a lightweight probe. Returns current status after probe."""
        now = time.monotonic()
        if now - self._last_probe_at < self.probe_interval and self.status == HostStatus.ALIVE:
            return self.status

        self._last_probe_at = now
        try:
            async with httpx.AsyncClient(timeout=self.http_timeout, follow_redirects=True) as client:
                await client.head(self.target_url)
            self._on_success()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError, httpx.ReadError):
            self._on_failure()

        return self.status

    async def probe_if_needed(self) -> HostStatus:
        """Probe only if enough time has passed since last probe."""
        if time.monotonic() - self._last_probe_at >= self.probe_interval:
            return await self.probe()
        return self.status

    def _on_success(self):
        was_dead_or_suspect = self.status != HostStatus.ALIVE
        self._consecutive_failures = 0
        self._first_failure_at = None
        self._last_success_at = time.monotonic()
        self.status = HostStatus.ALIVE

    def _on_failure(self):
        now = time.monotonic()
        self._consecutive_failures += 1
        if self._first_failure_at is None:
            self._first_failure_at = now

        if self._consecutive_failures >= 1 and self.status == HostStatus.UNKNOWN:
            self.status = HostStatus.SUSPECT
        elif self._consecutive_failures >= 1 and self.status == HostStatus.ALIVE:
            self.status = HostStatus.SUSPECT

        if self._first_failure_at and (now - self._first_failure_at) >= self.unreachable_timeout:
            self.status = HostStatus.DEAD

    @property
    def is_alive(self) -> bool:
        return self.status == HostStatus.ALIVE

    @property
    def is_dead(self) -> bool:
        return self.status == HostStatus.DEAD

    @property
    def is_suspect(self) -> bool:
        return self.status == HostStatus.SUSPECT

    @property
    def unreachable_for(self) -> float:
        if self._first_failure_at is None:
            return 0.0
        return time.monotonic() - self._first_failure_at
