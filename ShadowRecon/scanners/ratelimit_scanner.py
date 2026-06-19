import asyncio
import time
from typing import Optional

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


RAPID_REQUESTS = 20
RATE_WINDOW = 5.0


@register_scanner(manifest=ScannerManifest(
    name="ratelimit_scanner",
    category="analysis",
    risk_level="moderate",
    estimated_cost=20,
    produces_tag_patterns=["ratelimit", "dos"],
))
class RateLimitScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "ratelimit_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        statuses: list[int] = []
        timings: list[float] = []
        start = time.monotonic()

        for i in range(RAPID_REQUESTS):
            try:
                t0 = time.monotonic()
                resp = await self.request("GET", target.url)
                elapsed = time.monotonic() - t0
                statuses.append(resp.status_code)
                timings.append(elapsed)
            except Exception:
                statuses.append(0)
                timings.append(0)

        elapsed_total = time.monotonic() - start
        rate = RAPID_REQUESTS / elapsed_total if elapsed_total > 0 else 0
        has_429 = any(s == 429 for s in statuses)
        has_503 = any(s == 503 for s in statuses)
        has_variance = len(set(s for s in statuses if s > 0)) > 1
        avg_response = sum(timings) / len(timings) if timings else 0

        if has_429 or has_503:
            findings.append(self.make_finding(
                title="Rate Limiting Detected",
                description=f"Server returned {RAPID_REQUESTS} requests in {elapsed_total:.1f}s "
                            f"({rate:.1f} req/s). Status 429/503 observed.",
                severity="info",
                endpoint=self.make_endpoint(target.url, discovered_by=self.name),
                evidence={"rate": round(rate, 1), "window": round(elapsed_total, 1),
                          "statuses": statuses, "avg_response_ms": round(avg_response * 1000, 1)},
                confidence=1.0,
                tags=["ratelimit"],
            ))
        elif has_variance:
            findings.append(self.make_finding(
                title="Unstable Rate Limiting Behavior",
                description=f"Server response status varied: {statuses}. "
                            f"Possible soft rate limiting in place.",
                severity="low",
                endpoint=self.make_endpoint(target.url, discovered_by=self.name),
                evidence={"rate": round(rate, 1), "window": round(elapsed_total, 1),
                          "statuses": statuses, "avg_response_ms": round(avg_response * 1000, 1)},
                confidence=0.6,
                tags=["ratelimit"],
            ))
        else:
            findings.append(self.make_finding(
                title="No Rate Limiting Detected",
                description=f"All {RAPID_REQUESTS} requests succeeded at rate {rate:.1f} req/s. "
                            "No 429 or 503 responses observed.",
                severity="info",
                endpoint=self.make_endpoint(target.url, discovered_by=self.name),
                evidence={"rate": round(rate, 1), "window": round(elapsed_total, 1),
                          "avg_response_ms": round(avg_response * 1000, 1)},
                confidence=1.0,
                tags=["ratelimit"],
            ))

        return findings, endpoints
