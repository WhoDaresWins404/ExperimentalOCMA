import asyncio
import json
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

RACE_ENDPOINTS = [
    "/api/coupon", "/api/apply-coupon", "/api/v1/coupon",
    "/api/checkout", "/api/purchase", "/api/order",
    "/api/transfer", "/api/withdraw", "/api/v1/transfer",
    "/api/vote", "/api/like", "/api/follow",
    "/api/redeem", "/api/claim", "/api/bonus",
    "/api/signup", "/api/register",
]


@register_scanner(manifest=ScannerManifest(
    name="race_condition_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=90,
    produces_tag_patterns=["race-condition", "turbo", "concurrency"],
    produces_endpoint_types=[],
))
class RaceConditionScanner(BaseScanner):
    name = "race_condition_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        for path in RACE_ENDPOINTS:
            url = f"{base}{path}"
            probe_resp = None
            try:
                probe_resp = await client.post(url, json={"test": 1})
                self._stats["requests"] += 1
            except Exception:
                continue
            if probe_resp.status_code in (401, 403, 404):
                continue

            payloads = [
                {"code": "DISCOUNT50", "amount": 1},
                {"code": "FREESHIP", "amount": 1},
                {"item_id": 1, "quantity": 1},
                {"from": "a", "to": "b", "amount": 1},
            ]

            races = 20

            for payload in payloads:
                try:
                    results = await asyncio.gather(
                        *[client.post(url, json=payload) for _ in range(races)],
                        return_exceptions=True,
                    )
                    self._stats["requests"] += races

                    statuses = [r.status_code for r in results if isinstance(r, Exception) is False]
                    successes = [s for s in statuses if s == 200]
                    if len(successes) > 1:
                        ep = self.make_endpoint(url=url, status_code=200, discovered_by=self.name)
                        endpoints.append(ep)
                        findings.append(self.make_finding(
                            title="Race Condition — Concurrent Request Anomaly",
                            description=f"Sent {races} concurrent requests to {url}. Got {len(successes)} successful responses "
                                        f"(expected ~1). Race window may exist.",
                            severity=FindingSeverity.HIGH.value,
                            endpoint=ep,
                            evidence={
                                "url": url,
                                "payload": json.dumps(payload),
                                "concurrent_requests": races,
                                "successful_responses": len(successes),
                                "status_distribution": {str(s): statuses.count(s) for s in set(statuses)},
                            },
                            confidence=0.65,
                            tags=["race-condition", "concurrency"],
                        ))
                except Exception:
                    self._stats["errors"] += 1

        return findings, endpoints
