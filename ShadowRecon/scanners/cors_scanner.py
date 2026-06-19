import asyncio
from typing import Optional
from urllib.parse import urlparse

from httpx import AsyncClient

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://sub.attacker.io",
    "https://target.com.evil.com",
    "https://evil-target.com",
    "https://target.com:9999",
]


@register_scanner(manifest=ScannerManifest(
    name="cors_scanner",
    category="analysis",
    risk_level="safe",
    estimated_cost=10,
    produces_tag_patterns=["cors", "misconfiguration"],
))
class CorsScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "cors_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        parsed = urlparse(target.url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        for origin in TEST_ORIGINS:
            try:
                resp = await self.request(
                    "GET", target.url,
                    headers={"Origin": origin, "Referer": origin},
                )
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == origin or acao == "*":
                    severity = "high" if acao == origin else "medium"
                    if acao == origin and acac == "true":
                        severity = "critical"
                    findings.append(self.make_finding(
                        title=f"CORS Misconfiguration — reflects untrusted origin: {origin}",
                        description=f"Server reflects Origin header value in Access-Control-Allow-Origin. "
                                    f"ACAO: {acao}, ACAC: {acac}",
                        severity=severity,
                        endpoint=self.make_endpoint(target.url, discovered_by=self.name),
                        evidence={"origin": origin, "acao": acao, "acac": acac},
                        confidence=0.9,
                        tags=["cors", "misconfiguration"],
                    ))
            except Exception:
                pass

        return findings, endpoints
