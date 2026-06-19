from typing import Optional
from urllib.parse import urlencode, urlparse, urlunparse

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


OPEN_REDIRECT_PAYLOADS = [
    "//evil.com",
    "//evil.com/",
    "https://evil.com/",
    "http://evil.com/",
    "/\\evil.com",
    "//evil.com%2f..",
    "/redirect?url=https://evil.com",
    "/@evil.com",
]


@register_scanner(manifest=ScannerManifest(
    name="redirect_scanner",
    category="analysis",
    risk_level="safe",
    estimated_cost=10,
    produces_tag_patterns=["redirect", "open-redirect"],
))
class RedirectScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "redirect_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        for payload in OPEN_REDIRECT_PAYLOADS:
            test_url = self._inject_payload(target.url, payload)
            try:
                resp = await self.request("GET", test_url, follow_redirects=False)
                location = resp.headers.get("Location", "")
                if location and any(evil in location for evil in ["evil.com", "//evil"]):
                    findings.append(self.make_finding(
                        title="Open Redirect detected",
                        description=f"Server redirects to attacker-controlled domain via payload: {payload}",
                        severity="medium",
                        endpoint=self.make_endpoint(test_url, status_code=resp.status_code,
                                                     discovered_by=self.name),
                        evidence={"payload": payload, "location": location, "status": resp.status_code},
                        confidence=0.8,
                        tags=["redirect", "open-redirect"],
                    ))
            except Exception:
                pass

        return findings, endpoints

    @staticmethod
    def _inject_payload(url: str, payload: str) -> str:
        parsed = urlparse(url)
        if parsed.query:
            return f"{url}&next={payload}"
        return f"{url}?next={payload}"
