from typing import Optional

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


CONTENT_TYPE_PROBES = [
    ("application/json", '{"test":"value"}'),
    ("application/xml", "<root><test>value</test></root>"),
    ("text/plain", "test=value"),
    ("multipart/form-data", "test=value"),
]

FUZZ_PATHS = [
    "/api/v1/users", "/api/v1/admin", "/api/v1/config", "/api/v1/debug",
    "/api/v1/logs", "/api/v1/health", "/api/v1/metrics", "/api/v1/keys",
    "/api/v1/tokens", "/api/v1/secrets", "/api/v1/backup", "/api/v1/export",
    "/api/v1/import", "/api/v1/execute", "/api/v1/upload", "/api/v1/delete",
    "/api/v1/flag", "/api/v1/report",
]

TEST_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]


@register_scanner(manifest=ScannerManifest(
    name="api_fuzzer",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=60,
    produces_tag_patterns=["api", "fuzzing"],
))
class ApiFuzzer(BaseScanner):
    @property
    def name(self) -> str:
        return "api_fuzzer"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        base = target.url.rstrip("/")

        for path in FUZZ_PATHS:
            url = f"{base}{path}"
            for method in TEST_METHODS:
                try:
                    resp = await self.request(method, url, timeout=10)
                    if resp.status_code not in (404, 405, 403, 401):
                        findings.append(self.make_finding(
                            title=f"API Endpoint Accessible — {method} {path}",
                            description=f"Endpoint {method} {url} returned {resp.status_code}. "
                                        "May expose functionality.",
                            severity="low" if resp.status_code in (200, 201, 202) else "info",
                            endpoint=self.make_endpoint(url, method=method,
                                                         status_code=resp.status_code,
                                                         discovered_by=self.name),
                            evidence={"status": resp.status_code, "method": method,
                                      "body_snippet": resp.text[:200]},
                            confidence=0.7,
                            tags=["api", "fuzzing"],
                        ))
                except Exception:
                    pass

        for ct, body in CONTENT_TYPE_PROBES:
            try:
                resp = await self.request("POST", base, content=body,
                                          headers={"Content-Type": ct}, timeout=10)
                if resp.status_code not in (404, 415, 400, 405):
                    findings.append(self.make_finding(
                        title=f"API Content-Type Accepted — {ct}",
                        description=f"Server accepts Content-Type {ct} on POST requests.",
                        severity="info",
                        endpoint=self.make_endpoint(base, method="POST",
                                                     status_code=resp.status_code,
                                                     discovered_by=self.name),
                        evidence={"content_type": ct, "status": resp.status_code},
                        confidence=0.5,
                        tags=["api", "fuzzing"],
                    ))
            except Exception:
                pass

        return findings, endpoints
