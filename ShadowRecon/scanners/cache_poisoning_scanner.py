from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity
import hashlib

POISON_HEADERS = [
    ("X-Forwarded-Host", "evil.com"),
    ("X-Forwarded-Host", "attacker-controlled.com"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Remote-IP", "127.0.0.1"),
    ("Client-IP", "127.0.0.1"),
    ("X-Forwarded-Proto", "http"),
    ("X-Original-Host", "evil.com"),
    ("X-HTTP-Method-Override", "POST"),
]


@register_scanner(manifest=ScannerManifest(
    name="cache_poisoning_scanner",
    category="discovery",
    risk_level="safe",
    estimated_cost=50,
    produces_tag_patterns=["cache-poisoning", "cache-deception", "web-cache"],
    produces_endpoint_types=[],
))
class CachePoisoningScanner(BaseScanner):
    name = "cache_poisoning_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base_headers = {"User-Agent": "CachePoisoningScanner/1.0"}
        cache_hit_indicators = ["X-Cache: hit", "X-Cache: HIT", "CF-Cache-Status: HIT",
                                "X-Cache-Status: HIT", "X-Varnish-Cache: HIT", "Age:"]

        try:
            clean_resp = await client.get(target.url, headers=base_headers, follow_redirects=False)
            self._stats["requests"] += 1
            clean_body = clean_resp.text or ""
            clean_headers = {k.lower(): v for k, v in dict(clean_resp.headers).items()}
            is_cached = any(indicator.lower() in str(clean_resp.headers).lower() for indicator in cache_hit_indicators)
        except Exception:
            return [], []

        for header_name, header_value in POISON_HEADERS:
            try:
                poison_headers = dict(base_headers)
                poison_headers[header_name] = header_value
                poison_resp = await client.get(target.url, headers=poison_headers, follow_redirects=False)
                self._stats["requests"] += 1

                poison_body = poison_resp.text or ""
                poison_headers_out = {k.lower(): v for k, v in dict(poison_resp.headers).items()}
                diff = False

                if "evil.com" in poison_body or "attacker-controlled" in poison_body:
                    diff = True
                elif "127.0.0.1" in poison_body and "127.0.0.1" not in clean_body:
                    diff = True
                elif "/admin" in poison_body and "/admin" not in clean_body:
                    diff = True

                if diff:
                    ep = self.make_endpoint(url=target.url, status_code=poison_resp.status_code, discovered_by=self.name)
                    endpoints.append(ep)
                    findings.append(self.make_finding(
                        title="Cache Poisoning — Header Injection",
                        description=f"Sending {header_name}: {header_value} at {target.url} modified the response.",
                        severity=FindingSeverity.HIGH.value,
                        endpoint=ep,
                        evidence={
                            "url": target.url,
                            "header": header_name,
                            "value": header_value,
                            "clean_body_length": len(clean_body),
                            "poisoned_body_preview": poison_body[:200],
                        },
                        confidence=0.6,
                        tags=["cache-poisoning", "header-injection"],
                    ))
            except Exception:
                self._stats["errors"] += 1

        return findings, endpoints
