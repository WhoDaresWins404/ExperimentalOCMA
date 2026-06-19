import re
from typing import Optional
from urllib.parse import urljoin, urlparse

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


SENSITIVE_PATTERNS = [
    (r'(["\']?)AWS[A-Z0-9_]{10,}\1', "AWS Access Key"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'(sk|pk)_(live|test)_[a-zA-Z0-9]{24,}', "Stripe Key"),
    (r'github_pat_[a-zA-Z0-9]{22,}', "GitHub PAT"),
    (r'ghp_[a-zA-Z0-9]{36,}', "GitHub Token"),
    (r'api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-]{16,}["\']', "API Key"),
    (r'secret["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-!@#$%^&*()]{8,}["\']', "Secret"),
    (r'password["\']?\s*[:=]\s*["\'][^"\']{6,}["\']', "Password"),
    (r'token["\']?\s*[:=]\s*["\'][a-zA-Z0-9_\-\.]{8,}["\']', "Token"),
    (r'bearer\s+[a-zA-Z0-9_\-\.]{10,}', "Bearer Token"),
    (r'http[s]?://[^"\'\s>]+', "Internal URL"),
    (r'/\*+<!--.*?-->', "Hidden Comment"),
]

SCRIPT_TAG = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
INLINE_SCRIPT = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
API_ENDPOINT = re.compile(r'["\']((/api/v[12]|/v[12]/api|/rest|/graphql)[^"\'\s]*)["\']', re.IGNORECASE)


@register_scanner(manifest=ScannerManifest(
    name="js_analyzer",
    category="recon",
    risk_level="safe",
    estimated_cost=30,
    produces_tag_patterns=["javascript", "recon", "secret"],
))
class JsAnalyzer(BaseScanner):
    @property
    def name(self) -> str:
        return "js_analyzer"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        js_urls = await self._discover_scripts(target.url)

        for js_url in js_urls:
            try:
                resp = await self.request("GET", js_url, timeout=15)
                body = resp.text
            except Exception:
                continue

            secrets_found = []
            for pattern, label in SENSITIVE_PATTERNS:
                matches = re.findall(pattern, body)
                for m in matches:
                    val = m[0] if isinstance(m, tuple) else m
                    if len(val) > 4:
                        secrets_found.append(f"{label}: {val[:20]}...")

            endpoints_found = set(API_ENDPOINT.findall(body))
            endpoints_found = [m[0] for m in endpoints_found]

            if secrets_found:
                findings.append(self.make_finding(
                    title=f"Secrets in JavaScript — {js_url}",
                    description=f"Found {len(secrets_found)} potential secrets in {js_url}.",
                    severity="high",
                    endpoint=self.make_endpoint(js_url, discovered_by=self.name),
                    evidence={"js_url": js_url, "secrets": secrets_found[:10]},
                    confidence=0.6,
                    tags=["javascript", "secret", "recon"],
                ))

            if endpoints_found:
                findings.append(self.make_finding(
                    title=f"API Endpoints in JavaScript — {js_url}",
                    description=f"Found {len(endpoints_found)} API endpoints in {js_url}.",
                    severity="info",
                    endpoint=self.make_endpoint(js_url, discovered_by=self.name),
                    evidence={"js_url": js_url, "endpoints": endpoints_found[:15]},
                    confidence=0.7,
                    tags=["javascript", "api", "recon"],
                ))

        return findings, endpoints

    async def _discover_scripts(self, url: str) -> list[str]:
        scripts: list[str] = []
        try:
            resp = await self.request("GET", url, timeout=15)
            body = resp.text
            for match in SCRIPT_TAG.findall(body):
                full_url = urljoin(url, match)
                if full_url not in scripts:
                    scripts.append(full_url)
        except Exception:
            pass
        return scripts
