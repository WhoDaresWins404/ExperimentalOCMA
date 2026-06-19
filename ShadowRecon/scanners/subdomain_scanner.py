import json
from typing import Optional
from urllib.parse import urlparse

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


@register_scanner(manifest=ScannerManifest(
    name="subdomain_scanner",
    category="recon",
    risk_level="safe",
    estimated_cost=40,
    produces_tag_patterns=["subdomain", "recon"],
))
class SubdomainScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "subdomain_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        domain = urlparse(target.url).netloc
        domain = domain.split(":")[0]
        parts = domain.split(".")
        if len(parts) < 2:
            return findings, endpoints
        root_domain = ".".join(parts[-2:])

        subdomains = await self._query_crtsh(root_domain)

        if not subdomains:
            return findings, endpoints

        findings.append(self.make_finding(
            title=f"Subdomains Discovered — {len(subdomains)} found",
            description=f"Discovered {len(subdomains)} subdomains for {root_domain} via crt.sh.",
            severity="info",
            endpoint=self.make_endpoint(target.url, discovered_by=self.name),
            evidence={"root_domain": root_domain, "subdomains": sorted(subdomains)[:50],
                      "total": len(subdomains)},
            confidence=0.9,
            tags=["subdomain", "recon", "crt.sh"],
        ))

        for sub in sorted(subdomains)[:10]:
            try:
                resp = await self.request("GET", f"https://{sub}", timeout=10)
                endpoints.append(self.make_endpoint(
                    f"https://{sub}", status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    discovered_by=self.name,
                ))
            except Exception:
                pass

        return findings, endpoints

    async def _query_crtsh(self, domain: str) -> list[str]:
        try:
            client = await self.get_client()
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            resp = await client.get(url, timeout=15)
            if resp.status_code != 200:
                return []
            entries = resp.json()
            subdomains: set[str] = set()
            for entry in entries:
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip()
                    if n and n.endswith(f".{domain}") or n == domain:
                        subdomains.add(n)
            return list(subdomains)
        except Exception:
            return []
