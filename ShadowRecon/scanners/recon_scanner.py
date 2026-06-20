import asyncio
import json
import re
import socket
from urllib.parse import urlparse

import httpx

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity


SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "blog", "shop", "app", "m", "mobile", "webmail", "vpn", "ns1",
    "ns2", "smtp", "pop3", "imap", "cpanel", "whm", "autodiscover",
    "remote", "support", "help", "status", "docs", "wiki", "git",
    "jenkins", "jira", "confluence", "grafana", "prometheus", "kibana",
    "dashboard", "monitor", "api-docs", "swagger", "graphql", "cdn",
    "assets", "static", "media", "upload", "files", "download",
    "backup", "db", "database", "redis", "mysql", "mq", "rabbitmq",
    "kafka", "elastic", "logs", "metrics", "internal", "corp", "hr",
    "portal", "partner", "vendors", "sso", "login", "auth", "oauth",
    "idp", "saml", "openid", "accounts", "register", "signup",
    "forgot", "reset", "password", "profile", "settings", "config",
    "adminer", "phpmyadmin", "pma", "mailhog", "mailcatcher",
    "maildev", "webmail", "roundcube", "squirrelmail", "rainloop",
    "calendar", "contacts", "drive", "cloud", "nextcloud", "owncloud",
    "synology", "nas", "storage", "s3", "bucket", "data",
    "analytics", "tracking", "pixel", "metrics", "reports",
    "billing", "invoices", "payments", "checkout", "cart", "orders",
    "marketplace", "community", "forum", "chat", "livechat", "helpdesk",
    "tickets", "service", "info", "newsletter", "events", "jobs",
    "careers", "team", "about", "contact", "feedback", "survey",
]

COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 9090, 22, 21, 3306, 5432, 6379, 27017, 1433, 9200, 5601, 8086, 9000, 8000, 8888]

CDN_PREFIXES = [
    "cloudfront.net", "akamaiedge.net", "akamaiedge-staging.net",
    "fastly.net", "fastlylb.net", "edgekey.net", "edgesuite.net",
    "azureedge.net", "azurefd.net", "trafficmanager.net",
    "cdn.cloudflare.net", "cloudflare.net",
]


@register_scanner(manifest=ScannerManifest(
    name="recon_scanner",
    category="recon",
    risk_level="safe",
    estimated_cost=80,
    produces_tag_patterns=["recon", "subdomain", "asset-discovery", "port-scan"],
    produces_endpoint_types=["web_page", "static_asset"],
))
class ReconScanner(BaseScanner):
    name = "recon_scanner"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._discovered: dict[str, set] = {"subdomains": set(), "ips": set(), "historical_urls": set(), "open_ports": set()}
        self._http_client: httpx.AsyncClient | None = None

    async def _http(self) -> httpx.AsyncClient:
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=15.0, follow_redirects=False, verify=False)
        return self._http_client

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        self._discovered = {"subdomains": set(), "ips": set(), "historical_urls": set(), "open_ports": set()}

        parsed = urlparse(target.url)
        domain = parsed.hostname or ""
        domain = domain.replace("www.", "", 1)

        await asyncio.gather(
            self._wayback_machine(domain, findings, endpoints),
            self._commoncrawl(domain, findings, endpoints),
            self._dns_bruteforce(domain, findings, endpoints),
            self._port_scan(domain, findings, endpoints),
            return_exceptions=True,
        )

        if self._discovered.get("subdomains"):
            subdomains = sorted(self._discovered["subdomains"])[:50]
            for sub in subdomains:
                ep = self.make_endpoint(url=f"https://{sub}/", type_hint="web_page", discovered_by=self.name)
                endpoints.append(ep)
            findings.append(self.make_finding(
                title=f"Subdomains Discovered ({len(subdomains)})",
                description=f"Found {len(subdomains)} subdomains for {domain}: {', '.join(subdomains[:15])}",
                severity=FindingSeverity.INFO.value,
                evidence={"domain": domain, "subdomains": subdomains[:50], "total": len(subdomains)},
                confidence=0.9,
                tags=["recon", "subdomain"],
            ))

        if self._discovered.get("open_ports"):
            ports = sorted(self._discovered["open_ports"])
            findings.append(self.make_finding(
                title=f"Open Ports Found ({len(ports)})",
                description=f"Open ports on {domain}: {', '.join(str(p) for p in ports[:20])}",
                severity=FindingSeverity.INFO.value,
                evidence={"domain": domain, "ports": ports[:50], "total": len(ports)},
                confidence=0.95,
                tags=["recon", "port-scan"],
            ))

        if self._discovered.get("historical_urls"):
            urls = list(self._discovered["historical_urls"])[:100]
            if self._discovered.get("ips"):
                ips = sorted(self._discovered["ips"])
                findings.append(self.make_finding(
                    title=f"Historical URLs & IPs for {domain}",
                    description=f"Wayback/CommonCrawl returned {len(urls)} unique URLs for {domain}. Resolved IPs: {', '.join(ips[:10])}",
                    severity=FindingSeverity.INFO.value,
                    evidence={"domain": domain, "historical_urls": urls[:50], "ips": ips[:20]},
                    confidence=0.85,
                    tags=["recon", "historical", "ip-discovery"],
                ))

        return findings, endpoints

    async def _wayback_machine(self, domain: str, findings: list, endpoints: list):
        try:
            client = await self._http()
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original,timestamp,statuscode&limit=5000"
            resp = await client.request("GET", cdx_url)
            self._stats["requests"] += 1
            if resp.status_code == 200:
                rows = resp.json()
                for row in rows[1:]:
                    url = row[0] if len(row) > 0 else ""
                    if url and self._is_relevant(url, domain):
                        self._discovered["historical_urls"].add(url)
        except Exception:
            self._stats["errors"] += 1

    async def _commoncrawl(self, domain: str, findings: list, endpoints: list):
        try:
            client = await self._http()
            cc_url = f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url={domain}/*&output=json&limit=1000"
            resp = await client.request("GET", cc_url)
            self._stats["requests"] += 1
            if resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    try:
                        entry = json.loads(line)
                        url = entry.get("url", "")
                        if url and self._is_relevant(url, domain):
                            self._discovered["historical_urls"].add(url)
                    except json.JSONDecodeError:
                        pass
        except Exception:
            self._stats["errors"] += 1

    async def _dns_bruteforce(self, domain: str, findings: list, endpoints: list):
        resolved = set()
        for prefix in SUBDOMAIN_WORDLIST:
            if self._stats["requests"] >= 200:
                break
            fqdn = f"{prefix}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                resolved.add(fqdn)
                self._discovered["subdomains"].add(fqdn)
                self._discovered["ips"].add(ip)
                self._stats["requests"] += 1
            except (socket.gaierror, OSError):
                pass
            await asyncio.sleep(0)

        try:
            main_ip = socket.gethostbyname(domain)
            self._discovered["ips"].add(main_ip)
        except Exception:
            pass

    async def _port_scan(self, domain: str, findings: list, endpoints: list):
        ip = None
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            return
        open_ports = []
        sem = asyncio.Semaphore(20)
        async def _check(port: int):
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port), timeout=3
                    )
                    writer.close()
                    await writer.wait_closed()
                    open_ports.append(port)
                    self._discovered["open_ports"].add(port)
                except Exception:
                    pass
        await asyncio.gather(*[_check(p) for p in COMMON_PORTS], return_exceptions=True)

    def _is_relevant(self, url: str, domain: str) -> bool:
        try:
            hostname = urlparse(url).hostname or ""
            return domain in hostname
        except Exception:
            return False
