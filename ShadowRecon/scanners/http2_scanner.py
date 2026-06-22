import asyncio
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity


@register_scanner(manifest=ScannerManifest(
    name="http2_scanner",
    category="discovery",
    risk_level="safe",
    estimated_cost=30,
    produces_tag_patterns=["http2", "h2", "protocol-downgrade"],
    produces_endpoint_types=[],
))
class Http2Scanner(BaseScanner):
    name = "http2_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        parsed = target.get_url()
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=use_ssl),
                timeout=10,
            )
            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.close()
            self._stats["requests"] += 1

            http2_magic = resp[:24]
            expected_magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

            if http2_magic != expected_magic and len(resp) > 0:
                ep = self.make_endpoint(url=target.url, status_code=0, discovered_by=self.name)
                endpoints.append(ep)
                findings.append(self.make_finding(
                    title="HTTP/2 Not Supported — Protocol Downgrade",
                    description=f"Server at {host}:{port} does not respond with HTTP/2 magic. "
                                f"Response: {resp[:50].hex() if resp else 'empty'}",
                    severity=FindingSeverity.INFO.value,
                    endpoint=ep,
                    evidence={"host": host, "port": port, "http2_supported": False},
                    confidence=0.9,
                    tags=["http2", "h2", "protocol"],
                ))
        except Exception as e:
            ep = self.make_endpoint(url=target.url, status_code=0, discovered_by=self.name)
            endpoints.append(ep)
            findings.append(self.make_finding(
                title="HTTP/2 Connection Failed",
                description=f"Cannot establish HTTP/2 connection to {host}:{port}. Error: {str(e)[:100]}",
                severity=FindingSeverity.INFO.value,
                endpoint=ep,
                evidence={"host": host, "port": port, "error": str(e)[:200]},
                confidence=0.8,
                tags=["http2", "h2", "connection-error"],
            ))

        try:
            alt_svc_resp = await client.get(target.url, headers={"Accept": "*/*"})
            self._stats["requests"] += 1
            alt_svc = alt_svc_resp.headers.get("alt-svc", alt_svc_resp.headers.get("Alt-Svc", ""))
            if "h2" in alt_svc.lower() or "h3" in alt_svc.lower():
                ep = self.make_endpoint(url=target.url, status_code=alt_svc_resp.status_code, discovered_by=self.name)
                endpoints.append(ep)
                findings.append(self.make_finding(
                    title="HTTP/2 or HTTP/3 Advertised via Alt-Svc",
                    description=f"Server advertises HTTP/2+/HTTP/3 via Alt-Svc header: {alt_svc}",
                    severity=FindingSeverity.INFO.value,
                    endpoint=ep,
                    evidence={"alt_svc": alt_svc, "host": host},
                    confidence=0.95,
                    tags=["http2", "h3", "alt-svc"],
                ))
        except Exception:
            pass

        return findings, endpoints
