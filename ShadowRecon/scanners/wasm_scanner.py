import json
import re
from urllib.parse import urljoin
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

WASM_PATTERNS = [
    r'\.wasm["\']',
    r'\.wasm\b',
    r'WebAssembly\.instantiate',
    r'WebAssembly\.instantiateStreaming',
    r'wasm=',
]

INTERESTING_WASM_STRINGS = [
    "api_key", "apiKey", "API_KEY", "secret", "SECRET",
    "password", "token", "jwt", "bearer", "authorization",
    "admin", "root", "internal", "private_key", "privateKey",
    "localhost", "127.0.0.1", "10.", "192.168.",
    "http://", "https://", "wss://",
    "username", "login", "auth", "proxy",
    "firebase", "dynamodb", "s3.", "s3-",
    "mongodb", "mysql://", "postgres://",
    "access_key", "accessKey", "aws_secret",
]


@register_scanner(manifest=ScannerManifest(
    name="wasm_scanner",
    category="discovery",
    risk_level="safe",
    estimated_cost=40,
    produces_tag_patterns=["wasm", "webassembly", "client-side-analysis"],
    produces_endpoint_types=[],
))
class WasmScanner(BaseScanner):
    name = "wasm_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()

        try:
            resp = await client.get(target.url, follow_redirects=True)
            self._stats["requests"] += 1
            html = resp.text or ""
        except Exception:
            return [], []

        wasm_paths = re.findall(r'(?:src|href)=["\']([^"\']+\.wasm)["\']', html, re.IGNORECASE)
        has_wasm_reference = bool(re.search(r'WebAssembly|\.wasm', html, re.IGNORECASE))

        if has_wasm_reference:
            ep = self.make_endpoint(url=target.url, status_code=resp.status_code, discovered_by=self.name)
            endpoints.append(ep)
            findings.append(self.make_finding(
                title="WebAssembly Detected on Page",
                description=f"Target page references WebAssembly. Found {len(wasm_paths)} direct .wasm file references.",
                severity=FindingSeverity.INFO.value,
                endpoint=ep,
                evidence={
                    "url": target.url,
                    "wasm_references_found": len(wasm_paths),
                    "wasm_paths": wasm_paths[:10],
                    "page_url": target.url,
                },
                confidence=0.95,
                tags=["wasm", "client-side", "recon"],
            ))

        for rel_path in wasm_paths[:5]:
            wasm_url = urljoin(target.url, rel_path)
            try:
                wasm_resp = await client.get(wasm_url, follow_redirects=True)
                self._stats["requests"] += 1
                if wasm_resp.status_code != 200:
                    continue
                wasm_bytes = wasm_resp.content
                if len(wasm_bytes) < 8 or wasm_bytes[:4] != b'\x00asm':
                    continue

                strings_found = self._extract_strings(wasm_bytes)
                secrets = []
                for s in strings_found:
                    for pattern in INTERESTING_WASM_STRINGS:
                        if pattern.lower() in s.lower():
                            secrets.append(s[:100])
                            break

                if secrets:
                    ep2 = self.make_endpoint(url=wasm_url, status_code=200, discovered_by=self.name)
                    endpoints.append(ep2)
                    findings.append(self.make_finding(
                        title="WebAssembly — Sensitive Strings Found",
                        description=f"WASM binary at {wasm_url} contains potentially sensitive strings: {secrets[:5]}",
                        severity=FindingSeverity.MEDIUM.value,
                        endpoint=ep2,
                        evidence={
                            "wasm_url": wasm_url,
                            "string_count": len(strings_found),
                            "secrets_found": secrets[:10],
                            "all_strings_sample": strings_found[:20],
                        },
                        confidence=0.7,
                        tags=["wasm", "secret-discovery", "client-side-analysis"],
                    ))
            except Exception:
                self._stats["errors"] += 1

        return findings, endpoints

    def _extract_strings(self, data: bytes, min_len: int = 6) -> list[str]:
        strings = []
        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    s = "".join(current)
                    if not s.startswith(("__", "0x")):
                        strings.append(s)
                current = []
        if len(current) >= min_len:
            s = "".join(current)
            if not s.startswith(("__", "0x")):
                strings.append(s)
        return strings[:50]
