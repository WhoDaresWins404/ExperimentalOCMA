from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

UPLOAD_PROBES = [
    {"ext": ".php", "content": "<?php echo 'test'; ?>", "mime": "application/x-php"},
    {"ext": ".php5", "content": "<?php echo 'test'; ?>", "mime": "application/x-php"},
    {"ext": ".phtml", "content": "<?php echo 'test'; ?>", "mime": "application/x-php"},
    {"ext": ".php.jpg", "content": "GIF89a<?php echo 'test'; ?>", "mime": "image/jpeg"},
    {"ext": ".pHp", "content": "<?php echo 'test'; ?>", "mime": "application/x-php"},
    {"ext": ".shtml", "content": "<!--#echo var=\"DATE_LOCAL\"-->", "mime": "text/html"},
    {"ext": ".jsp", "content": "<%= \"test\" %>", "mime": "application/x-jsp"},
    {"ext": ".asp", "content": "<% Response.Write \"test\" %>", "mime": "application/x-asp"},
]


@register_scanner(manifest=ScannerManifest(
    name="upload_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=40,
    produces_tag_patterns=["file-upload", "unrestricted-upload", "rce"],
    produces_endpoint_types=["backup_file"],
))
class UploadScanner(BaseScanner):
    name = "upload_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base_url = target.url.rstrip("/")

        upload_urls = self._find_upload_forms(base_url)
        if not upload_urls:
            for endpoint in ["/upload", "/uploads", "/api/upload", "/file/upload", "/media/upload", "/images/upload"]:
                upload_urls.append(base_url + endpoint)
        upload_urls = upload_urls[:3]

        for upload_url in upload_urls:
            for probe in UPLOAD_PROBES:
                try:
                    boundary = "----WebKitFormBoundary" + "x" * 16
                    body = (
                        f"--{boundary}\r\n"
                        f'Content-Disposition: form-data; name="file"; filename="test{probe["ext"]}"\r\n'
                        f"Content-Type: {probe['mime']}\r\n\r\n"
                        f"{probe['content']}\r\n"
                        f"--{boundary}--\r\n"
                    )
                    resp = await client.request(
                        "POST", upload_url,
                        content=body,
                        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                        follow_redirects=False,
                    )
                    self._stats["requests"] += 1
                    body_text = resp.text or ""
                    if resp.status_code in (200, 201, 302):
                        ep = self.make_endpoint(url=upload_url, discovered_by=self.name)
                        endpoints.append(ep)
                        findings.append(self.make_finding(
                            title=f"File Upload Accepted — {probe['ext']}",
                            description=f"Upload endpoint at {upload_url} accepted a file with extension `{probe['ext']}` ({probe['mime']}). "
                                        f"Response: {resp.status_code}",
                            severity=FindingSeverity.HIGH.value,
                            endpoint=ep,
                            evidence={
                                "upload_url": upload_url,
                                "extension": probe["ext"],
                                "mime": probe["mime"],
                                "response_status": resp.status_code,
                                "response_body": body_text[:300],
                            },
                            confidence=0.6,
                            tags=["file-upload", "unrestricted-upload"],
                        ))
                except Exception:
                    self._stats["errors"] += 1

        return findings, endpoints

    @staticmethod
    def _find_upload_forms(url: str) -> list[str]:
        return []
