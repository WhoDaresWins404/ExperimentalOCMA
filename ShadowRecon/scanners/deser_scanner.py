import base64
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

DESER_PROBES = [
    {
        "name": "PHP unserialize",
        "headers": {"Cookie": "user=O:3:\"Foo\":0:{}"},
        "detect": "unserialize",
    },
    {
        "name": "Python pickle",
        "headers": {"Cookie": "session=KGRwMAou"},
        "detect": "",
    },
    {
        "name": "Java serialized object",
        "headers": {"Cookie": "session=ACED0005"},
        "detect": "",
    },
    {
        "name": ".NET ViewState",
        "body": "__VIEWSTATE=/wEPDwULLTE4MTIzNDU2NzgPZBYCAgEPZBYCAgEPFCsAA2RkBQ==",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "detect": "",
    },
]

JAVA_GADGET_PROBES = [
    {
        "header": "spring4shell",
        "url_suffix": "/spring4shell?class.module.classLoader.URLs[0]=file:///etc/passwd",
        "detect": "root:",
    },
]


@register_scanner(manifest=ScannerManifest(
    name="deser_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=50,
    produces_tag_patterns=["deserialization", "rce", "java-deser", "php-deser"],
    produces_endpoint_types=[],
))
class DeserScanner(BaseScanner):
    name = "deser_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base_url = target.url.rstrip("/")

        for probe in DESER_PROBES:
            try:
                method = "POST" if "body" in probe else "GET"
                kwargs = {"headers": probe.get("headers", {}), "follow_redirects": False}
                if "body" in probe:
                    kwargs["content"] = probe["body"]
                resp = await client.request(method, base_url, **kwargs)
                self._stats["requests"] += 1
                body = resp.text or ""
                if probe["detect"] and probe["detect"] in body:
                    ep = self.make_endpoint(url=base_url, discovered_by=self.name)
                    endpoints.append(ep)
                    findings.append(self.make_finding(
                        title=f"Deserialization Probe — {probe['name']}",
                        description=f"Server at {base_url} reflected deserialization-related content for {probe['name']} probe.",
                        severity=FindingSeverity.HIGH.value,
                        endpoint=ep,
                        evidence={"probe": probe["name"], "body_preview": body[:300]},
                        confidence=0.6,
                        tags=["deserialization"],
                    ))
            except Exception:
                self._stats["errors"] += 1

        for probe in JAVA_GADGET_PROBES:
            try:
                url = base_url + probe.get("url_suffix", "")
                resp = await client.request("GET", url, follow_redirects=False)
                self._stats["requests"] += 1
                body = resp.text or ""
                if probe["detect"] and probe["detect"] in body:
                    ep = self.make_endpoint(url=url, discovered_by=self.name)
                    endpoints.append(ep)
                    findings.append(self.make_finding(
                        title=f"Deserialization CVE Probe — {probe['header']}",
                        description=f"Server at {url} responded with content indicating potential {probe['header']} vulnerability.",
                        severity=FindingSeverity.CRITICAL.value,
                        endpoint=ep,
                        evidence={"probe": probe["header"], "body_preview": body[:300]},
                        confidence=0.5,
                        tags=["deserialization", "cve", probe["header"]],
                    ))
            except Exception:
                self._stats["errors"] += 1

        return findings, endpoints
