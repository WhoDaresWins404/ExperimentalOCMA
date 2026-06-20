import re
from urllib.parse import urlparse, urljoin, parse_qs

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity


ID_RANGES = [
    range(1, 5),
    range(1000, 1003),
    range(10000, 10002),
]


@register_scanner(manifest=ScannerManifest(
    name="idor_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=50,
    prerequisites=[],
    produces_tag_patterns=["idor", "mass-assignment", "authorization-bypass"],
    produces_endpoint_types=[],
))
class IdorScanner(BaseScanner):
    name = "idor_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()

        candidate_ids = self._find_id_candidates(target.url)
        if not candidate_ids:
            return findings, endpoints

        for id_name, original_id in candidate_ids:
            for r in ID_RANGES:
                for test_id in r:
                    if str(test_id) == original_id:
                        continue
                    test_url = self._replace_param(target.url, id_name, str(test_id))
                    try:
                        resp = await client.request("GET", test_url, follow_redirects=False)
                        self._stats["requests"] += 1
                        if resp.status_code == 200:
                            ep = self.make_endpoint(url=test_url, status_code=200, discovered_by=self.name)
                            endpoints.append(ep)
                            findings.append(self.make_finding(
                                title="IDOR — Sequential ID Enumeration",
                                description=f"Endpoint at {test_url} returned 200 with ID `{test_id}`. "
                                            f"Parameter `{id_name}` accepts sequential values, suggesting Insecure Direct Object Reference.",
                                severity=FindingSeverity.HIGH.value,
                                endpoint=ep,
                                evidence={"parameter": id_name, "tested_id": test_id, "url": test_url, "body_preview": (resp.text or "")[:300]},
                                confidence=0.7,
                                tags=["idor", "authorization-bypass"],
                            ))
                            break
                    except Exception:
                        self._stats["errors"] += 1

        return findings, endpoints

    @staticmethod
    def _find_id_candidates(url: str) -> list[tuple[str, str]]:
        candidates = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for name, values in params.items():
            val = values[0] if values else ""
            if re.match(r"^\d+$", val):
                candidates.append((name, val))
        path_parts = parsed.path.rstrip("/").split("/")
        for part in reversed(path_parts):
            if re.match(r"^\d+$", part):
                candidates.append(("id", part))
                break
        return candidates

    @staticmethod
    def _replace_param(url: str, param: str, new_value: str) -> str:
        from urllib.parse import urlencode, parse_qs, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if param in params:
            params[param] = [new_value]
            new_qs = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_qs))
        path = parsed.path
        if path.endswith(f"/{param}"):
            return urlunparse(parsed._replace(path=f"{path}/{new_value}"))
        return url
