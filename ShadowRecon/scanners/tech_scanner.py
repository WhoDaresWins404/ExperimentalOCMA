import re
from pathlib import Path
from urllib.parse import urlparse

import yaml
import httpx

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget


@register_scanner(manifest=ScannerManifest(
    name="tech_scanner",
    category="recon",
    risk_level="safe",
    estimated_cost=10,
    produces_tag_patterns=["tech-detection", "fingerprint"],
    produces_endpoint_types=[],
))
class TechScanner(BaseScanner):
    name = "tech_scanner"

    def __init__(self, config, session_id, waf_state=None, directive_bus=None):
        super().__init__(config, session_id, waf_state, directive_bus)
        self._fingerprints = self._load_fingerprints()
        self._detected: dict[str, dict] = {}

    @property
    def detected_tech(self) -> dict[str, dict]:
        return dict(self._detected)

    def _load_fingerprints(self) -> dict:
        fp_path = Path(self.config.data_dir) / "fingerprints" / "tech_fingerprints.yaml"
        if fp_path.exists():
            raw = yaml.safe_load(fp_path.read_text())
            return raw or {}
        return {}

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        self._detected = {}

        try:
            client = await self.get_client()
            resp = await client.request("GET", target.url, follow_redirects=True)
            self._stats["requests"] += 1
            body = resp.text or ""
            headers = dict(resp.headers)
            cookies = dict(resp.cookies)

            parsed = urlparse(target.url)
            base_domain = parsed.hostname or ""

            self._detect("servers", headers, cookies, body, base_domain)
            self._detect("frameworks", headers, cookies, body, base_domain)
            self._detect("cms", headers, cookies, body, base_domain)
            self._detect("javascript", headers, cookies, body, base_domain)
            self._detect("cloud", headers, cookies, body, base_domain)
            self._detect("analytics", headers, cookies, body, base_domain)
            self._detect("cdn", headers, cookies, body, base_domain)

            robots_url = target.url.rstrip("/") + "/robots.txt"
            try:
                resp2 = await client.request("GET", robots_url)
                self._stats["requests"] += 1
                if resp2.status_code == 200:
                    body_lower = (resp2.text or "").lower()
                    if body_lower:
                        self._detected.setdefault("servers", {})
                        self._detected["robots"] = {"available": True}
            except Exception:
                pass

            if self._detected:
                ep = self.make_endpoint(
                    url=target.url,
                    type_hint="web_page",
                    status_code=resp.status_code,
                    content_type=headers.get("content-type", ""),
                    discovered_by=self.name,
                    metadata={"tech": self._detected},
                )
                endpoints.append(ep)
                findings.append(self.make_finding(
                    title="Technology Stack Detected",
                    description=f"Detected {self._summarize()} on {target.url}",
                    severity="info",
                    endpoint=ep,
                    evidence={"technology": self._detected, "headers": dict(resp.headers)},
                    confidence=0.9,
                    tags=["tech-detection", "fingerprint"],
                ))
        except Exception:
            pass

        return findings, endpoints

    def _detect(self, category: str, headers: dict, cookies: dict, body: str, domain: str):
        items = self._fingerprints.get(category, {})
        for name, fp in items.items():
            if self._matches(fp, headers, cookies, body, domain):
                self._detected.setdefault(category, {})[name] = True

    def _matches(self, fp: dict, headers: dict, cookies: dict, body: str, domain: str) -> bool:
        for h_pattern in fp.get("headers", []):
            key, _, val = h_pattern.partition(": ")
            if key.lower() in headers:
                if not val or val.lower() in headers.get(key.lower(), "").lower():
                    return True
        for c_pattern in fp.get("cookies", []):
            if any(c.startswith(c_pattern) for c in cookies):
                return True
        for url_pat in fp.get("urls", []):
            if url_pat in domain:
                return True
        for b_pattern in fp.get("body_patterns", []):
            if re.search(b_pattern, body, re.IGNORECASE):
                return True
        return False

    def _summarize(self) -> str:
        parts = []
        for cat, items in self._detected.items():
            if cat == "robots":
                continue
            names = list(items.keys())
            if names:
                parts.append(", ".join(names[:3]))
        return "; ".join(parts) if parts else "unknown technologies"
