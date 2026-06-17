import yaml
import re
import random
from pathlib import Path
from typing import Optional

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, EndpointType
from core.exceptions import WAFDetected


WAF_SIGNATURES_PATH = Path(__file__).parent.parent / "data" / "signatures" / "waf_signatures.yaml"

PASSIVE_MIN_CONFIDENCE = 0.4
DETECT_MIN_CONFIDENCE = 0.25

PROBE_PAYLOADS = [
    ("basic_xss", "<script>alert(1)</script>"),
    ("sqli", "' OR '1'='1"),
    ("path_traversal", "../../etc/passwd"),
    ("command_injection", "; cat /etc/passwd"),
    ("xss_encoded", "%3Cscript%3Ealert(1)%3C/script%3E"),
    ("large_payload", "A" * 10000),
    ("null_byte", "%00"),
    ("method_override", "X-HTTP-Method-Override: PUT"),
]

COOKIE_PROBE_PAYLOADS = [
    ("cookie_xss", "<script>alert(1)</script>"),
    ("cookie_sqli", "' OR '1'='1"),
    ("cookie_traversal", "../../etc/passwd"),
    ("cookie_cmdi", "; cat /etc/passwd"),
]

SUSPICIOUS_USER_AGENTS = [
    "nikto/2.1.5",
    "sqlmap/1.7.12",
    "Nmap Scripting Engine",
    "curl/8.0.1",
    "Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1)",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)",
]

ACL_BYPASS_PATHS = [
    "/admin",
    "/wp-admin",
    "/../",
    "/.%00/",
    "/..;/",
]

EVASION_TECHNIQUES = {
    "case_switching": lambda p: "".join(
        c.upper() if random.random() > 0.5 else c.lower() for c in p
    ),
    "url_encoding": lambda p: "".join(
        f"%{ord(c):02x}" if random.random() > 0.7 and c.isalpha() else c for c in p
    ),
    "double_encoding": lambda p: "".join(
        f"%25{ord(c):02x}" if random.random() > 0.8 and c.isalpha() else c for c in p
    ),
    "comment_injection": lambda p: p.replace("=", "/**/= ").replace("'", "'/*'"),
    "unicode_normalization": lambda p: p.replace("<", "%u003C").replace(">", "%u003E"),
    "parameter_pollution": lambda p: f"?q={p}&q={p[::-1][:10]}",
}


@register_scanner
class WAFDetector(BaseScanner):
    name = "waf_detector"

    def __init__(self, config, session_id, waf_state=None):
        super().__init__(config, session_id, waf_state)
        self.signatures = self._load_signatures()
        self.detected_waf: Optional[dict] = None
        self.evasion_strategies: list[str] = []

    def _load_signatures(self) -> list[dict]:
        path = WAF_SIGNATURES_PATH
        if not path.exists():
            return []
        with open(path) as f:
            data = yaml.safe_load(f)
        return data.get("wafs", [])

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        self.detected_waf = await self._detect(target)
        if self.detected_waf:
            sig = self.detected_waf
            ep = self.make_endpoint(
                url=target.url,
                method=target.method,
                type_hint=EndpointType.UNKNOWN,
                discovered_by="waf_detector",
                metadata={"waf_name": sig["name"], "confidence": sig.get("confidence", 0)},
            )
            endpoints.append(ep)
            finding = self.make_finding(
                title=f"WAF Detected: {sig['name']}",
                description=f"Web application firewall identified with {sig.get('confidence', 0)*100:.0f}% confidence. "
                            f"Fingerprint: {sig.get('fingerprint', 'N/A')}",
                severity="none",
                endpoint=ep,
                evidence={"waf_name": sig["name"], "confidence": sig["confidence"],
                          "fingerprint": sig.get("fingerprint", "")},
                tags=["waf", "fingerprint"],
            )
            findings.append(finding)
            self.evasion_strategies = sig.get("evasion", [])
            selected = self._select_evasion()
            if selected:
                evasion_evidence = {"techniques": selected}
                evasion_results = await self._test_evasion(target, selected)
                if evasion_results:
                    evasion_evidence["results"] = evasion_results
                finding = self.make_finding(
                    title=f"WAF Evasion: {', '.join(selected)}",
                    description=f"Selected {len(selected)} evasion techniques to bypass {sig['name']}",
                    severity="none",
                    evidence=evasion_evidence,
                    tags=["waf", "evasion"],
                )
                findings.append(finding)
        else:
            ep = self.make_endpoint(
                url=target.url,
                method=target.method,
                type_hint=EndpointType.UNKNOWN,
                discovered_by="waf_detector",
                metadata={"waf_name": "none"},
            )
            endpoints.append(ep)
            finding = self.make_finding(
                title="No WAF Detected",
                description="No web application firewall fingerprint matched during initial probes.",
                severity="none",
                evidence={"probes_sent": len(PROBE_PAYLOADS), "signatures_checked": len(self.signatures)},
                tags=["waf", "info"],
            )
            findings.append(finding)
        return findings, endpoints

    async def _detect(self, target: ScanTarget) -> Optional[dict]:
        best_match = None
        best_score = 0
        normal_fingerprint = None
        normal_resp = None
        try:
            normal_resp = await self.request("GET", target.url)
            normal_fingerprint = {
                "status": normal_resp.status_code,
                "headers": dict(normal_resp.headers),
                "body_len": len(normal_resp.text),
            }
        except Exception:
            pass

        if normal_resp and normal_fingerprint:
            for sig in self.signatures:
                score = self._match_signature(sig, normal_fingerprint, normal_resp)
                if score > best_score:
                    best_score = score
                    best_match = sig

            if best_score >= PASSIVE_MIN_CONFIDENCE:
                best_match["confidence"] = best_score
                return best_match

        base_url = target.url.rstrip("/")
        default_headers = {"User-Agent": "Mozilla/5.0"}

        for name, payload in PROBE_PAYLOADS:
            try:
                test_url = f"{base_url}/?q={payload}"
                resp = await self.request("GET", test_url)
                for sig in self.signatures:
                    score = self._match_signature(sig, normal_fingerprint, resp)
                    if score > best_score:
                        best_score = score
                        best_match = sig
            except Exception:
                continue

        for name, payload in COOKIE_PROBE_PAYLOADS:
            try:
                resp = await self.request(
                    "GET", base_url,
                    headers={"Cookie": f"waf_test={payload}"},
                )
                for sig in self.signatures:
                    score = self._match_signature(sig, normal_fingerprint, resp)
                    if score > best_score:
                        best_score = score
                        best_match = sig
            except Exception:
                continue

        for ua in SUSPICIOUS_USER_AGENTS:
            try:
                resp = await self.request("GET", base_url, headers={"User-Agent": ua})
                for sig in self.signatures:
                    score = self._match_signature(sig, normal_fingerprint, resp)
                    if score > best_score:
                        best_score = score
                        best_match = sig
            except Exception:
                continue

        for path in ACL_BYPASS_PATHS:
            try:
                resp = await self.request("GET", f"{base_url}{path}")
                for sig in self.signatures:
                    score = self._match_signature(sig, normal_fingerprint, resp)
                    if score > best_score:
                        best_score = score
                        best_match = sig
            except Exception:
                continue

        if best_match and best_score >= DETECT_MIN_CONFIDENCE:
            best_match["confidence"] = best_score
            return best_match
        return None

    def _match_signature(self, sig: dict, normal: dict, response) -> float:
        score = 0.0
        checks = sig.get("checks", {})
        statuses = checks.get("status_codes", [])
        if response.status_code in statuses:
            score += 0.3

        headers_check = checks.get("headers", {})
        for h, pattern in headers_check.items():
            val = response.headers.get(h, "")
            if re.search(pattern, val, re.I):
                score += 0.25

        body_patterns = checks.get("body", [])
        text = response.text or ""
        for pattern in body_patterns:
            if re.search(pattern, text, re.I):
                score += 0.2

        cookies = checks.get("cookies", {})
        for cookie_name, pattern in cookies.items():
            c_val = response.cookies.get(cookie_name, "")
            if c_val and re.search(pattern, c_val, re.I):
                score += 0.2

        block_score = checks.get("block_score", 0.5)
        if (normal and response.status_code in (403, 406, 429, 503)
                and normal.get("status") == 200):
            score += block_score
        return min(score, 1.0)

    def _select_evasion(self) -> list[str]:
        if not self.evasion_strategies:
            return []
        available = [e for e in self.evasion_strategies if e in EVASION_TECHNIQUES]
        if not available:
            available = list(EVASION_TECHNIQUES.keys())
        count = min(len(available), random.randint(1, 3))
        return random.sample(available, count)

    async def _test_evasion(self, target: ScanTarget, strategies: list[str] = None) -> list[dict]:
        active = strategies if strategies else self.evasion_strategies
        if not active:
            return []
        results = []
        client = await self.get_client()
        for name, payload in PROBE_PAYLOADS:
            try:
                test_url = f"{target.url.rstrip('/')}/?q={payload}"
                normal_resp = await client.get(test_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
                was_blocked = normal_resp.status_code in (403, 406, 429, 503)
                if not was_blocked:
                    continue
                evaded_payload = self.apply_evasion(payload, strategies=active)
                evaded_url = f"{target.url.rstrip('/')}/?q={evaded_payload}"
                evaded_headers = {"User-Agent": "Mozilla/5.0"}
                eh = self.get_evasion_headers()
                if eh:
                    evaded_headers.update(eh)
                evaded_resp = await client.get(evaded_url, headers=evaded_headers, timeout=10)
                if evaded_resp.status_code not in (403, 406, 429, 503):
                    results.append({
                        "probe": name,
                        "original_payload": payload,
                        "evaded_payload": evaded_payload,
                        "original_status": normal_resp.status_code,
                        "evaded_status": evaded_resp.status_code,
                        "success": True,
                    })
                else:
                    results.append({
                        "probe": name,
                        "original_payload": payload,
                        "evaded_payload": evaded_payload,
                        "original_status": normal_resp.status_code,
                        "evaded_status": evaded_resp.status_code,
                        "success": False,
                    })
            except Exception:
                continue
        return results

    def get_evasion_headers(self) -> dict:
        headers = {}
        if "rate_spoofing" in self.evasion_strategies:
            headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
            headers["X-Real-IP"] = headers["X-Forwarded-For"]
        if "header_spoofing" in self.evasion_strategies:
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            headers["Accept-Language"] = random.choice(["en-US", "de-DE", "fr-FR", "ja-JP"])
        return headers

    def apply_evasion(self, payload: str, strategies: list[str] = None) -> str:
        active = strategies if strategies is not None else self.evasion_strategies
        if not active:
            return payload
        for strategy in active:
            if strategy in EVASION_TECHNIQUES:
                payload = EVASION_TECHNIQUES[strategy](payload)
        return payload

    async def cleanup(self):
        await super().cleanup()
