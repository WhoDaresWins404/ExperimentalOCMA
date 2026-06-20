import re
import secrets
from urllib.parse import urlparse, urljoin, parse_qs

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity


@register_scanner(manifest=ScannerManifest(
    name="csrf_scanner",
    category="analysis",
    risk_level="safe",
    estimated_cost=40,
    produces_tag_patterns=["csrf", "xsrf", "token-analysis"],
    produces_endpoint_types=[],
))
class CsrfScanner(BaseScanner):
    name = "csrf_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()

        base_url = target.url.rstrip("/")
        try:
            resp = await client.request("GET", base_url, follow_redirects=True)
            self._stats["requests"] += 1
            body = resp.text or ""
        except Exception:
            return findings, endpoints

        forms = self._extract_forms(body, base_url)

        for form in forms:
            ep = self.make_endpoint(url=form["action"], method=form["method"], discovered_by=self.name)
            endpoints.append(ep)
            token_name = self._find_csrf_token(form)

            if not token_name:
                findings.append(self.make_finding(
                    title="Missing CSRF Token",
                    description=f"Form at {form['action']} has no anti-CSRF token field. State-changing requests may be vulnerable to CSRF.",
                    severity=FindingSeverity.HIGH.value,
                    endpoint=ep,
                    evidence={"form_action": form["action"], "form_method": form["method"], "fields": form["fields"]},
                    confidence=0.7,
                    tags=["csrf", "missing-token"],
                ))
                continue

            token_value = form["fields"].get(token_name, "")
            token_issues = self._analyze_token(token_name, token_value, form["action"])

            if token_issues:
                findings.append(self.make_finding(
                    title=f"CSRF Token Weakness — {token_issues}",
                    description=f"Form at {form['action']} has a CSRF token (`{token_name}`) with weakness: {token_issues}.",
                    severity=FindingSeverity.MEDIUM.value if token_issues == "short token" or token_issues == "static value" else FindingSeverity.HIGH.value,
                    endpoint=ep,
                    evidence={"form_action": form["action"], "token_name": token_name, "token_value": token_value, "issue": token_issues, "fields": form["fields"]},
                    confidence=0.75,
                    tags=["csrf", "token-weakness"],
                ))

            bypass_result = await self._test_bypass(client, form, base_url)
            if bypass_result:
                findings.append(self.make_finding(
                    title="CSRF Token Bypass — Stripping Works",
                    description=f"Form at {form['action']} accepted the request without the CSRF token `{token_name}`.",
                    severity=FindingSeverity.CRITICAL.value,
                    endpoint=ep,
                    evidence={"form_action": form["action"], "method": form["method"], "response_status": bypass_result},
                    confidence=0.85,
                    tags=["csrf", "bypass", "token-stripping"],
                ))

        return findings, endpoints

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        forms = []
        for match in re.finditer(r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>', html, re.I):
            action = urljoin(base_url, match.group(1))
            method = match.group(2).upper()
            fields = self._extract_fields(html, match.end())
            forms.append({"action": action, "method": method, "fields": fields})
        for match in re.finditer(r'<form[^>]*method=["\']([^"\']*)["\'][^>]*action=["\']([^"\']*)["\'][^>]*>', html, re.I):
            action = urljoin(base_url, match.group(2))
            method = match.group(1).upper()
            if not any(f["action"] == action for f in forms):
                fields = self._extract_fields(html, match.end())
                forms.append({"action": action, "method": method, "fields": fields})
        return forms

    @staticmethod
    def _extract_fields(html: str, start: int) -> dict:
        fields = {}
        sub = html[start:start + 2000]
        for m in re.finditer(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\']', sub, re.I):
            fields[m.group(1)] = m.group(2)
        for m in re.finditer(r'<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']*)["\']', sub, re.I):
            fields[m.group(2)] = m.group(1)
        return fields

    CSRF_NAMES = {"csrf", "xsrf", "token", "_token", "csrf_token", "xsrf_token", "csrfmiddlewaretoken", "authenticity_token", "__csrf", "_csrf", "cst"}

    def _find_csrf_token(self, form: dict) -> str | None:
        for name in form["fields"]:
            if name.lower() in self.CSRF_NAMES or "csrf" in name.lower() or "token" in name.lower():
                return name
        return None

    @staticmethod
    def _analyze_token(name: str, value: str, action: str) -> str | None:
        if not value or len(value) < 8:
            return "short token"
        if value in ("1", "true", "ok", name):
            return "static value"
        if re.match(r'^\d+$', value) and len(value) < 12:
            return "numeric — predictable"
        return None

    async def _test_bypass(self, client, form: dict, base_url: str) -> int | None:
        try:
            stripped_fields = {k: v for k, v in form["fields"].items() if "csrf" not in k.lower() and "token" not in k.lower()}
            method = form["method"] if form["method"] in ("POST", "PUT", "DELETE", "PATCH") else "POST"
            origin_resp = await client.request(method, form["action"], data=form["fields"] if method in ("POST",) else None, follow_redirects=False) if method == "POST" else await client.request(method, form["action"], json=stripped_fields, follow_redirects=False)
            self._stats["requests"] += 1
            stripped_resp = await client.request(method, form["action"], data=stripped_fields if method == "POST" else None, follow_redirects=False) if method == "POST" else await client.request(method, form["action"], json=stripped_fields, follow_redirects=False)
            self._stats["requests"] += 1
            if stripped_resp.status_code == origin_resp.status_code and stripped_resp.status_code not in (400, 403, 422, 500):
                return stripped_resp.status_code
        except Exception:
            pass
        return None
