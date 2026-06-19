import re
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode
from uuid import uuid4

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


CONTEXT_REGEXES: list[tuple[str, re.Pattern]] = [
    ("script", re.compile(r'<script[^>]*>.*?{marker}.*?</script>', re.I | re.S)),
    ("attribute_dq", re.compile(r'<[^>]+"{marker}"[^>]*>', re.I | re.S)),
    ("attribute_sq", re.compile(r"<[^>]+'{marker}'[^>]*>", re.I | re.S)),
    ("attribute_unquoted", re.compile(r'<[^>]+={marker}[>\s]', re.I | re.S)),
    ("href", re.compile(r'(?:href|src|action|data)="[^"]*{marker}[^"]*"', re.I | re.S)),
    ("style", re.compile(r'<style[^>]*>.*?{marker}.*?</style>', re.I | re.S)),
    ("comment", re.compile(r'<!--.*?{marker}.*?-->', re.I | re.S)),
    ("json_string", re.compile(r'"{marker}"', re.I | re.S)),
]

COMMON_PARAMS = [
    "q", "s", "search", "query", "id", "page", "p", "lang", "sort",
    "filter", "type", "category", "name", "user", "term", "keyword",
    "file", "path", "url", "next", "redirect", "return", "callback",
    "jsonp", "format", "view", "mode", "action", "msg", "message",
    "error", "text", "output", "debug", "log", "theme", "color",
    "target", "host", "port", "referer", "ref", "source", "site",
    "template", "include", "document", "folder", "page", "style",
]


@register_scanner(manifest=ScannerManifest(
    name="reflection_mapper",
    category="recon",
    risk_level="safe",
    estimated_cost=30,
    produces_tag_patterns=["reflection", "discovery", "parameter"],
))
class ReflectionMapper(BaseScanner):
    @property
    def name(self) -> str:
        return "reflection_mapper"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []

        params = await self._discover_params(target.url, endpoints)
        if not params:
            return findings, endpoints

        base = target.url.split("?")[0].rstrip("/")

        for param_name in params:
            marker = f"SRR_{uuid4().hex[:8]}"
            try:
                resp = await self.request("GET", base, params={param_name: marker})
                contexts = self._detect_context(resp.text, marker)
                header_contexts = self._detect_header_context(dict(resp.headers), marker)

                if contexts:
                    findings.append(self.make_finding(
                        title="Parameter Reflection Found",
                        description=f"Parameter '{param_name}' at {base} reflects in response "
                                    f"body in context: {', '.join(contexts)}",
                        severity="info",
                        endpoint=self.make_endpoint(base, discovered_by=self.name),
                        evidence={"param": param_name, "contexts": contexts, "marker": marker},
                        confidence=1.0,
                        tags=["reflection", "discovery", *contexts],
                    ))

                if header_contexts:
                    findings.append(self.make_finding(
                        title="Parameter Reflection in Response Headers",
                        description=f"Parameter '{param_name}' at {base} reflects in HTTP "
                                    f"response headers: {', '.join(header_contexts)}",
                        severity="medium",
                        endpoint=self.make_endpoint(base, discovered_by=self.name),
                        evidence={"param": param_name, "header_contexts": header_contexts, "marker": marker},
                        confidence=1.0,
                        tags=["reflection", "header", *header_contexts],
                    ))

                if not contexts and not header_contexts:
                    try:
                        resp_post = await self.request("POST", base, data={param_name: marker})
                        contexts = self._detect_context(resp_post.text, marker)
                        if contexts:
                            findings.append(self.make_finding(
                                title="Parameter Reflection (POST body)",
                                description=f"POST parameter '{param_name}' at {base} reflects in "
                                            f"response in context: {', '.join(contexts)}",
                                severity="info",
                                endpoint=self.make_endpoint(base, method="POST", discovered_by=self.name),
                                evidence={"param": param_name, "contexts": contexts, "marker": marker},
                                confidence=0.9,
                                tags=["reflection", "discovery", "post", *contexts],
                            ))
                    except Exception:
                        pass
            except Exception:
                pass

        return findings, endpoints

    def _detect_context(self, body: str, marker: str) -> list[str]:
        if not body or marker not in body:
            return []
        result: list[str] = []
        escaped = re.escape(marker)
        for ctx_name, pattern in CONTEXT_REGEXES:
            pat = re.compile(pattern.pattern.replace("{marker}", escaped), pattern.flags)
            if pat.search(body):
                result.append(ctx_name)
        if not result:
            result.append("html_body")
        return result

    def _detect_header_context(self, headers: dict, marker: str) -> list[str]:
        result: list[str] = []
        for key, value in headers.items():
            if marker in value:
                result.append(f"header:{key}")
        return result

    async def _discover_params(self, url: str, endpoints: list) -> list[str]:
        params: set[str] = set()

        parsed = urlparse(url)
        for p in parse_qs(parsed.query):
            params.add(p)

        for p in COMMON_PARAMS:
            params.add(p)

        try:
            resp = await self.request("GET", url)
            for match in re.finditer(r'<input[^>]*name=["\']([^"\']+)["\']', resp.text, re.I):
                params.add(match.group(1))
            for match in re.finditer(r'<select[^>]*name=["\']([^"\']+)["\']', resp.text, re.I):
                params.add(match.group(1))
            for match in re.finditer(r'<textarea[^>]*name=["\']([^"\']+)["\']', resp.text, re.I):
                params.add(match.group(1))
            for match in re.finditer(r'name=["\']([^"\']+)["\']', resp.text, re.I):
                params.add(match.group(1))
            for match in re.finditer(r'data-[\w-]+=["\'][^"\']*\{[^}]+\}[^"\']*["\']', resp.text, re.I):
                pass
        except Exception:
            pass

        return list(params)
