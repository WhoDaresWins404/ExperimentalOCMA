import socket
import ssl
from urllib.parse import urlparse

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity


WEAK_CIPHERS = [
    "RC4", "3DES", "DES", "aNULL", "eNULL", "EXPORT", "LOW", "MD5",
    "PSK", "SRP", "CAMELLIA", "SEED", "IDEA",
]

PROTOCOLS = [
    ("SSLv3", ssl.PROTOCOL_SSLv23 if hasattr(ssl, "PROTOCOL_SSLv23") else None),
    ("TLSv1.0", ssl.PROTOCOL_TLSv1 if hasattr(ssl, "PROTOCOL_TLSv1") else None),
    ("TLSv1.1", ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, "PROTOCOL_TLSv1_1") else None),
    ("TLSv1.2", ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, "PROTOCOL_TLSv1_2") else None),
]


@register_scanner(manifest=ScannerManifest(
    name="tls_scanner",
    category="analysis",
    risk_level="safe",
    estimated_cost=20,
    produces_tag_patterns=["tls", "ssl", "certificate", "cipher"],
    produces_endpoint_types=[],
))
class TlsScanner(BaseScanner):
    name = "tls_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []

        parsed = urlparse(target.url)
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        ep = self.make_endpoint(url=f"https://{hostname}:{port}/", type_hint="web_page", discovered_by=self.name)
        endpoints.append(ep)

        cert_info = self._get_certificate(hostname, port)
        if cert_info:
            issues = self._check_cert_issues(cert_info, hostname)
            if issues:
                findings.append(self.make_finding(
                    title="TLS Certificate Issues",
                    description=f"Certificate issues for {hostname}: {', '.join(issues)}",
                    severity=FindingSeverity.HIGH.value,
                    endpoint=ep,
                    evidence={"hostname": hostname, "cert_info": cert_info, "issues": issues},
                    confidence=0.9,
                    tags=["tls", "certificate"],
                ))

        weak_protocols = []
        for name, proto in PROTOCOLS:
            if proto and self._protocol_accepted(hostname, port, proto):
                weak_protocols.append(name)

        if weak_protocols:
            findings.append(self.make_finding(
                title="Weak TLS Protocols Accepted",
                description=f"Server at {hostname}:{port} accepts deprecated protocols: {', '.join(weak_protocols)}.",
                severity=FindingSeverity.MEDIUM.value,
                endpoint=ep,
                evidence={"hostname": hostname, "port": port, "weak_protocols": weak_protocols},
                confidence=0.9,
                tags=["tls", "protocol", "weak"],
            ))

        weak_ciphers = self._detect_weak_ciphers(hostname, port)
        if weak_ciphers:
            findings.append(self.make_finding(
                title="Weak Cipher Suites Accepted",
                description=f"Server at {hostname}:{port} accepts weak ciphers: {', '.join(weak_ciphers[:5])}.",
                severity=FindingSeverity.HIGH.value if "RC4" in str(weak_ciphers) else FindingSeverity.MEDIUM.value,
                endpoint=ep,
                evidence={"hostname": hostname, "port": port, "weak_ciphers": weak_ciphers},
                confidence=0.85,
                tags=["tls", "cipher", "weak"],
            ))

        hsts = await self._check_hsts(hostname, port)
        if hsts is False:
            findings.append(self.make_finding(
                title="HSTS Not Enabled",
                description=f"Server at {hostname} does not include Strict-Transport-Security header.",
                severity=FindingSeverity.LOW.value,
                endpoint=ep,
                evidence={"hostname": hostname},
                confidence=0.8,
                tags=["tls", "hsts"],
            ))

        return findings, endpoints

    @staticmethod
    def _get_certificate(hostname: str, port: int) -> dict | None:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return {
                            "subject": dict(cert.get("subject", [])),
                            "issuer": dict(cert.get("issuer", [])),
                            "version": cert.get("version"),
                            "notBefore": cert.get("notBefore"),
                            "notAfter": cert.get("notAfter"),
                            "serialNumber": cert.get("serialNumber"),
                            "subjectAltName": cert.get("subjectAltName", []),
                        }
        except Exception:
            pass
        return None

    @staticmethod
    def _check_cert_issues(cert: dict, hostname: str) -> list[str]:
        issues = []
        from datetime import datetime
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                if expiry < datetime.utcnow():
                    issues.append("Certificate expired")
                elif (expiry - datetime.utcnow()).days < 30:
                    issues.append(f"Certificate expires soon ({expiry})")
            except ValueError:
                pass
        sans = [s[1] for s in cert.get("subjectAltName", []) if s[0] == "DNS"]
        if sans and hostname not in sans:
            close = [s for s in sans if hostname.replace("www.", "") in s or s.replace("www.", "") in hostname]
            if not close:
                issues.append(f"Hostname mismatch — cert is for {', '.join(sans[:3])}")
        return issues

    @staticmethod
    def _protocol_accepted(hostname: str, port: int, protocol) -> bool:
        try:
            ctx = ssl.SSLContext(protocol)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssock.do_handshake()
                    return True
        except Exception:
            return False

    @staticmethod
    def _detect_weak_ciphers(hostname: str, port: int) -> list[str]:
        found = []
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher and any(w in cipher[0].upper() for w in WEAK_CIPHERS):
                        found.append(cipher[0])
        except Exception:
            pass
        return found

    @staticmethod
    async def _check_hsts(hostname: str, port: int) -> bool | None:
        try:
            import httpx
            async with httpx.AsyncClient(verify=False) as client:
                resp = await client.request("GET", f"https://{hostname}:{port}/", follow_redirects=False, timeout=10)
                hdr = resp.headers.get("strict-transport-security", "")
                return bool(hdr and "max-age" in hdr)
        except Exception:
            return None
