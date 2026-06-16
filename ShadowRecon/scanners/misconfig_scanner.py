import re
import socket
from urllib.parse import urlparse

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, EndpointType
from core.exceptions import TargetUnreachable


SECURITY_HEADERS = {
    "strict-transport-security": "HTTP Strict Transport Security (HSTS) — prevents protocol downgrade attacks",
    "content-security-policy": "Content Security Policy (CSP) — mitigates XSS and data injection",
    "x-content-type-options": "X-Content-Type-Options — prevents MIME type sniffing",
    "x-frame-options": "X-Frame-Options — prevents clickjacking",
    "x-xss-protection": "X-XSS-Protection — legacy XSS filter",
    "referrer-policy": "Referrer-Policy — controls referrer header leakage",
    "permissions-policy": "Permissions-Policy — restricts browser API access",
    "access-control-allow-origin": "CORS header — controls cross-origin access",
}

COMMON_PORTS = [80, 443, 8080, 8443, 3000, 5000, 9090, 9000, 8000, 3001, 4443, 5432, 3306, 27017, 6379]

DEBUG_PATHS = [
    "/debug", "/debug/", "/debug?source=test",
    "/console", "/console/",
    "/actuator", "/actuator/health", "/actuator/info",
    "/.env", "/.git/config",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php",
    "/status", "/health", "/metrics", "/version",
]

STACK_TRACE_PATTERNS = re.compile(
    r'(?:Traceback \(most recent call last\)|'
    r'at\s+[\w.]+\([\w./]+:\d+\)|'
    r'in\s+[\w.]+\([\w./]+:\d+\)|'
    r'Exception|Error|Warning|Fatal|Parse\s+error|'
    r'Stack trace|Stacktrace|Call\s+stack|'
    r'java\.lang\.\w+Exception|'
    r'SyntaxError|TypeError|ReferenceError|'
    r'SQLSTATE|PDOException|mysqli_error)',
    re.I
)


@register_scanner
class MisconfigScanner(BaseScanner):
    name = "misconfig_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        base_url = target.url.rstrip("/")

        header_eps, header_findings = await self._check_security_headers(target)
        endpoints.extend(header_eps)
        findings.extend(header_findings)

        cors_eps, cors_findings = await self._check_cors(target)
        endpoints.extend(cors_eps)
        findings.extend(cors_findings)

        debug_eps, debug_findings = await self._check_debug_paths(target)
        endpoints.extend(debug_eps)
        findings.extend(debug_findings)

        stack_eps, stack_findings = await self._check_stack_traces(target)
        endpoints.extend(stack_eps)
        findings.extend(stack_findings)

        port_eps, port_findings = await self._check_ports(target)
        endpoints.extend(port_eps)
        findings.extend(port_findings)

        server_eps, server_findings = await self._check_server_info(target)
        endpoints.extend(server_eps)
        findings.extend(server_findings)

        return findings, endpoints

    async def _check_security_headers(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        try:
            resp = await self.request("GET", target.url)
        except Exception:
            return [], []
        ep = self.make_endpoint(
            url=target.url, method="GET", type_hint=EndpointType.WEB_PAGE,
            status_code=resp.status_code,
            content_type=resp.headers.get("content-type", ""),
        )
        endpoints.append(ep)
        present = []
        missing = []
        for header, desc in SECURITY_HEADERS.items():
            val = resp.headers.get(header)
            if val:
                present.append({"header": header, "value": val, "description": desc})
            else:
                missing.append({"header": header, "description": desc})
        if missing:
            findings.append(self.make_finding(
                title=f"Missing Security Headers ({len(missing)}/{len(SECURITY_HEADERS)})",
                description=f"Missing {len(missing)} security headers: {', '.join(h['header'] for h in missing)}",
                severity="medium" if len(missing) > 3 else "low",
                endpoint=ep,
                evidence={"missing": missing, "present": present},
                tags=["headers", "misconfiguration"],
            ))
        if present:
            findings.append(self.make_finding(
                title=f"Security Headers Present ({len(present)}/{len(SECURITY_HEADERS)})",
                description=f"Found {len(present)} security headers: {', '.join(h['header'] for h in present)}",
                severity="none", endpoint=ep,
                evidence={"present": present},
                tags=["headers", "info"],
            ))
        return endpoints, findings

    async def _check_cors(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        try:
            resp = await self.request("GET", target.url, headers={"Origin": "https://evil.com"})
        except Exception:
            return [], []
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")
        if acao == "*":
            ep = self.make_endpoint(
                url=target.url, method="GET", type_hint=EndpointType.WEB_PAGE,
                status_code=resp.status_code, discovered_by="cors_check",
                metadata={"acao": acao, "acac": acac},
            )
            endpoints.append(ep)
            findings.append(self.make_finding(
                title="Permissive CORS Policy: Wildcard Origin",
                description=f"CORS allows all origins (*). Any website can read cross-origin responses.",
                severity="high", endpoint=ep,
                evidence={"access_control_allow_origin": acao,
                          "access_control_allow_credentials": acac},
                tags=["cors", "misconfiguration"],
            ))
        if acao == "https://evil.com":
            ep = self.make_endpoint(
                url=target.url, method="GET", type_hint=EndpointType.WEB_PAGE,
                status_code=resp.status_code, discovered_by="cors_check",
                metadata={"acao": acao, "acac": acac},
            )
            endpoints.append(ep)
            findings.append(self.make_finding(
                title="Permissive CORS Policy: Origin Reflection",
                description=f"CORS reflects arbitrary origins. Sent 'evil.com', got it echoed back in ACAO header.",
                severity="high", endpoint=ep,
                evidence={"sent_origin": "https://evil.com", "received_acao": acao},
                tags=["cors", "misconfiguration"],
            ))
        if acao and acac == "true":
            findings.append(self.make_finding(
                title="CORS with Credentials Enabled",
                description=f"CORS allows credentials with specific origin. Potential for credential-bearing cross-origin attacks.",
                severity="medium",
                evidence={"acao": acao, "acac": acac},
                tags=["cors", "credentials"],
            ))
        return endpoints, findings

    async def _check_debug_paths(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        base_url = target.url.rstrip("/")
        for path in DEBUG_PATHS:
            url = f"{base_url}/{path.lstrip('/')}"
            try:
                resp = await self.request("GET", url)
            except Exception:
                continue
            if resp.status_code not in (404, 403):
                ep = self.make_endpoint(
                    url=url, method="GET", type_hint=EndpointType.HIDDEN_PATH,
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type", ""),
                    metadata={"debug_path": path},
                )
                endpoints.append(ep)
                if "actuator" in path:
                    findings.append(self.make_finding(
                        title=f"Spring Actuator Endpoint: {path}",
                        description=f"Spring Boot actuator endpoint accessible at {url} (HTTP {resp.status_code}). May leak system info.",
                        severity="high", endpoint=ep,
                        evidence={"path": path, "status": resp.status_code},
                        tags=["actuator", "spring", "exposure"],
                    ))
                elif resp.status_code == 200 and "debug" in path:
                    findings.append(self.make_finding(
                        title=f"Debug Endpoint Exposed: {path}",
                        description=f"Debug interface accessible at {url} (HTTP {resp.status_code}).",
                        severity="high", endpoint=ep,
                        evidence={"path": path, "preview": resp.text[:300]},
                        tags=["debug", "exposure"],
                    ))
        return endpoints, findings

    async def _check_stack_traces(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        probes = [
            ("invalid_path", f"{target.url.rstrip('/')}/nonexistent_path_{__import__('uuid').uuid4().hex[:8]}"),
            ("sql_error", f"{target.url.rstrip('/')}/?id=1'"),
            ("json_error", f"{target.url.rstrip('/')}/"),
        ]
        for probe_type, url in probes:
            try:
                resp = await self.request("GET", url)
                if STACK_TRACE_PATTERNS.search(resp.text or ""):
                    ep = self.make_endpoint(
                        url=url, method="GET", type_hint=EndpointType.WEB_PAGE,
                        status_code=resp.status_code,
                        discovered_by="stack_trace_check",
                    )
                    endpoints.append(ep)
                    findings.append(self.make_finding(
                        title="Stack Trace / Error Disclosure",
                        description=f"Application leaked stack trace/debug info when probing {probe_type} at {url}.",
                        severity="high", endpoint=ep,
                        evidence={"probe": probe_type, "preview": resp.text[:500]},
                        tags=["information_disclosure", "stack_trace", "debug"],
                    ))
            except Exception:
                continue
        return endpoints, findings

    async def _check_ports(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        parsed = urlparse(target.url)
        host = parsed.netloc.split(":")[0]
        for port in COMMON_PORTS:
            if parsed.scheme and port == parsed.port:
                continue
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3)
                result = s.connect_ex((host, port))
                s.close()
                if result == 0:
                    ep = self.make_endpoint(
                        url=f"{'https' if port == 443 else 'http'}://{host}:{port}/",
                        method="GET", type_hint=EndpointType.UNKNOWN,
                        discovered_by="port_scan",
                        metadata={"port": port, "service": self._guess_service(port)},
                    )
                    endpoints.append(ep)
                    if port not in (80, 443):
                        findings.append(self.make_finding(
                            title=f"Non-standard Port Open: {port}",
                            description=f"Port {port} ({self._guess_service(port)}) is open on {host}.",
                            severity="medium" if port not in (3000, 5000, 8080, 8443) else "low",
                            endpoint=ep,
                            evidence={"port": port, "service": self._guess_service(port)},
                            tags=["port_scan", "discovery"],
                        ))
            except Exception:
                continue
        return endpoints, findings

    async def _check_server_info(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        try:
            resp = await self.request("GET", target.url)
        except Exception:
            return [], []
        server = resp.headers.get("server", "")
        x_powered = resp.headers.get("x-powered-by", "")
        via = resp.headers.get("via", "")
        ep = self.make_endpoint(
            url=target.url, method="GET", type_hint=EndpointType.WEB_PAGE,
            status_code=resp.status_code,
            metadata={"server": server, "x-powered-by": x_powered, "via": via},
        )
        endpoints.append(ep)
        if server:
            findings.append(self.make_finding(
                title=f"Server Fingerprinted: {server}",
                description=f"Server header reveals: {server}",
                severity="low", endpoint=ep,
                evidence={"server": server},
                tags=["fingerprint", "server"],
            ))
        if x_powered:
            findings.append(self.make_finding(
                title=f"Technology Revealed: {x_powered}",
                description=f"X-Powered-By header reveals: {x_powered}",
                severity="low", endpoint=ep,
                evidence={"x-powered-by": x_powered},
                tags=["fingerprint", "technology"],
            ))
        return endpoints, findings

    @staticmethod
    def _guess_service(port: int) -> str:
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
            443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
            27017: "MongoDB", 6379: "Redis", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 3000: "Node.js/Dev", 5000: "Flask/Dev",
            9090: "HTTP-Alt", 27017: "MongoDB",
        }
        return services.get(port, f"Unknown(TCP-{port})")
