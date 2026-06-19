import statistics
import time
import re
from collections import Counter
from urllib.parse import urlparse

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, EndpointType, ScannerManifest
from core.exceptions import WAFDetected


@register_scanner(manifest=ScannerManifest(
    name="anomaly_detector",
    category="analysis",
    risk_level="safe",
    estimated_cost=15,
    produces_tag_patterns=["anomaly", "timing", "behavior"],
))
class AnomalyDetector(BaseScanner):
    name = "anomaly_detector"

    def __init__(self, config, session_id, waf_state=None, **kwargs):
        super().__init__(config, session_id, waf_state, **kwargs)
        self._timings: list[float] = []
        self._status_codes: list[int] = []
        self._response_sizes: list[int] = []
        self._requests_log: list[dict] = []

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        base_url = target.url.rstrip("/")

        timing_eps, timing_findings = await self._check_response_timing(target)
        endpoints.extend(timing_eps)
        findings.extend(timing_findings)

        status_eps, status_findings = await self._check_status_anomalies(target)
        endpoints.extend(status_eps)
        findings.extend(status_findings)

        cookie_eps, cookie_findings = await self._check_cookie_anomalies(target)
        endpoints.extend(cookie_eps)
        findings.extend(cookie_findings)

        tls_eps, tls_findings = await self._check_tls_fingerprint(target)
        endpoints.extend(tls_eps)
        findings.extend(tls_findings)

        content_eps, content_findings = await self._check_content_anomalies(target)
        endpoints.extend(content_eps)
        findings.extend(content_findings)

        return findings, endpoints

    async def _check_response_timing(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        timings = []
        n_requests = 10

        for _ in range(n_requests):
            try:
                start = time.perf_counter()
                await self.request("GET", target.url)
                elapsed = (time.perf_counter() - start) * 1000
                timings.append(elapsed)
            except Exception:
                continue

        if len(timings) < 3:
            return [], []

        mean = statistics.mean(timings)
        stdev = statistics.stdev(timings) if len(timings) > 1 else 0
        cv = stdev / mean if mean > 0 else 0

        if cv > 0.5:
            ep = self.make_endpoint(
                url=target.url, method="GET", type_hint=EndpointType.WEB_PAGE,
                discovered_by="timing_analysis",
                metadata={"mean_ms": round(mean, 2), "stdev_ms": round(stdev, 2), "cv": round(cv, 3)},
            )
            endpoints.append(ep)
            findings.append(self.make_finding(
                title="High Response Time Variance",
                description=f"Response times show high variance (CV={cv:.3f}). "
                            f"Mean: {mean:.0f}ms, StdDev: {stdev:.0f}ms across {len(timings)} requests. "
                            "May indicate rate limiting, WAF dynamic scoring, or resource contention.",
                severity="medium" if cv > 1.0 else "low",
                endpoint=ep,
                evidence={"timings_ms": [round(t, 2) for t in timings],
                          "mean_ms": round(mean, 2), "stdev_ms": round(stdev, 2),
                          "cv": round(cv, 3)},
                tags=["anomaly", "timing"],
            ))

        if mean > 5000:
            ep = self.make_endpoint(
                url=target.url, method="GET", type_hint=EndpointType.WEB_PAGE,
                discovered_by="timing_analysis",
            )
            endpoints.append(ep)
            findings.append(self.make_finding(
                title="Slow Response Times",
                description=f"Average response time is {mean:.0f}ms. May indicate server performance issues or request processing delays.",
                severity="low", endpoint=ep,
                evidence={"mean_ms": round(mean, 2)},
                tags=["anomaly", "performance"],
            ))

        return endpoints, findings

    async def _check_status_anomalies(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        statuses = []

        paths = ["/", "/admin", "/api", "/test", "/.env", "/login", "/status"]
        for path in paths:
            url = f"{target.url.rstrip('/')}/{path.lstrip('/')}"
            try:
                resp = await self.request("GET", url)
                statuses.append(resp.status_code)
            except Exception:
                continue

        if not statuses:
            return [], []

        counter = Counter(statuses)
        unique_count = len(counter)

        if unique_count == 1 and 200 in counter:
            ep = self.make_endpoint(
                url=target.url, method="GET", type_hint=EndpointType.WEB_PAGE,
                discovered_by="status_analysis",
            )
            endpoints.append(ep)
            findings.append(self.make_finding(
                title="Uniform 200 Responses — Possible WAF Bypass or Catch-All",
                description=f"All {len(statuses)} requests returned HTTP 200. The server may have a catch-all handler "
                            "or WAF may be transparently blocking and returning fake 200 pages.",
                severity="medium", endpoint=ep,
                evidence={"paths_tested": paths, "status_counts": dict(counter)},
                tags=["anomaly", "waf", "status_code"],
            ))

        if 403 in counter and counter[403] > len(statuses) * 0.5:
            ep = self.make_endpoint(
                url=target.url, method="GET", type_hint=EndpointType.WEB_PAGE,
                discovered_by="status_analysis",
            )
            endpoints.append(ep)
            findings.append(self.make_finding(
                title="High Rate of 403 Forbidden Responses",
                description=f"{counter[403]}/{len(statuses)} requests returned 403. WAF or IP blocking likely active.",
                severity="high", endpoint=ep,
                evidence={"status_counts": dict(counter), "paths_tested": paths},
                tags=["anomaly", "waf", "blocking"],
            ))

        return endpoints, findings

    async def _check_cookie_anomalies(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []

        try:
            resp = await self.request("GET", target.url)
        except Exception:
            return [], []

        cookies = resp.headers.get_all("set-cookie") if hasattr(resp.headers, "get_all") else \
                  [resp.headers.get("set-cookie", "")]

        if not cookies or all(not c for c in cookies):
            return [], []

        ep = self.make_endpoint(
            url=target.url, method="GET", type_hint=EndpointType.WEB_PAGE,
            status_code=resp.status_code,
            discovered_by="cookie_analysis",
        )
        endpoints.append(ep)

        for cookie_str in cookies:
            if not cookie_str:
                continue
            issues = []
            if "Secure" not in cookie_str:
                issues.append("missing Secure flag")
            if "HttpOnly" not in cookie_str:
                issues.append("missing HttpOnly flag")
            if "SameSite" not in cookie_str:
                issues.append("missing SameSite attribute")
            if not re.search(r'SameSite=(Strict|Lax)', cookie_str, re.I):
                pass
            if issues:
                name = cookie_str.split("=")[0]
                findings.append(self.make_finding(
                    title=f"Insecure Cookie: {name}",
                    description=f"Cookie '{name}' has security issues: {', '.join(issues)}",
                    severity="low", endpoint=ep,
                    evidence={"cookie": cookie_str, "issues": issues},
                    tags=["cookie", "anomaly"],
                ))

        return endpoints, findings

    async def _check_tls_fingerprint(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []

        try:
            resp = await self.request("GET", target.url)
        except Exception:
            return [], []

        server = resp.headers.get("server", "").lower()
        ep = self.make_endpoint(
            url=target.url, method="GET", type_hint=EndpointType.WEB_PAGE,
            status_code=resp.status_code,
            discovered_by="tls_fingerprint",
        )
        endpoints.append(ep)

        if not server:
            return endpoints, findings

        known_servers = {
            "cloudflare": "Cloudflare CDN/WAF",
            "akamai": "Akamai CDN",
            "nginx": "Nginx",
            "apache": "Apache HTTP Server",
            "iis": "Microsoft IIS",
            "openresty": "OpenResty (Nginx + Lua)",
            "gunicorn": "Gunicorn (Python WSGI)",
            "wsgi": "Python WSGI Server",
            "caddy": "Caddy Server",
            "traefik": "Traefik Proxy",
            "envoy": "Envoy Proxy",
        }

        detected = [v for k, v in known_servers.items() if k in server]
        if detected:
            findings.append(self.make_finding(
                title=f"Server Technology Identified: {', '.join(detected)}",
                description=f"Server header reveals: {resp.headers.get('server')}",
                severity="info", endpoint=ep,
                evidence={"server_header": resp.headers.get("server")},
                tags=["fingerprint", "tls", "server"],
            ))

        return endpoints, findings

    async def _check_content_anomalies(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []

        base_url = target.url.rstrip("/")
        sizes = []
        for path in ["/", "/api", "/admin", "/login", "/test"]:
            url = f"{base_url}/{path.lstrip('/')}"
            try:
                resp = await self.request("GET", url)
                sizes.append(len(resp.text or ""))
            except Exception:
                continue

        if len(sizes) < 3:
            return [], []

        if len(set(sizes)) == 1 and sizes[0] > 0:
            ep = self.make_endpoint(
                url=base_url, method="GET", type_hint=EndpointType.WEB_PAGE,
                discovered_by="content_analysis",
            )
            endpoints.append(ep)
            findings.append(self.make_finding(
                title="Identical Response Sizes — Possible WAF Block Page",
                description=f"All {len(sizes)} different paths returned identical response size ({sizes[0]} bytes). "
                            "WAF may be returning a generic block page for all requests.",
                severity="high", endpoint=ep,
                evidence={"response_sizes": sizes, "paths_tested": ["/", "/api", "/admin", "/login", "/test"]},
                tags=["anomaly", "waf", "content"],
            ))

        return endpoints, findings
