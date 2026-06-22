import json
from urllib.parse import urljoin
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

OPENAPI_PATHS = [
    "/openapi.json", "/swagger.json", "/api/openapi.json",
    "/api/swagger.json", "/api/v1/openapi.json", "/api/v1/swagger.json",
    "/api-docs", "/api/docs", "/swagger/v1/swagger.json",
    "/openapi/v1/openapi.json", "/spec.json", "/api/spec.json",
    "/v1/api-docs", "/api/v1/api-docs",
]


@register_scanner(manifest=ScannerManifest(
    name="openapi_scanner",
    category="discovery",
    risk_level="safe",
    estimated_cost=20,
    produces_tag_patterns=["openapi", "swagger", "api-spec"],
    produces_endpoint_types=["api"],
))
class OpenApiScanner(BaseScanner):
    name = "openapi_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        for rel_path in OPENAPI_PATHS:
            url = urljoin(base, rel_path)
            try:
                resp = await client.get(url, follow_redirects=True)
                self._stats["requests"] += 1
                if resp.status_code != 200:
                    continue
                body = resp.text or ""
                spec = None
                try:
                    spec = json.loads(body) if body.startswith("{") else None
                except (json.JSONDecodeError, ValueError):
                    continue
                if not spec or not isinstance(spec, dict):
                    continue
                if "openapi" in spec or "swagger" in spec:
                    ep = self.make_endpoint(url=url, status_code=200, discovered_by=self.name)
                    endpoints.append(ep)
                    info = spec.get("info", {})
                    paths = list(spec.get("paths", {}).keys())[:20]

                    findings.append(self.make_finding(
                        title=f"OpenAPI/Swagger Specification Exposed",
                        description=f"OpenAPI/Swagger spec found at {url}. Version: {spec.get('openapi', spec.get('swagger', 'unknown'))}. "
                                    f"Title: {info.get('title', 'N/A')}. Paths discovered: {len(spec.get('paths', {}))}",
                        severity=FindingSeverity.MEDIUM.value,
                        endpoint=ep,
                        evidence={
                            "url": url,
                            "version": spec.get("openapi", spec.get("swagger", "")),
                            "title": info.get("title", ""),
                            "paths_sample": paths,
                            "endpoint_count": len(spec.get("paths", {})),
                        },
                        confidence=0.95,
                        tags=["openapi", "api-spec", "information-disclosure"],
                    ))

                    paths_found = spec.get("paths", {})
                    for path, methods in paths_found.items():
                        for method in methods:
                            if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                                full_url = urljoin(base, path.lstrip("/"))
                                ep2 = self.make_endpoint(url=full_url, discovered_by=self.name)
                                if ep2 not in endpoints:
                                    endpoints.append(ep2)
            except Exception:
                self._stats["errors"] += 1

        return findings, endpoints
