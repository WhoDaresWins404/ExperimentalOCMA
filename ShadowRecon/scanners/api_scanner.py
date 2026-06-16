import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, EndpointType


API_WORDLIST_PATH = Path(__file__).parent.parent / "data" / "wordlists" / "api_paths.txt"

GRAPHQL_PROBES = [
    "/graphql", "/graphql/console", "/graphiql", "/v1/graphql",
    "/v2/graphql", "/api/graphql", "/gql",
]

SWAGGER_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/api/swagger.json",
    "/swagger.yaml", "/swagger/v1/swagger.yaml",
    "/openapi.json", "/api/openapi.json", "/docs", "/api/docs",
]

API_PATTERNS = re.compile(
    r'(?:api|v[0-9]+|rest|graphql|soap|json|xml)/'
    r'[\w\-./]+|'
    r'["\'](/[\w\-./]*(?:api|v[0-9]+|rest)[\w\-./]*)["\']|'
    r'(?:fetch|axios|ajax|getJSON|\.get|\.post|\.put|\.delete)\s*\(\s*["\']([^"\']+)["\']',
    re.I
)


@register_scanner
class ApiScanner(BaseScanner):
    name = "api_scanner"

    def __init__(self, config, session_id, waf_state=None):
        super().__init__(config, session_id, waf_state)
        self.wordlist = self._load_wordlist()

    def _load_wordlist(self) -> list[str]:
        path = API_WORDLIST_PATH
        if not path.exists():
            return self._default_wordlist()
        with open(path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]

    @staticmethod
    def _default_wordlist() -> list[str]:
        return [
            "api", "api/v1", "api/v2", "api/v3", "api/rest", "api/users",
            "api/login", "api/register", "api/auth", "api/token", "api/oauth",
            "api/health", "api/status", "api/metrics", "api/config",
            "api/admin", "api/search", "api/query", "api/mutation",
            "v1", "v2", "rest", "graphql", "swagger.json", "openapi.json",
            "health", "status", "metrics", "version", "info",
            ".well-known/openid-configuration", ".well-known/security.txt",
        ]

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        base_url = target.url.rstrip("/")

        seen_urls = set()
        common_paths = self.wordlist + GRAPHQL_PROBES + SWAGGER_PATHS

        for path in common_paths:
            url = f"{base_url}/{path.lstrip('/')}"
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                resp = await self.request("GET", url)
            except Exception:
                continue
            ep_type = self._classify_endpoint(url, resp)
            metadata = {"response_preview": resp.text[:500], "content_type": resp.headers.get("content-type", "")}
            ep = self.make_endpoint(
                url=url, method="GET", type_hint=ep_type,
                status_code=resp.status_code, content_type=resp.headers.get("content-type"),
                response_body=resp.text, metadata=metadata,
            )
            endpoints.append(ep)
            finding = self._analyze_response(ep, resp)
            if finding:
                findings.append(finding)
            if resp.status_code == 200 and ep_type in (EndpointType.API_REST, EndpointType.API_GRAPHQL):
                deeper = await self._discover_deeper(base_url, path, seen_urls)
                for dep_ep in deeper:
                    endpoints.append(dep_ep)

        js_endpoints = await self._scan_js_for_endpoints(target)
        for ep in js_endpoints:
            if ep.url not in seen_urls:
                seen_urls.add(ep.url)
                endpoints.append(ep)

        return findings, endpoints

    def _classify_endpoint(self, url: str, response) -> EndpointType:
        path = urlparse(url).path.lower()
        ct = (response.headers.get("content-type", "") or "").lower()
        if "graphql" in path or "graphiql" in path:
            return EndpointType.API_GRAPHQL
        if "swagger" in path or "openapi" in path or "docs" in path:
            return EndpointType.API_REST
        if "api" in path or "/v1/" in path or "/v2/" in path or "/rest/" in path:
            return EndpointType.API_REST
        if "json" in ct or "xml" in ct:
            return EndpointType.API_REST
        if "soap" in ct or "soap" in path:
            return EndpointType.API_SOAP
        if "admin" in path or "login" in path or "auth" in path:
            return EndpointType.AUTH_PROVIDER
        return EndpointType.UNKNOWN

    def _analyze_response(self, ep: Endpoint, resp) -> Finding | None:
        ct = resp.headers.get("content-type", "")
        text = resp.text
        if resp.status_code == 200:
            if "application/json" in ct:
                try:
                    data = json.loads(text)
                    if isinstance(data, list):
                        return self.make_finding(
                            title=f"API Collection Endpoint: {ep.url}",
                            description=f"REST API endpoint returning JSON array ({len(data)} items).",
                            severity="none", endpoint=ep,
                            evidence={"item_count": len(data), "sample": str(data[:2])[:500]},
                            tags=["api", "rest"],
                        )
                    keys = list(data.keys())[:10]
                    return self.make_finding(
                        title=f"API Object Endpoint: {ep.url}",
                        description=f"REST API endpoint returning JSON object. Keys: {', '.join(keys)}",
                        severity="none", endpoint=ep,
                        evidence={"keys": keys, "has_data": len(data) > 0},
                        tags=["api", "rest"],
                    )
                except json.JSONDecodeError:
                    pass
            if "xml" in ct:
                return self.make_finding(
                    title=f"XML/SOAP Endpoint: {ep.url}",
                    description="Endpoint returning XML data — potential SOAP/XML-RPC service.",
                    severity="none", endpoint=ep,
                    tags=["api", "xml", "soap"],
                )
        if resp.status_code in (401, 403):
            return self.make_finding(
                title=f"Authenticated Endpoint: {ep.url}",
                description=f"Endpoint requires authentication (HTTP {resp.status_code}).",
                severity="low", endpoint=ep,
                evidence={"status_code": resp.status_code, "www_auth": resp.headers.get("www-authenticate", "")},
                tags=["api", "auth"],
            )
        return None

    async def _discover_deeper(self, base_url: str, parent_path: str, seen: set) -> list:
        deeper = []
        parent = parent_path.rstrip("/")
        suffixes = ["/users", "/admin", "/config", "/status", "/health", "/info", "/docs"]
        for suffix in suffixes:
            url = f"{base_url}/{parent.lstrip('/')}{suffix}"
            if url in seen:
                continue
            seen.add(url)
            try:
                resp = await self.request("GET", url)
            except Exception:
                continue
            if resp.status_code != 404:
                ep = self.make_endpoint(
                    url=url, method="GET", type_hint=EndpointType.API_REST,
                    status_code=resp.status_code,
                    content_type=resp.headers.get("content-type"),
                )
                deeper.append(ep)
        return deeper

    async def _scan_js_for_endpoints(self, target: ScanTarget) -> list[Endpoint]:
        endpoints = []
        base_url = target.url.rstrip("/")
        try:
            resp = await self.request("GET", base_url)
        except Exception:
            return endpoints
        if "text/html" not in (resp.headers.get("content-type", "")):
            return endpoints

        matches = API_PATTERNS.findall(resp.text)
        for match in matches:
            path = match if isinstance(match, str) else match[0] or match[1] or match[2]
            if not path or path.startswith("#") or path.startswith("//"):
                continue
            if path.startswith("http"):
                url = path
            elif path.startswith("/"):
                parsed = urlparse(base_url)
                url = f"{parsed.scheme}://{parsed.netloc}{path}"
            else:
                url = urljoin(base_url, path)
            if not self.is_valid_url(url):
                continue
            endpoints.append(self.make_endpoint(
                url=url, method="GET", type_hint=EndpointType.API_REST,
                discovered_by="js_parser",
                metadata={"source": "js_analysis"},
            ))
        return endpoints
