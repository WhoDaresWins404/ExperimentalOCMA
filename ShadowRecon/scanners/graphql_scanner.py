import json
from typing import Optional

from .base import BaseScanner
from .registry import register_scanner
from core.models import ScanTarget, Endpoint, Finding, ScannerManifest


INTROSPECTION_QUERY = """
query {
  __schema {
    types {
      name
      fields { name type { name kind } }
    }
  }
}
"""

SUGGESTION_QUERIES = [
    ("query { __typename }", "__typename"),
    ("{ user(id: 1) { id name email password } }", "password"),
    ("{ users { id name email password } }", "password"),
    ('mutation { login(username: "admin", password: "admin") { token } }', "token"),
]


@register_scanner(manifest=ScannerManifest(
    name="graphql_scanner",
    category="discovery",
    risk_level="safe",
    estimated_cost=30,
    produces_tag_patterns=["graphql", "api"],
))
class GraphQLScanner(BaseScanner):
    @property
    def name(self) -> str:
        return "graphql_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list[Finding], list[Endpoint]]:
        findings: list[Finding] = []
        endpoints: list[Endpoint] = []
        graphql_urls = self._find_graphql_endpoints(target.url)

        for gql_url in graphql_urls:
            seen = await self._try_introspection(gql_url, findings)
            await self._try_suggestions(gql_url, findings)

        return findings, endpoints

    def _find_graphql_endpoints(self, base_url: str) -> list[str]:
        candidates = [
            "/graphql", "/v1/graphql", "/v2/graphql", "/api/graphql",
            "/gql", "/query", "/api", "/graph", "/playground",
        ]
        base = base_url.rstrip("/")
        results = []
        for path in candidates:
            results.append(f"{base}{path}")
        return results

    async def _try_introspection(self, url: str, findings: list[Finding]):
        try:
            resp = await self.request("POST", url, json={"query": INTROSPECTION_QUERY}, timeout=15)
            data = resp.json()
            if "data" in data and "__schema" in data["data"]:
                schema = data["data"]["__schema"]
                type_names = [t["name"] for t in schema.get("types", []) if t.get("name")]
                has_sensitive = any("password" in t.lower() or "secret" in t.lower() for t in type_names)
                findings.append(self.make_finding(
                    title="GraphQL Introspection Enabled",
                    description=f"GraphQL endpoint at {url} has introspection enabled. "
                                f"Schema reveals {len(type_names)} types.",
                    severity="high" if has_sensitive else "medium",
                    endpoint=self.make_endpoint(url, method="POST", discovered_by=self.name),
                    evidence={"schema_types": type_names[:30], "has_sensitive_types": has_sensitive},
                    confidence=1.0,
                    tags=["graphql", "introspection"],
                ))
        except Exception:
            pass

    async def _try_suggestions(self, url: str, findings: list[Finding]):
        for query, indicator in SUGGESTION_QUERIES:
            try:
                resp = await self.request("POST", url, json={"query": query}, timeout=15)
                data = resp.json()
                body = json.dumps(data).lower()
                if indicator in body:
                    findings.append(self.make_finding(
                        title=f"GraphQL Sensitive Data Exposure",
                        description=f"Query '{query[:60]}...' returned data containing '{indicator}'.",
                        severity="high",
                        endpoint=self.make_endpoint(url, method="POST", discovered_by=self.name),
                        evidence={"query": query, "response_snippet": json.dumps(data)[:300]},
                        confidence=0.8,
                        tags=["graphql", "data-exposure"],
                    ))
            except Exception:
                pass
