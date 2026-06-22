import json
import asyncio
from .base import BaseScanner
from .registry import register_scanner
from core.models import ScannerManifest, ScanTarget, FindingSeverity

BATCH_QUERY = """
query {{
    __typename
    __typename
    __typename
    __typename
    __typename
    __typename
    __typename
    __typename
    __typename
    __typename
}}
"""

ALIAS_FRAGMENT = """
fragment AliasedFields on User {{
    id
    username
    email
    role
    ... on Admin {{
        secret
    }}
}}
"""

BATCH_MUTATION = """
mutation {{
    a: createUser(input: {{name: "test1"}}) {{ id }}
    b: createUser(input: {{name: "test2"}}) {{ id }}
    c: createUser(input: {{name: "test3"}}) {{ id }}
    d: createUser(input: {{name: "test4"}}) {{ id }}
    e: createUser(input: {{name: "test5"}}) {{ id }}
}}
"""

DEPTH_QUERY = """
query {{
    user(id: 1) {{
        posts {{
            comments {{
                author {{
                    posts {{
                        comments {{
                            author {{
                                name
                            }}
                        }}
                    }}
                }}
            }}
        }}
    }}
}}
"""

GRAPHIQL_PATHS = [
    "/graphql", "/graphiql", "/api/graphql", "/api/v1/graphql",
    "/gql", "/query", "/api/query",
]


@register_scanner(manifest=ScannerManifest(
    name="graphql_batch_scanner",
    category="exploit",
    risk_level="safe",
    estimated_cost=40,
    produces_tag_patterns=["graphql", "graphql-batching", "graphql-depth", "api-abuse"],
    produces_endpoint_types=[],
))
class GraphQLBatchScanner(BaseScanner):
    name = "graphql_batch_scanner"

    async def scan(self, target: ScanTarget) -> tuple[list, list]:
        findings = []
        endpoints = []
        client = await self.get_client()
        base = target.url.rstrip("/")

        for path in GRAPHIQL_PATHS:
            url = f"{base}{path}"
            for attack_name, query in [
                ("batching", BATCH_QUERY),
                ("alias_mutation", BATCH_MUTATION),
                ("depth_recursion", DEPTH_QUERY),
            ]:
                try:
                    start = asyncio.get_event_loop().time()
                    resp = await client.post(url, json={"query": query.strip()},
                                             headers={"Content-Type": "application/json"})
                    elapsed = asyncio.get_event_loop().time() - start
                    self._stats["requests"] += 1

                    if resp.status_code == 200:
                        ep = self.make_endpoint(url=url, status_code=200, discovered_by=self.name)
                        endpoints.append(ep)
                        data = resp.json()
                        errors = data.get("errors", []) if isinstance(data, dict) else []

                        if attack_name == "batching":
                            findings.append(self.make_finding(
                                title="GraphQL — Batching Attack Surface",
                                description=f"GraphQL endpoint at {url} allows repeated field batching. Response time: {elapsed:.2f}s.",
                                severity=FindingSeverity.MEDIUM.value,
                                endpoint=ep,
                                evidence={"url": url, "elapsed": elapsed, "response_size": len(resp.text)},
                                confidence=0.7,
                                tags=["graphql", "batching", "dos-surface"],
                            ))
                        elif attack_name == "alias_mutation" and not errors:
                            findings.append(self.make_finding(
                                title="GraphQL — Alias Mutation Allowed",
                                description=f"GraphQL endpoint at {url} processed alias mutations ({resp.json().get('data', {})})",
                                severity=FindingSeverity.HIGH.value,
                                endpoint=ep,
                                evidence={"url": url, "response": resp.json() if isinstance(resp.json(), dict) else {}},
                                confidence=0.8,
                                tags=["graphql", "alias-mutation", "batch-mutation"],
                            ))
                        elif attack_name == "depth_recursion" and elapsed > 2.0:
                            findings.append(self.make_finding(
                                title="GraphQL — Deep Recursion / DoS Surface",
                                description=f"Deeply nested query at {url} took {elapsed:.1f}s. Possible DoS via recursive queries.",
                                severity=FindingSeverity.MEDIUM.value,
                                endpoint=ep,
                                evidence={"url": url, "elapsed": elapsed, "depth": 5},
                                confidence=0.6,
                                tags=["graphql", "depth-attack", "dos"],
                            ))
                except Exception:
                    self._stats["errors"] += 1

        return findings, endpoints
