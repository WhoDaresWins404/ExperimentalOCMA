import json
from uuid import uuid4
from typing import Any

import networkx as nx

from core.models import GraphNode, GraphEdge, NodeType, EdgeType, Endpoint, Finding


class EndpointGraph:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.graph = nx.MultiDiGraph()
        self._nodes: dict[str, GraphNode] = {}
        self._edges: list[GraphEdge] = []

    def add_host(self, url: str, metadata: dict = None) -> GraphNode:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc or parsed.hostname or url
        node_id = f"host_{uuid4().hex[:8]}"
        node = GraphNode(
            id=node_id,
            session_id=self.session_id,
            node_type=NodeType.HOST,
            label=host,
            url=f"{parsed.scheme}://{host}" if parsed.scheme else f"https://{host}",
            metadata=metadata or {},
        )
        self.graph.add_node(node_id, **node.model_dump())
        self._nodes[node_id] = node
        return node

    def add_endpoint(self, endpoint: Endpoint) -> GraphNode:
        node_id = f"ep_{uuid4().hex[:8]}"
        ntype = self._map_endpoint_type(endpoint.type)
        node = GraphNode(
            id=node_id,
            session_id=self.session_id,
            node_type=ntype,
            label=endpoint.url.split("/")[-1] or endpoint.url,
            url=endpoint.url,
            metadata={
                "method": endpoint.method,
                "status_code": endpoint.status_code,
                "content_type": endpoint.content_type,
                "discovered_by": endpoint.discovered_by,
                **endpoint.metadata,
            },
        )
        self.graph.add_node(node_id, **node.model_dump())
        self._nodes[node_id] = node
        return node

    def add_finding_node(self, finding: Finding) -> GraphNode:
        node_id = f"finding_{uuid4().hex[:8]}"
        llm_info = {}
        if finding.llm_analysis:
            llm_info = {
                "llm_description": finding.llm_analysis.natural_description[:200],
                "llm_impact": finding.llm_analysis.impact_analysis[:200],
                "llm_model": finding.llm_analysis.model_used,
            }
        node = GraphNode(
            id=node_id,
            session_id=self.session_id,
            node_type=NodeType.ENDPOINT,
            label=finding.title[:50],
            metadata={
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "cvss_score": finding.cvss_score,
                "scanner": finding.scanner_name,
                "finding_id": finding.id,
                "is_finding": True,
                "description": finding.description[:300],
                "remediation": finding.remediation[:300] if finding.remediation else "",
                "confidence": finding.confidence,
                "tags": finding.tags[:5],
                **llm_info,
            },
        )
        self.graph.add_node(node_id, **node.model_dump())
        self._nodes[node_id] = node
        return node

    def add_edge(
        self, source_id: str, target_id: str,
        edge_type: EdgeType, label: str = "", metadata: dict = None,
    ) -> GraphEdge:
        edge_id = f"edge_{uuid4().hex[:8]}"
        edge = GraphEdge(
            id=edge_id,
            session_id=self.session_id,
            source_node=source_id,
            target_node=target_id,
            edge_type=edge_type,
            label=label,
            metadata=metadata or {},
        )
        self.graph.add_edge(source_id, target_id, key=edge_id, **edge.model_dump())
        self._edges.append(edge)
        return edge

    def link_endpoint_to_host(self, endpoint_node: GraphNode, host_node: GraphNode) -> GraphEdge:
        return self.add_edge(
            endpoint_node.id, host_node.id,
            EdgeType.DEPENDS_ON,
            label="hosted_on",
        )

    def link_finding_to_endpoint(self, finding_node: GraphNode, endpoint_node: GraphNode) -> GraphEdge:
        return self.add_edge(
            finding_node.id, endpoint_node.id,
            EdgeType.PROBES_TO,
            label="affects",
            metadata={"finding_severity": finding_node.metadata.get("severity", "none")},
        )

    EXCLUDE_STATUS_CODES = {404, 405, 410, 501}

    def build_from_results(self, endpoints: list[Endpoint], findings: list[Finding], target_url: str):
        host_node = self.add_host(target_url)
        for ep in endpoints:
            if ep.status_code and ep.status_code in self.EXCLUDE_STATUS_CODES:
                continue
            ep_node = self.add_endpoint(ep)
            self.link_endpoint_to_host(ep_node, host_node)
        for finding in findings:
            finding_node = self.add_finding_node(finding)
            linked = False
            if finding.endpoint_id:
                for nid, node in self._nodes.items():
                    if (node.metadata.get("status_code") is not None and
                        node.metadata.get("discovered_by") == finding.scanner_name):
                        self.link_finding_to_endpoint(finding_node, node)
                        linked = True
                        break
            if not linked:
                self.link_finding_to_endpoint(finding_node, host_node)
                finding_node.metadata["orphan"] = True
        related = self._find_related_endpoints(endpoints)
        for ep_a, ep_b, rel_type, label in related:
            a_id = next((n.id for n in self._nodes.values() if n.url == ep_a.url), None)
            b_id = next((n.id for n in self._nodes.values() if n.url == ep_b.url), None)
            if a_id and b_id:
                self.add_edge(a_id, b_id, rel_type, label=label)

    def _find_related_endpoints(self, endpoints: list[Endpoint]) -> list[tuple]:
        from urllib.parse import urlparse
        related = []
        for i, a in enumerate(endpoints):
            for j, b in enumerate(endpoints):
                if i >= j:
                    continue
                parsed_a = urlparse(a.url)
                parsed_b = urlparse(b.url)
                if parsed_a.path and parsed_b.path:
                    if parsed_b.path.startswith(parsed_a.path.rstrip("/") + "/"):
                        related.append((a, b, EdgeType.HTTP_LINKS_TO,
                                      f"{a.url} -> {b.url}"))
                    elif parsed_a.path.startswith(parsed_b.path.rstrip("/") + "/"):
                        related.append((b, a, EdgeType.HTTP_LINKS_TO,
                                      f"{b.url} -> {a.url}"))
        return related

    def _map_endpoint_type(self, ep_type: Any) -> NodeType:
        type_map = {
            "api_rest": NodeType.API,
            "api_graphql": NodeType.API,
            "api_soap": NodeType.API,
            "web_page": NodeType.ENDPOINT,
            "static_asset": NodeType.STATIC_ASSET,
            "admin_panel": NodeType.ENDPOINT,
            "backup_file": NodeType.ENDPOINT,
            "hidden_path": NodeType.ENDPOINT,
            "auth_provider": NodeType.AUTH_PROVIDER,
            "database": NodeType.DATABASE,
        }
        val = ep_type.value if hasattr(ep_type, "value") else str(ep_type)
        return type_map.get(val, NodeType.UNKNOWN)

    def to_json(self) -> dict:
        nodes_data = []
        for nid, data in self.graph.nodes(data=True):
            nodes_data.append(dict(data) if data else {"id": nid})
        edges_data = []
        for u, v, k, data in self.graph.edges(data=True, keys=True):
            edges_data.append(dict(data) if data else {"source": u, "target": v, "key": k})
        return {"nodes": nodes_data, "edges": edges_data}

    def to_graphml(self) -> str:
        import io
        out = io.StringIO()
        nx.write_graphml(self.graph, out)
        return out.getvalue()

    def get_nodes_list(self) -> list[GraphNode]:
        return list(self._nodes.values())

    def get_edges_list(self) -> list[GraphEdge]:
        return self._edges
