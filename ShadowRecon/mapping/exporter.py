import json

from .graph import EndpointGraph


class GraphExporter:
    def __init__(self, graph: EndpointGraph):
        self.graph = graph

    def export_json(self) -> str:
        data = self.graph.to_json()
        return json.dumps(data, indent=2)

    def export_cytoscape(self) -> str:
        data = self.graph.to_json()
        elements = []
        for node in data.get("nodes", []):
            elements.append({
                "data": {
                    "id": node.get("id"),
                    "label": node.get("label", ""),
                    "type": node.get("node_type", "unknown"),
                    **node.get("metadata", {}),
                }
            })
        for edge in data.get("edges", []):
            elements.append({
                "data": {
                    "id": edge.get("id"),
                    "source": edge.get("source_node", ""),
                    "target": edge.get("target_node", ""),
                    "label": edge.get("label", ""),
                    "type": edge.get("edge_type", "unknown"),
                }
            })
        return json.dumps(elements, indent=2)

    def export_visjs(self) -> dict:
        data = self.graph.to_json()
        nodes = []
        edges = []
        for node in data.get("nodes", []):
            ntype = node.get("node_type", "unknown")
            color_map = {
                "host": "#4CAF50", "endpoint": "#2196F3", "api": "#FF9800",
                "parameter": "#9C27B0", "auth_provider": "#F44336",
                "database": "#795548", "static_asset": "#607D8B",
                "application": "#00BCD4", "unknown": "#9E9E9E",
            }
            is_finding = node.get("metadata", {}).get("is_finding", False)
            nodes.append({
                "id": node.get("id"),
                "label": node.get("label", ""),
                "title": f"<b>{node.get('label', '')}</b><br>Type: {ntype}",
                "color": {"background": "#FFD700", "border": "#FF5722"} if is_finding else color_map.get(ntype, "#9E9E9E"),
                "borderWidth": 2 if is_finding else 1,
                "size": 25 if is_finding else 15,
            })
        for edge in data.get("edges", []):
            edges.append({
                "from": edge.get("source_node", ""),
                "to": edge.get("target_node", ""),
                "label": edge.get("label", ""),
                "arrows": "to",
                "color": {"color": "#90A4AE"},
                "font": {"size": 10, "color": "#B0BEC5"},
            })
        return {"nodes": nodes, "edges": edges}
