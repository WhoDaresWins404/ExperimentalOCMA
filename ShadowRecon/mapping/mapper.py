from .graph import EndpointGraph
from core.models import Endpoint, Finding


class Mapper:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.graph = EndpointGraph(session_id)

    def process_results(self, endpoints: list[Endpoint], findings: list[Finding], target_url: str) -> EndpointGraph:
        self.graph.build_from_results(endpoints, findings, target_url)
        return self.graph

    def get_graph_json(self) -> dict:
        return self.graph.to_json()

    def get_graph_nodes(self) -> list:
        return self.graph.get_nodes_list()

    def get_graph_edges(self) -> list:
        return self.graph.get_edges_list()
