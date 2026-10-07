"""Dependency relationships and reachability summaries."""
import networkx as nx


def build_dependency_graph(dependencies: list[dict], edges: list[tuple[str, str]] | None = None) -> nx.DiGraph:
    graph = nx.DiGraph()
    graph.add_node("__project__", kind="project")
    for dependency in dependencies:
        name = dependency["name"]
        graph.add_node(name, version=dependency.get("version"), direct=dependency.get("direct"))
        if dependency.get("direct") is True:
            graph.add_edge("__project__", name, source=dependency.get("source", "manifest"))
    for parent, child in edges or []:
        graph.add_edge(parent, child, source="provided_lock_data")
    return graph


def summarize_graph(graph: nx.DiGraph) -> dict:
    summary = []
    for node, attrs in graph.nodes(data=True):
        if node == "__project__":
            continue
        try:
            depth = nx.shortest_path_length(graph, "__project__", node)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            depth = None
        summary.append({"name": node, "version": attrs.get("version"), "direct": attrs.get("direct"), "depth": depth})
    return {"nodes": len(summary), "edges": graph.number_of_edges(), "dependencies": summary}
