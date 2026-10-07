from app.tools.dependency_graph import build_dependency_graph, summarize_graph


def test_known_direct_and_transitive_depths():
    graph = build_dependency_graph([{ "name": "a", "version": "1", "direct": True }, { "name": "b", "version": "2", "direct": False }], [("a", "b")])
    items = {item["name"]: item for item in summarize_graph(graph)["dependencies"]}
    assert items["a"]["depth"] == 1
    assert items["b"]["depth"] == 2


def test_unknown_relationship_remains_unreachable():
    graph = build_dependency_graph([{ "name": "x", "version": "1", "direct": False }])
    assert summarize_graph(graph)["dependencies"][0]["depth"] is None
