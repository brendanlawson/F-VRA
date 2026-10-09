from f_vra.analysis.package.callgraph import LibraryAnalyzer
from f_vra.analysis.package.summary import build_library_summary
from f_vra.analysis.project.entrypoints import scan_project
from f_vra.analysis.project.project_graph import build_project_graph


def test_package_analysis_builds_callgraph_and_summary():
    analyzer = LibraryAnalyzer()
    graph = analyzer.build_library_graph("tests/fixtures/sample_app")
    summary = build_library_summary(graph, analyzer.index.public_api)

    edges = {(edge.caller.qualified_name, edge.callee.qualified_name) for edge in graph.edges}

    assert ("pkg.lib.public_api", "pkg.lib.Client.fetch") in edges
    assert ("pkg.lib.Client.fetch", "requests.get") in edges
    assert "requests.get" in summary.outer_summary["pkg.lib.public_api"]
    assert "pkg.lib.Client.fetch" in summary.inner_summary["pkg.lib.public_api"]


def test_project_analysis_discovers_entrypoint_and_reachable_usage_only():
    entrypoints = scan_project("tests/fixtures/sample_app")
    graph, usage_index = build_project_graph("tests/fixtures/sample_app")

    assert [entry.entry_type.value for entry in entrypoints] == ["main"]
    assert {node.identity_string for node in usage_index} == {"requests.get"}

    edges = {(edge.caller.qualified_name, edge.callee.qualified_name) for edge in graph.edges}
    assert ("pkg.app.main", "pkg.lib.public_api") in edges
    assert ("pkg.lib.unused_api", "requests.post") not in edges
