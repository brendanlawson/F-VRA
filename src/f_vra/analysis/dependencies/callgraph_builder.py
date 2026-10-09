from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from f_vra.core.models import DependencyGraphArtifact, DependencyRecord


@dataclass(frozen=True)
class DependencyCallgraphBuildResult:
    dependency_report: Path
    resolver: str
    output_dir: Path
    unique_packages: int
    built: int = 0
    skipped: int = 0


def load_dependency_graph(path: Path) -> DependencyGraphArtifact:
    return DependencyGraphArtifact.model_validate_json(path.read_text(encoding="utf-8"))


def node_name(node) -> str:
    return getattr(node, "qualified_name", "") or getattr(node, "function_name", "")


def edge_dict(edge) -> dict:
    return {
        "caller": node_name(edge.caller),
        "callee": node_name(edge.callee),
        "callee_type": "external" if edge.callee.is_external else "internal",
        "edge_type": getattr(edge, "edge_type", "confirmed_static"),
        "confidence": getattr(edge, "confidence", 1.0),
        "resolver": getattr(edge, "resolver", "static"),
        "reason": getattr(edge, "reason", ""),
        "call_expr": getattr(edge, "call_expr", ""),
        "line_number": getattr(edge, "line_number", 0),
    }


def function_metadata(graph) -> list[dict]:
    out: list[dict] = []
    for node in sorted(graph.internal_nodes, key=lambda item: item.qualified_name or item.function_name):
        out.append(
            {
                "name": node.qualified_name or node.function_name,
                "file_path": node.file_path,
                "line_number": node.line_number,
                "module": node.module,
                "scope": node.scope,
                "signature": node.signature,
                "arity": node.arity,
                "source_snippet": node.source_snippet,
            }
        )
    return out


def package_report(record: DependencyRecord, graph, public_api_aliases: dict[str, str] | None = None) -> dict:
    edges_detail = [edge_dict(edge) for edge in graph.edges]
    return {
        "mode": "package",
        "package": record.name,
        "normalized_name": record.normalized_name,
        "version": record.version,
        "root": record.source_path,
        "dependency_source": record.source_file,
        "dependency_source_type": record.source_type,
        "purl": record.purl,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "internal_nodes": len(graph.internal_nodes),
        "external_nodes": len(graph.external_nodes),
        "internal_edges": len(graph.internal_edges),
        "external_edges": len(graph.external_edges),
        "public_api_aliases": public_api_aliases or {},
        "external_targets": sorted({edge.callee.qualified_name for edge in graph.external_edges}),
        "unresolved_calls": graph.metadata.get("unresolved_calls", []),
        "candidate_edges": graph.metadata.get("candidate_edges", []),
        "llm_kept_edges": graph.metadata.get("llm_kept_edges", []),
        "llm_pruned_edges": graph.metadata.get("llm_pruned_edges", []),
        "assignment_type_facts": graph.metadata.get("assignment_type_facts", []),
        "return_type_facts": graph.metadata.get("return_type_facts", []),
        "external_model_facts": graph.metadata.get("external_model_facts", []),
        "function_summaries": graph.metadata.get("function_summaries", {}),
        "function_context_summaries": graph.metadata.get("function_context_summaries", {}),
        "function_type_graphs": graph.metadata.get("function_type_graphs", {}),
        "unresolved_public_exports": graph.metadata.get("unresolved_public_exports", []),
        "skipped_files": graph.metadata.get("skipped_files", []),
        "function_metadata": function_metadata(graph),
        "edges_detail": edges_detail,
        "final_edges_detail": list(edges_detail),
    }


def source_root_for_record(record: DependencyRecord) -> Path | None:
    if not record.source_path.strip():
        return None
    source_path = Path(record.source_path)
    if not source_path.exists():
        return None
    return source_path if source_path.is_dir() else source_path.parent


def build_dependency_callgraphs(
    dependency_report: Path,
    output_dir: Path,
    *,
    limit: int = 0,
) -> DependencyCallgraphBuildResult:
    from f_vra.analysis.package.callgraph import LibraryAnalyzer

    data = load_dependency_graph(dependency_report)
    unique: dict[str, DependencyRecord] = {}
    for dep in data.dependencies:
        key = f"{dep.normalized_name}=={dep.version or dep.specifier}"
        unique.setdefault(key, dep)

    output_dir.mkdir(parents=True, exist_ok=True)
    built = 0
    skipped = 0
    for dep in unique.values():
        if limit and built >= limit:
            break
        root = source_root_for_record(dep)
        if root is None:
            skipped += 1
            continue
        try:
            analyzer = LibraryAnalyzer()
            graph_obj = analyzer.build_library_graph(root)
        except Exception:
            skipped += 1
            continue

        safe_name = dep.normalized_name or dep.name or "package"
        version = dep.version or "unlocked"
        output = output_dir / f"{safe_name}-{version}-callgraph-package.json"
        aliases = analyzer.index.public_api_aliases() if analyzer.index is not None else {}
        output.write_text(
            json.dumps(package_report(dep, graph_obj, aliases), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        built += 1

    return DependencyCallgraphBuildResult(
        dependency_report=dependency_report,
        resolver=data.resolver,
        output_dir=output_dir,
        unique_packages=len(unique),
        built=built,
        skipped=skipped,
    )
