from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any, Mapping, Sequence, Set

from f_vra.core.models import (
    AnalysisFingerprint,
    EntryPointType,
    LibrarySummary,
    PackageIdentity,
    PackageSummaryArtifact,
    ProjectGraphArtifact,
    ProjectIdentity,
    ReachabilityPath,
    ScanReport,
    ScanResult,
    Verdict,
)
from f_vra.analysis.package.callgraph import LibraryAnalyzer
from f_vra.analysis.package.summary import (
    apply_public_api_aliases,
    build_library_summary,
    filter_verdict_affecting_warnings,
    is_verdict_noise_symbol,
)
from f_vra.analysis.project.project_graph import build_project_graph
from f_vra.reachability.engine import ReachabilityQueryEngine
from f_vra.storage.client import ClientCache
from f_vra.runtime.conda import RuntimeEnvironment, RuntimePackage


@dataclass
class TransitiveReachabilityResult:
    project: Path
    verdict: Verdict
    vulnerable_targets: list[str]
    hit_set: list[str] = field(default_factory=list)
    paths: list[ReachabilityPath] = field(default_factory=list)
    usage_index: list[str] = field(default_factory=list)
    loaded_summaries: list[str] = field(default_factory=list)
    used_summaries: list[str] = field(default_factory=list)
    unresolved_targets: list[str] = field(default_factory=list)
    unresolved_target_related: list[str] = field(default_factory=list)
    unresolved_unrelated: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    analysis_warnings: dict[str, Any] = field(default_factory=dict)
    query_time_ms: float = 0.0

    def to_dict(self, *, explain: bool = True) -> dict[str, Any]:
        paths = [
            {
                "project_api": path.project_api,
                "target": path.vulnerable_target,
                "path": path.tpl_chain,
                "used_summaries": path.used_summaries,
            }
            for path in self.paths
        ]
        if not explain and paths:
            paths = paths[:1]
        return {
            "project": str(self.project),
            "verdict": self.verdict.value,
            "vulnerable_targets": self.vulnerable_targets,
            "hit_set": self.hit_set,
            "paths": paths,
            "usage_index": self.usage_index,
            "loaded_summaries": self.loaded_summaries,
            "used_summaries": self.used_summaries,
            "unresolved_targets": self.unresolved_targets,
            "unresolved_target_related": self.unresolved_target_related,
            "unresolved_unrelated": self.unresolved_unrelated,
            "entry_points": self.entry_points,
            "analysis_warnings": self.analysis_warnings,
            "query_time_ms": self.query_time_ms,
        }


def _edge_rows(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = report.get("final_edges_detail") or report.get("edges_detail") or []
    return [row for row in rows if row.get("caller") and row.get("callee")]


def _matches_qualified_suffix(value: str, suffix: str) -> bool:
    return value == suffix or value.endswith(f".{suffix}")


def _root_module(dotted: str) -> str:
    return dotted.split(".", 1)[0] if dotted else ""


def _leaf_name(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1] if dotted else ""


def _target_roots(targets: Set[str]) -> set[str]:
    roots: set[str] = set()
    for target in targets:
        parts = [part for part in str(target or "").split(".") if part]
        if not parts:
            continue
        roots.add(parts[0])
        if parts[0] == "src" and len(parts) > 1:
            roots.add(parts[1])
    return roots


def _target_related_symbol(
    symbol: str,
    targets: Set[str],
    summary_roots: set[str],
) -> bool:
    symbol = str(symbol or "").strip()
    if not symbol:
        return False
    symbol_root = _root_module(symbol)
    symbol_leaf = _leaf_name(symbol)
    target_roots = _target_roots(targets)
    for target in targets:
        target = str(target or "").strip()
        if not target:
            continue
        if _matches_qualified_suffix(symbol, target) or _matches_qualified_suffix(target, symbol):
            return True
        if symbol_leaf and symbol_leaf == _leaf_name(target) and ("." not in symbol or "." not in target):
            return True
    return False


def _usage_roots(usage_index: Sequence[Any]) -> set[str]:
    roots: set[str] = set()
    for item in usage_index:
        identity = getattr(item, "identity_string", item)
        root = _root_module(str(identity or ""))
        if root:
            roots.add(root)
    return roots


def _usage_identities(usage_index: Sequence[Any]) -> list[str]:
    out: list[str] = []
    for item in usage_index:
        identity = getattr(item, "identity_string", item)
        text = str(identity or "").strip()
        if text:
            out.append(text)
    return out


def _potential_usage_symbols(graph: Any) -> set[str]:
    out: set[str] = set()
    for edge in getattr(graph, "external_edges", []):
        if str(getattr(edge, "edge_type", "")).startswith("potential"):
            identity = getattr(edge.callee, "identity_string", "")
            if identity:
                out.add(identity)
    return out


def _is_unresolved_noise_symbol(symbol: str, target_roots: set[str]) -> bool:
    root = _root_module(str(symbol or ""))
    if root and root in target_roots and "." in str(symbol or ""):
        return False
    return is_verdict_noise_symbol(symbol)


def _graph_warning_related_items(
    graph_metadata: Mapping[str, Any] | None,
    targets: Set[str],
    summary_roots: set[str],
) -> list[dict[str, Any]]:
    if not graph_metadata:
        return []
    filtered = filter_verdict_affecting_warnings(graph_metadata)
    related: list[dict[str, Any]] = []
    for item in filtered.get("unresolved_calls") or []:
        probes = [
            str(item.get("call_name", "")),
            str(item.get("call_expr", "")).split("(", 1)[0],
            ".".join(part for part in (str(item.get("receiver", "")), str(item.get("call_name", ""))) if part),
        ]
        if any(_target_related_symbol(probe, targets, summary_roots) for probe in probes):
            related.append(item)
    candidate_items = (
        filtered.get("llm_kept_edges")
        if graph_metadata.get("llm_pruning")
        else filtered.get("candidate_edges")
    ) or []
    for item in candidate_items:
        probes = [str(item.get("callee", "")), str(item.get("caller", ""))]
        if any(_target_related_symbol(probe, targets, summary_roots) for probe in probes):
            related.append(item)
    return related


def _summary_keys_for_usage(
    root: str,
    summary: LibrarySummary,
    usage_index: Sequence[Any],
) -> set[str]:
    keys = set(summary.inner_summary) | set(summary.outer_summary)
    if not keys:
        return set()
    selected: set[str] = set()
    for identity in _usage_identities(usage_index):
        if _root_module(identity) != root:
            continue
        for key in keys:
            if _matches_qualified_suffix(identity, key) or _matches_qualified_suffix(key, identity):
                selected.add(key)
    return selected


def _summary_warning_item_related(
    item: Mapping[str, Any],
    *,
    selected_api_keys: set[str],
    selected_callers: set[str],
    targets: Set[str],
    summary_roots: set[str],
) -> bool:
    caller = str(item.get("caller") or "")
    caller_selected = bool(caller and (
        caller in selected_callers
        or any(_matches_qualified_suffix(caller, selected) for selected in selected_callers)
    ))
    probes = [
        str(item.get("target", "")),
        str(item.get("callee", "")),
        str(item.get("call_name", "")),
        str(item.get("call_expr", "")).split("(", 1)[0],
    ]
    probe_target_related = any(_target_related_symbol(probe, targets, summary_roots) for probe in probes)
    if probe_target_related:
        return caller_selected
    call_name = str(item.get("call_name") or str(item.get("call_expr", "")).split("(", 1)[0])
    callee = str(item.get("callee") or item.get("target") or "")
    if caller_selected and callee and not _is_unresolved_noise_symbol(callee, _target_roots(targets)):
        target_roots = _target_roots(targets)
        if target_roots and target_roots.isdisjoint(summary_roots):
            return True
    high_risk_dynamic = call_name in {
        "getattr",
        "setattr",
        "delattr",
        "__import__",
        "importlib.import_module",
        "import_module",
        "eval",
        "exec",
        "compile",
    }
    return high_risk_dynamic and (
        caller in selected_api_keys
        or any(_matches_qualified_suffix(caller, target.rsplit(".", 1)[0]) for target in targets if "." in target)
    )


def _summary_has_verdict_affecting_warning(
    root: str,
    summary: LibrarySummary,
    usage_index: Sequence[Any],
    targets: Set[str],
    summary_roots: set[str],
) -> bool:
    filtered = filter_verdict_affecting_warnings(summary.analysis_warnings)
    if not filtered:
        return False

    selected_api_keys = _summary_keys_for_usage(root, summary, usage_index)
    if not selected_api_keys:
        return False
    selected_callers = set(selected_api_keys)
    for api_key in selected_api_keys:
        selected_callers.update(summary.inner_summary.get(api_key, set()))

    for key, value in filtered.items():
        if key == "unresolved_public_exports":
            continue
        if not isinstance(value, list):
            return bool(value)
        for item in value:
            if isinstance(item, Mapping) and _summary_warning_item_related(
                item,
                selected_api_keys=selected_api_keys,
                selected_callers=selected_callers,
                targets=targets,
                summary_roots=summary_roots,
            ):
                return True
    return False


def _summary_warning_related_roots(
    summaries: Mapping[str, LibrarySummary],
    usage_index: Sequence[Any],
    targets: Set[str],
) -> list[str]:
    roots = _usage_roots(usage_index)
    summary_roots = set(summaries)
    warning_roots = getattr(summaries, "warning_roots", None)
    if warning_roots is not None:
        candidate_roots = sorted(set(warning_roots) & roots)
        return [
            root
            for root in candidate_roots
            if (summary := summaries.get(root)) is not None
            and _summary_has_verdict_affecting_warning(root, summary, usage_index, targets, summary_roots)
        ]
    return sorted(
        root
        for root, summary in summaries.items()
        if root in roots
        and _summary_has_verdict_affecting_warning(root, summary, usage_index, targets, summary_roots)
    )


def _unresolved_frontier_target_related(
    symbol: str,
    targets: Set[str],
    summary_roots: set[str],
) -> bool:
    target_roots = _target_roots(targets)
    if _is_unresolved_noise_symbol(symbol, target_roots):
        return False
    unresolved_root = _root_module(symbol)
    if unresolved_root in summary_roots and unresolved_root in target_roots:
        return _target_related_symbol(symbol, targets, summary_roots)
    if target_roots and target_roots.isdisjoint(summary_roots):
        return bool(unresolved_root and not is_verdict_noise_symbol(unresolved_root))
    return _target_related_symbol(symbol, targets, summary_roots)


def classify_reachability_uncertainty(
    report: Any,
    targets: Set[str],
    summaries: Mapping[str, LibrarySummary],
    usage_index: Sequence[Any],
    graph_metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Partition incomplete analysis evidence into target-related and unrelated."""
    summary_roots = set(summaries)
    transitive_frontier = set(getattr(report, "unresolved_frontier", []) or [])
    target_related: list[str] = []
    unrelated: list[str] = []
    for target in getattr(report, "unresolved_targets", []) or []:
        unresolved_root = _root_module(str(target or ""))
        if (
            _target_related_symbol(target, targets, summary_roots)
            or (
                unresolved_root in _target_roots(targets)
                and unresolved_root not in summary_roots
                and not _is_unresolved_noise_symbol(target, _target_roots(targets))
            )
            or (
                target in transitive_frontier
                and _unresolved_frontier_target_related(target, targets, summary_roots)
            )
        ):
            target_related.append(target)
        else:
            unrelated.append(target)
    return {
        "unresolved_target_related": sorted(set(target_related)),
        "unresolved_unrelated": sorted(set(unrelated)),
        "summary_warning_roots": _summary_warning_related_roots(summaries, usage_index, targets),
        "graph_warning_related": _graph_warning_related_items(graph_metadata, targets, summary_roots),
    }


def decide_reachability_verdict(
    report: Any,
    targets: Set[str],
    summaries: Mapping[str, LibrarySummary],
    usage_index: Sequence[Any],
    *,
    graph_metadata: Mapping[str, Any] | None = None,
    potential_usage_symbols: set[str] | None = None,
) -> tuple[Verdict, dict[str, Any]]:
    uncertainty = classify_reachability_uncertainty(
        report,
        targets,
        summaries,
        usage_index,
        graph_metadata,
    )
    potential_symbols = potential_usage_symbols or set()
    if getattr(report, "is_vulnerable", False):
        if any(path.project_api in potential_symbols for path in getattr(report, "paths", [])):
            return Verdict.POTENTIALLY_REACHABLE, uncertainty
        return Verdict.REACHABLE, uncertainty
    if (
        uncertainty["unresolved_target_related"]
        or uncertainty["summary_warning_roots"]
        or uncertainty["graph_warning_related"]
    ):
        return Verdict.POTENTIALLY_REACHABLE, uncertainty
    return Verdict.NOT_REACHABLE, uncertainty


def _expand_public_api_aliases(
    summary: LibrarySummary,
    aliases: Mapping[str, Any],
    *,
    root: str | None,
) -> None:
    apply_public_api_aliases(summary, aliases, import_root=root)


def summary_from_callgraph_report(
    report: Mapping[str, Any],
    *,
    root: str | None = None,
) -> LibrarySummary:
    """Build a LibrarySummary from a package callgraph JSON report."""
    edges = _edge_rows(report)
    adjacency: dict[str, list[tuple[str, str]]] = {}
    callers: set[str] = set()
    for edge in edges:
        caller = str(edge["caller"])
        callee = str(edge["callee"])
        callee_type = str(edge.get("callee_type", "internal"))
        callers.add(caller)
        adjacency.setdefault(caller, []).append((callee, callee_type))

    summary = LibrarySummary()
    for api in sorted(callers):
        queue = [api]
        paths = {api: [api]}
        visited = {api}
        inner: set[str] = set()
        outer: set[str] = set()
        inner_paths = summary.inner_paths.setdefault(api, {})
        outer_paths = summary.outer_paths.setdefault(api, {})
        while queue:
            node = queue.pop(0)
            for nxt, callee_type in adjacency.get(node, []):
                if callee_type == "external":
                    outer.add(nxt)
                    outer_paths.setdefault(nxt, [*paths[node], nxt])
                    continue
                if nxt in visited:
                    continue
                visited.add(nxt)
                paths[nxt] = [*paths[node], nxt]
                inner.add(nxt)
                inner_paths.setdefault(nxt, paths[nxt])
                queue.append(nxt)
        summary.inner_summary[api] = inner
        summary.outer_summary[api] = outer
    aliases = report.get("public_api_aliases", {})
    if isinstance(aliases, Mapping):
        _expand_public_api_aliases(summary, aliases, root=root)
    summary.analysis_warnings = filter_verdict_affecting_warnings({
        key: report.get(key, [])
        for key in ("candidate_edges", "unresolved_public_exports", "unresolved_calls")
        if report.get(key)
    })
    return summary


def load_package_report_summaries(specs: Sequence[str]) -> dict[str, LibrarySummary]:
    """Load ROOT=package-report.json specs into a summary map."""
    summaries: dict[str, LibrarySummary] = {}
    for spec in specs:
        root, sep, raw_path = spec.partition("=")
        if not sep or not root.strip() or not raw_path.strip():
            raise ValueError(
                "package report must use ROOT=PATH, for example "
                "alpha=./alpha-callgraph-package.json"
            )
        path = Path(raw_path).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"package report does not exist: {path}")
        report = json.loads(path.read_text(encoding="utf-8-sig"))
        summaries[root.strip()] = summary_from_callgraph_report(report, root=root.strip())
    return summaries


def read_vulnerable_targets(path: str | Path) -> set[str]:
    """Read vulnerable function targets from a JSON list/object or JSONL file."""
    source = Path(path)
    if not source.exists():
        raise FileNotFoundError(f"VF file does not exist: {source}")
    text = source.read_text(encoding="utf-8-sig").strip()
    if not text:
        return set()

    def add_from_item(item: Any, out: set[str]) -> None:
        if isinstance(item, str) and item.strip():
            out.add(item.strip())
        elif isinstance(item, Mapping):
            for key in ("qualified_name", "vf", "target", "name"):
                value = item.get(key)
                if isinstance(value, str) and value.strip():
                    out.add(value.strip())
                    return

    targets: set[str] = set()
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                add_from_item(json.loads(line), targets)
            except json.JSONDecodeError:
                targets.add(line)
        return targets

    if isinstance(payload, list):
        for item in payload:
            add_from_item(item, targets)
    elif isinstance(payload, Mapping):
        for key in ("vulnerabilities", "vfs", "targets"):
            items = payload.get(key)
            if isinstance(items, list):
                for item in items:
                    add_from_item(item, targets)
                break
        else:
            add_from_item(payload, targets)
    else:
        add_from_item(payload, targets)
    return targets


def _entry_points(graph) -> list[str]:
    return sorted(
        node.qualified_name or node.function_name
        for node in graph.internal_nodes
        if node.entry_type != EntryPointType.UNKNOWN
    )


def _analysis_warnings(graph) -> dict[str, Any]:
    keys = ["unresolved_calls", "skipped_files"]
    keys.append("llm_kept_edges" if graph.metadata.get("llm_pruning") else "candidate_edges")
    warnings = {key: graph.metadata.get(key, []) for key in keys if graph.metadata.get(key)}
    if graph.metadata.get("llm_pruning"):
        warnings["llm_pruning"] = graph.metadata["llm_pruning"]
    return warnings


def _node_name(node: Any) -> str:
    return getattr(node, "qualified_name", "") or getattr(node, "function_name", "")


def _project_callers_by_target(graph: Any) -> dict[str, list[str]]:
    callers: dict[str, set[str]] = {}
    for edge in getattr(graph, "external_edges", []) or []:
        target = getattr(edge.callee, "identity_string", "") or _node_name(edge.callee)
        caller = _node_name(edge.caller)
        if not target or not caller:
            continue
        callers.setdefault(target, set()).add(caller)
    return {target: sorted(values) for target, values in callers.items()}


def _with_project_callers(paths: Sequence[ReachabilityPath], graph: Any) -> list[ReachabilityPath]:
    callers_by_target = _project_callers_by_target(graph)
    expanded: list[ReachabilityPath] = []
    seen: set[tuple[str, ...]] = set()

    for path in paths:
        if not path.tpl_chain:
            continue
        first_hop = path.tpl_chain[0]
        callers = callers_by_target.get(first_hop, [])
        if not callers:
            key = tuple(path.tpl_chain)
            if key not in seen:
                seen.add(key)
                expanded.append(path)
            continue

        for caller in callers:
            chain = path.tpl_chain if path.tpl_chain[0] == caller else [caller, *path.tpl_chain]
            key = tuple(chain)
            if key in seen:
                continue
            seen.add(key)
            expanded.append(
                ReachabilityPath(
                    project_api=caller,
                    tpl_chain=chain,
                    vulnerable_target=path.vulnerable_target,
                    used_summaries=list(path.used_summaries),
                )
            )

    return expanded


def _graph_artifact(project: Path, graph, usage_index) -> ProjectGraphArtifact:
    edges = [
        {
            "caller": _node_name(edge.caller),
            "callee": _node_name(edge.callee),
            "callee_type": "external" if edge.callee.is_external else "internal",
            "edge_type": getattr(edge, "edge_type", "confirmed_static"),
            "confidence": getattr(edge, "confidence", 1.0),
            "resolver": getattr(edge, "resolver", "static"),
            "reason": getattr(edge, "reason", ""),
            "call_expr": getattr(edge, "call_expr", ""),
            "line_number": getattr(edge, "line_number", 0),
        }
        for edge in graph.edges
    ]
    resolved = project.resolve()
    project_id = ProjectIdentity(root=str(resolved), fingerprint=str(resolved))
    return ProjectGraphArtifact(
        project=project_id,
        fingerprint=AnalysisFingerprint(python_version=f"{sys.version_info.major}.{sys.version_info.minor}"),
        entry_points=_entry_points(graph),
        usage_index=sorted(node.identity_string for node in usage_index),
        graph={
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "edges_detail": edges,
            "metadata": graph.metadata,
        },
        analysis_warnings=_analysis_warnings(graph),
    )


def _project_cache_key(project: Path) -> str:
    resolved = project.resolve()
    return f"{resolved}|py={sys.version_info.major}.{sys.version_info.minor}|scanner=0.3.0|config=default"


def _normalize_name(name: str) -> str:
    return name.replace("_", "-").lower()


def _source_for_root(root: str) -> tuple[Path | None, str, str]:
    wanted = root.replace("-", "_").lower()
    for dist in metadata.distributions():
        name = dist.metadata.get("Name", dist.name or "")
        top_level = ""
        try:
            top_level = dist.read_text("top_level.txt") or ""
        except Exception:
            top_level = ""
        tops = [line.strip() for line in top_level.splitlines() if line.strip()]
        if wanted not in {top.lower() for top in tops} and wanted != name.replace("-", "_").lower():
            continue
        files = list(dist.files or [])
        for top in tops or [root]:
            package_init = f"{top}/__init__.py"
            module_file = f"{top}.py"
            for file in files:
                posix = file.as_posix()
                if posix == package_init:
                    return Path(dist.locate_file(file).parent), name, dist.version or ""
                if posix == module_file:
                    return Path(dist.locate_file(file)), name, dist.version or ""
    return None, root, ""


def _package_key(identity: PackageIdentity) -> str:
    return f"{identity.normalized_name or _normalize_name(identity.name)}=={identity.version}"


def _build_package_summary(root: str) -> tuple[str, PackageSummaryArtifact] | None:
    source, package, version = _source_for_root(root)
    if source is None or not source.exists():
        return None
    return _build_package_summary_from_source(
        root,
        source,
        package,
        version,
        provenance={"source": "installed_distribution", "root": root},
        python_version=f"{sys.version_info.major}.{sys.version_info.minor}",
    )


def _build_package_summary_from_source(
    root: str,
    source: Path,
    package: str,
    version: str,
    *,
    provenance: Mapping[str, Any] | None = None,
    python_version: str = "",
) -> tuple[str, PackageSummaryArtifact]:
    """Build a summary from an explicitly captured source path.

    The runtime-aware benchmark uses this entry point so the analyzer never
    asks the f_vra environment which distribution owns an import root.
    """
    # Keep a single-module distribution scoped to its captured file.  Using
    # ``source.parent`` here would analyze the entire runtime site-packages
    # directory for modules such as ``mypy_extensions.py``.
    analysis_root = source
    # Package summaries only consume the call graph and verdict-affecting
    # warnings.  Per-function type graphs and assignment/return diagnostics
    # are not serialized into ``LibrarySummary``; avoid retaining them across
    # thousands of definitions in large distributions such as pip.
    analyzer = LibraryAnalyzer(retain_analysis_details=False)
    graph = analyzer.build_library_graph(analysis_root)
    public_apis = analyzer.index.public_api if analyzer.index is not None else []
    summary = build_library_summary(
        graph,
        public_apis,
        public_api_aliases=analyzer.index.public_api_aliases() if analyzer.index is not None else {},
        import_root=root,
    )
    identity = PackageIdentity(
        name=package or root,
        normalized_name=_normalize_name(package or root),
        version=version,
        python_version=python_version or f"{sys.version_info.major}.{sys.version_info.minor}",
    )
    artifact = PackageSummaryArtifact(
        package=identity,
        fingerprint=AnalysisFingerprint(python_version=identity.python_version),
        summary=summary,
        source_path=str(source),
        provenance=dict(provenance or {"source": "explicit_source", "root": root}),
    )
    return _package_key(identity), artifact


def _build_package_summary_from_runtime(
    root: str,
    runtime: RuntimeEnvironment,
) -> tuple[str, PackageSummaryArtifact] | None:
    package = runtime.package_by_root().get(root)
    if package is None or not package.python_source or not package.source_path:
        return None
    source = _runtime_source_for_root(root, package)
    if source is None or not source.exists():
        return None
    return _build_package_summary_from_source(
        root,
        source,
        package.name,
        package.version,
        provenance={
            "source": "conda_runtime",
            "root": root,
            "project_id": runtime.project_id,
            "conda_prefix": runtime.prefix,
            "environment_fingerprint": runtime.fingerprint,
            "source_fingerprint": package.source_fingerprint,
        },
        python_version=runtime.python_version,
    )


def _runtime_source_for_root(root: str, package: RuntimePackage) -> Path | None:
    """Resolve the captured source belonging to one import root.

    A distribution may publish many top-level roots (notably ``pywin32``).
    ``importlib.metadata`` gives us one preferred source path for the
    distribution, but using that same path for every root would analyze the
    wrong module.  Resolve each root relative to the distribution's
    site-packages parent and return ``None`` when the root is binary-only.
    """
    preferred = Path(package.source_path)
    root_value = str(root).replace("\\", "/").strip("/")
    if not root_value:
        return None
    root_path = Path(*[part for part in root_value.split("/") if part])
    if preferred.exists() and preferred.is_file() and preferred.stem == root_path.name:
        return preferred
    if preferred.exists() and preferred.is_dir() and preferred.name == root_path.name and len(root_path.parts) == 1:
        return preferred
    base = preferred.parent
    candidates = [base / root_path, base / f"{root_path}.py"]
    for candidate in candidates:
        if candidate.exists() and (candidate.is_dir() or candidate.suffix == ".py"):
            return candidate
    return None


def _load_or_build_summaries(usage_index, cache: ClientCache) -> dict[str, LibrarySummary]:
    summaries: dict[str, LibrarySummary] = {}
    roots = sorted({node.target_module.split(".", 1)[0] for node in usage_index if node.target_module})
    for root in roots:
        cached_keys = [key for key in cache.list("package-summary") if key.startswith(f"{_normalize_name(root)}==")]
        artifact = cache.get_package_summary(cached_keys[0]) if cached_keys else None
        if artifact is None:
            built = _build_package_summary(root)
            if built is None:
                continue
            key, artifact = built
            cache.put_package_summary(key, artifact)
        summaries[root] = artifact.summary
    return summaries


def query_with_cache(
    cve_id: str,
    project: Path,
    vf: str,
    explain: bool = False,
    *,
    cache: ClientCache,
    vulnerabilities: Set[str] | None = None,
    max_depth: int = 25,
    max_paths: int = 100,
) -> ScanResult:
    started = time.perf_counter()
    targets = set(vulnerabilities or ())
    if vf:
        targets.add(vf)
    if not targets:
        return ScanResult(
            cve_id=cve_id,
            project=project,
            verdict=Verdict.UNKNOWN,
            query_time_ms=(time.perf_counter() - started) * 1000,
        )

    graph, usage_index = build_project_graph(project)
    cache.put_project(_project_cache_key(project), _graph_artifact(project, graph, usage_index))
    summaries = _load_or_build_summaries(usage_index, cache)
    report = ReachabilityQueryEngine(
        usage_index,
        summaries,
        targets,
        max_depth=max_depth,
        max_paths=max_paths,
    ).check_reachability()

    verdict, _uncertainty = decide_reachability_verdict(
        report,
        targets,
        summaries,
        usage_index,
        graph_metadata=graph.metadata,
        potential_usage_symbols=_potential_usage_symbols(graph),
    )
    report.paths = _with_project_callers(report.paths, graph)

    result = ScanResult(
        cve_id=cve_id,
        project=project,
        verdict=verdict,
        vf=vf or (sorted(targets)[0] if len(targets) == 1 else ""),
        entry_points=_entry_points(graph),
        hit_set=sorted({path.vulnerable_target for path in report.paths}),
        call_chain=report.paths[0].tpl_chain if report.paths and explain else [],
        query_time_ms=(time.perf_counter() - started) * 1000,
    )
    scan_id = f"{cve_id}:{_project_cache_key(project)}:{','.join(sorted(targets))}"
    cache.put_scan_report(
        ScanReport(
            scan_id=scan_id,
            cve_id=cve_id,
            project=ProjectIdentity(root=str(project.resolve()), fingerprint=str(project.resolve())),
            verdict=result.verdict,
            vulnerable_targets=sorted(targets),
            hit_set=result.hit_set,
        paths=[{"path": path.tpl_chain, "target": path.vulnerable_target} for path in report.paths],
        unresolved_targets=report.unresolved_targets,
        loaded_summaries=sorted(summaries),
            query_time_ms=result.query_time_ms,
        )
    )
    return result


def _summary_warnings(summaries: Mapping[str, LibrarySummary]) -> dict[str, Any]:
    return {
        root: summary.analysis_warnings
        for root, summary in summaries.items()
        if summary.analysis_warnings
    }


def check_transitive_reachability(
    project: str | Path,
    vulnerabilities: Set[str],
    *,
    summaries: Mapping[str, LibrarySummary] | None = None,
    max_depth: int = 25,
    max_paths: int = 100,
    project_graph: Any | None = None,
    usage_index: Sequence[Any] | None = None,
) -> TransitiveReachabilityResult:
    """Run project-to-package transitive vulnerable-function reachability."""
    started = time.perf_counter()
    project_path = Path(project)
    targets = {target for target in vulnerabilities if target}

    if not targets:
        return TransitiveReachabilityResult(
            project=project_path,
            verdict=Verdict.UNKNOWN,
            vulnerable_targets=[],
            query_time_ms=(time.perf_counter() - started) * 1000,
        )

    if project_graph is None or usage_index is None:
        graph, usage_index = build_project_graph(project_path)
    else:
        graph = project_graph
    summary_map = dict(summaries or {})
    report = ReachabilityQueryEngine(
        usage_index,
        summary_map,
        targets,
        max_depth=max_depth,
        max_paths=max_paths,
    ).check_reachability()

    summary_warnings = _summary_warnings(summary_map)

    verdict, uncertainty = decide_reachability_verdict(
        report,
        targets,
        summary_map,
        usage_index,
        graph_metadata=graph.metadata,
        potential_usage_symbols=_potential_usage_symbols(graph),
    )
    report.paths = _with_project_callers(report.paths, graph)

    return TransitiveReachabilityResult(
        project=project_path,
        verdict=verdict,
        vulnerable_targets=sorted(targets),
        hit_set=sorted({path.vulnerable_target for path in report.paths}),
        paths=report.paths,
        usage_index=sorted(node.identity_string for node in usage_index),
        loaded_summaries=sorted(summary_map),
        used_summaries=report.used_summaries,
        unresolved_targets=report.unresolved_targets,
        unresolved_target_related=uncertainty["unresolved_target_related"],
        unresolved_unrelated=uncertainty["unresolved_unrelated"],
        entry_points=_entry_points(graph),
        analysis_warnings={
            **_analysis_warnings(graph),
            **({"package_summaries": summary_warnings} if summary_warnings else {}),
            **({"target_related_summary_warnings": uncertainty["summary_warning_roots"]} if uncertainty["summary_warning_roots"] else {}),
            **({"target_related_graph_warnings": uncertainty["graph_warning_related"]} if uncertainty["graph_warning_related"] else {}),
        },
        query_time_ms=(time.perf_counter() - started) * 1000,
    )


def query(
    cve_id: str,
    project: Path,
    vf: str,
    explain: bool = False,
    *,
    summaries: Mapping[str, LibrarySummary] | None = None,
    vulnerabilities: Set[str] | None = None,
    max_depth: int = 25,
    max_paths: int = 100,
) -> ScanResult:
    """Run direct or transitive vulnerable-function reachability."""
    started = time.perf_counter()
    targets = set(vulnerabilities or ())
    if vf:
        targets.add(vf)

    if not targets:
        return ScanResult(
            cve_id=cve_id,
            project=project,
            verdict=Verdict.UNKNOWN,
            query_time_ms=(time.perf_counter() - started) * 1000,
        )

    graph, usage_index = build_project_graph(project)
    report = ReachabilityQueryEngine(
        usage_index,
        dict(summaries or {}),
        targets,
        max_depth=max_depth,
        max_paths=max_paths,
    ).check_reachability()

    entry_points = _entry_points(graph)
    verdict, _uncertainty = decide_reachability_verdict(
        report,
        targets,
        dict(summaries or {}),
        usage_index,
        graph_metadata=graph.metadata,
        potential_usage_symbols=_potential_usage_symbols(graph),
    )
    report.paths = _with_project_callers(report.paths, graph)

    return ScanResult(
        cve_id=cve_id,
        project=project,
        verdict=verdict,
        vf=vf or (sorted(targets)[0] if len(targets) == 1 else ""),
        entry_points=entry_points,
        hit_set=sorted({path.vulnerable_target for path in report.paths}),
        call_chain=report.paths[0].tpl_chain if report.paths and explain else [],
        query_time_ms=(time.perf_counter() - started) * 1000,
    )
