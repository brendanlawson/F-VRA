from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict, is_dataclass
from importlib import metadata
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from f_vra.analysis.callgraph.jarvis_backend import (  # noqa: E402
    JarvisOptions,
    build_jarvis_project_graph,
)
from f_vra.core.models import LibrarySummary  # noqa: E402
from f_vra.reachability.engine import ReachabilityQueryEngine  # noqa: E402
from f_vra.reachability.service import (  # noqa: E402
    _build_package_summary,
    _graph_artifact,
    _with_project_callers,
    decide_reachability_verdict,
)


def _resolve(path_value: str | Path) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else REPO_ROOT / path


def _json_default(value: Any) -> Any:
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default),
        encoding="utf-8",
    )


def _default_jarvis_root() -> Path | None:
    env_value = os.getenv("F_VRA_JARVIS_ROOT")
    if env_value:
        return _resolve(env_value)
    bundled = REPO_ROOT / "vendor" / "pythonJaRvis" / "Jarvis"
    return bundled if (bundled / "tool" / "Jarvis" / "jarvis_cli.py").exists() else None


def _root(identity: str) -> str:
    return identity.split(".", 1)[0] if identity else ""


def _usage_summary(graph: Any, usage_index: list[Any]) -> dict[str, Any]:
    return {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "internal_edges": len(graph.internal_edges),
        "external_edges": len(graph.external_edges),
        "usage_index_count": len(usage_index),
        "entry_points": graph.metadata.get("entry_points", []),
        "metadata": graph.metadata,
        "usage_index": [
            {
                "identity": node.identity_string,
                "target_module": node.target_module,
                "target_name": node.target_name,
            }
            for node in usage_index
        ],
    }


def _summary_keys(summary: LibrarySummary) -> set[str]:
    return set(summary.inner_summary) | set(summary.outer_summary)


def _suffix_overlap(left: str, right: str) -> int:
    out = 0
    for a, b in zip(reversed(left.split(".")), reversed(right.split("."))):
        if a != b:
            break
        out += 1
    return out


def _resolve_api_keys(target: str, summary: LibrarySummary) -> list[str]:
    keys = _summary_keys(summary)
    scored: dict[str, tuple[int, int]] = {}

    def add(candidate: str, rank: int, score: int = 0) -> None:
        if candidate not in keys:
            return
        value = (rank, score)
        current = scored.get(candidate)
        if current is None or value > current:
            scored[candidate] = value

    add(target, 100, len(target.split(".")))
    canonical = summary.api_aliases.get(target)
    if canonical:
        add(canonical, 95, len(canonical.split(".")))
    parts = [part for part in target.split(".") if part]
    for probe in [target, *(".".join(parts[index:]) for index in range(1, len(parts)))]:
        for item in summary.alias_table.get(probe, []):
            add(str(item.get("canonical") or ""), 80, len(str(item.get("canonical") or "").split(".")))
    for key in keys:
        if target == key or target.endswith("." + key) or key.endswith("." + target):
            add(key, 70, _suffix_overlap(target, key))
    if not scored and parts:
        tail = parts[-1]
        for key in keys:
            if key.rsplit(".", 1)[-1] == tail:
                add(key, 40, 1)
    return [
        key
        for key, _score in sorted(
            scored.items(),
            key=lambda item: (item[1][0], item[1][1], item[0]),
            reverse=True,
        )
    ]


def _build_summary(root: str) -> tuple[LibrarySummary | None, dict[str, Any]]:
    started = time.perf_counter()
    try:
        built = _build_package_summary(root)
    except Exception as exc:
        return None, {
            "root": root,
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_s": round(time.perf_counter() - started, 3),
        }
    if built is None:
        return None, {
            "root": root,
            "status": "missing_source",
            "elapsed_s": round(time.perf_counter() - started, 3),
        }
    key, artifact = built
    return artifact.summary, {
        "root": root,
        "status": "built",
        "cache_key": key,
        "package": artifact.package.model_dump(mode="json"),
        "source_path": artifact.source_path,
        "summary_counts": {
            "api_keys": len(_summary_keys(artifact.summary)),
            "inner_targets": sum(len(values) for values in artifact.summary.inner_summary.values()),
            "outer_targets": sum(len(values) for values in artifact.summary.outer_summary.values()),
        },
        "elapsed_s": round(time.perf_counter() - started, 3),
    }


def _build_recursive_summaries(
    initial_roots: list[str],
    *,
    max_roots: int,
    max_depth: int,
) -> tuple[dict[str, LibrarySummary], list[dict[str, Any]]]:
    installed_roots = _installed_import_roots()
    summaries: dict[str, LibrarySummary] = {}
    status: list[dict[str, Any]] = []
    queue: list[tuple[str, int]] = [
        (root, 0) for root in initial_roots if root and root in installed_roots
    ]
    seen: set[str] = set()
    while queue and len(summaries) < max_roots:
        root, depth = queue.pop(0)
        if root in seen:
            continue
        seen.add(root)
        summary, item = _build_summary(root)
        item["depth"] = depth
        status.append(item)
        if summary is None:
            continue
        summaries[root] = summary
        if depth >= max_depth:
            continue
        next_roots = sorted(
            {
                _root(target)
                for targets in summary.outer_summary.values()
                for target in targets
                if _root(target)
                and _root(target) != root
                and _root(target) in installed_roots
            }
        )
        for next_root in next_roots:
            if next_root not in seen and next_root not in {queued for queued, _ in queue}:
                queue.append((next_root, depth + 1))
    return summaries, status


def _installed_import_roots() -> set[str]:
    roots: set[str] = set()
    for dist in metadata.distributions():
        name = (dist.metadata.get("Name") or dist.name or "").replace("-", "_").lower()
        try:
            top_level = dist.read_text("top_level.txt") or ""
        except Exception:
            top_level = ""
        for line in top_level.splitlines():
            root = line.strip()
            if root:
                roots.add(root)
        if name:
            roots.add(name)
    return roots


def _candidate_c_vfs(c_api: str, c_summary: LibrarySummary) -> list[str]:
    keys = _resolve_api_keys(c_api, c_summary)
    out: list[str] = []
    for key in keys:
        out.extend(sorted(c_summary.inner_summary.get(key, set())))
        out.extend(sorted(c_summary.outer_summary.get(key, set())))
    return [item for item in out if item and item != c_api]


def _find_real_transitive_chain(
    usage_identities: list[str],
    summaries: dict[str, LibrarySummary],
) -> dict[str, Any] | None:
    for usage in usage_identities:
        a_root = _root(usage)
        a_summary = summaries.get(a_root)
        if a_summary is None:
            continue
        for a_api in _resolve_api_keys(usage, a_summary):
            for b_api in sorted(a_summary.outer_summary.get(a_api, set())):
                b_root = _root(b_api)
                if not b_root or b_root == a_root:
                    continue
                b_summary = summaries.get(b_root)
                if b_summary is None:
                    continue
                for b_key in _resolve_api_keys(b_api, b_summary):
                    for c_api in sorted(b_summary.outer_summary.get(b_key, set())):
                        c_root = _root(c_api)
                        if not c_root or c_root in {a_root, b_root}:
                            continue
                        c_summary = summaries.get(c_root)
                        if c_summary is None:
                            continue
                        for vf in _candidate_c_vfs(c_api, c_summary):
                            return {
                                "usage_identity": usage,
                                "package_a": a_root,
                                "a_api": a_api,
                                "package_b": b_root,
                                "b_api": b_api,
                                "b_key": b_key,
                                "package_c": c_root,
                                "c_api": c_api,
                                "vf": vf,
                                "vf_root": _root(vf),
                            }
    return None


def run(args: argparse.Namespace) -> int:
    project_root = _resolve(args.project_root)
    if not project_root.exists():
        raise RuntimeError(f"project root does not exist: {project_root}")
    run_dir = _resolve(args.output_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    jarvis_root = _resolve(args.jarvis_root) if args.jarvis_root else _default_jarvis_root()
    if jarvis_root is None:
        raise RuntimeError("Jarvis root not found; set F_VRA_JARVIS_ROOT or pass --jarvis-root")

    _write_json(
        run_dir / "manifest.json",
        {
            "project_root": str(project_root),
            "jarvis_root": str(jarvis_root),
            "runner": args.runner,
            "scope": args.scope,
            "mode": args.mode,
            "started_at_epoch": time.time(),
            "note": "No mock package summaries are used; summaries are built from installed distributions.",
        },
    )
    graph, usage_index = build_jarvis_project_graph(
        project_root,
        JarvisOptions(
            jarvis_root=jarvis_root,
            runner=args.runner,
            scope=args.scope,
            mode=args.mode,
            timeout_s=args.timeout,
            pip_install=args.pip_install,
        ),
    )
    _write_json(run_dir / "project_graph_jarvis.json", _graph_artifact(project_root, graph, usage_index))
    _write_json(run_dir / "usage_index.json", _usage_summary(graph, usage_index))

    usage_identities = sorted({node.identity_string for node in usage_index if node.identity_string})
    initial_roots = sorted({_root(identity) for identity in usage_identities if _root(identity)})
    if args.summary_root:
        summaries: dict[str, LibrarySummary] = {}
        summary_status: list[dict[str, Any]] = []
        for root in args.summary_root:
            summary, item = _build_summary(root)
            item["depth"] = "explicit"
            summary_status.append(item)
            if summary is not None:
                summaries[root] = summary
    else:
        summaries, summary_status = _build_recursive_summaries(
            initial_roots,
            max_roots=args.max_summary_roots,
            max_depth=args.summary_depth,
        )
    _write_json(run_dir / "package_summary_status.json", summary_status)
    for root, summary in summaries.items():
        _write_json(run_dir / "package_summaries" / f"{root}.json", summary)

    chain = _find_real_transitive_chain(usage_identities, summaries)
    if chain is None:
        _write_json(
            run_dir / "summary.json",
            {
                "project_root": str(project_root),
                "counts": {
                    "project_nodes": len(graph.nodes),
                    "project_edges": len(graph.edges),
                    "usage_index": len(usage_index),
                    "summaries_built": len(summaries),
                },
                "status": "no_project_a_b_c_chain_found",
                "initial_roots": initial_roots,
                "built_roots": sorted(summaries),
            },
        )
        print(f"NO_CHAIN real-transitive {args.project_id}")
        print(f"run_dir: {run_dir.relative_to(REPO_ROOT)}")
        print(f"project: nodes={len(graph.nodes)} edges={len(graph.edges)} usage_index={len(usage_index)}")
        print(f"summaries_built: {len(summaries)} roots={sorted(summaries)}")
        return 2

    targets = {chain["vf"]}
    report = ReachabilityQueryEngine(
        usage_index,
        summaries,
        targets,
        max_depth=args.max_depth,
        max_paths=args.max_paths,
    ).check_reachability()
    verdict, uncertainty = decide_reachability_verdict(
        report,
        targets,
        summaries,
        usage_index,
        graph_metadata=graph.metadata,
    )
    report.paths = _with_project_callers(report.paths, graph)

    needed = {chain["package_a"], chain["package_b"], chain["package_c"]}
    missing_b = {key: value for key, value in summaries.items() if key != chain["package_b"]}
    missing_report = ReachabilityQueryEngine(
        usage_index,
        missing_b,
        targets,
        max_depth=args.max_depth,
        max_paths=args.max_paths,
    ).check_reachability()
    missing_verdict, missing_uncertainty = decide_reachability_verdict(
        missing_report,
        targets,
        missing_b,
        usage_index,
        graph_metadata=graph.metadata,
    )
    missing_report.paths = _with_project_callers(missing_report.paths, graph)

    reachability = {
        "verdict": verdict.value,
        "chain": chain,
        "target": chain["vf"],
        "paths": [
            {
                "project_api": path.project_api,
                "target": path.vulnerable_target,
                "path": path.tpl_chain,
                "used_summaries": path.used_summaries,
            }
            for path in report.paths
        ],
        "hit_set": sorted({path.vulnerable_target for path in report.paths}),
        "used_summaries": report.used_summaries,
        "needed_chain_summaries_loaded": sorted(needed & set(report.used_summaries)),
        "unresolved_targets": report.unresolved_targets,
        "unresolved_frontier": report.unresolved_frontier,
        "uncertainty": uncertainty,
    }
    _write_json(run_dir / "real_transitive_reachability_report.json", reachability)
    missing_payload = {
        "verdict": missing_verdict.value,
        "omitted_summary": chain["package_b"],
        "target": chain["vf"],
        "paths": [
            {
                "project_api": path.project_api,
                "target": path.vulnerable_target,
                "path": path.tpl_chain,
                "used_summaries": path.used_summaries,
            }
            for path in missing_report.paths
        ],
        "used_summaries": missing_report.used_summaries,
        "unresolved_targets": missing_report.unresolved_targets,
        "unresolved_frontier": missing_report.unresolved_frontier,
        "uncertainty": missing_uncertainty,
    }
    _write_json(run_dir / "missing_middle_summary_report.json", missing_payload)

    summary_payload = {
        "project_root": str(project_root),
        "artifacts": {
            "manifest": str(run_dir / "manifest.json"),
            "project_graph": str(run_dir / "project_graph_jarvis.json"),
            "usage_index": str(run_dir / "usage_index.json"),
            "package_summary_status": str(run_dir / "package_summary_status.json"),
            "package_summaries": str(run_dir / "package_summaries"),
            "reachability": str(run_dir / "real_transitive_reachability_report.json"),
            "missing_middle_summary": str(run_dir / "missing_middle_summary_report.json"),
        },
        "counts": {
            "project_nodes": len(graph.nodes),
            "project_edges": len(graph.edges),
            "usage_index": len(usage_index),
            "initial_roots": len(initial_roots),
            "summaries_built": len(summaries),
            "reachable_paths": len(report.paths),
            "missing_middle_paths": len(missing_report.paths),
        },
        "chain": chain,
        "verdict": verdict.value,
        "used_summaries": report.used_summaries,
        "missing_middle_summary_verdict": missing_verdict.value,
    }
    _write_json(run_dir / "summary.json", summary_payload)
    _write_json(
        REPO_ROOT / "results" / "metrics" / f"{args.project_id}_jarvis_real_transitive_probe.json",
        summary_payload,
    )

    print(f"PASS real-transitive {args.project_id}")
    print(f"run_dir: {run_dir.relative_to(REPO_ROOT)}")
    print(f"project: nodes={len(graph.nodes)} edges={len(graph.edges)} usage_index={len(usage_index)}")
    print(f"summaries_built: {len(summaries)} roots={sorted(summaries)}")
    print(
        "chain: "
        f"{chain['usage_identity']} -> {chain['b_api']} -> {chain['c_api']} -> {chain['vf']}"
    )
    print(f"reachability: verdict={verdict.value} paths={len(report.paths)} used_summaries={report.used_summaries}")
    print(
        "missing_middle_summary: "
        f"omitted={chain['package_b']} verdict={missing_verdict.value} "
        f"paths={len(missing_report.paths)} frontier={missing_report.unresolved_frontier}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find and query a real project->A->B->C transitive path using installed package summaries."
    )
    parser.add_argument("--project-id", default="alerta__alerta")
    parser.add_argument("--project-root", type=Path, default=REPO_ROOT / "data" / "raw" / "projects" / "alerta__alerta")
    parser.add_argument("--jarvis-root", type=Path, default=None)
    parser.add_argument("--runner", choices=["docker", "local"], default="docker")
    parser.add_argument("--scope", choices=["entrypoints", "whole-project", "whole_project", "all"], default="entrypoints")
    parser.add_argument("--mode", choices=["EA", "DW", "AW"], default="EA")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--pip-install", default="")
    parser.add_argument("--summary-depth", type=int, default=2)
    parser.add_argument("--max-summary-roots", type=int, default=35)
    parser.add_argument(
        "--summary-root",
        action="append",
        default=[],
        help="Build only this installed package root. May be repeated.",
    )
    parser.add_argument("--max-depth", type=int, default=25)
    parser.add_argument("--max-paths", type=int, default=25)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=REPO_ROOT / "artifacts" / "pipeline_runs" / "alerta_jarvis_real_transitive_probe",
    )
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
