from __future__ import annotations

import argparse
import json
import os
import subprocess
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
DEFAULT_BENCHMARK = REPO_ROOT / "data" / "final" / "cve_vf_benchmark_accepted.jsonl"

from f_vra.analysis.callgraph.jarvis_backend import (  # noqa: E402
    JarvisOptions,
    build_jarvis_project_graph,
)
from f_vra.analysis.dependencies.resolver import resolve_dependency_graph  # noqa: E402
from f_vra.core.models import ExternalNode, LibrarySummary  # noqa: E402
from f_vra.reachability.engine import ReachabilityQueryEngine  # noqa: E402
from f_vra.reachability.service import (  # noqa: E402
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
        json.dumps(payload, indent=2, default=_json_default),
        encoding="utf-8",
    )


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]


def _project_from_manifest(manifest_path: Path, project_id: str) -> dict[str, Any]:
    manifest = _load_json(manifest_path)
    for project in manifest.get("projects", []):
        if project.get("id") == project_id:
            if not project.get("enabled", True):
                raise RuntimeError(f"project is disabled in local manifest: {project_id}")
            return project
    raise RuntimeError(f"project is not listed in local manifest: {project_id}")


def _target_vfs(record: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    for item in record.get("target_vfs") or []:
        value = str(item.get("qualified_name") or "").strip()
        if value and value not in targets:
            targets.append(value)
    fallback = str(record.get("vf_qualified_name") or "").strip()
    if fallback and fallback not in targets:
        targets.append(fallback)
    return targets


def _benchmark_records_for_project(benchmark_path: Path, project_id: str) -> list[dict[str, Any]]:
    records = []
    for record in _load_jsonl(benchmark_path):
        if record.get("benchmark_status") != "accepted":
            continue
        if project_id not in set(record.get("projects") or []):
            continue
        targets = _target_vfs(record)
        if not targets:
            continue
        records.append(
            {
                "group_id": record.get("group_id", ""),
                "cve_id": record.get("cve_id", ""),
                "package": record.get("package", ""),
                "evidence_level": record.get("evidence_level", ""),
                "mapping_type": record.get("mapping_type", ""),
                "confidence": record.get("confidence", ""),
                "target_vfs": targets,
            }
        )
    return records


def _target_root(target: str) -> str:
    parts = [part for part in str(target or "").split(".") if part]
    if not parts:
        return ""
    if parts[0] == "src" and len(parts) > 1:
        return parts[1]
    if parts[0] == "python" and len(parts) > 1:
        return parts[1]
    return parts[0]


def _default_jarvis_root() -> Path | None:
    env_value = os.getenv("F_VRA_JARVIS_ROOT")
    if env_value:
        return _resolve(env_value)
    bundled = REPO_ROOT / "vendor" / "pythonJaRvis" / "Jarvis"
    return bundled if (bundled / "tool" / "Jarvis" / "jarvis_cli.py").exists() else None


def _node_name(node: Any) -> str:
    return getattr(node, "qualified_name", "") or getattr(node, "function_name", "")


def _graph_summary(graph: Any, usage_index: list[ExternalNode]) -> dict[str, Any]:
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


def _run_pip_audit(requirements: Path, output: Path) -> dict[str, Any]:
    command = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(requirements),
        "-f",
        "json",
        "-o",
        str(output),
    ]
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
        timeout=300,
    )
    payload = _load_json(output) if output.exists() else {"dependencies": [], "fixes": []}
    payload["_run"] = {
        "command": command,
        "returncode": completed.returncode,
        "elapsed_s": round(time.perf_counter() - started, 3),
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
    }
    _write_json(output, payload)
    return payload


def _vulnerable_packages(audit: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for dependency in audit.get("dependencies", []):
        vulns = dependency.get("vulns") or []
        if not vulns:
            continue
        name = str(dependency.get("name") or "").replace("_", "-").lower()
        out[name] = {
            "name": dependency.get("name", ""),
            "version": dependency.get("version", ""),
            "vulnerabilities": vulns,
        }
    return out


def _top_level_imports_by_distribution() -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for dist in metadata.distributions():
        name = (dist.metadata.get("Name") or dist.name or "").replace("_", "-").lower()
        if not name:
            continue
        tops: set[str] = set()
        try:
            text = dist.read_text("top_level.txt") or ""
        except Exception:
            text = ""
        for line in text.splitlines():
            line = line.strip()
            if line:
                tops.add(line)
        if not tops:
            tops.add(name.replace("-", "_"))
        mapping.setdefault(name, set()).update(tops)
    return mapping


def _proxy_targets_from_usage(
    usage_index: list[ExternalNode],
    vulnerable_packages: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    imports_by_dist = _top_level_imports_by_distribution()
    usage_by_root: dict[str, set[str]] = {}
    for node in usage_index:
        identity = node.identity_string
        root = (node.target_module or identity).split(".", 1)[0]
        if root and identity:
            usage_by_root.setdefault(root, set()).add(identity)

    proxy: dict[str, list[str]] = {}
    for package in vulnerable_packages:
        roots = imports_by_dist.get(package, {package.replace("-", "_")})
        targets: set[str] = set()
        for root in roots:
            targets.update(usage_by_root.get(root, set()))
        if targets:
            proxy[package] = sorted(targets)
    return proxy


def _build_summary_for_root(root: str) -> tuple[LibrarySummary | None, dict[str, Any]]:
    from f_vra.reachability.service import _build_package_summary

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
            "inner_keys": len(artifact.summary.inner_summary),
            "outer_keys": len(artifact.summary.outer_summary),
            "outer_targets": sum(len(values) for values in artifact.summary.outer_summary.values()),
        },
        "elapsed_s": round(time.perf_counter() - started, 3),
    }


def run(args: argparse.Namespace) -> int:
    project = _project_from_manifest(_resolve(args.local_projects), args.project_id)
    project_root = _resolve(project["path"])
    if not project_root.exists():
        raise RuntimeError(f"project path does not exist: {project_root}")

    run_dir = _resolve(args.output_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    jarvis_root = _resolve(args.jarvis_root) if args.jarvis_root else _default_jarvis_root()
    if jarvis_root is None:
        raise RuntimeError("Jarvis root not found; set F_VRA_JARVIS_ROOT or pass --jarvis-root")

    manifest = {
        "project": project,
        "run_dir": str(run_dir),
        "started_at_epoch": time.time(),
        "steps": [],
    }
    _write_json(run_dir / "manifest.json", manifest)

    graph, usage_index = build_jarvis_project_graph(
        project_root,
        JarvisOptions(
            jarvis_root=jarvis_root,
            runner=args.runner,
            scope=args.scope,
            mode=args.mode,
            timeout_s=args.timeout,
        ),
    )
    project_graph_artifact = _graph_artifact(project_root, graph, usage_index)
    _write_json(run_dir / "project_graph_jarvis.json", project_graph_artifact)
    _write_json(run_dir / "usage_index.json", _graph_summary(graph, usage_index))

    dependency_graph = resolve_dependency_graph(project_root)
    _write_json(run_dir / "dependency_graph.json", dependency_graph)

    requirements = project_root / "requirements.txt"
    audit = _run_pip_audit(requirements, run_dir / "sca_pip_audit.json")
    vulnerable_packages = _vulnerable_packages(audit)
    _write_json(run_dir / "package_vulnerabilities.json", vulnerable_packages)

    benchmark_records = _benchmark_records_for_project(_resolve(args.benchmark), args.project_id)
    true_vf_targets = {
        record["group_id"] or record["cve_id"]: record["target_vfs"]
        for record in benchmark_records
    }
    targets = sorted({target for values in true_vf_targets.values() for target in values})

    usage_roots = {node.target_module.split(".", 1)[0] for node in usage_index if node.target_module}
    target_roots = {_target_root(target) for target in targets if _target_root(target)}
    roots = sorted(usage_roots | target_roots)
    summaries: dict[str, LibrarySummary] = {}
    summary_status: list[dict[str, Any]] = []
    summary_dir = run_dir / "package_summaries"
    for root in roots:
        summary, status = _build_summary_for_root(root)
        summary_status.append(status)
        if summary is None:
            continue
        summaries[root] = summary
        _write_json(summary_dir / f"{root}.json", summary)
    _write_json(run_dir / "package_summary_status.json", summary_status)

    proxy_targets = _proxy_targets_from_usage(usage_index, vulnerable_packages)
    proxy_target_set = sorted({target for values in proxy_targets.values() for target in values})

    if targets:
        target_source = "vf_annotations"
        query_targets = set(targets)
    else:
        target_source = "package_level_usage_proxy"
        query_targets = set(proxy_target_set)

    query_report = ReachabilityQueryEngine(
        usage_index,
        summaries,
        query_targets,
        max_depth=args.max_depth,
        max_paths=args.max_paths,
    ).check_reachability()
    verdict, uncertainty = decide_reachability_verdict(
        query_report,
        query_targets,
        summaries,
        usage_index,
        graph_metadata=graph.metadata,
    )
    query_report.paths = _with_project_callers(query_report.paths, graph)

    reachability = {
        "verdict": verdict.value if query_targets else "unknown",
        "target_source": target_source if query_targets else "none",
        "target_source_note": (
            "No VF-level annotation was available; proxy targets are Usage Index "
            "symbols belonging to packages with SCA findings."
            if target_source == "package_level_usage_proxy"
            else "VF-level annotations were used."
        ),
        "vulnerable_packages": vulnerable_packages,
        "proxy_vf_targets": proxy_targets,
        "true_vf_targets": true_vf_targets,
        "benchmark_records": benchmark_records,
        "query_targets": sorted(query_targets),
        "hit_set": sorted({path.vulnerable_target for path in query_report.paths}),
        "paths": [
            {
                "project_api": path.project_api,
                "target": path.vulnerable_target,
                "path": path.tpl_chain,
                "used_summaries": path.used_summaries,
            }
            for path in query_report.paths
        ],
        "unresolved_targets": query_report.unresolved_targets,
        "unresolved_frontier": query_report.unresolved_frontier,
        "loaded_summaries": sorted(summaries),
        "used_summaries": query_report.used_summaries,
        "uncertainty": uncertainty,
    }
    _write_json(run_dir / "reachability_report.json", reachability)

    summary = {
        "project": project,
        "artifacts": {
            "manifest": str(run_dir / "manifest.json"),
            "project_graph": str(run_dir / "project_graph_jarvis.json"),
            "usage_index": str(run_dir / "usage_index.json"),
            "dependency_graph": str(run_dir / "dependency_graph.json"),
            "sca": str(run_dir / "sca_pip_audit.json"),
            "package_vulnerabilities": str(run_dir / "package_vulnerabilities.json"),
            "package_summary_status": str(run_dir / "package_summary_status.json"),
            "package_summaries": str(summary_dir),
            "reachability": str(run_dir / "reachability_report.json"),
        },
        "counts": {
            "project_nodes": len(graph.nodes),
            "project_edges": len(graph.edges),
            "usage_index": len(usage_index),
            "dependencies": len(dependency_graph.dependencies),
            "vulnerable_packages": len(vulnerable_packages),
            "package_summary_roots": len(summaries),
            "vf_annotation_records": len(benchmark_records),
            "vf_targets": len(targets),
            "query_targets": len(query_targets),
            "reachable_paths": len(query_report.paths),
        },
        "verdict": reachability["verdict"],
        "target_source": reachability["target_source"],
    }
    _write_json(run_dir / "summary.json", summary)
    _write_json(REPO_ROOT / "results" / "metrics" / f"{args.project_id}_full_reachability_summary.json", summary)

    print(f"PASS full-pipeline {args.project_id}")
    print(f"run_dir: {run_dir.relative_to(REPO_ROOT)}")
    print(f"project: nodes={len(graph.nodes)} edges={len(graph.edges)} usage_index={len(usage_index)}")
    print(f"dependencies: {len(dependency_graph.dependencies)}")
    print(f"vulnerable_packages: {len(vulnerable_packages)}")
    print(f"package_summaries: {len(summaries)}/{len(roots)}")
    print(f"reachability: verdict={reachability['verdict']} paths={len(query_report.paths)} target_source={reachability['target_source']}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local full reachability pipeline.")
    parser.add_argument("--project-id", default="alerta")
    parser.add_argument("--local-projects", type=Path, default=REPO_ROOT / "configs" / "local_projects.json")
    parser.add_argument("--jarvis-root", type=Path, default=None)
    parser.add_argument("--runner", choices=["docker", "local"], default="docker")
    parser.add_argument("--scope", choices=["entrypoints", "whole-project", "whole_project", "all"], default="entrypoints")
    parser.add_argument("--mode", choices=["EA", "DW", "AW"], default="EA")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--max-depth", type=int, default=25)
    parser.add_argument("--max-paths", type=int, default=100)
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "artifacts" / "pipeline_runs" / "alerta_full_reachability")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
