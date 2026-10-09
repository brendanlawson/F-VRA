"""Recover failed targeted package summaries from captured Conda runtimes.

This runner deliberately does not install packages and does not invoke Jarvis.
It consumes the existing runtime and Jarvis graph artifacts, retries only the
requested failed roots, and writes a separate recovery run for auditability.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from f_vra.core.models import CallEdge, CallGraph, ExternalNode, FunctionNode, PackageSummaryArtifact  # noqa: E402
from f_vra.reachability.service import _with_project_callers  # noqa: E402
from f_vra.runtime.conda import RuntimeEnvironment, RuntimePackage  # noqa: E402
from f_vra.runtime.progress import ProgressMonitor  # noqa: E402

from run_conda_cve_vf_rebuild import (  # noqa: E402
    SUMMARY_BUILDER_VERSION,
    _DiskBackedSummaryMap,
    _build_package_summary_isolated,
    _csv_row,
    _join,
    _load_json,
    _map_target_import_root,
    _query_record,
    _summary_counts,
    _write_json,
)
from run_current_cve_vf_full_reachability import _benchmark_by_project  # noqa: E402


DEFAULT_SOURCE_RUN = REPO_ROOT / ".tmp" / "current_run_sources" / "reachability_run_conda_targeted_28"
DEFAULT_RECOVERY_RUN = REPO_ROOT / ".tmp" / "current_run_sources" / "reachability_run_conda_targeted_28_recovery"

TARGET_FAILURES: dict[str, set[str]] = {
    "eosphoros-ai__DB-GPT": {"vllm", "transformers", "pip", "torch", "ray", "urllib3"},
    "Cinnamon__kotaemon": {"nltk", "torch", "transformers"},
    "Chainlit__chainlit": {"nltk"},
    "Open-LLM-VTuber__Open-LLM-VTuber": {"torch"},
    "ATH-MaaS__Pixelle-MCP": {"litellm"},
}


def _node(name: str, external: bool, project_root: Path) -> FunctionNode:
    if external:
        module, _, target = name.rpartition(".")
        return ExternalNode(
            file_path="",
            function_name=name,
            qualified_name=name,
            target_module=module,
            target_name=target or module,
        )
    return FunctionNode(
        file_path=str(project_root),
        function_name=name,
        qualified_name=name,
    )


def _load_graph(project_root: Path, path: Path) -> tuple[CallGraph, list[ExternalNode]]:
    payload = _load_json(path)
    graph_payload = payload.get("graph") or {}
    graph = CallGraph(metadata=dict(graph_payload.get("metadata") or {}))
    nodes: dict[tuple[str, bool], FunctionNode] = {}

    def get_node(name: str, external: bool) -> FunctionNode:
        key = (name, external)
        if key not in nodes:
            nodes[key] = _node(name, external, project_root)
            graph.add_node(nodes[key])
        return nodes[key]

    for edge_payload in graph_payload.get("edges_detail", []) or []:
        caller_name = str(edge_payload.get("caller") or "")
        callee_name = str(edge_payload.get("callee") or "")
        if not caller_name or not callee_name:
            continue
        caller = get_node(caller_name, False)
        callee = get_node(callee_name, str(edge_payload.get("callee_type")) == "external")
        graph.edges.append(
            CallEdge(
                caller=caller,
                callee=callee,
                edge_type=str(edge_payload.get("edge_type") or "confirmed_static"),
                confidence=float(edge_payload.get("confidence") or 1.0),
                resolver=str(edge_payload.get("resolver") or "static"),
                reason=str(edge_payload.get("reason") or ""),
                call_expr=str(edge_payload.get("call_expr") or ""),
                line_number=int(edge_payload.get("line_number") or 0),
            )
        )

    usage: list[ExternalNode] = []
    for name in payload.get("usage_index", []) or []:
        external = get_node(str(name), True)
        if isinstance(external, ExternalNode):
            usage.append(external)
    return graph, usage


def _project_root(project_id: str) -> Path:
    return (REPO_ROOT / "data" / "raw" / "projects" / project_id).resolve()


def _load_statuses(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    payload = _load_json(path)
    return [dict(item) for item in payload if isinstance(item, dict) and item.get("root")]


def _register_summaries(statuses: list[dict[str, Any]]) -> _DiskBackedSummaryMap:
    summaries = _DiskBackedSummaryMap()
    for item in statuses:
        if item.get("status") not in {"built", "built_with_warnings"}:
            continue
        summary_path = Path(str(item.get("summary_path") or ""))
        if summary_path.exists():
            summaries.register(str(item["root"]), summary_path, warning=item["status"] == "built_with_warnings")
    return summaries


def _merge_statuses(base: list[dict[str, Any]], updates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged = {str(item["root"]): dict(item) for item in base if item.get("root")}
    merged.update({str(item["root"]): dict(item) for item in updates if item.get("root")})
    return [merged[root] for root in sorted(merged)]


def _write_history(path: Path, events: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True, default=str) + "\n")


def recover_project(project_id: str, source_root: Path, recovery_root: Path, records: list[dict[str, Any]], monitor: ProgressMonitor) -> dict[str, Any]:
    started = time.perf_counter()
    source_dir = source_root / project_id
    out_dir = recovery_root / project_id
    out_dir.mkdir(parents=True, exist_ok=True)
    runtime_payload = _load_json(source_dir / "runtime_environment.json")
    runtime = RuntimeEnvironment.from_json(runtime_payload)
    if not runtime.fingerprint or not runtime.prefix:
        raise RuntimeError("runtime snapshot has no fingerprint or Conda prefix")
    if not Path(runtime.prefix).exists():
        raise RuntimeError(f"captured Conda prefix does not exist: {runtime.prefix}")
    _write_json(out_dir / "runtime_environment.json", runtime.to_json())
    for filename in ("dependency_graph.json", "project_graph_jarvis.json", "usage_index.json"):
        source_path = source_dir / filename
        if source_path.exists():
            shutil.copy2(source_path, out_dir / filename)

    base_statuses = _load_statuses(source_dir / "package_summary_status.json")
    retry_roots = sorted(TARGET_FAILURES[project_id])
    package_by_root = runtime.package_by_root()
    summary_dir = out_dir / "package_summaries"
    summary_dir.mkdir(parents=True, exist_ok=True)
    monitor.emit({"project": project_id, "phase": "summary_recovery_started", "package_total": len(retry_roots)})
    history: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []

    for attempt, root in enumerate(retry_roots, 1):
        package = package_by_root.get(root)
        started_root = time.perf_counter()
        event: dict[str, Any] = {
            "project": project_id,
            "root": root,
            "attempt": attempt,
            "summary_builder_version": SUMMARY_BUILDER_VERSION,
            "environment_fingerprint": runtime.fingerprint,
            "package_version": package.version if package else "",
            "status_before": next((item.get("status") for item in base_statuses if item.get("root") == root), "missing"),
        }
        telemetry: dict[str, Any] = {}
        try:
            if package is None:
                raise RuntimeError(f"failed root is not present in captured runtime: {root}")
            built = _build_package_summary_isolated(
                root,
                runtime,
                out_dir / "runtime_environment.json",
                out_dir,
                monitor,
                summary_timeout_seconds=None,
                resource_telemetry=telemetry,
            )
            if built is None:
                status = "no_python_source"
                summary_path = ""
                error = "runtime root has no accessible Python source"
            else:
                key, artifact_path, has_warnings = built
                summary_path_obj = summary_dir / f"{root}__{package.normalized_name}__{package.version or 'unknown'}__env-{runtime.fingerprint[:16]}__src-{package.source_fingerprint[:16]}.json"
                shutil.copy2(artifact_path, summary_path_obj)
                status = "built_with_warnings" if has_warnings else "built"
                summary_path = str(summary_path_obj)
                error = ""
                updates.append(
                    {
                        "root": root,
                        "package": package.name,
                        "package_version": package.version,
                        "source_path": package.source_path,
                        "source_fingerprint": package.source_fingerprint,
                        "environment_fingerprint": runtime.fingerprint,
                        "python_version": runtime.python_version,
                        "summary_attempted": True,
                        "summary_builder_version": SUMMARY_BUILDER_VERSION,
                        "status": status,
                        "summary_key": key,
                        "summary_path": str(summary_path_obj),
                        "summary_source_path": package.source_path,
                        "elapsed_s": round(time.perf_counter() - started_root, 3),
                        "retry_attempt": attempt,
                        "resource_telemetry": telemetry,
                    }
                )
        except Exception as exc:
            status = "analysis_failed"
            summary_path = ""
            error = f"{type(exc).__name__}: {exc}"
            updates.append(
                {
                    "root": root,
                    "package": package.name if package else "",
                    "package_version": package.version if package else "",
                    "source_path": package.source_path if package else "",
                    "source_fingerprint": package.source_fingerprint if package else "",
                    "environment_fingerprint": runtime.fingerprint,
                    "python_version": runtime.python_version,
                    "summary_attempted": bool(package),
                    "summary_builder_version": SUMMARY_BUILDER_VERSION,
                    "status": status,
                    "error": error,
                    "retry_attempt": attempt,
                    "resource_telemetry": telemetry,
                    "elapsed_s": round(time.perf_counter() - started_root, 3),
                }
            )
        event.update({"status_after": status, "summary_path": summary_path, "error": error, "elapsed_s": round(time.perf_counter() - started_root, 3), "resource_telemetry": telemetry})
        history.append(event)
        monitor.emit({"project": project_id, "phase": "summary_recovery_completed", "package": root, "status": status, "attempt": attempt})

    merged_statuses = _merge_statuses(base_statuses, updates)
    _write_json(out_dir / "package_summary_status.json", merged_statuses)
    _write_history(out_dir / "summary_retry_history.jsonl", history)

    graph, usage_index = _load_graph(_project_root(project_id), out_dir / "project_graph_jarvis.json")
    summaries = _register_summaries(merged_statuses)
    record_payloads: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    loaded_summary_roots: set[str] = set()
    import_root_map: dict[str, dict[str, Any]] = {}
    target_resolution_rows: list[dict[str, Any]] = []
    for record in records:
        result = _query_record(record, graph, usage_index, summaries, merged_statuses, runtime, max_depth=25, max_paths=100)
        record_payloads.append(result)
        loaded_summary_roots.update(str(item) for item in result.get("loaded_summaries") or [])
        for mapping in result.get("import_root_mapping") or []:
            key = f"{mapping.get('original', '')}|{mapping.get('package', record.get('package', ''))}"
            import_root_map[key] = mapping
        target_resolution_rows.append(
            {
                "cve_id": record.get("cve_id", ""),
                "package": record.get("package", ""),
                "target_vfs": result.get("original_query_targets", []),
                "query_targets": result.get("query_targets", []),
                "target_summary_status": result.get("target_summary_status", {}),
                "missing_target_summary_roots": result.get("missing_target_summary_roots", []),
            }
        )
        rows.append(_csv_row(result, project_id, "docker", graph, usage_index, round(time.perf_counter() - started, 3)))
        summaries.clear_loaded()
    report = {
        "project": _load_json(source_dir / "summary.json").get("project", {"id": project_id}),
        "runtime_environment_fingerprint": runtime.fingerprint,
        "target_source": "vf_annotations",
        "records": record_payloads,
        "counts": {
            "records": len(record_payloads),
            "query_targets": len({target for record in records for target in record.get("target_vfs", [])}),
            "verdict_counts": {key: sum(1 for item in record_payloads if item.get("verdict") == key) for key in {item.get("verdict") for item in record_payloads}},
            "paths": sum(int(item.get("path_count") or 0) for item in record_payloads),
        },
    }
    _write_json(out_dir / "reachability_report.json", report)
    _write_json(out_dir / "distribution_import_root_map.json", sorted(import_root_map.values(), key=lambda item: (str(item.get("package", "")), str(item.get("original", "")))))
    _write_json(out_dir / "target_resolution_status.json", target_resolution_rows)
    old_summary = _load_json(source_dir / "summary.json")
    summary = {
        **old_summary,
        "status": "success",
        "runner": "docker",
        "environment_fingerprint": runtime.fingerprint,
        "artifacts": {
            **(old_summary.get("artifacts") or {}),
            "runtime_environment": str(out_dir / "runtime_environment.json"),
            "package_summary_status": str(out_dir / "package_summary_status.json"),
            "reachability": str(out_dir / "reachability_report.json"),
        },
        "counts": {
            **(old_summary.get("counts") or {}),
            "records": len(record_payloads),
            "query_targets": report["counts"]["query_targets"],
            "package_summary_status": _summary_counts(merged_statuses),
            "available_summaries": len(summaries),
            "loaded_summaries": len(loaded_summary_roots),
        },
        "recovery": {"summary_roots": retry_roots, "history": str(out_dir / "summary_retry_history.jsonl")},
        "elapsed_s": round(time.perf_counter() - started, 3),
    }
    _write_json(out_dir / "summary.json", summary)
    _write_json(out_dir / "project_state.json", {"project": project_id, "status": "completed", "environment_fingerprint": runtime.fingerprint, "summary_completed": len(merged_statuses), "summary_total": len(merged_statuses), "updated_at": time.time()})
    return {"project": project_id, "summary": summary, "rows": rows, "history": history}


def main() -> int:
    parser = argparse.ArgumentParser(description="Retry failed targeted package summaries using captured Conda runtimes.")
    parser.add_argument("--source-run", type=Path, default=DEFAULT_SOURCE_RUN)
    parser.add_argument("--recovery-run", type=Path, default=DEFAULT_RECOVERY_RUN)
    parser.add_argument("--benchmark", type=Path, default=REPO_ROOT / "data" / "final" / "cve_vf_benchmark_accepted.jsonl")
    parser.add_argument("--project-id", action="append", choices=sorted(TARGET_FAILURES), default=[])
    args = parser.parse_args()
    source_root = args.source_run.resolve()
    recovery_root = args.recovery_run.resolve()
    recovery_root.mkdir(parents=True, exist_ok=True)
    _, grouped = _benchmark_by_project(args.benchmark.resolve())
    projects = args.project_id or sorted(TARGET_FAILURES)
    monitor = ProgressMonitor(recovery_root)
    results: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for project_id in projects:
        try:
            results.append(recover_project(project_id, source_root, recovery_root, grouped.get(project_id, []), monitor))
        except Exception as exc:
            failure = {"project": project_id, "status": "analysis_failed", "error": f"{type(exc).__name__}: {exc}"}
            failures.append(failure)
            monitor.emit({"project": project_id, "phase": "summary_recovery_failed", "error": failure["error"]})
    _write_json(recovery_root / "recovery_manifest.json", {"source_run": str(source_root), "projects_requested": projects, "projects_completed": len(results), "projects_failed": len(failures), "failures": failures, "summary_roots": {project: sorted(TARGET_FAILURES[project]) for project in projects}, "builder_version": SUMMARY_BUILDER_VERSION})
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
