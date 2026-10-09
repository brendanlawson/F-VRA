"""Refresh runtime import mappings and rerun affected-project queries.

This is deliberately a second phase: it consumes the recovery summary
artifacts, re-captures metadata from the existing Conda prefixes (without
installing anything), builds only summaries for mapped benchmark targets, and
then reruns reachability against the existing Jarvis graph.
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

from f_vra.runtime.conda import CondaEnvironmentManager, RuntimeEnvironment  # noqa: E402
from f_vra.runtime.progress import ProgressMonitor  # noqa: E402

from recover_targeted_summaries import (  # noqa: E402
    TARGET_FAILURES,
    _load_graph,
    _load_statuses,
    _merge_statuses,
    _project_root,
    _register_summaries,
)
from run_conda_cve_vf_rebuild import (  # noqa: E402
    SUMMARY_BUILDER_VERSION,
    _build_package_summary_isolated,
    _csv_row,
    _map_target_import_root,
    _package_for_import_root,
    _query_record,
    _summary_counts,
    _write_json,
)
from run_current_cve_vf_full_reachability import _benchmark_by_project, _load_json  # noqa: E402


DEFAULT_RUN = REPO_ROOT / ".tmp" / "current_run_sources" / "reachability_run_conda_targeted_28_recovery"


def _target_records(records: list[dict[str, Any]]) -> tuple[set[str], list[dict[str, Any]]]:
    roots: set[str] = set()
    mappings: list[dict[str, Any]] = []
    for record in records:
        for value in record.get("target_vfs") or []:
            original = value.get("qualified_name", "") if isinstance(value, dict) else str(value)
            canonical, mapping = _map_target_import_root(original, str(record.get("package") or ""), _target_records.runtime)
            roots.add(canonical.split(".", 1)[0] if canonical else "")
            mappings.append(mapping)
    return {root for root in roots if root}, mappings


def _write_project_outputs(
    project_id: str,
    records: list[dict[str, Any]],
    source_dir: Path,
    out_dir: Path,
    runtime: RuntimeEnvironment,
    statuses: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
) -> dict[str, Any]:
    graph, usage_index = _load_graph(_project_root(project_id), out_dir / "project_graph_jarvis.json")
    summaries = _register_summaries(
        [
            item
            for item in statuses
            if item.get("environment_fingerprint") == runtime.fingerprint
        ]
    )
    payloads: list[dict[str, Any]] = []
    rows: list[dict[str, Any]] = []
    target_resolution: list[dict[str, Any]] = []
    started = time.perf_counter()
    for record in records:
        result = _query_record(record, graph, usage_index, summaries, statuses, runtime, max_depth=25, max_paths=100)
        payloads.append(result)
        target_resolution.append(
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
        "records": payloads,
        "counts": {
            "records": len(payloads),
            "query_targets": len({target for record in records for target in record.get("target_vfs", [])}),
            "verdict_counts": {
                key: sum(1 for item in payloads if item.get("verdict") == key)
                for key in {item.get("verdict") for item in payloads}
            },
            "paths": sum(int(item.get("path_count") or 0) for item in payloads),
        },
    }
    _write_json(out_dir / "reachability_report.json", report)
    unique_mappings = {json.dumps(item, sort_keys=True): item for item in [*mappings, *(m for p in payloads for m in p.get("import_root_mapping") or [])]}
    _write_json(out_dir / "distribution_import_root_map.json", sorted(unique_mappings.values(), key=lambda item: (str(item.get("package", "")), str(item.get("original", "")))))
    _write_json(out_dir / "target_resolution_status.json", target_resolution)
    return {"report": report, "rows": rows}


def recover_project(project_id: str, recovery_root: Path, records: list[dict[str, Any]], monitor: ProgressMonitor) -> dict[str, Any]:
    source_dir = recovery_root / project_id
    out_dir = source_dir
    runtime = RuntimeEnvironment.from_json(_load_json(out_dir / "runtime_environment.json"))
    prefix = Path(runtime.prefix)
    if not prefix.exists():
        raise RuntimeError(f"existing Conda prefix is unavailable: {prefix}")

    manager = CondaEnvironmentManager(recovery_root / "_capture_workspaces")
    monitor.emit({"project": project_id, "phase": "import_root_runtime_refresh_started"})
    refreshed = manager.capture(
        project_id,
        Path(runtime.project_path),
        prefix,
        log_dir=out_dir / "commands",
        progress=monitor.command_progress(project_id, "runtime_capture"),
        install_commands=runtime.install_commands,
        bootstrap_tools=runtime.bootstrap_tools,
    )
    _write_json(out_dir / "runtime_environment.json", refreshed.to_json())
    _target_records.runtime = refreshed
    selected_roots, mappings = _target_records(records)
    old_statuses = _load_statuses(out_dir / "package_summary_status.json")
    updates: list[dict[str, Any]] = []
    summary_dir = out_dir / "package_summaries"
    summary_dir.mkdir(parents=True, exist_ok=True)
    by_root = refreshed.package_by_root()
    for index, root in enumerate(sorted(selected_roots), 1):
        package = by_root.get(root)
        monitor.emit({"project": project_id, "phase": "import_root_summary_building", "package": root, "completed": index - 1, "total": len(selected_roots)})
        base = next((item for item in old_statuses if item.get("root") == root), None)
        if package is None:
            updates.append({"root": root, "status": "not_installed_in_runtime", "summary_attempted": False, "environment_fingerprint": refreshed.fingerprint, "python_version": refreshed.python_version})
            continue
        package = _package_for_import_root(root, package, refreshed)
        if not package.python_source:
            updates.append({"root": root, "package": package.name, "package_version": package.version, "source_path": package.source_path, "source_fingerprint": package.source_fingerprint, "environment_fingerprint": refreshed.fingerprint, "python_version": refreshed.python_version, "summary_attempted": True, "status": "no_python_source"})
            continue
        if base and base.get("status") in {"built", "built_with_warnings"} and base.get("environment_fingerprint") == refreshed.fingerprint and Path(str(base.get("summary_path") or "")).exists():
            updates.append(dict(base))
            continue
        telemetry: dict[str, Any] = {}
        try:
            built = _build_package_summary_isolated(root, refreshed, out_dir / "runtime_environment.json", out_dir, monitor, summary_timeout_seconds=None, resource_telemetry=telemetry)
            if built is None:
                status = "no_python_source"
                summary_path = ""
                key = ""
                error = "runtime root has no accessible Python source"
                has_warnings = False
            else:
                key, artifact_path, has_warnings = built
                target = summary_dir / f"{root}__{package.normalized_name}__{package.version or 'unknown'}__env-{refreshed.fingerprint[:16]}__src-{package.source_fingerprint[:16]}.json"
                shutil.copy2(artifact_path, target)
                status = "built_with_warnings" if has_warnings else "built"
                summary_path = str(target)
                error = ""
            updates.append({"root": root, "package": package.name, "package_version": package.version, "source_path": package.source_path, "source_fingerprint": package.source_fingerprint, "environment_fingerprint": refreshed.fingerprint, "python_version": refreshed.python_version, "summary_attempted": True, "summary_builder_version": SUMMARY_BUILDER_VERSION, "status": status, "summary_key": key, "summary_path": summary_path, "summary_source_path": package.source_path, "resource_telemetry": telemetry, "error": error})
        except Exception as exc:
            updates.append({"root": root, "package": package.name, "package_version": package.version, "source_path": package.source_path, "source_fingerprint": package.source_fingerprint, "environment_fingerprint": refreshed.fingerprint, "python_version": refreshed.python_version, "summary_attempted": True, "summary_builder_version": SUMMARY_BUILDER_VERSION, "status": "analysis_failed", "error": f"{type(exc).__name__}: {exc}", "resource_telemetry": telemetry})
    statuses = _merge_statuses(old_statuses, updates)
    _write_json(out_dir / "package_summary_status.json", statuses)
    result = _write_project_outputs(project_id, records, source_dir, out_dir, refreshed, statuses, mappings)
    monitor.checkpoint(project_id, {"status": "completed", "phase": "import_root_mapping", "environment_fingerprint": refreshed.fingerprint, "summary_completed": len(updates), "summary_total": len(selected_roots)})
    return {"project": project_id, "rows": result["rows"], "counts": result["report"]["counts"], "selected_roots": sorted(selected_roots)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Apply runtime-verified distribution/import-root recovery.")
    parser.add_argument("--recovery-run", type=Path, default=DEFAULT_RUN)
    parser.add_argument("--benchmark", type=Path, default=REPO_ROOT / "data" / "final" / "cve_vf_benchmark_accepted.jsonl")
    parser.add_argument("--project-id", action="append", choices=sorted(TARGET_FAILURES), default=[])
    args = parser.parse_args()
    recovery_root = args.recovery_run.resolve()
    _, grouped = _benchmark_by_project(args.benchmark.resolve())
    projects = args.project_id or sorted(TARGET_FAILURES)
    monitor = ProgressMonitor(recovery_root)
    results = []
    for project_id in projects:
        if not (recovery_root / project_id / "summary_retry_history.jsonl").exists():
            raise RuntimeError(f"summary recovery is incomplete for {project_id}; run phase 1 first")
        monitor.emit({"project": project_id, "phase": "import_root_mapping_started"})
        results.append(recover_project(project_id, recovery_root, grouped.get(project_id, []), monitor))
    _write_json(recovery_root / "import_root_recovery_manifest.json", {"status": "completed", "projects": results, "phase": "import_root_mapping"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
