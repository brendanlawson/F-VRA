from __future__ import annotations

import argparse
import csv
import json
import statistics
import subprocess
import sys
import time
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from f_vra.analysis.callgraph.jarvis_backend import JarvisOptions, build_jarvis_project_graph  # noqa: E402
from f_vra.analysis.dependencies.resolver import resolve_dependency_graph  # noqa: E402
from f_vra.core.models import LibrarySummary, Verdict  # noqa: E402
from f_vra.reachability.engine import ReachabilityQueryEngine  # noqa: E402
from f_vra.reachability.service import _graph_artifact, _with_project_callers, decide_reachability_verdict  # noqa: E402

from build_local_projects_manifest import build_manifest  # noqa: E402
from run_full_reachability_pipeline import (  # noqa: E402
    DEFAULT_BENCHMARK,
    _benchmark_records_for_project,
    _default_jarvis_root,
    _graph_summary,
    _json_default,
    _load_json,
    _load_jsonl,
    _resolve,
    _target_root,
    _target_vfs,
    _write_json,
)


DEFAULT_LOCAL_PROJECTS = REPO_ROOT / "configs" / "local_projects.json"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "artifacts" / "pipeline_runs" / "current_cve_vf_full_reachability"
DEFAULT_RESULTS_JSON = REPO_ROOT / "results" / "metrics" / "current_cve_vf_full_reachability_summary.json"
DEFAULT_RESULTS_CSV = REPO_ROOT / "results" / "tables" / "current_cve_vf_reachability_results.csv"
DEFAULT_RESULTS_MD = REPO_ROOT / "results" / "tables" / "current_cve_vf_reachability_report.md"


def _root(identity: str) -> str:
    return identity.split(".", 1)[0] if identity else ""


def _counter_dict(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return round(values[0], 3)
    ordered = sorted(values)
    index = (len(ordered) - 1) * percentile
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    weight = index - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 3)


def _join(values: list[str] | set[str]) -> str:
    return ";".join(sorted(str(value) for value in values if str(value)))


def _manifest_projects(path: Path) -> dict[str, dict[str, Any]]:
    payload = _load_json(path)
    return {project["id"]: project for project in payload.get("projects", []) if project.get("enabled", True)}


def _benchmark_by_project(path: Path) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    records = [record for record in _load_jsonl(path) if record.get("benchmark_status") == "accepted"]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        targets = _target_vfs(record)
        if not targets:
            continue
        item = {
            "group_id": record.get("group_id", ""),
            "cve_id": record.get("cve_id", ""),
            "package": record.get("package", ""),
            "evidence_level": record.get("evidence_level", ""),
            "mapping_type": record.get("mapping_type", ""),
            "confidence": record.get("confidence", ""),
            "target_vfs": targets,
            "scan_alert_count": record.get("scan_alert_count", 0),
            "scanner_count": record.get("scanner_count", 0),
            "scanners": record.get("scanners", []),
            "resolved_versions": record.get("resolved_versions", []),
        }
        for project in record.get("projects") or []:
            grouped[project].append(dict(item, project=project))
    return records, grouped


def _try_build_jarvis(
    project_root: Path,
    *,
    jarvis_root: Path,
    primary_runner: str,
    fallback_runner: str,
    scope: str,
    mode: str,
    timeout: int,
) -> tuple[Any | None, list[Any] | None, list[dict[str, Any]]]:
    attempts: list[dict[str, Any]] = []
    runners = [primary_runner]
    if fallback_runner and fallback_runner not in runners:
        runners.append(fallback_runner)
    for runner in runners:
        # Docker Desktop can be alive while its Linux engine named pipe is
        # still coming up.  Retry that infrastructure condition briefly; do
        # not retry analyzer failures or hide them as timeouts.
        docker_attempts = 3 if runner == "docker" else 1
        for attempt_number in range(1, docker_attempts + 1):
            started = time.perf_counter()
            try:
                graph, usage_index = build_jarvis_project_graph(
                    project_root,
                    JarvisOptions(
                        jarvis_root=jarvis_root,
                        runner=runner,
                        scope=scope,
                        mode=mode,
                        timeout_s=timeout,
                    ),
                )
            except Exception as exc:
                error_text = f"{type(exc).__name__}: {exc}"
                attempts.append(
                    {
                        "runner": runner,
                        "attempt": attempt_number,
                        "status": "failed",
                        "elapsed_s": round(time.perf_counter() - started, 3),
                        "error": error_text,
                    }
                )
                docker_pipe_error = runner == "docker" and any(
                    marker in error_text.lower()
                    for marker in ("docker api", "dockerdesktoplinuxengine", "docker daemon")
                )
                if docker_pipe_error and attempt_number < docker_attempts:
                    time.sleep(5)
                    continue
                break
            attempts.append(
                {
                    "runner": runner,
                    "attempt": attempt_number,
                    "status": "success",
                    "elapsed_s": round(time.perf_counter() - started, 3),
                }
            )
            return graph, usage_index, attempts
    return None, None, attempts


def _build_project_summaries(
    roots: list[str],
    run_dir: Path,
    *,
    cache: dict[str, tuple[LibrarySummary | None, dict[str, Any]]],
    max_roots: int,
    summary_depth: int,
    root_timeout_s: int,
) -> tuple[dict[str, LibrarySummary], list[dict[str, Any]]]:
    summaries: dict[str, LibrarySummary] = {}
    statuses: list[dict[str, Any]] = []
    queue: list[tuple[str, int]] = [(root, 0) for root in roots if root]
    queued = {root for root, _depth in queue}
    seen: set[str] = set()

    while queue and len(seen) < max_roots:
        root, depth = queue.pop(0)
        if root in seen:
            continue
        seen.add(root)
        if root in cache:
            summary, original_status = cache[root]
            status = dict(original_status)
            status["status"] = f"{status.get('status', 'unknown')}_cached"
            status["elapsed_s"] = 0.0
        else:
            summary, status = _build_summary_for_root_with_timeout(root, root_timeout_s)
            cache[root] = (summary, dict(status))
        status["depth"] = depth
        statuses.append(status)
        if summary is None:
            continue
        summaries[root] = summary
        _write_json(run_dir / "package_summaries" / f"{root}.json", summary)
        if depth >= summary_depth:
            continue
        next_roots = sorted(
            {
                _root(target)
                for targets in summary.outer_summary.values()
                for target in targets
                if _root(target) and _root(target) not in seen
            }
        )
        for next_root in next_roots:
            if next_root not in queued and len(queued) < max_roots:
                queue.append((next_root, depth + 1))
                queued.add(next_root)
    return summaries, statuses


def _query_record(
    record: dict[str, Any],
    graph: Any,
    usage_index: list[Any],
    summaries: dict[str, LibrarySummary],
    summary_status: list[dict[str, Any]],
    *,
    max_depth: int,
    max_paths: int,
) -> dict[str, Any]:
    started = time.perf_counter()
    targets = set(record["target_vfs"])
    report = ReachabilityQueryEngine(
        usage_index,
        summaries,
        targets,
        max_depth=max_depth,
        max_paths=max_paths,
    ).check_reachability()
    verdict, uncertainty = decide_reachability_verdict(
        report,
        targets,
        summaries,
        usage_index,
        graph_metadata=graph.metadata,
    )
    report.paths = _with_project_callers(report.paths, graph)

    usage_roots = {_root(node.identity_string) for node in usage_index if node.identity_string}
    target_roots = {_target_root(target) for target in targets if _target_root(target)}
    missing_roots = {
        status["root"]
        for status in summary_status
        if status.get("root") in target_roots and str(status.get("status", "")).startswith(("missing_source", "failed"))
    }
    if verdict == Verdict.NOT_REACHABLE and usage_roots & missing_roots:
        verdict = Verdict.POTENTIALLY_REACHABLE
        uncertainty.setdefault("missing_target_summary_roots", sorted(usage_roots & missing_roots))

    paths = [
        {
            "project_api": path.project_api,
            "target": path.vulnerable_target,
            "path": path.tpl_chain,
            "used_summaries": path.used_summaries,
        }
        for path in report.paths
    ]
    return {
        **record,
        "target_source": "vf_annotations",
        "query_targets": sorted(targets),
        "verdict": verdict.value,
        "hit_set": sorted({path.vulnerable_target for path in report.paths}),
        "path_count": len(paths),
        "paths": paths,
        "path_lengths": [len(path["path"]) for path in paths],
        "used_summaries": report.used_summaries,
        "loaded_summaries": sorted(summaries),
        "unresolved_targets": report.unresolved_targets,
        "unresolved_frontier": report.unresolved_frontier,
        "uncertainty": uncertainty,
        "query_time_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "project",
        "cve_id",
        "group_id",
        "package",
        "evidence_level",
        "mapping_type",
        "target_count",
        "query_targets",
        "verdict",
        "path_count",
        "hit_count",
        "hit_set",
        "used_summaries",
        "loaded_summaries_count",
        "unresolved_targets_count",
        "unresolved_target_related_count",
        "missing_target_summary_roots",
        "jarvis_runner",
        "jarvis_status",
        "project_nodes",
        "project_edges",
        "usage_index",
        "query_time_ms",
        "project_elapsed_s",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fields})


def _summary_counts(statuses: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for status in statuses:
        value = str(status.get("status", "unknown"))
        base = value.removesuffix("_cached")
        counts[base] += 1
    return dict(sorted(counts.items()))


def _build_summary_for_root_with_timeout(root: str, timeout_s: int) -> tuple[LibrarySummary | None, dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="f_vra-summary-") as tmp:
        output = Path(tmp) / "summary.json"
        command = [
            sys.executable,
            str(REPO_ROOT / "experiments" / "build_package_summary_once.py"),
            root,
            str(output),
        ]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                cwd=str(REPO_ROOT),
                text=True,
                capture_output=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return None, {
                "root": root,
                "status": "failed_timeout",
                "error": f"package summary timed out after {timeout_s}s",
                "elapsed_s": round(time.perf_counter() - started, 3),
            }
        if not output.exists():
            return None, {
                "root": root,
                "status": "failed",
                "error": (completed.stderr or completed.stdout or "summary subprocess wrote no output")[-2000:],
                "elapsed_s": round(time.perf_counter() - started, 3),
            }
        payload = json.loads(output.read_text(encoding="utf-8"))
        status = dict(payload.get("status") or {})
        status.setdefault("root", root)
        status.setdefault("elapsed_s", round(time.perf_counter() - started, 3))
        summary_payload = payload.get("summary")
        summary = LibrarySummary.model_validate(summary_payload) if summary_payload else None
        return summary, status


def _csv_row_from_result(
    result: dict[str, Any],
    *,
    project_id: str,
    runner: str,
    jarvis_status: str,
    project_nodes: int,
    project_edges: int,
    usage_index_count: int,
    project_elapsed_s: float,
) -> dict[str, Any]:
    uncertainty = result.get("uncertainty") or {}
    return {
        "project": project_id,
        "cve_id": result["cve_id"],
        "group_id": result["group_id"],
        "package": result["package"],
        "evidence_level": result["evidence_level"],
        "mapping_type": result["mapping_type"],
        "target_count": len(result["query_targets"]),
        "query_targets": _join(result["query_targets"]),
        "verdict": result["verdict"],
        "path_count": result["path_count"],
        "hit_count": len(result["hit_set"]),
        "hit_set": _join(result["hit_set"]),
        "used_summaries": _join(result["used_summaries"]),
        "loaded_summaries_count": len(result["loaded_summaries"]),
        "unresolved_targets_count": len(result["unresolved_targets"]),
        "unresolved_target_related_count": len(uncertainty.get("unresolved_target_related") or []),
        "missing_target_summary_roots": _join(uncertainty.get("missing_target_summary_roots") or []),
        "jarvis_runner": runner,
        "jarvis_status": jarvis_status,
        "project_nodes": project_nodes,
        "project_edges": project_edges,
        "usage_index": usage_index_count,
        "query_time_ms": result["query_time_ms"],
        "project_elapsed_s": project_elapsed_s,
    }


def _markdown_report(summary: dict[str, Any], csv_path: Path) -> str:
    verdicts = summary["reachability"]["verdict_counts"]
    pipeline = summary["pipeline"]
    coverage = summary["benchmark"]
    return "\n".join(
        [
            "# Current CVE-VF Reachability Report",
            "",
            "## Scope",
            "",
            f"- Accepted CVE-VF records: {coverage['accepted_records']}",
            f"- Project-CVE query rows: {coverage['project_cve_query_rows']}",
            f"- Projects requested: {coverage['accepted_project_count']}",
            f"- VF targets queried: {coverage['vf_target_count']}",
            "",
            "## Pipeline Coverage",
            "",
            f"- Projects completed: {pipeline['projects_completed']}",
            f"- Projects failed: {pipeline['projects_failed']}",
            f"- Jarvis attempts: {pipeline['jarvis_attempt_counts']}",
            f"- Package summary statuses: {pipeline['package_summary_status_counts']}",
            "",
            "## Reachability Outcomes",
            "",
            f"- Verdict counts: {verdicts}",
            f"- Rows with witness paths: {summary['reachability']['rows_with_paths']}",
            f"- Total witness paths: {summary['reachability']['total_paths']}",
            f"- Median path length: {summary['witness_paths']['median_path_length']}",
            f"- Max path length: {summary['witness_paths']['max_path_length']}",
            "",
            "## Cost",
            "",
            f"- Total elapsed seconds: {summary['cost']['total_elapsed_s']}",
            f"- Jarvis elapsed seconds: {summary['cost']['jarvis_elapsed_s']}",
            f"- Package summary elapsed seconds: {summary['cost']['package_summary_elapsed_s']}",
            f"- Query latency p50/p95 ms: {summary['cost']['query_time_p50_ms']} / {summary['cost']['query_time_p95_ms']}",
            "",
            "## Accuracy And Safe Demotion",
            "",
            "Not computable from the current CVE-to-VF annotation alone. The current dataset supplies oracle VF anchors and evidence, but does not include adjudicated project-to-VF reachability labels. The CSV is denominator-ready for later gold-label adjudication.",
            "",
            "## Artifacts",
            "",
            f"- Query table: `{csv_path.relative_to(REPO_ROOT)}`",
            "- Per-project run directories: `artifacts/pipeline_runs/current_cve_vf_full_reachability/<project>/`",
            "- Target source: `vf_annotations`",
            "",
        ]
    )


def run(args: argparse.Namespace) -> int:
    started_all = time.perf_counter()
    if args.generate_local_projects or not _resolve(args.local_projects).exists():
        manifest_args = argparse.Namespace(
            environment_manifest=_resolve(args.environment_manifest),
            benchmark=_resolve(args.benchmark),
            output=_resolve(args.local_projects),
        )
        payload = build_manifest(manifest_args)
        _resolve(args.local_projects).parent.mkdir(parents=True, exist_ok=True)
        _resolve(args.local_projects).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    manifest = _manifest_projects(_resolve(args.local_projects))
    accepted_records, grouped = _benchmark_by_project(_resolve(args.benchmark))
    jarvis_root = _resolve(args.jarvis_root) if args.jarvis_root else _default_jarvis_root()
    if jarvis_root is None:
        raise RuntimeError("Jarvis root not found; set F_VRA_JARVIS_ROOT or pass --jarvis-root")

    output_dir = _resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_rows: list[dict[str, Any]] = []
    project_summaries: list[dict[str, Any]] = []
    summary_cache: dict[str, tuple[LibrarySummary | None, dict[str, Any]]] = {}

    projects = sorted(grouped)
    if args.project_id:
        wanted = set(args.project_id)
        projects = [project for project in projects if project in wanted]
    if args.limit:
        projects = projects[: args.limit]

    for index, project_id in enumerate(projects, 1):
        project_started = time.perf_counter()
        project = manifest.get(project_id)
        run_dir = output_dir / project_id
        run_dir.mkdir(parents=True, exist_ok=True)
        print(f"[{index}/{len(projects)}] {project_id}", flush=True)
        summary_path = run_dir / "summary.json"
        reachability_path = run_dir / "reachability_report.json"
        if args.resume and not args.force and summary_path.exists() and reachability_path.exists():
            project_summary = _load_json(summary_path)
            reachability_report = _load_json(reachability_path)
            if project_summary.get("status") == "success":
                print(f"  resume existing success", flush=True)
                project_summaries.append(project_summary)
                counts = project_summary.get("counts", {})
                for result in reachability_report.get("records", []):
                    all_rows.append(
                        _csv_row_from_result(
                            result,
                            project_id=project_id,
                            runner=str(project_summary.get("runner", "")),
                            jarvis_status="success",
                            project_nodes=int(counts.get("project_nodes") or 0),
                            project_edges=int(counts.get("project_edges") or 0),
                            usage_index_count=int(counts.get("usage_index") or 0),
                            project_elapsed_s=float(project_summary.get("elapsed_s") or 0),
                        )
                    )
                continue
        if project is None:
            failure = {"project": project_id, "status": "failed", "error": "project missing from local manifest"}
            _write_json(run_dir / "summary.json", failure)
            project_summaries.append(failure)
            continue

        project_root = _resolve(project["path"])
        graph, usage_index, jarvis_attempts = _try_build_jarvis(
            project_root,
            jarvis_root=jarvis_root,
            primary_runner=args.runner,
            fallback_runner=args.fallback_runner,
            scope=args.scope,
            mode=args.mode,
            timeout=args.timeout,
        )
        jarvis_success = graph is not None and usage_index is not None
        if not jarvis_success:
            failure = {
                "project": project,
                "status": "failed",
                "jarvis_attempts": jarvis_attempts,
                "elapsed_s": round(time.perf_counter() - project_started, 3),
            }
            _write_json(run_dir / "summary.json", failure)
            project_summaries.append(failure)
            for record in grouped[project_id]:
                all_rows.append(
                    {
                        "project": project_id,
                        "cve_id": record["cve_id"],
                        "group_id": record["group_id"],
                        "package": record["package"],
                        "evidence_level": record["evidence_level"],
                        "mapping_type": record["mapping_type"],
                        "target_count": len(record["target_vfs"]),
                        "query_targets": _join(record["target_vfs"]),
                        "verdict": "unknown",
                        "path_count": 0,
                        "hit_count": 0,
                        "hit_set": "",
                        "used_summaries": "",
                        "loaded_summaries_count": 0,
                        "unresolved_targets_count": 0,
                        "unresolved_target_related_count": 0,
                        "missing_target_summary_roots": "",
                        "jarvis_runner": "",
                        "jarvis_status": "failed",
                        "project_nodes": 0,
                        "project_edges": 0,
                        "usage_index": 0,
                        "query_time_ms": 0,
                        "project_elapsed_s": failure["elapsed_s"],
                    }
                )
            continue

        dependency_started = time.perf_counter()
        try:
            dependency_graph = resolve_dependency_graph(project_root)
            dependency_status = {
                "status": "success",
                "dependency_count": len(dependency_graph.dependencies),
                "elapsed_s": round(time.perf_counter() - dependency_started, 3),
            }
            _write_json(run_dir / "dependency_graph.json", dependency_graph)
        except Exception as exc:
            dependency_status = {
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "dependency_count": 0,
                "elapsed_s": round(time.perf_counter() - dependency_started, 3),
            }

        _write_json(run_dir / "project_graph_jarvis.json", _graph_artifact(project_root, graph, usage_index))
        _write_json(run_dir / "usage_index.json", _graph_summary(graph, usage_index))

        query_targets = sorted({target for record in grouped[project_id] for target in record["target_vfs"]})
        usage_roots = sorted({_root(node.identity_string) for node in usage_index if node.identity_string})
        target_roots = sorted({_target_root(target) for target in query_targets if _target_root(target)})
        initial_roots = sorted(set(usage_roots) | set(target_roots))
        summaries, summary_status = _build_project_summaries(
            initial_roots,
            run_dir,
            cache=summary_cache,
            max_roots=args.max_summary_roots,
            summary_depth=args.summary_depth,
            root_timeout_s=args.package_summary_timeout,
        )
        _write_json(run_dir / "package_summary_status.json", summary_status)

        record_payloads: list[dict[str, Any]] = []
        runner_used = next(item["runner"] for item in jarvis_attempts if item["status"] == "success")
        project_elapsed_for_rows = 0.0
        for record in grouped[project_id]:
            result = _query_record(
                record,
                graph,
                usage_index,
                summaries,
                summary_status,
                max_depth=args.max_depth,
                max_paths=args.max_paths,
            )
            record_payloads.append(result)
            project_elapsed_for_rows = round(time.perf_counter() - project_started, 3)
            all_rows.append(
                _csv_row_from_result(
                    result,
                    project_id=project_id,
                    runner=runner_used,
                    jarvis_status="success",
                    project_nodes=len(graph.nodes),
                    project_edges=len(graph.edges),
                    usage_index_count=len(usage_index),
                    project_elapsed_s=project_elapsed_for_rows,
                )
            )

        reachability_report = {
            "project": project,
            "target_source": "vf_annotations",
            "records": record_payloads,
            "counts": {
                "records": len(record_payloads),
                "query_targets": len(query_targets),
                "verdict_counts": _counter_dict([record["verdict"] for record in record_payloads]),
                "paths": sum(record["path_count"] for record in record_payloads),
            },
        }
        _write_json(run_dir / "reachability_report.json", reachability_report)

        project_summary = {
            "project": project,
            "status": "success",
            "runner": runner_used,
            "jarvis_attempts": jarvis_attempts,
            "dependency_graph": dependency_status,
            "artifacts": {
                "project_graph": str(run_dir / "project_graph_jarvis.json"),
                "usage_index": str(run_dir / "usage_index.json"),
                "package_summary_status": str(run_dir / "package_summary_status.json"),
                "reachability": str(run_dir / "reachability_report.json"),
            },
            "counts": {
                "project_nodes": len(graph.nodes),
                "project_edges": len(graph.edges),
                "usage_index": len(usage_index),
                "records": len(record_payloads),
                "query_targets": len(query_targets),
                "package_summary_status": _summary_counts(summary_status),
                "loaded_summaries": len(summaries),
            },
            "elapsed_s": round(time.perf_counter() - project_started, 3),
        }
        _write_json(run_dir / "summary.json", project_summary)
        project_summaries.append(project_summary)

    _write_csv(_resolve(args.results_csv), all_rows)

    completed_projects = [item for item in project_summaries if item.get("status") == "success"]
    failed_projects = [item for item in project_summaries if item.get("status") != "success"]
    query_times = [float(row["query_time_ms"]) for row in all_rows if row.get("jarvis_status") == "success"]
    path_lengths = [
        length
        for project_id in projects
        for payload_path in [(output_dir / project_id / "reachability_report.json")]
        if payload_path.exists()
        for record in _load_json(payload_path).get("records", [])
        for length in record.get("path_lengths", [])
    ]
    all_summary_statuses = [
        status
        for project_id in projects
        for status_path in [(output_dir / project_id / "package_summary_status.json")]
        if status_path.exists()
        for status in json.loads(status_path.read_text(encoding="utf-8"))
    ]
    jarvis_attempt_statuses = [
        f"{attempt['runner']}:{attempt['status']}"
        for project in project_summaries
        for attempt in project.get("jarvis_attempts", [])
    ]

    evidence_counts = _counter_dict([record.get("evidence_level", "") for record in accepted_records])
    mapping_counts = _counter_dict([record.get("mapping_type", "") for record in accepted_records])
    accepted_projects = sorted({project for record in accepted_records for project in record.get("projects") or []})
    vf_targets = sorted({target for record in accepted_records for target in _target_vfs(record)})
    summary_payload = {
        "benchmark": {
            "accepted_records": len(accepted_records),
            "accepted_project_count": len(accepted_projects),
            "project_cve_query_rows": len(all_rows),
            "vf_target_count": len(vf_targets),
            "evidence_level_counts": evidence_counts,
            "mapping_type_counts": mapping_counts,
        },
        "pipeline": {
            "projects_requested": len(projects),
            "projects_completed": len(completed_projects),
            "projects_failed": len(failed_projects),
            "failed_projects": [item.get("project", {}).get("id", item.get("project")) for item in failed_projects],
            "jarvis_attempt_counts": _counter_dict(jarvis_attempt_statuses),
            "package_summary_status_counts": _summary_counts(all_summary_statuses),
        },
        "reachability": {
            "verdict_counts": _counter_dict([str(row.get("verdict", "")) for row in all_rows]),
            "rows_with_paths": sum(1 for row in all_rows if int(row.get("path_count") or 0) > 0),
            "total_paths": sum(int(row.get("path_count") or 0) for row in all_rows),
            "rows_with_hits": sum(1 for row in all_rows if int(row.get("hit_count") or 0) > 0),
        },
        "witness_paths": {
            "median_path_length": round(statistics.median(path_lengths), 3) if path_lengths else 0,
            "max_path_length": max(path_lengths) if path_lengths else 0,
        },
        "cost": {
            "total_elapsed_s": round(sum(float(project.get("elapsed_s") or 0) for project in project_summaries), 3),
            "aggregation_elapsed_s": round(time.perf_counter() - started_all, 3),
            "jarvis_elapsed_s": round(
                sum(attempt.get("elapsed_s", 0) for project in project_summaries for attempt in project.get("jarvis_attempts", [])),
                3,
            ),
            "package_summary_elapsed_s": round(sum(float(status.get("elapsed_s") or 0) for status in all_summary_statuses), 3),
            "query_time_p50_ms": _percentile(query_times, 0.5),
            "query_time_p95_ms": _percentile(query_times, 0.95),
            "query_time_p99_ms": _percentile(query_times, 0.99),
        },
        "accuracy_and_safe_demotion": {
            "status": "not_computable",
            "reason": "Current artifacts provide CVE-to-VF annotations and evidence, but no adjudicated project-to-VF reachability labels.",
        },
        "artifacts": {
            "output_dir": str(output_dir),
            "results_csv": str(_resolve(args.results_csv)),
            "results_json": str(_resolve(args.results_json)),
            "results_markdown": str(_resolve(args.results_markdown)),
        },
    }
    _write_json(_resolve(args.results_json), summary_payload)
    _resolve(args.results_markdown).parent.mkdir(parents=True, exist_ok=True)
    _resolve(args.results_markdown).write_text(
        _markdown_report(summary_payload, _resolve(args.results_csv)),
        encoding="utf-8",
    )

    print("PASS current-cve-vf-full-reachability")
    print(f"projects: {len(completed_projects)}/{len(projects)} completed")
    print(f"rows: {len(all_rows)}")
    print(f"verdicts: {summary_payload['reachability']['verdict_counts']}")
    print(f"report: {_resolve(args.results_markdown).relative_to(REPO_ROOT)}")
    return 0 if not failed_projects else 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Run full Jarvis reachability over current accepted CVE-VF benchmark.")
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--local-projects", type=Path, default=DEFAULT_LOCAL_PROJECTS)
    parser.add_argument("--environment-manifest", type=Path, default=REPO_ROOT / "data" / "interim" / "resolved_versions" / "project_environment_manifest.csv")
    parser.add_argument("--generate-local-projects", action="store_true")
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--project-id", action="append", default=[])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--jarvis-root", type=Path, default=None)
    parser.add_argument("--runner", choices=["docker", "local"], default="docker")
    parser.add_argument("--fallback-runner", choices=["docker", "local", ""], default="local")
    parser.add_argument("--scope", choices=["entrypoints", "whole-project", "whole_project", "all"], default="entrypoints")
    parser.add_argument("--mode", choices=["EA", "DW", "AW"], default="EA")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--summary-depth", type=int, default=2)
    parser.add_argument("--max-summary-roots", type=int, default=60)
    parser.add_argument("--package-summary-timeout", type=int, default=45)
    parser.add_argument("--max-depth", type=int, default=25)
    parser.add_argument("--max-paths", type=int, default=100)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--results-json", type=Path, default=DEFAULT_RESULTS_JSON)
    parser.add_argument("--results-csv", type=Path, default=DEFAULT_RESULTS_CSV)
    parser.add_argument("--results-markdown", type=Path, default=DEFAULT_RESULTS_MD)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
