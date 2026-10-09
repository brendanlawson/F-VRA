from __future__ import annotations

import argparse
import csv
from dataclasses import replace
import hashlib
import json
import multiprocessing as mp
import os
import shutil
import statistics
import sys
import time
import traceback
from collections import Counter, defaultdict
from collections.abc import Iterator, MutableMapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from f_vra.analysis.callgraph.jarvis_backend import build_jarvis_project_graph, JarvisOptions  # noqa: E402
from f_vra.analysis.dependencies.resolver import resolve_dependency_graph_from_runtime  # noqa: E402
from f_vra.core.models import LibrarySummary, PackageSummaryArtifact, Verdict  # noqa: E402
from f_vra.reachability.engine import ReachabilityQueryEngine  # noqa: E402
from f_vra.reachability.service import (  # noqa: E402
    _build_package_summary_from_runtime,
    _graph_artifact,
    _with_project_callers,
    decide_reachability_verdict,
)
from f_vra.runtime.conda import (  # noqa: E402
    CondaEnvironmentManager,
    RuntimeCommandError,
    RuntimeEnvironment,
    RuntimePackage,
    _source_fingerprint,
    _stable_hash,
    select_python_version,
)
from f_vra.runtime.closure import DependencyClosure, build_dependency_closure, normalize_name  # noqa: E402
from f_vra.runtime.progress import ProgressMonitor  # noqa: E402

from build_local_projects_manifest import build_manifest  # noqa: E402
from run_current_cve_vf_full_reachability import (  # noqa: E402
    DEFAULT_BENCHMARK,
    _benchmark_by_project,
    _default_jarvis_root,
    _graph_summary,
    _join,
    _load_json,
    _load_jsonl,
    _resolve,
    _summary_counts,
    _try_build_jarvis,
    _write_csv,
    _write_json,
)


DEFAULT_LOCAL_PROJECTS = REPO_ROOT / "configs" / "local_projects.json"
DEFAULT_RUN_DIR = REPO_ROOT / ".tmp" / "current_run_sources" / "reachability_run_conda_targeted_28"
DEFAULT_RESULTS_JSON = REPO_ROOT / "results" / "metrics" / "current_architecture_reachability_conda_targeted_28_summary.json"
DEFAULT_RESULTS_CSV = REPO_ROOT / "results" / "tables" / "current_architecture_reachability_conda_targeted_28_results.csv"
DEFAULT_RESULTS_MD = REPO_ROOT / "results" / "tables" / "current_architecture_reachability_conda_targeted_28_report.md"
SUMMARY_BUILDER_VERSION = "runtime-summary-single-file-v2"
SUMMARY_MIN_AVAILABLE_MEMORY_BYTES = 512 * 1024 * 1024
SUMMARY_EMERGENCY_AVAILABLE_MEMORY_BYTES = 1024 * 1024 * 1024
SUMMARY_MAX_WORKER_MEMORY_BYTES = 6 * 1024 * 1024 * 1024
DEFAULT_SUMMARY_TIMEOUT_SECONDS = 7200


def _build_constraints_for_project(project_id: str, run_dir: Path) -> Path | None:
    """Return a narrow build constraint for known legacy build metadata.

    This does not alter locked runtime versions.  It only constrains the
    isolated PEP 517 build environment for a project whose setup.py imports
    the removed ``setuptools.convert_path`` helper.
    """
    if project_id != "milesmcc__shynet":
        return None
    path = run_dir / "commands" / "build_constraints.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("setuptools<66\n", encoding="utf-8")
    return path


def _python_candidates_for_project(project_id: str, candidates: list[str]) -> list[str]:
    """Apply compatibility constraints required by a locked legacy build.

    Shynet's pinned setuptools build imports ``pkgutil.ImpImporter``, which
    was removed in Python 3.12.  Python 3.11 still satisfies its declared
    ``^3.8`` constraint, so keep the runtime inside that valid range rather
    than selecting an interpreter that can never build the locked package.
    """
    if project_id == "milesmcc__shynet":
        compatible = []
        for candidate in candidates:
            try:
                major, minor = (int(part) for part in str(candidate).split(".", 2)[:2])
            except (TypeError, ValueError):
                continue
            if (major, minor) < (3, 12):
                compatible.append(str(candidate))
        if compatible:
            return compatible
    return candidates


def _available_memory_bytes() -> int | None:
    """Return host-available memory for a safety guard, when observable.

    This is deliberately not a wall-clock timeout.  A package analysis is
    allowed to run indefinitely, but a runaway graph must not exhaust the
    host and take the whole benchmark down.  If the optional resource probe
    is unavailable, the package is left to run normally.
    """
    try:
        import psutil  # type: ignore

        return int(psutil.virtual_memory().available)
    except Exception:
        return None


def _summary_worker_entry(runtime_path: str, root: str, result_path: str, artifact_path: str) -> None:
    """Build one real runtime summary in an isolated process.

    Isolation is intentionally not a timeout mechanism.  It bounds memory
    retained by the analyzer between packages while allowing a large package
    to run until it completes or raises a genuine exception.
    """
    try:
        runtime = RuntimeEnvironment.from_json(_load_json(Path(runtime_path)))
        built = _build_package_summary_from_runtime(root, runtime)
        payload: dict[str, Any] = {"built": built is not None}
        if built is not None:
            key, artifact = built
            # Keep the large summary in a separate file.  The parent only
            # needs a small completion record; loading a multi-GB JSON payload
            # in the orchestrator can otherwise exhaust the host after the
            # worker has already completed successfully.
            with Path(artifact_path).open("w", encoding="utf-8") as handle:
                json.dump(artifact.model_dump(mode="json"), handle, ensure_ascii=False, default=str)
            payload.update({"key": key, "artifact_path": artifact_path, "has_warnings": bool(artifact.summary.analysis_warnings)})
        Path(result_path).write_text(json.dumps(payload, ensure_ascii=False, default=str), encoding="utf-8")
    except Exception as exc:
        Path(result_path).write_text(
            json.dumps({"error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()}, ensure_ascii=False),
            encoding="utf-8",
        )
        raise


def _project_path(project_id: str, project: dict[str, Any]) -> Path:
    configured = Path(str(project.get("path") or ""))
    if configured.exists():
        return configured.resolve()
    local = REPO_ROOT / "data" / "raw" / "projects" / project_id
    if local.exists():
        return local.resolve()
    return configured.resolve()


def _config_hash(project_id: str, project_path: Path, project: dict[str, Any], python_version: str) -> str:
    files = []
    for path in sorted(project_path.iterdir() if project_path.exists() else [], key=lambda item: item.name):
        if path.is_file() and (path.name in {".python-version", "pyproject.toml", "uv.lock", "poetry.lock", "Pipfile.lock"} or path.name.startswith("requirements")):
            files.append((path.name, hashlib.sha256(path.read_bytes()).hexdigest()))
    return _stable_hash(
        {
            "project_id": project_id,
            "commit": project.get("commit", ""),
            "python_version": python_version,
            "install_configuration": "native-lock-or-all-manifests-v1",
            "files": files,
        }
    )


def _root(value: str) -> str:
    return str(value or "").split(".", 1)[0]


def _target_root(value: str) -> str:
    parts = [part for part in str(value or "").split(".") if part]
    if not parts:
        return ""
    if parts[0] in {"src", "python"} and len(parts) > 1:
        return parts[1]
    return parts[0]


def _benchmark_roots(records: list[dict[str, Any]]) -> tuple[set[str], set[str]]:
    distribution_roots: set[str] = set()
    target_import_roots: set[str] = set()
    for record in records:
        package = str(record.get("package") or "").strip()
        if package:
            distribution_roots.add(normalize_name(package))
        for target in record.get("target_vfs") or []:
            qualified = target.get("qualified_name", "") if isinstance(target, dict) else str(target)
            root = _target_root(str(qualified))
            if root:
                target_import_roots.add(root)
                distribution_roots.add(normalize_name(root))
    return distribution_roots, target_import_roots


def _runtime_import_root_map(runtime: RuntimeEnvironment) -> dict[str, list[dict[str, Any]]]:
    """Index the observed import roots by normalized distribution name.

    ``top_level.txt`` is only a hint.  The runtime probe also records roots
    discovered through ``packages_distributions()``, so this index is the
    source of truth for recovery-time target normalization.
    """
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for package in runtime.packages:
        roots = [str(root) for root in package.import_roots if str(root)]
        result[package.normalized_name].append(
            {
                "distribution": package.name,
                "normalized_distribution": package.normalized_name,
                "version": package.version,
                "roots": roots,
                "source_path": package.source_path,
                "source_fingerprint": package.source_fingerprint,
                "environment_fingerprint": runtime.fingerprint,
            }
        )
    return result


def _map_target_import_root(
    target: str,
    package: str,
    runtime: RuntimeEnvironment,
) -> tuple[str, dict[str, Any]]:
    """Map a benchmark target to an observed runtime import namespace.

    Project source layouts often prefix third-party imports with ``src``,
    ``libs`` or ``Lib``.  Distribution names also do not necessarily equal
    import roots (``PyJWT``/``jwt``, ``python-multipart``/``multipart`` and
    ``PyMuPDF``/``fitz``).  The returned audit record deliberately retains the
    original target and the reason for the selected mapping.
    """
    original = str(target or "")
    parts = [part for part in original.split(".") if part]
    if not parts:
        return original, {"original": original, "canonical": original, "status": "empty_target"}

    by_distribution = _runtime_import_root_map(runtime)
    package_key = normalize_name(package)
    package_candidates = [item for item in by_distribution.get(package_key, [])]
    package_roots = [root for item in package_candidates for root in item.get("roots", [])]
    root_lookup: dict[str, str] = {}
    for item in runtime.packages:
        for root in item.import_roots:
            root_lookup.setdefault(str(root).casefold(), str(root))

    prefix_layouts = {"src", "python", "libs", "lib"}
    selected_root = ""
    reason = "already_runtime_root"
    suffix_parts = parts

    # Find the longest known import-root component after an internal source
    # layout prefix.  For example, ``libs.community.langchain_core.X`` becomes
    # ``langchain_core.X`` and ``python.google.protobuf.X`` becomes
    # ``google.protobuf.X``.
    if parts[0].casefold() in prefix_layouts:
        for index in range(1, len(parts)):
            candidate = root_lookup.get(parts[index].casefold())
            if candidate:
                selected_root = candidate
                suffix_parts = [candidate, *parts[index + 1 :]]
                reason = "internal_source_prefix"
                break

    if not selected_root:
        selected_root = root_lookup.get(parts[0].casefold(), "")
        if selected_root:
            suffix_parts = [selected_root, *parts[1:]]

    # If the first component is a distribution spelling rather than an
    # observed root, use the roots belonging to that exact runtime package.
    if not selected_root and package_roots:
        first_key = parts[0].replace("-", "_").casefold()
        dist_key = package_key.replace("-", "_").casefold()
        if first_key == dist_key or parts[0].casefold() in {"__main__", "main"} or (
            parts[0].casefold() in prefix_layouts
            and len(parts) > 1
            and parts[1].casefold() in {"__main__", "main"}
        ):
            selected_root = str(package_roots[0])
            suffix_parts = [
                selected_root,
                *(
                    []
                    if parts[0].casefold() in {"__main__", "main"}
                    else parts[1:]
                ),
            ]
            reason = "distribution_import_alias"

    canonical = ".".join(suffix_parts) if selected_root else original
    status = "mapped" if canonical != original else "unchanged"
    return canonical, {
        "original": original,
        "canonical": canonical,
        "status": status,
        "reason": reason,
        "package": package,
        "package_version": package_candidates[0].get("version", "") if package_candidates else "",
        "candidate_import_roots": sorted(set(package_roots)),
        "environment_fingerprint": runtime.fingerprint,
    }


def _reachability_path_roots(graph: Any, target_vfs: list[str]) -> set[str]:
    """Return external import roots on graph paths leading to benchmark targets."""

    target_roots = {_target_root(target) for target in target_vfs if _target_root(target)}
    edges = list(getattr(graph, "edges", []) or [])
    reachable: set[Any] = {
        edge.callee
        for edge in edges
        if getattr(edge.callee, "is_external", False)
        and _target_root(getattr(edge.callee, "identity_string", "")) in target_roots
    }
    roots = set(target_roots)
    changed = True
    while changed:
        changed = False
        for edge in edges:
            if edge.callee in reachable and not getattr(edge.caller, "is_external", False) and edge.caller not in reachable:
                reachable.add(edge.caller)
                changed = True
            if edge.caller in reachable and getattr(edge.callee, "is_external", False):
                root = _target_root(getattr(edge.callee, "identity_string", ""))
                if root and root not in roots:
                    roots.add(root)
                    changed = True
    return roots


def _state_path(run_dir: Path) -> Path:
    return run_dir / "project_state.json"


def _load_runtime(path: Path) -> RuntimeEnvironment | None:
    if not path.exists():
        return None
    try:
        return RuntimeEnvironment.from_json(_load_json(path))
    except Exception:
        return None


def _write_runtime(path: Path, runtime: RuntimeEnvironment) -> None:
    _write_json(path, runtime.to_json())


def _summary_filename(package: RuntimePackage, root: str, environment_fingerprint: str) -> str:
    safe = "".join(char if char.isalnum() or char in "-_." else "_" for char in root)
    return f"{safe}__{package.normalized_name}__{package.version or 'unknown'}__env-{environment_fingerprint[:16]}__src-{package.source_fingerprint[:16]}.json"


def _build_package_summary_isolated(
    root: str,
    runtime: RuntimeEnvironment,
    runtime_path: Path,
    run_dir: Path,
    monitor: ProgressMonitor,
    summary_timeout_seconds: float | None = DEFAULT_SUMMARY_TIMEOUT_SECONDS,
    resource_telemetry: dict[str, Any] | None = None,
) -> tuple[str, Path, bool] | None:
    worker_dir = run_dir / "summary_workers"
    worker_dir.mkdir(parents=True, exist_ok=True)
    safe_root = "".join(char if char.isalnum() or char in "-_." else "_" for char in root)
    result_path = worker_dir / f"{safe_root}.json"
    artifact_path = worker_dir / f"{safe_root}.artifact.json"
    if result_path.exists():
        result_path.unlink()
    if artifact_path.exists():
        artifact_path.unlink()
    # Do not start another analyzer while the host is already under pressure.
    # This is a scheduling gate, not a timeout: a large package may run for as
    # long as it needs once its worker has been admitted.
    while True:
        available_memory = _available_memory_bytes()
        if resource_telemetry is not None:
            resource_telemetry["admission_available_memory_bytes"] = available_memory
        if available_memory is None or available_memory >= SUMMARY_MIN_AVAILABLE_MEMORY_BYTES:
            break
        monitor.emit(
            {
                "project": runtime.project_id,
                "phase": "summary_resource_wait",
                "package": root,
                "available_memory_bytes": available_memory,
                "threshold_bytes": SUMMARY_MIN_AVAILABLE_MEMORY_BYTES,
            }
        )
        time.sleep(10)

    context = mp.get_context("spawn")
    process = context.Process(
        target=_summary_worker_entry,
        args=(str(runtime_path), root, str(result_path), str(artifact_path)),
        name=f"f_vra-summary-{safe_root}",
    )
    started = time.perf_counter()
    process.start()
    try:
        while process.is_alive():
            elapsed = time.perf_counter() - started
            available_memory = _available_memory_bytes()
            worker_memory: int | None = None
            try:
                import psutil  # type: ignore

                worker_memory = int(psutil.Process(process.pid).memory_info().rss)
            except Exception:
                worker_memory = None
            if resource_telemetry is not None:
                resource_telemetry["max_worker_rss_bytes"] = max(
                    int(resource_telemetry.get("max_worker_rss_bytes") or 0),
                    int(worker_memory or 0),
                )
                if available_memory is not None:
                    previous_min = resource_telemetry.get("min_available_memory_bytes")
                    resource_telemetry["min_available_memory_bytes"] = min(
                        int(previous_min) if previous_min is not None else available_memory,
                        available_memory,
                    )
            monitor.emit(
                {
                    "project": runtime.project_id,
                    "phase": "summary_process_live",
                    "package": root,
                    "pid": process.pid,
                    "elapsed_s": round(elapsed, 1),
                    "summary_timeout_seconds": summary_timeout_seconds,
                    "worker_rss_bytes": worker_memory,
                    "available_memory_bytes": available_memory,
                }
            )
            if (
                available_memory is not None
                and available_memory < SUMMARY_EMERGENCY_AVAILABLE_MEMORY_BYTES
            ):
                # This is an emergency host-safety stop, not a wall-clock
                # timeout.  It records a real resource exhaustion condition so
                # one analyzer cannot take down the rest of the recovery run.
                process.terminate()
                process.join(timeout=30)
                if process.is_alive():
                    process.kill()
                    process.join()
                raise RuntimeError(
                    "summary worker terminated due to emergency host resource pressure "
                    f"(available={available_memory} bytes, "
                    f"threshold={SUMMARY_EMERGENCY_AVAILABLE_MEMORY_BYTES} bytes)"
                )
            if summary_timeout_seconds is not None and elapsed >= summary_timeout_seconds:
                process.terminate()
                process.join(timeout=30)
                if process.is_alive():
                    process.kill()
                    process.join()
                raise TimeoutError(
                    "summary worker exceeded configured timeout "
                    f"({summary_timeout_seconds} seconds)"
                )
            process.join(timeout=10)
        process.join()
        exitcode = process.exitcode
    except KeyboardInterrupt:
        if process.is_alive():
            process.terminate()
            process.join(timeout=30)
            if process.is_alive():
                process.kill()
                process.join()
        raise
    finally:
        process.close()
    payload = _load_json(result_path) if result_path.exists() else {}
    if exitcode != 0:
        detail = payload.get("error") or f"summary worker exited with code {exitcode}"
        raise RuntimeError(detail)
    if not payload.get("built"):
        return None
    artifact_path_value = Path(str(payload.get("artifact_path") or artifact_path))
    if not artifact_path_value.exists():
        raise RuntimeError("summary worker completed without writing its artifact")
    return str(payload["key"]), artifact_path_value, bool(payload.get("has_warnings"))


class _DiskBackedSummaryMap(MutableMapping[str, LibrarySummary]):
    """Lazy summary mapping backed by per-root JSON artifacts."""

    def __init__(self) -> None:
        self._paths: dict[str, Path] = {}
        self._loaded: dict[str, LibrarySummary] = {}
        self._warning_roots: set[str] = set()

    def register(self, root: str, path: Path, *, warning: bool = False) -> None:
        self._paths[root] = path
        if warning:
            self._warning_roots.add(root)

    @property
    def warning_roots(self) -> set[str]:
        return set(self._warning_roots)

    @property
    def loaded_keys(self) -> set[str]:
        return set(self._loaded)

    def clear_loaded(self) -> None:
        self._loaded.clear()

    def __getitem__(self, root: str) -> LibrarySummary:
        if root in self._loaded:
            return self._loaded[root]
        path = self._paths.get(root)
        if path is None or not path.exists():
            raise KeyError(root)
        artifact = PackageSummaryArtifact.model_validate(_load_json(path))
        self._loaded[root] = artifact.summary
        return artifact.summary

    def __setitem__(self, root: str, summary: LibrarySummary) -> None:
        self._loaded[root] = summary
        self._paths.setdefault(root, Path())

    def __delitem__(self, root: str) -> None:
        self._paths.pop(root, None)
        self._loaded.pop(root, None)
        self._warning_roots.discard(root)

    def __iter__(self) -> Iterator[str]:
        return iter(self._paths)

    def __len__(self) -> int:
        return len(self._paths)


def _package_for_import_root(root: str, package: RuntimePackage, runtime: RuntimeEnvironment) -> RuntimePackage:
    """Resolve source metadata for one import root, not just its distribution.

    A distribution can expose both Python modules and binary loaders (cffi and
    pywin32 are common examples).  A single distribution-level source path is
    therefore insufficient for summary status or cache identity.
    """
    candidate_text = package.import_root_paths.get(root, "")
    candidates = [Path(candidate_text)] if candidate_text else []
    normalized_root = str(root).replace("\\", "/").strip("/")
    if normalized_root:
        project_path = Path(runtime.project_path)
        candidates.extend(
            [
                project_path / normalized_root,
                project_path / f"{normalized_root}.py",
                project_path / "src" / normalized_root,
                project_path / "src" / f"{normalized_root}.py",
                # Several upstream monorepos (including kotaemon) keep the
                # editable Python distributions below ``libs/`` rather than
                # at the repository root.  Resolve that real source tree
                # before treating a stale editable finder path as missing.
                project_path / "libs" / normalized_root,
                project_path / "libs" / f"{normalized_root}.py",
            ]
        )
        for base in runtime.sys_path:
            base_path = Path(base)
            candidates.extend([base_path / normalized_root, base_path / f"{normalized_root}.py"])
    if package.source_path:
        candidates.append(Path(package.source_path))

    source: Path | None = None
    for candidate in candidates:
        try:
            if candidate.exists():
                source = candidate.resolve()
                break
        except OSError:
            continue
    python_source = False
    if source is not None:
        if source.is_file():
            python_source = source.suffix.lower() == ".py"
        else:
            try:
                python_source = any(source.rglob("*.py"))
            except OSError:
                python_source = False
    source_path = str(source) if source is not None else ""
    return replace(
        package,
        source_path=source_path,
        python_source=python_source,
        source_fingerprint=_source_fingerprint(source) if source is not None and python_source else "",
    )


def _build_all_runtime_summaries(
    project_id: str,
    runtime: RuntimeEnvironment,
    run_dir: Path,
    monitor: ProgressMonitor,
    selected_roots: set[str],
    summary_timeout_seconds: float | None = DEFAULT_SUMMARY_TIMEOUT_SECONDS,
) -> tuple[dict[str, LibrarySummary], list[dict[str, Any]]]:
    summaries = _DiskBackedSummaryMap()
    statuses: list[dict[str, Any]] = []
    roots: dict[str, RuntimePackage] = {}
    for package in runtime.packages:
        for root in package.import_roots:
            if root in selected_roots:
                roots.setdefault(root, package)

    summary_dir = run_dir / "package_summaries"
    summary_dir.mkdir(parents=True, exist_ok=True)
    total = len(roots)
    existing_statuses: dict[str, dict[str, Any]] = {}
    status_path = run_dir / "package_summary_status.json"
    if status_path.exists():
        try:
            for item in _load_json(status_path):
                if isinstance(item, dict) and item.get("root"):
                    existing_statuses[str(item["root"])] = item
        except Exception:
            existing_statuses = {}
    for index, root in enumerate(sorted(roots), 1):
        package = _package_for_import_root(root, roots[root], runtime)
        started = time.perf_counter()
        monitor.emit({"project": project_id, "phase": "summary_building", "package": root, "completed": index - 1, "total": total})
        existing = existing_statuses.get(root)
        if existing and (
            existing.get("environment_fingerprint") == runtime.fingerprint
            and existing.get("source_fingerprint") == package.source_fingerprint
            and existing.get("package_version") == package.version
            and existing.get("source_path") == package.source_path
        ):
            existing_status = str(existing.get("status") or "")
            if existing_status == "no_python_source":
                resumed = dict(existing)
                resumed["summary_builder_version"] = SUMMARY_BUILDER_VERSION
                statuses.append(resumed)
                _write_json(status_path, statuses)
                monitor.checkpoint(project_id, {"status": "summaries_in_progress", "summary_completed": index, "summary_total": total, "environment_fingerprint": runtime.fingerprint})
                monitor.emit({"project": project_id, "phase": "summary_resumed", "package": root, "status": existing_status, "completed": index, "total": total})
                continue
            summary_path_value = existing.get("summary_path") or ""
            summary_source_path = existing.get("summary_source_path") or ""
            summary_path = Path(summary_path_value)
            if (
                existing_status in {"built", "built_with_warnings"}
                and summary_source_path == package.source_path
                and summary_path.exists()
            ):
                try:
                    summaries.register(root, summary_path, warning=existing_status == "built_with_warnings")
                    resumed = dict(existing)
                    resumed["summary_builder_version"] = SUMMARY_BUILDER_VERSION
                    statuses.append(resumed)
                    _write_json(status_path, statuses)
                    monitor.checkpoint(project_id, {"status": "summaries_in_progress", "summary_completed": index, "summary_total": total, "environment_fingerprint": runtime.fingerprint})
                    monitor.emit({"project": project_id, "phase": "summary_resumed", "package": root, "status": existing_status, "completed": index, "total": total})
                    continue
                except Exception:
                    pass
            # A previous run could have completed the worker and written its
            # payload, but failed while collecting process metadata. Recover
            # that real artifact instead of analyzing the package again.
            if existing_status == "analysis_failed":
                safe_root = "".join(char if char.isalnum() or char in "-_." else "_" for char in root)
                worker_path = run_dir / "summary_workers" / f"{safe_root}.json"
                if worker_path.exists():
                    try:
                        worker_payload = _load_json(worker_path)
                        if worker_payload.get("built") and worker_payload.get("artifact"):
                            artifact = PackageSummaryArtifact.model_validate(worker_payload["artifact"])
                            summary_path = summary_dir / _summary_filename(package, root, runtime.fingerprint)
                            _write_json(summary_path, artifact)
                            resumed_status = dict(existing)
                            resumed_status.update(
                                {
                                    "status": "built_with_warnings" if artifact.summary.analysis_warnings else "built",
                                    "summary_attempted": True,
                                    "summary_key": worker_payload.get("key"),
                                    "summary_path": str(summary_path),
                                    "summary_source_path": artifact.source_path,
                                    "summary_builder_version": SUMMARY_BUILDER_VERSION,
                                    "recovered_from_worker": True,
                                    "error": None,
                                }
                            )
                            summaries.register(
                                root,
                                summary_path,
                                warning=bool(artifact.summary.analysis_warnings),
                            )
                            statuses.append(resumed_status)
                            _write_json(status_path, statuses)
                            monitor.checkpoint(project_id, {"status": "summaries_in_progress", "summary_completed": index, "summary_total": total, "environment_fingerprint": runtime.fingerprint})
                            monitor.emit({"project": project_id, "phase": "summary_recovered", "package": root, "status": resumed_status["status"], "completed": index, "total": total})
                            continue
                    except Exception:
                        # If the worker payload is incomplete or cannot be
                        # validated, fall through to a genuine fresh attempt.
                        pass
        status: dict[str, Any] = {
            "root": root,
            "package": package.name,
            "package_version": package.version,
            "source_path": package.source_path,
            "source_fingerprint": package.source_fingerprint,
            "environment_fingerprint": runtime.fingerprint,
            "python_version": runtime.python_version,
            "summary_attempted": False,
            "summary_builder_version": SUMMARY_BUILDER_VERSION,
        }
        source_path = Path(package.source_path) if package.source_path else None
        if not package.python_source or not source_path or not source_path.exists():
            # Runtime probes can expose binary-only import roots (for example
            # pywin32 loaders) with a nominal site-packages path that is not a
            # real Python source tree.  This is a source-availability state,
            # not an analyzer failure and must not inflate analysis_failed.
            status.update(
                {
                    "status": "no_python_source",
                    "summary_attempted": False,
                    "error": "captured runtime has no accessible Python source for this import root",
                }
            )
        else:
            status["summary_attempted"] = True
            try:
                built = _build_package_summary_isolated(
                    root,
                    runtime,
                    run_dir / "runtime_environment.json",
                    run_dir,
                    monitor,
                    summary_timeout_seconds=summary_timeout_seconds,
                )
                if built is None:
                    status.update(
                        {
                            "status": "no_python_source",
                            "summary_attempted": False,
                            "error": "captured runtime has no Python source for this import root",
                        }
                    )
                else:
                    key, artifact_path, has_warnings = built
                    summary_path = summary_dir / _summary_filename(package, root, runtime.fingerprint)
                    shutil.copy2(artifact_path, summary_path)
                    summaries.register(root, summary_path, warning=has_warnings)
                    status.update(
                        {
                            "status": "built_with_warnings" if has_warnings else "built",
                            "summary_key": key,
                            "summary_path": str(summary_path),
                            "summary_source_path": package.source_path,
                        }
                    )
            except Exception as exc:
                status.update(
                    {
                        "status": "analysis_failed",
                        "error": f"{type(exc).__name__}: {exc}",
                        "failure_kind": "summary_timeout" if isinstance(exc, TimeoutError) else "analysis_error",
                        "summary_timeout_seconds": summary_timeout_seconds,
                    }
                )
        status["elapsed_s"] = round(time.perf_counter() - started, 3)
        statuses.append(status)
        _write_json(run_dir / "package_summary_status.json", statuses)
        monitor.checkpoint(project_id, {"status": "summaries_in_progress", "summary_completed": index, "summary_total": total, "environment_fingerprint": runtime.fingerprint})
        monitor.emit({"project": project_id, "phase": "summary_completed", "package": root, "status": status["status"], "completed": index, "total": total})
    return summaries, statuses


def _query_record(
    record: dict[str, Any],
    graph: Any,
    usage_index: list[Any],
    summaries: MutableMapping[str, LibrarySummary],
    summary_status: list[dict[str, Any]],
    runtime: RuntimeEnvironment,
    *,
    max_depth: int,
    max_paths: int,
) -> dict[str, Any]:
    started = time.perf_counter()
    target_mapping: list[dict[str, Any]] = []
    canonical_targets: set[str] = set()
    for value in record["target_vfs"]:
        original = value.get("qualified_name", "") if isinstance(value, dict) else str(value)
        canonical, mapping = _map_target_import_root(original, str(record.get("package") or ""), runtime)
        canonical_targets.add(canonical)
        target_mapping.append(mapping)
    targets = canonical_targets
    report = ReachabilityQueryEngine(usage_index, summaries, targets, max_depth=max_depth, max_paths=max_paths).check_reachability()
    verdict, uncertainty = decide_reachability_verdict(report, targets, summaries, usage_index, graph_metadata=graph.metadata)
    report.paths = _with_project_callers(report.paths, graph)
    status_by_root = {str(item.get("root")): item for item in summary_status}
    target_roots = sorted({_target_root(target) for target in targets if _target_root(target)})
    target_details = {root: status_by_root.get(root, {"root": root, "status": "not_installed_in_runtime", "summary_attempted": False}) for root in target_roots}
    missing = [root for root, item in target_details.items() if item.get("status") not in {"built", "built_with_warnings"}]
    if missing and verdict == Verdict.NOT_REACHABLE:
        verdict = Verdict.POTENTIALLY_REACHABLE
    if missing:
        uncertainty["missing_target_summary_roots"] = missing
    paths = [{"project_api": path.project_api, "target": path.vulnerable_target, "path": path.tpl_chain, "used_summaries": path.used_summaries} for path in report.paths]
    loaded_summary_roots = sorted(getattr(summaries, "loaded_keys", set(summaries)))
    return {
        **record,
        "target_source": "vf_annotations",
        "query_targets": sorted(targets),
        "original_query_targets": sorted(str(item.get("original") or "") for item in target_mapping),
        "import_root_mapping": target_mapping,
        "verdict": verdict.value,
        "hit_set": sorted({path.vulnerable_target for path in report.paths}),
        "path_count": len(paths),
        "paths": paths,
        "path_lengths": [len(path["path"]) for path in paths],
        "used_summaries": report.used_summaries,
        "loaded_summaries": loaded_summary_roots,
        "unresolved_targets": report.unresolved_targets,
        "unresolved_frontier": report.unresolved_frontier,
        "uncertainty": uncertainty,
        "target_summary_status": {root: item.get("status", "") for root, item in target_details.items()},
        "missing_target_summary_roots": missing,
        "summary_attempted": {root: bool(item.get("summary_attempted")) for root, item in target_details.items()},
        "summary_source_path": {root: item.get("summary_source_path") or item.get("source_path", "") for root, item in target_details.items()},
        "summary_package_version": {root: item.get("package_version", "") for root, item in target_details.items()},
        "summary_environment_fingerprint": runtime.fingerprint,
        "query_time_ms": round((time.perf_counter() - started) * 1000, 3),
    }


def _csv_row(result: dict[str, Any], project_id: str, runner: str, graph: Any, usage_index: list[Any], elapsed: float) -> dict[str, Any]:
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
        "missing_target_summary_roots": _join(result.get("missing_target_summary_roots") or []),
        "target_summary_status": json.dumps(result.get("target_summary_status") or {}, sort_keys=True),
        "summary_environment_fingerprint": result.get("summary_environment_fingerprint", ""),
        "jarvis_runner": runner,
        "jarvis_status": "success",
        "project_nodes": len(graph.nodes),
        "project_edges": len(graph.edges),
        "usage_index": len(usage_index),
        "query_time_ms": result["query_time_ms"],
        "project_elapsed_s": elapsed,
    }


def _write_rebuild_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    fields = [
        "project", "cve_id", "group_id", "package", "evidence_level", "mapping_type", "target_count", "query_targets", "verdict",
        "path_count", "hit_count", "hit_set", "used_summaries", "loaded_summaries_count", "unresolved_targets_count",
        "unresolved_target_related_count", "missing_target_summary_roots", "target_summary_status", "summary_environment_fingerprint",
        "jarvis_runner", "jarvis_status", "project_nodes", "project_edges", "usage_index", "query_time_ms", "project_elapsed_s",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in fields} for row in rows)


def _rebuild_markdown(summary: dict[str, Any], csv_path: Path) -> str:
    return "\n".join(
        [
            "# Conda Per-Project CVE-VF Reachability Rebuild",
            "",
            f"- Projects: {summary['pipeline']['projects_completed']}/{summary['pipeline']['projects_requested']} completed",
            f"- Query rows: {summary['benchmark']['project_cve_query_rows']}",
            f"- Verdicts: {summary['reachability']['verdict_counts']}",
            f"- Package summary statuses: {summary['pipeline']['package_summary_status_counts']}",
            "",
            f"- Results CSV: `{csv_path}`",
            f"- Run directory: `{summary['artifacts']['output_dir']}`",
            "",
        ]
    )


def run(args: argparse.Namespace) -> int:
    started_all = time.perf_counter()
    summary_timeout_seconds = args.package_summary_timeout if args.package_summary_timeout > 0 else None
    local_projects = _resolve(args.local_projects)
    if not args.aggregate_only and (args.generate_local_projects or not local_projects.exists()):
        payload = build_manifest(argparse.Namespace(environment_manifest=_resolve(args.environment_manifest), benchmark=_resolve(args.benchmark), output=local_projects))
        local_projects.parent.mkdir(parents=True, exist_ok=True)
        local_projects.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    manifest = {item["id"]: item for item in _load_json(local_projects).get("projects", []) if item.get("enabled", True)}
    accepted_records, grouped = _benchmark_by_project(_resolve(args.benchmark))
    if args.aggregate_only:
        manifest = {project_id: {"id": project_id, "name": project_id, "enabled": True} for project_id in grouped}
    def _project_priority(project_id: str) -> tuple[int, int, str]:
        project = manifest.get(project_id) or {}
        try:
            resolved_count = int(project.get("resolved_package_count") or 10**9)
        except (TypeError, ValueError):
            resolved_count = 10**9
        # Use the manifest's resolved package count as a stable proxy for
        # project size before a targeted runtime exists.  Benchmark row count
        # breaks ties while keeping project IDs deterministic.
        return resolved_count, len(grouped.get(project_id, [])), project_id

    projects = sorted(grouped, key=_project_priority)
    if args.project_id:
        projects = [project for project in projects if project in set(args.project_id)]
    if args.limit:
        projects = projects[: args.limit]
    jarvis_root = None if args.aggregate_only else (_resolve(args.jarvis_root) if args.jarvis_root else _default_jarvis_root())
    if jarvis_root is None and not args.aggregate_only:
        raise RuntimeError("Jarvis root not found; set F_VRA_JARVIS_ROOT or pass --jarvis-root")

    output_dir = _resolve(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    monitor = ProgressMonitor(output_dir)
    manager = None if args.aggregate_only else CondaEnvironmentManager(_resolve(args.conda_prefix_root), conda_executable=_resolve(args.conda_executable) if args.conda_executable else None)
    all_rows: list[dict[str, Any]] = []
    project_summaries: list[dict[str, Any]] = []

    for number, project_id in enumerate(projects, 1):
        project_started = time.perf_counter()
        project = manifest.get(project_id)
        run_dir = output_dir / project_id
        run_dir.mkdir(parents=True, exist_ok=True)
        monitor.emit({"project": project_id, "phase": "project_started", "project_number": number, "project_total": len(projects)})
        if project is None:
            failure = {"project": project_id, "status": "not_attempted", "error": "project missing from local manifest"}
            monitor.checkpoint(project_id, failure)
            project_summaries.append(failure)
            continue
        if args.aggregate_only:
            summary_path = run_dir / "summary.json"
            report_path = run_dir / "reachability_report.json"
            if not summary_path.exists() or not report_path.exists():
                failure = {
                    "project": project,
                    "status": "not_attempted",
                    "error": "existing summary or reachability artifact is missing",
                }
                project_summaries.append(failure)
                monitor.emit({"project": project_id, "phase": "aggregate_missing_artifact", "error": failure["error"]})
                continue
            summary = _load_json(summary_path)
            report = _load_json(report_path)
            if summary.get("status") != "success":
                failure = {
                    "project": project,
                    "status": summary.get("status", "analysis_failed"),
                    "error": "existing project summary is not successful",
                    "existing_summary": str(summary_path),
                }
                project_summaries.append(failure)
                monitor.emit({"project": project_id, "phase": "aggregate_failed_artifact", "error": failure["error"]})
                continue
            project_summaries.append(summary)
            fake_graph = type(
                "Graph",
                (),
                {
                    "nodes": [None] * int(summary.get("counts", {}).get("project_nodes", 0)),
                    "edges": [None] * int(summary.get("counts", {}).get("project_edges", 0)),
                },
            )()
            for result in report.get("records", []):
                all_rows.append(
                    _csv_row(
                        result,
                        project_id,
                        summary.get("runner", ""),
                        fake_graph,
                        [None] * int(summary.get("counts", {}).get("usage_index", 0)),
                        float(summary.get("elapsed_s", 0)),
                    )
                )
            monitor.emit({
                "project": project_id,
                "phase": "aggregate_resumed",
                "environment_fingerprint": summary.get("environment_fingerprint", ""),
                "records": len(report.get("records", [])),
            })
            continue
        project_root: Path | None = None
        python_version = ""
        benchmark_roots: set[str] = set()
        target_import_roots: set[str] = set()
        closure: DependencyClosure | None = None
        config_hash = ""
        selected_requirements = run_dir / "commands" / "targeted_requirements.txt"
        try:
            benchmark_roots, target_import_roots = _benchmark_roots(grouped.get(project_id, []))
            project_root = _project_path(project_id, project)
            python_version = select_python_version(
                project_root,
                _python_candidates_for_project(project_id, args.python_candidates),
                distribution_names=benchmark_roots,
            )
            closure = build_dependency_closure(
                project_id,
                project_root,
                benchmark_roots,
                python_version=python_version,
                target_import_roots=target_import_roots,
            )
            config_hash = _stable_hash(
                {
                    "base": _config_hash(project_id, project_root, project, python_version),
                    "mode": "targeted-closure-v1",
                    "roots": sorted(benchmark_roots),
                    "lockfile_fingerprint": closure.lockfile_fingerprint,
                }
            )
            _write_json(run_dir / "dependency_closure.json", closure.to_json())
            selected_requirements.parent.mkdir(parents=True, exist_ok=True)
            selected_requirements.write_text("\n".join(closure.install_requirements) + ("\n" if closure.install_requirements else ""), encoding="utf-8")
            _write_json(
                run_dir / "summary_scope.json",
                {
                    "mode": "dependency_closure_and_reachability_path",
                    "benchmark_distribution_roots": sorted(benchmark_roots),
                    "benchmark_target_import_roots": sorted(target_import_roots),
                    "closure_package_names": sorted(closure.package_names),
                    "path_import_roots": [],
                    "selected_import_roots": sorted(target_import_roots),
                },
            )
        except Exception as exc:
            failure = {
                "project": project,
                "status": "analysis_failed",
                "phase": "resolve_dependency_closure",
                "error": f"{type(exc).__name__}: {exc}",
                "config_hash": config_hash,
                "python_version": python_version,
                "benchmark_distribution_roots": sorted(benchmark_roots),
                "elapsed_s": round(time.perf_counter() - project_started, 3),
            }
            _write_json(run_dir / "summary.json", failure)
            _write_json(run_dir / "preflight_failure.json", failure)
            monitor.checkpoint(project_id, failure)
            project_summaries.append(failure)
            for record in grouped[project_id]:
                all_rows.append({"project": project_id, "cve_id": record["cve_id"], "group_id": record["group_id"], "package": record["package"], "verdict": "unknown", "jarvis_status": "analysis_failed"})
            monitor.emit({"project": project_id, "phase": "analysis_failed", "error": failure["error"]})
            continue
        state = _load_json(_state_path(run_dir)) if _state_path(run_dir).exists() else {}
        previous_runtime = _load_runtime(run_dir / "runtime_environment.json")
        if args.resume and not args.force and not args.rebuild_summaries and state.get("status") == "completed" and state.get("config_hash") == config_hash and previous_runtime and state.get("environment_fingerprint") == previous_runtime.fingerprint and (run_dir / "reachability_report.json").exists():
            report = _load_json(run_dir / "reachability_report.json")
            summary = _load_json(run_dir / "summary.json")
            project_summaries.append(summary)
            fake_graph = type(
                "Graph",
                (),
                {
                    "nodes": [None] * int(summary.get("counts", {}).get("project_nodes", 0)),
                    "edges": [None] * int(summary.get("counts", {}).get("project_edges", 0)),
                },
            )()
            for result in report.get("records", []):
                all_rows.append(
                    _csv_row(
                        result,
                        project_id,
                        summary.get("runner", ""),
                        fake_graph,
                        [None] * int(summary.get("counts", {}).get("usage_index", 0)),
                        float(summary.get("elapsed_s", 0)),
                    )
                )
            monitor.emit({"project": project_id, "phase": "resumed", "environment_fingerprint": previous_runtime.fingerprint})
            continue

        project_root = project_root.resolve()
        project_run = run_dir
        callback = monitor.command_progress(project_id, "command")
        build_constraints = _build_constraints_for_project(project_id, project_run)
        try:
            reusable_runtime = (
                args.resume
                and not args.force
                and previous_runtime is not None
                and state.get("config_hash") == config_hash
                and state.get("environment_fingerprint") == previous_runtime.fingerprint
                and (
                    state.get("status") in {"snapshot_captured", "summaries_in_progress", "summaries_completed", "analysis_failed"}
                    or (args.rebuild_summaries and state.get("status") == "completed")
                )
            )
            if reusable_runtime:
                runtime = previous_runtime
                monitor.emit({"project": project_id, "phase": "runtime_resumed", "environment_fingerprint": runtime.fingerprint})
                monitor.checkpoint(project_id, {"status": "snapshot_captured", "config_hash": config_hash, "environment_fingerprint": runtime.fingerprint, "package_count": len(runtime.packages)})
            else:
                monitor.checkpoint(project_id, {"status": "creating_env", "config_hash": config_hash, "python_version": python_version, "project_commit": project.get("commit", "")})
                prefix, create_commands = manager.create(project_id, project_root, python_version=python_version, config_hash=config_hash, log_dir=project_run / "commands", progress=callback)
                monitor.checkpoint(project_id, {"status": "installing", "config_hash": config_hash, "prefix": str(prefix), "python_version": python_version})
                install_commands, bootstrap_tools = manager.install(
                    project_id,
                    project_root,
                    prefix,
                    log_dir=project_run / "commands",
                    progress=callback,
                    selected_requirements=selected_requirements,
                    install_project_editable=closure.install_project_editable,
                    build_constraints=build_constraints,
                )
                monitor.checkpoint(project_id, {"status": "capturing_runtime", "config_hash": config_hash, "prefix": str(prefix)})
                runtime = manager.capture(project_id, project_root, prefix, log_dir=project_run / "commands", progress=callback, install_commands=[*create_commands, *install_commands], bootstrap_tools=bootstrap_tools)
                _write_runtime(run_dir / "runtime_environment.json", runtime)
                monitor.checkpoint(project_id, {"status": "snapshot_captured", "config_hash": config_hash, "environment_fingerprint": runtime.fingerprint, "package_count": len(runtime.packages)})
            dependency_graph = resolve_dependency_graph_from_runtime(project_root, runtime, runtime_manifest=run_dir / "runtime_environment.json")
            _write_json(run_dir / "dependency_graph.json", dependency_graph)
        except Exception as exc:
            status = "install_failed" if state.get("status") in {"creating_env", "installing", "capturing_runtime"} or isinstance(exc, RuntimeCommandError) else "analysis_failed"
            failure = {"project": project, "status": status, "error": f"{type(exc).__name__}: {exc}", "config_hash": config_hash, "python_version": python_version, "elapsed_s": round(time.perf_counter() - project_started, 3)}
            _write_json(run_dir / "summary.json", failure)
            monitor.checkpoint(project_id, failure)
            project_summaries.append(failure)
            for record in grouped[project_id]:
                all_rows.append({"project": project_id, "cve_id": record["cve_id"], "group_id": record["group_id"], "package": record["package"], "verdict": "unknown", "jarvis_status": status})
            monitor.emit({"project": project_id, "phase": status, "error": failure["error"]})
            continue

        # Jarvis does not depend on package summaries.  Run it first so the
        # summary scope can be restricted to the closure and external roots on
        # paths leading to benchmark targets.
        graph, usage_index, jarvis_attempts = _try_build_jarvis(project_root, jarvis_root=jarvis_root, primary_runner=args.runner, fallback_runner=args.fallback_runner, scope=args.scope, mode=args.mode, timeout=args.timeout)
        path_roots = _reachability_path_roots(
            graph,
            [str(target.get("qualified_name", "")) for record in grouped.get(project_id, []) for target in record.get("target_vfs", []) if isinstance(target, dict)],
        ) if graph is not None else set()
        selected_roots = set(target_import_roots) | path_roots
        for package in runtime.packages:
            if package.normalized_name in closure.package_names:
                selected_roots.update(package.import_roots)
        _write_json(
            run_dir / "summary_scope.json",
            {
                "mode": "dependency_closure_and_reachability_path",
                "benchmark_distribution_roots": sorted(benchmark_roots),
                "benchmark_target_import_roots": sorted(target_import_roots),
                "closure_package_names": sorted(closure.package_names),
                "path_import_roots": sorted(path_roots),
                "selected_import_roots": sorted(selected_roots),
                "runtime_package_count": len(runtime.packages),
            },
        )
        summaries, summary_status = _build_all_runtime_summaries(
            project_id,
            runtime,
            run_dir,
            monitor,
            selected_roots,
            summary_timeout_seconds=summary_timeout_seconds,
        )
        monitor.checkpoint(
            project_id,
            {
                "status": "summaries_completed",
                "config_hash": config_hash,
                "environment_fingerprint": runtime.fingerprint,
                "summary_completed": len(summary_status),
                "summary_total": len(summary_status),
            },
        )
        if graph is None or usage_index is None:
            failure = {"project": project, "status": "analysis_failed", "jarvis_attempts": jarvis_attempts, "config_hash": config_hash, "environment_fingerprint": runtime.fingerprint, "elapsed_s": round(time.perf_counter() - project_started, 3)}
            _write_json(run_dir / "summary.json", failure)
            monitor.checkpoint(project_id, failure)
            project_summaries.append(failure)
            continue
        _write_json(run_dir / "project_graph_jarvis.json", _graph_artifact(project_root, graph, usage_index))
        _write_json(run_dir / "usage_index.json", _graph_summary(graph, usage_index))
        monitor.checkpoint(project_id, {"status": "jarvis_completed", "config_hash": config_hash, "environment_fingerprint": runtime.fingerprint})
        query_targets = sorted({target for record in grouped[project_id] for target in record["target_vfs"]})
        runner_used = next(item["runner"] for item in jarvis_attempts if item["status"] == "success")
        record_payloads = []
        loaded_summary_roots: set[str] = set()
        for record in grouped[project_id]:
            result = _query_record(record, graph, usage_index, summaries, summary_status, runtime, max_depth=args.max_depth, max_paths=args.max_paths)
            record_payloads.append(result)
            loaded_summary_roots.update(str(item) for item in result.get("loaded_summaries") or [])
            all_rows.append(_csv_row(result, project_id, runner_used, graph, usage_index, round(time.perf_counter() - project_started, 3)))
            summaries.clear_loaded()
        _write_json(run_dir / "reachability_report.json", {"project": project, "runtime_environment_fingerprint": runtime.fingerprint, "target_source": "vf_annotations", "records": record_payloads, "counts": {"records": len(record_payloads), "query_targets": len(query_targets), "verdict_counts": dict(Counter(record["verdict"] for record in record_payloads)), "paths": sum(record["path_count"] for record in record_payloads)}})
        summary = {"project": project, "status": "success", "runner": runner_used, "jarvis_attempts": jarvis_attempts, "config_hash": config_hash, "environment_fingerprint": runtime.fingerprint, "dependency_count": len(dependency_graph.dependencies), "artifacts": {"runtime_environment": str(run_dir / "runtime_environment.json"), "dependency_graph": str(run_dir / "dependency_graph.json"), "package_summary_status": str(run_dir / "package_summary_status.json"), "reachability": str(run_dir / "reachability_report.json")}, "counts": {"project_nodes": len(graph.nodes), "project_edges": len(graph.edges), "usage_index": len(usage_index), "records": len(record_payloads), "query_targets": len(query_targets), "package_summary_status": _summary_counts(summary_status), "available_summaries": len(summaries), "loaded_summaries": len(loaded_summary_roots)}, "elapsed_s": round(time.perf_counter() - project_started, 3)}
        _write_json(run_dir / "summary.json", summary)
        monitor.checkpoint(project_id, {"status": "completed", "config_hash": config_hash, "environment_fingerprint": runtime.fingerprint, "summary_completed": len(summary_status), "summary_total": len(summary_status)})
        project_summaries.append(summary)
        monitor.emit({"project": project_id, "phase": "project_completed", "elapsed_s": summary["elapsed_s"], "verdict_counts": dict(Counter(record["verdict"] for record in record_payloads))})

    _write_rebuild_csv(_resolve(args.results_csv), all_rows)
    completed = [item for item in project_summaries if item.get("status") == "success"]
    failed = [item for item in project_summaries if item.get("status") != "success"]
    all_statuses = [status for project_id in projects for path in [(output_dir / project_id / "package_summary_status.json")] if path.exists() for status in _load_json(path) if isinstance(_load_json(path), list)]
    def _summary_project_id(item: dict[str, Any]) -> str:
        project_value = item.get("project")
        if isinstance(project_value, dict):
            return str(project_value.get("id") or project_value.get("name") or "")
        return str(project_value or item.get("project_id") or "")

    vf_targets = {
        item.get("qualified_name", "") if isinstance(item, dict) else str(item)
        for record in accepted_records
        for item in record.get("target_vfs") or []
        if (item.get("qualified_name", "") if isinstance(item, dict) else str(item))
    }
    summary_payload = {"benchmark": {"accepted_records": len(accepted_records), "accepted_project_count": len(projects), "project_cve_query_rows": len(all_rows), "vf_target_count": len(vf_targets)}, "pipeline": {"projects_requested": len(projects), "projects_completed": len(completed), "projects_failed": len(failed), "failed_projects": [_summary_project_id(item) for item in failed], "package_summary_status_counts": _summary_counts(all_statuses)}, "reachability": {"verdict_counts": dict(Counter(row.get("verdict", "") for row in all_rows)), "rows_with_paths": sum(1 for row in all_rows if int(row.get("path_count") or 0) > 0), "total_paths": sum(int(row.get("path_count") or 0) for row in all_rows if str(row.get("path_count", "")).isdigit())}, "cost": {"total_elapsed_s": round(sum(float(item.get("elapsed_s") or 0) for item in project_summaries), 3), "aggregation_elapsed_s": round(time.perf_counter() - started_all, 3)}, "artifacts": {"output_dir": str(output_dir), "results_csv": str(_resolve(args.results_csv)), "results_json": str(_resolve(args.results_json)), "results_markdown": str(_resolve(args.results_markdown))}}
    _write_json(_resolve(args.results_json), summary_payload)
    _resolve(args.results_markdown).parent.mkdir(parents=True, exist_ok=True)
    _resolve(args.results_markdown).write_text(_rebuild_markdown(summary_payload, _resolve(args.results_csv)), encoding="utf-8")
    monitor.emit({"phase": "run_completed", "projects_completed": len(completed), "projects_failed": len(failed), "rows": len(all_rows)})
    return 0 if not failed else 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild the accepted CVE-VF benchmark with one real Conda runtime per project.")
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--local-projects", type=Path, default=DEFAULT_LOCAL_PROJECTS)
    parser.add_argument("--environment-manifest", type=Path, default=REPO_ROOT / "data" / "interim" / "resolved_versions" / "project_environment_manifest.csv")
    parser.add_argument("--generate-local-projects", action="store_true")
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--rebuild-summaries", action="store_true", help="Reuse captured project runtimes but revalidate/rebuild root-specific summaries.")
    parser.add_argument("--aggregate-only", action="store_true", help="Aggregate existing successful project artifacts without creating environments or rerunning analysis.")
    parser.add_argument("--project-id", action="append", default=[])
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--jarvis-root", type=Path, default=None)
    parser.add_argument("--runner", choices=["docker", "local"], default="docker")
    parser.add_argument("--fallback-runner", choices=["docker", "local", ""], default="", help="Optional Jarvis fallback; default keeps the benchmark Docker-only.")
    parser.add_argument("--scope", choices=["entrypoints", "whole-project", "whole_project", "all"], default="entrypoints")
    parser.add_argument("--mode", choices=["EA", "DW", "AW"], default="EA")
    parser.add_argument("--timeout", type=int, default=300, help="Jarvis watchdog timeout in seconds.")
    parser.add_argument(
        "--package-summary-timeout",
        type=int,
        default=DEFAULT_SUMMARY_TIMEOUT_SECONDS,
        help="Per-package summary watchdog in seconds; use 0 to disable.",
    )
    parser.add_argument("--max-depth", type=int, default=25)
    parser.add_argument("--max-paths", type=int, default=100)
    parser.add_argument("--conda-executable", type=Path, default=None)
    parser.add_argument("--conda-prefix-root", type=Path, default=REPO_ROOT / ".tmp" / "conda_envs")
    parser.add_argument("--python-candidates", nargs="+", default=["3.14", "3.13", "3.12", "3.11", "3.10"])
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_RUN_DIR)
    parser.add_argument("--results-json", type=Path, default=DEFAULT_RESULTS_JSON)
    parser.add_argument("--results-csv", type=Path, default=DEFAULT_RESULTS_CSV)
    parser.add_argument("--results-markdown", type=Path, default=DEFAULT_RESULTS_MD)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
