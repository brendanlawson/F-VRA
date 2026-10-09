"""Same graph and decision logic for all four artifact policies."""

from __future__ import annotations

import random
import sys
import hashlib
import time
import uuid
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

import yaml

from f_vra.evaluation.artifacts import ArtifactStore
from f_vra.evaluation.backend import BackendFailure, JarvisAdapter
from f_vra.evaluation.contracts import Decision, QueryOutcome, UnknownReason, digest
from f_vra.evaluation.environment import _jarvis_version
from f_vra.evaluation.io import read_json, read_parquet, write_json, write_parquet
from f_vra.evaluation.policies import ArtifactPolicy, EagerSharedPolicy, POLICIES


def ordered_queries(queries: list[dict[str, Any]], order: str, seed: int = 0) -> list[dict[str, Any]]:
    rows = list(queries)
    if order == "PROJECT_MAJOR":
        rows.sort(key=lambda item: (item["project_id"], item["cve_id"], item["query_id"]))
    elif order == "CVE_MAJOR":
        rows.sort(key=lambda item: (item["cve_id"], item["project_id"], item["query_id"]))
    elif order == "RANDOM":
        rows.sort(key=lambda item: item["query_id"])
        random.Random(seed).shuffle(rows)
    else:
        raise ValueError(f"unsupported ordering {order}")
    return rows


class ExperimentRunner:
    def __init__(self, dataset_dir: Path, jarvis_root: Path, *, timeout_s: int = 600, fragment_timeout_s: int = 300) -> None:
        self.dataset_dir = dataset_dir
        self.dataset_meta = read_json(dataset_dir / "dataset.json")
        protocol_path = dataset_dir / "protocol.yaml"
        self.protocol = yaml.safe_load(protocol_path.read_text(encoding="utf-8")) if protocol_path.is_file() else {}
        backend_config = self.protocol.get("backend") or {}
        entrypoint_config = self.protocol.get("entrypoints") or {}
        self.timeout_s = int(backend_config.get("query_timeout_s", timeout_s))
        self.adapter = JarvisAdapter(
            jarvis_root,
            fragment_timeout_s=int(backend_config.get("fragment_timeout_s", fragment_timeout_s)),
            entrypoint_ignore_dirs=tuple(entrypoint_config.get("ignore_directories") or ()),
            entrypoint_types=tuple(entrypoint_config.get("include_types") or ("main", "cli", "web")),
        )
        self.projects = {row["snapshot_id"]: row for row in read_parquet(dataset_dir / "projects.parquet")}
        self.environments = {row["env_id"]: row for row in read_parquet(dataset_dir / "environments.parquet")}
        self.packages = read_parquet(dataset_dir / "packages.parquet")
        self.all_queries = read_parquet(dataset_dir / "queries.parquet")
        self.queries = [row for row in self.all_queries if str(row.get("eligibility_reason") or "eligible") == "eligible"]
        self.by_env: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
        for package in self.packages:
            env_id = package["env_id"]
            for root in package.get("import_roots") or []:
                providers = self.by_env[env_id][root]
                if not any(item["package_id"] == package["package_id"] for item in providers):
                    providers.append(package)

    def _project_graph(self, env: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        path = self.dataset_dir / "project_graphs" / f"{env['env_id']}.json"
        backend_key = digest({
            "image": env["docker_image_digest"],
            "jarvis": _jarvis_version(self.adapter.jarvis_root),
            "driver": hashlib.sha256(Path(__file__).with_name("jarvis_driver.py").read_bytes()).hexdigest(),
            "protocol_sha256": self.dataset_meta.get("protocol_sha256", ""),
        })
        if path.is_file():
            payload = read_json(path)
            if payload.get("backend_key") == backend_key:
                return payload["graph"], True
        project_root = Path(__file__).resolve().parents[3] / "data" / "raw" / "projects" / str(env["project_id"])
        graph = self.adapter.project_graph(env, project_root)
        write_json(path, {"backend_key": backend_key, "graph": graph})
        return graph, False

    @staticmethod
    def _vf_matches(symbol: str, targets: set[str]) -> bool:
        return symbol.removeprefix("src.") in targets

    def _decide(
        self, query: dict[str, Any], graph: dict[str, Any], policy: ArtifactPolicy,
        *, root_budget: int | None = None, max_depth: int | None = None,
        fallback_expansion: bool = False,
    ) -> QueryOutcome:
        started_wall, started_cpu = time.perf_counter(), time.process_time()
        query_id = str(query["query_id"])
        before = len(policy.events)
        targets = {str(item["qualified_name"]).removeprefix("src.") for item in query.get("vf_set") or []}
        eligibility_reason = str(query.get("eligibility_reason") or "eligible")
        unknown: set[UnknownReason] = set()
        if graph.get("parse_errors"):
            unknown.add(UnknownReason.PARSE)
        if not graph.get("frontier_complete", True):
            unknown.add(UnknownReason.UNRESOLVED)
        if eligibility_reason != "eligible" or not targets:
            unknown.add(UnknownReason.VF_MISMATCH)
        witnesses: list[tuple[str, ...]] = []
        queue = deque((target, (target,), 0) for target in graph.get("usage_index") or [])
        visited: set[str] = set()
        demand_count = 0
        env_id = str(query["env_id"])
        env = self.environments[env_id]
        while queue:
            if time.perf_counter() - started_wall > self.timeout_s:
                unknown.add(UnknownReason.TIMEOUT)
                break
            current, path, depth = queue.popleft()
            normalized = current.removeprefix("src.")
            if self._vf_matches(current, targets):
                if len(witnesses) < 100:
                    witnesses.append(path)
                # Continue the search so an exhausted frontier is still logged.
                continue
            if normalized in visited:
                continue
            visited.add(normalized)
            if max_depth is not None and depth >= max_depth:
                unknown.add(UnknownReason.BUDGET)
                continue
            root = normalized.split(".", 1)[0]
            if root in sys.stdlib_module_names:
                continue
            providers = self.by_env[env_id].get(root) or []
            if not providers:
                unknown.add(UnknownReason.UNRESOLVED)
                continue
            analyzable = [package for package in providers if package["source_status"] == "SOURCE_AVAILABLE"]
            if not analyzable:
                statuses = {str(package["source_status"]) for package in providers}
                unknown.add(UnknownReason.NATIVE_BOUNDARY if "NATIVE_ONLY" in statuses else UnknownReason.SOURCE)
                continue
            # A PEP 420 namespace may be supplied by several distributions.
            # Expanding every provider preserves soundness and avoids choosing
            # a distribution from an ambiguous top-level import name.
            for package in analyzable:
                if root_budget is not None and demand_count >= root_budget:
                    unknown.add(UnknownReason.BUDGET)
                    break
                demand_count += 1
                try:
                    fragment, _hit = policy.get_or_build(
                        package_id=str(package["package_id"]), root=normalized,
                        project_snapshot_id=str(query["project_snapshot_id"]), query_id=query_id,
                        build=lambda package=package: self.adapter.fragment(package, normalized, env),
                    )
                except BackendFailure as exc:
                    unknown.add(exc.reason)
                    continue
                if fragment.get("parse_errors"):
                    unknown.add(UnknownReason.PARSE)
                for target, subpath in fragment.get("inner_paths", {}).items():
                    if self._vf_matches(target, targets) and len(witnesses) < 100:
                        witnesses.append((*path, *subpath[1:]))
                for target, subpath in fragment.get("outer_paths", {}).items():
                    if target not in path:
                        queue.append((target, (*path, *subpath[1:]), depth + 1))
        if fallback_expansion and not witnesses and UnknownReason.BUDGET in unknown:
            expanded = self._decide(query, graph, policy, root_budget=None, max_depth=None, fallback_expansion=False)
            events = policy.events[before:]
            value = lambda field: sum(int(event.get(field) or 0) for event in events)
            return expanded.model_copy(update={
                "wall_clock_ms": (time.perf_counter() - started_wall) * 1000,
                "cpu_time_ms": sum(float(event.get("cpu_time_ms") or 0) for event in events),
                "functions_analyzed": value("functions_analyzed"),
                "call_edges_materialized": value("call_edges_materialized"),
                "fragments_built": value("fragments_built"), "fragments_reused": value("fragments_reused"),
                "artifact_bytes_read": value("artifact_bytes_read"), "artifact_bytes_written": value("artifact_bytes_written"),
                "cache_lookup_count": value("cache_lookup_count"), "cache_hit_count": value("cache_hit_count"),
                "details": {**expanded.details, "fallback_expansion": True},
            })
        if witnesses:
            decision, reason = Decision.REACHABLE, None
        elif unknown:
            decision, reason = Decision.UNKNOWN, sorted(unknown, key=lambda item: item.value)[0]
        else:
            decision, reason = Decision.UNREACHABLE, None
        events = policy.events[before:]
        value = lambda field: sum(int(event.get(field) or 0) for event in events)
        return QueryOutcome(
            query_id=query_id, strategy=policy.name, decision=decision, unknown_reason=reason,
            witnesses=tuple(witnesses), wall_clock_ms=(time.perf_counter() - started_wall) * 1000,
            cpu_time_ms=(time.process_time() - started_cpu) * 1000 + sum(float(event.get("cpu_time_ms") or 0) for event in events),
            peak_rss_mb=max((float(event.get("peak_rss_mb") or 0) for event in events), default=0.0),
            functions_analyzed=value("functions_analyzed"), unique_functions_analyzed=value("unique_functions_analyzed"),
            call_edges_materialized=value("call_edges_materialized"), fragments_built=value("fragments_built"),
            fragments_reused=value("fragments_reused"), artifact_bytes_read=value("artifact_bytes_read"),
            artifact_bytes_written=value("artifact_bytes_written"), cache_lookup_count=value("cache_lookup_count"),
            cache_hit_count=value("cache_hit_count"), witness_length=min((len(path) for path in witnesses), default=0),
            details={"unknown_reasons": sorted(reason.value for reason in unknown), "demand_count": demand_count},
        )

    def _baseline_decide(self, query: dict[str, Any], graph: dict[str, Any] | None, strategy: str) -> QueryOutcome:
        if strategy == "package_exposure":
            decision, reason = Decision.REACHABLE, None
            details = {"basis": "affected distribution and version are installed"}
        elif strategy == "usage_filter":
            package = next((row for row in self.packages if row["package_id"] == query["affected_package_id"]), None)
            roots = set(package.get("import_roots") or ()) if package else set()
            used = bool(graph) and any(str(symbol).split(".", 1)[0] in roots for symbol in graph.get("usage_index") or ())
            if used:
                decision, reason = Decision.REACHABLE, None
            elif graph and graph.get("parse_errors"):
                decision, reason = Decision.UNKNOWN, UnknownReason.PARSE
            elif not graph or not graph.get("frontier_complete", True):
                decision, reason = Decision.UNKNOWN, UnknownReason.UNRESOLVED
            else:
                decision, reason = Decision.UNREACHABLE, None
            details = {"basis": "project dependency usage", "import_roots": sorted(roots), "used": used}
        else:
            raise ValueError(f"unknown baseline strategy {strategy}")
        return QueryOutcome(
            query_id=str(query["query_id"]), strategy=strategy, decision=decision,
            unknown_reason=reason, details=details,
        )

    @staticmethod
    def _update_registry(path: Path, record: dict[str, Any]) -> None:
        rows = read_parquet(path) if path.exists() else []
        rows = [row for row in rows if row.get("run_id") != record["run_id"]]
        rows.append(record)
        write_parquet(path, rows)

    def run(
        self, output_root: Path, *, strategy: str, order: str = "RANDOM", seed: int = 1,
        root_budget: int | None = None, max_depth: int | None = None,
        fallback_expansion: bool = False, limit: int = 0,
        run_label: str = "",
    ) -> dict[str, Any]:
        baseline_strategies = {"package_exposure", "usage_filter"}
        if strategy not in POLICIES and strategy not in baseline_strategies:
            raise ValueError(f"unknown strategy {strategy}")
        ordered = ordered_queries(self.queries, order, seed)
        if limit:
            ordered = ordered[:limit]
        config_base = {
            "dataset_id": self.dataset_meta["dataset_id"],
            "protocol_sha256": self.dataset_meta.get("protocol_sha256", ""),
            "strategy": strategy, "order": order, "seed": seed, "root_budget": root_budget,
            "max_depth": max_depth, "fallback_expansion": fallback_expansion,
            "run_label": run_label, "limit": limit,
            "query_timeout_s": self.timeout_s, "fragment_timeout_s": self.adapter.fragment_timeout_s,
            "network": "none", "cpus": 8, "memory_gb": 16,
        }
        config_hash = digest(config_base)
        output_root.mkdir(parents=True, exist_ok=True)
        registry_path = output_root.parent / "run_registry.parquet"
        registry = read_parquet(registry_path) if registry_path.exists() else []
        for record in registry:
            existing = Path(str(record.get("run_dir") or ""))
            if record.get("config_hash") == config_hash and record.get("status") == "COMPLETE" and (existing / "summary.json").is_file():
                return read_json(existing / "summary.json") | {"resumed": True}
        run_id = uuid.uuid4().hex
        run_dir = output_root / run_id
        run_dir.mkdir(parents=True, exist_ok=False)
        registry_record = {
            "run_id": run_id, "config_hash": config_hash, "status": "RUNNING",
            "run_dir": str(run_dir.resolve()), "strategy": strategy, "order": order, "seed": seed,
            "dataset_id": self.dataset_meta["dataset_id"], "error": "",
        }
        self._update_registry(registry_path, registry_record)
        try:
            policy = POLICIES[strategy](ArtifactStore(run_dir / "cache")) if strategy in POLICIES else None
            graphs: dict[str, dict[str, Any]] = {}
            graph_events = []
            if strategy != "package_exposure":
                for env_id in sorted({row["env_id"] for row in ordered}):
                    graph, cached = self._project_graph(self.environments[env_id])
                    graphs[env_id] = graph
                    graph_events.append({
                        "env_id": env_id, "event": "PROJECT_GRAPH", "cached": cached,
                        "wall_clock_ms": graph.get("wall_clock_ms", 0),
                        "cpu_time_ms": graph.get("cpu_time_ms", 0),
                        "functions_analyzed": graph.get("functions_analyzed", 0),
                        "unique_functions_analyzed": graph.get("unique_functions_analyzed", 0),
                        "call_edges_materialized": graph.get("call_edges_materialized", 0),
                        "peak_rss_mb": graph.get("peak_rss_mb", 0),
                    })
            if isinstance(policy, EagerSharedPolicy):
                unique = {}
                for query in ordered:
                    for package in self.packages:
                        if package["env_id"] == query["env_id"]:
                            unique.setdefault(package["package_id"], (package, self.environments[query["env_id"]]))
                for package_id, (package, env) in sorted(unique.items()):
                    if package["source_status"] != "SOURCE_AVAILABLE":
                        continue
                    started = time.perf_counter()
                    try:
                        roots = self.adapter.inventory(package, env)
                    except BackendFailure as exc:
                        policy.events.append({"event": "INVENTORY_FAILED", "package_id": package_id, "precomputation": True, "unknown_reason": exc.reason.value})
                        continue
                    policy.events.append({"event": "INVENTORY", "package_id": package_id, "precomputation": True, "wall_clock_ms": (time.perf_counter() - started) * 1000})
                    for root in roots:
                        if root.rsplit(".", 1)[-1].startswith("_"):
                            continue
                        try:
                            policy.get_or_build(
                                package_id=package_id, root=root, project_snapshot_id="precompute", query_id="PRECOMPUTE",
                                build=lambda package=package, root=root, env=env: self.adapter.fragment(package, root, env), precompute=True,
                            )
                        except BackendFailure as exc:
                            policy.events.append({"event": "PRECOMPUTE_FAILED", "package_id": package_id, "root": root, "precomputation": True, "unknown_reason": exc.reason.value})
            if policy is None:
                outcomes = [self._baseline_decide(row, graphs.get(row["env_id"]), strategy) for row in ordered]
                artifact_events: list[dict[str, Any]] = []
            else:
                outcomes = [self._decide(row, graphs[row["env_id"]], policy, root_budget=root_budget, max_depth=max_depth, fallback_expansion=fallback_expansion) for row in ordered]
                artifact_events = policy.events
            result_rows = [
                item.model_dump(mode="json") | {
                    "project_id": query["project_id"], "cve_id": query["cve_id"],
                    "env_id": query["env_id"], "candidate_id": query.get("candidate_id", ""),
                }
                for item, query in zip(outcomes, ordered)
            ]
            config = {"run_id": run_id, "config_hash": config_hash, **config_base}
            (run_dir / "config.yaml").write_text(yaml.safe_dump(config, sort_keys=True), encoding="utf-8")
            write_parquet(run_dir / "query_results.parquet", result_rows)
            write_parquet(run_dir / "artifact_events.parquet", artifact_events)
            write_parquet(run_dir / "analysis_events.parquet", graph_events)
            used_env_ids = sorted({str(row["env_id"]) for row in ordered})
            write_json(run_dir / "environment.json", {env_id: self.environments[env_id] for env_id in used_env_ids})
            summary = {
                "run_id": run_id, "config_hash": config_hash,
                "queries": len(outcomes), "verdict_counts": dict(Counter(item.decision.value for item in outcomes)),
                "query_wall_clock_ms": sum(item.wall_clock_ms for item in outcomes),
                "query_cpu_time_ms": sum(item.cpu_time_ms for item in outcomes),
                "precomputation_ms": sum(float(event.get("wall_clock_ms") or 0) for event in artifact_events if event.get("precomputation")),
                "precomputation_cpu_time_ms": sum(float(event.get("cpu_time_ms") or 0) for event in artifact_events if event.get("precomputation")),
                "functions_analyzed": sum(item.functions_analyzed for item in outcomes) + sum(int(event.get("functions_analyzed") or 0) for event in artifact_events if event.get("precomputation")),
                "unique_functions_analyzed": len({
                    str(function) for event in artifact_events
                    for function in event.get("analyzed_functions") or []
                }),
                "call_edges_materialized": sum(item.call_edges_materialized for item in outcomes) + sum(int(event.get("call_edges_materialized") or 0) for event in artifact_events if event.get("precomputation")),
                "peak_rss_mb": max(
                    [item.peak_rss_mb for item in outcomes]
                    + [float(event.get("peak_rss_mb") or 0) for event in artifact_events]
                    + [float(event.get("peak_rss_mb") or 0) for event in graph_events]
                    + [0.0]
                ),
                "artifact_bytes_read": sum(item.artifact_bytes_read for item in outcomes),
                "artifact_bytes_written": sum(int(event.get("artifact_bytes_written") or 0) for event in artifact_events),
                "project_graph_cost_ms": sum(float(event.get("wall_clock_ms") or 0) for event in graph_events),
                "project_graph_cpu_time_ms": sum(float(event.get("cpu_time_ms") or 0) for event in graph_events),
            }
            summary["cumulative_wall_clock_ms"] = summary["query_wall_clock_ms"] + summary["precomputation_ms"]
            summary["cumulative_cpu_time_ms"] = summary["query_cpu_time_ms"] + summary["precomputation_cpu_time_ms"]
            write_json(run_dir / "summary.json", summary)
            self._update_registry(registry_path, registry_record | {"status": "COMPLETE"})
            return summary
        except Exception as exc:
            self._update_registry(registry_path, registry_record | {"status": "FAILED", "error": str(exc)[-2000:]})
            raise
