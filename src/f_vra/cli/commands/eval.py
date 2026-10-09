"""Research experiment lifecycle. Each command has an explicit input snapshot."""
from __future__ import annotations

import csv
import hashlib
import json
import os
from pathlib import Path

import typer

from f_vra.evaluation.dataset import freeze_dataset
from f_vra.evaluation.environment import EnvironmentResolver, build_environments
from f_vra.evaluation.io import read_parquet, write_json, write_parquet
from f_vra.evaluation.metrics import vf_input_quality
from f_vra.evaluation.oracle import adjudicate_oracle, import_oracle
from f_vra.evaluation.reports import generate_report
from f_vra.evaluation.runner import ExperimentRunner
from f_vra.evaluation.rq3 import (
    audit_rq3_benchmark,
    build_rq3_vf_variants,
    downstream_consequence,
    error_propagation,
    exact_group_join,
    freeze_rq3_benchmark,
    _fingerprint,
    localization_quality,
    parse_case,
    pair_rq3_downstream_runs,
    run_localization_batch,
)
from f_vra.evaluation.vf import build_vf_variants
from f_vra.evaluation.vf_experiment import dispatch_vf_mode, prepare_vf_inputs
from f_vra.evaluation.vf_sharding import (
    create_vf_index_shards,
    create_vf_machine_shards,
    merge_vf_machine_shards,
    run_vf_index_shard,
    run_vf_machine_shard,
)
from f_vra.evaluation.vf_metrics import compute_vf_report


app = typer.Typer(help="Freeze, run and report F-VRA research experiments", no_args_is_help=True)
REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_DATASET = REPO_ROOT / "experiments" / "dataset" / "current"
DEFAULT_RUNS = REPO_ROOT / "experiments" / "runs"
DEFAULT_JARVIS = REPO_ROOT / "vendor" / "pythonJaRvis" / "Jarvis"
DEFAULT_RQ3_SNAPSHOT_ROOT = Path(os.environ.get("USERPROFILE", str(REPO_ROOT.parent))) / "rq3-snapshots"
DEFAULT_RQ3_BENCHMARK = REPO_ROOT / "data" / "benchmarks" / "vf_benchmark_finalized.jsonl"
DEFAULT_RQ3_MANIFEST = REPO_ROOT / "experiments" / "vf" / "prepared_manifest_v6.jsonl"
DEFAULT_RQ3_NEW_MANIFEST = REPO_ROOT / "experiments" / "vf" / "prepared_manifest.jsonl"
DEFAULT_VF_INPUTS = REPO_ROOT / "experiments" / "vf" / "inputs"
DEFAULT_VF_RESULTS = REPO_ROOT / "experiments" / "vf" / "results"


@app.command("freeze")
def freeze(
    output_dir: Path = typer.Option(DEFAULT_DATASET),
    projects: Path = typer.Option(REPO_ROOT / "configs" / "local_projects.json"),
    benchmark: Path = typer.Option(REPO_ROOT / "data" / "final" / "cve_vf_benchmark_accepted.jsonl"),
    protocol: Path = typer.Option(REPO_ROOT / "experiments" / "protocol" / "protocol.yaml"),
    resolved_packages: Path = typer.Option(REPO_ROOT / "data" / "interim" / "resolved_versions" / "resolved_packages.csv"),
) -> None:
    typer.echo(json.dumps(freeze_dataset(
        REPO_ROOT, output_dir, manifest=projects, benchmark=benchmark,
        protocol=protocol, resolved_packages=resolved_packages,
    ), indent=2))


@app.command("build-env")
def build_env(
    dataset: Path = typer.Option(DEFAULT_DATASET), jarvis_root: Path = typer.Option(DEFAULT_JARVIS),
    project_id: list[str] = typer.Option([], "--project-id"), limit: int = typer.Option(0),
    force: bool = typer.Option(False, help="Rebuild even when the frozen environment is resumable."),
) -> None:
    typer.echo(json.dumps(build_environments(EnvironmentResolver(REPO_ROOT, dataset, jarvis_root), project_ids=set(project_id) or None, limit=limit, force_rebuild=force), indent=2))


@app.command("audit")
def audit(dataset: Path = typer.Option(DEFAULT_DATASET)) -> None:
    from collections import Counter, defaultdict

    result = {}
    for name in ("snapshot_audit", "environment_audit", "package_source_audit", "query_eligibility", "oracle_import_audit"):
        path = dataset / f"{name}.parquet"
        if path.exists():
            result[name] = dict(Counter(str(row.get("status") or "") for row in read_parquet(path)))
    eligibility_path = dataset / "query_eligibility.parquet"
    if eligibility_path.exists():
        rows = read_parquet(eligibility_path)
        candidates = {
            str(row["candidate_id"]): row
            for row in read_parquet(dataset / "query_candidates.parquet")
        }
        queries = {
            str(row["query_id"]): row
            for row in read_parquet(dataset / "queries.parquet")
        } if (dataset / "queries.parquet").exists() else {}
        stages = (
            ("candidate", None),
            ("affected_package_installed", "package_installed"),
            ("affected_version_installed", "affected_version"),
            ("source_available", "source_available"),
            ("vf_bound", "vf_bound"),
            ("query_eligible", "query_eligible"),
        )
        funnel = [
            {"stage": stage, "count": len(rows) if field is None else sum(bool(row.get(field)) for row in rows)}
            for stage, field in stages
        ]
        eligible_rows = [row for row in rows if bool(row.get("query_eligible"))]
        dependency_types = Counter(
            str(queries.get(str(row.get("query_id") or ""), {}).get("dependency_type") or "unknown")
            for row in eligible_rows
        )
        vf_multiplicity = Counter(
            str(len(candidates.get(str(row.get("candidate_id") or ""), {}).get("target_vfs") or []))
            for row in eligible_rows
        )
        eligibility_summary = {
            "candidate_count": len(rows),
            "status_counts": dict(Counter(str(row.get("status") or "") for row in rows)),
            "funnel": funnel,
            "eligible_strata": {
                "project_count": len({str(row.get("project_id")) for row in eligible_rows}),
                "package_count": len({
                    str(candidates.get(str(row.get("candidate_id") or ""), {}).get("affected_distribution") or "")
                    for row in eligible_rows
                }),
                "dependency_type_counts": dict(dependency_types),
                "vf_multiplicity_counts": dict(vf_multiplicity),
            },
        }
        write_json(dataset / "eligibility_summary.json", eligibility_summary)
        with (dataset / "eligibility_funnel.csv").open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=["stage", "count"])
            writer.writeheader()
            writer.writerows(funnel)
        result["eligibility"] = eligibility_summary
        issues = []
        for row in rows:
            if row.get("query_eligible"):
                continue
            candidate = candidates.get(str(row.get("candidate_id") or ""), {})
            issues.append({
                "project_id": row.get("project_id"), "cve_id": row.get("cve_id"),
                "candidate_id": row.get("candidate_id"),
                "affected_distribution": candidate.get("affected_distribution"),
                "status": row.get("status"),
            })
        write_parquet(dataset / "eligibility_issues.parquet", issues)
    packages_path = dataset / "packages.parquet"
    if packages_path.exists():
        providers: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for package in read_parquet(packages_path):
            for root in package.get("import_roots") or []:
                providers[(str(package["env_id"]), str(root))].append(package)
        root_audit = []
        for (env_id, root), rows in sorted(providers.items()):
            unique = {str(row["package_id"]): row for row in rows}
            distributions = sorted(str(row["distribution"]) for row in unique.values())
            analyzable = sorted(
                str(row["distribution"]) for row in unique.values()
                if row.get("source_status") == "SOURCE_AVAILABLE"
            )
            if len(unique) == 1:
                status = "UNIQUE"
            elif analyzable:
                status = "RESOLVED_MULTI_PROVIDER_EXPANSION"
            else:
                status = "UNRESOLVED_NO_SOURCE_PROVIDER"
            root_audit.append({
                "env_id": env_id, "import_root": root, "provider_count": len(unique),
                "distributions": distributions, "analyzable_distributions": analyzable,
                "status": status,
            })
        write_parquet(dataset / "import_root_audit.parquet", root_audit)
        counts = Counter(row["status"] for row in root_audit)
        result["import_root_audit"] = {
            "root_count": len(root_audit),
            "collision_count": sum(row["provider_count"] > 1 for row in root_audit),
            "unresolved_collision_count": counts["UNRESOLVED_NO_SOURCE_PROVIDER"],
            "status_counts": dict(counts),
            "resolution": "expand every source-available provider for a shared namespace root",
        }
    write_json(dataset / "audit_summary.json", result)
    typer.echo(json.dumps(result, indent=2))


@app.command("repro-check")
def repro_check(
    dataset: Path = typer.Option(DEFAULT_DATASET),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS),
    project_id: list[str] = typer.Option([], "--project-id"),
) -> None:
    """Rebuild one environment per lockfile type twice and compare stable identities."""
    environments = read_parquet(dataset / "environments.parquet")
    if not environments:
        raise typer.BadParameter("build environments before running reproducibility checks")
    by_project = {str(row["project_id"]): row for row in environments}
    if project_id:
        selected = list(dict.fromkeys(project_id))
    else:
        by_lock = {}
        for row in sorted(environments, key=lambda item: str(item["project_id"])):
            by_lock.setdefault(str(row["lockfile_type"]), str(row["project_id"]))
        selected = [by_lock[key] for key in sorted(by_lock)]
    unknown = sorted(set(selected) - by_project.keys())
    if unknown:
        raise typer.BadParameter(f"unknown or unbuilt project ids: {unknown}")

    def identity(project: str) -> dict:
        current_env = next(row for row in read_parquet(dataset / "environments.parquet") if row["project_id"] == project)
        package_ids = sorted(
            str(row["package_id"]) for row in read_parquet(dataset / "packages.parquet")
            if row["project_id"] == project
        )
        return {
            "project_id": project,
            "lockfile_type": current_env["lockfile_type"],
            "installed_distribution_manifest_hash": current_env["installed_distribution_manifest_hash"],
            "package_ids": package_ids,
        }

    resolver = EnvironmentResolver(REPO_ROOT, dataset, jarvis_root)
    records = []
    for project in selected:
        baseline = identity(project)
        previous = baseline
        for repeat in (1, 2):
            build_result = build_environments(resolver, project_ids={project}, force_rebuild=True)
            current = identity(project)
            build_ok = build_result["environment_count"] == 1
            manifest_match = build_ok and current["installed_distribution_manifest_hash"] == baseline["installed_distribution_manifest_hash"]
            package_ids_match = build_ok and current["package_ids"] == baseline["package_ids"]
            records.append({
                "project_id": project, "lockfile_type": baseline["lockfile_type"], "repeat": repeat,
                "build_ok": build_ok,
                "manifest_match": manifest_match, "package_ids_match": package_ids_match,
                "manifest_hash": current["installed_distribution_manifest_hash"],
                "package_id_count": len(current["package_ids"]),
                "same_as_previous_repeat": current == previous,
            })
            previous = current
    payload = {
        "status": "PASS" if all(row["manifest_match"] and row["package_ids_match"] for row in records) else "FAIL",
        "selected_projects": selected, "records": records,
    }
    write_json(dataset / "reproducibility_summary.json", payload)
    typer.echo(json.dumps(payload, indent=2))
    if payload["status"] != "PASS":
        raise typer.Exit(2)


@app.command("oracle-import")
def oracle_import(workbook: Path = typer.Argument(..., exists=True), dataset: Path = typer.Option(DEFAULT_DATASET)) -> None:
    typer.echo(json.dumps(import_oracle(workbook, dataset), indent=2))


@app.command("oracle-review")
def oracle_review(decisions: Path = typer.Argument(..., exists=True), dataset: Path = typer.Option(DEFAULT_DATASET)) -> None:
    typer.echo(json.dumps(adjudicate_oracle(dataset, decisions), indent=2))


def _runner(dataset: Path, jarvis_root: Path) -> ExperimentRunner:
    if not jarvis_root.is_dir():
        raise typer.BadParameter(f"JARVIS root missing: {jarvis_root}")
    return ExperimentRunner(dataset, jarvis_root)


@app.command("fresh")
def fresh(
    dataset: Path = typer.Option(DEFAULT_DATASET), output_root: Path = typer.Option(DEFAULT_RUNS),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS), limit: int = typer.Option(0),
) -> None:
    typer.echo(json.dumps(_runner(dataset, jarvis_root).run(output_root, strategy="fresh", order="PROJECT_MAJOR", limit=limit), indent=2))


@app.command("baselines")
def baselines(
    dataset: Path = typer.Option(DEFAULT_DATASET), output_root: Path = typer.Option(DEFAULT_RUNS),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS), limit: int = typer.Option(0),
) -> None:
    """Run RQ1 package-exposure and project-usage baselines."""
    runner = _runner(dataset, jarvis_root)
    summaries = [
        runner.run(output_root, strategy=strategy, order="PROJECT_MAJOR", limit=limit)
        for strategy in ("package_exposure", "usage_filter")
    ]
    typer.echo(json.dumps(summaries, indent=2))


@app.command("determinism")
def determinism(
    dataset: Path = typer.Option(DEFAULT_DATASET), output_root: Path = typer.Option(DEFAULT_RUNS),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS), seed: int = typer.Option(17),
    fraction: float = typer.Option(0.1, min=0.0, max=1.0),
) -> None:
    """Run a deterministic 10% sample three times and compare semantic/work counters."""
    runner = _runner(dataset, jarvis_root)
    import random

    sample = list(runner.queries)
    random.Random(seed).shuffle(sample)
    runner.queries = sample[: max(1, round(len(sample) * fraction))]
    summaries, result_sets = [], []
    for repeat in range(1, 4):
        summary = runner.run(
            output_root, strategy="fresh", order="PROJECT_MAJOR",
            run_label=f"determinism-seed-{seed}-repeat-{repeat}",
        )
        summaries.append(summary)
        result_sets.append({row["query_id"]: row for row in read_parquet(output_root / summary["run_id"] / "query_results.parquet")})
    reference = result_sets[0]
    mismatches = []
    for repeat, results in enumerate(result_sets[1:], 2):
        for query_id, first in reference.items():
            second = results.get(query_id)
            fields = ("decision", "witnesses", "functions_analyzed", "unique_functions_analyzed", "call_edges_materialized")
            if second is None or any(first[field] != second[field] for field in fields):
                mismatches.append({"repeat": repeat, "query_id": query_id})
    payload = {"sample_size": len(reference), "runs": summaries, "mismatch_count": len(mismatches), "mismatches": mismatches}
    write_json(output_root / f"determinism-{seed}.json", payload)
    typer.echo(json.dumps(payload, indent=2))
    if mismatches:
        raise typer.Exit(2)


@app.command("compare")
def compare(
    dataset: Path = typer.Option(DEFAULT_DATASET), output_root: Path = typer.Option(DEFAULT_RUNS),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS),
    strategy: list[str] = typer.Option(["fresh", "project_local", "eager_shared", "progressive_shared"], "--strategy"),
    order: list[str] = typer.Option(["PROJECT_MAJOR", "CVE_MAJOR", "RANDOM"], "--order"),
    seed: int = typer.Option(1), seeds: str = typer.Option("1:30"), limit: int = typer.Option(0),
) -> None:
    runner = _runner(dataset, jarvis_root)
    if ":" in seeds:
        low, high = (int(part) for part in seeds.split(":", 1))
        random_seeds = range(low, high + 1)
    else:
        random_seeds = [int(part) for part in seeds.split(",") if part.strip()]
    summaries = []
    for ordering in order:
        for current_seed in (random_seeds if ordering == "RANDOM" else [seed]):
            for current_strategy in strategy:
                summaries.append(runner.run(output_root, strategy=current_strategy, order=ordering, seed=current_seed, limit=limit))
    typer.echo(json.dumps(summaries, indent=2))


@app.command("ablate")
def ablate(
    dataset: Path = typer.Option(DEFAULT_DATASET), output_root: Path = typer.Option(DEFAULT_RUNS),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS), limit: int = typer.Option(0),
) -> None:
    runner = _runner(dataset, jarvis_root)
    summaries = []
    for strategy in ("fresh", "project_local", "eager_shared", "progressive_shared"):
        summaries.append(runner.run(output_root, strategy=strategy, order="PROJECT_MAJOR", limit=limit))
    for budget in (20, 40, 60, 100, None):
        summaries.append(runner.run(output_root, strategy="progressive_shared", order="PROJECT_MAJOR", root_budget=budget, limit=limit))
    for depth in (1, 2, 3, 4, None):
        summaries.append(runner.run(output_root, strategy="progressive_shared", order="PROJECT_MAJOR", max_depth=depth, limit=limit))
    summaries.append(runner.run(output_root, strategy="progressive_shared", order="PROJECT_MAJOR", root_budget=60, max_depth=2, fallback_expansion=False, limit=limit))
    summaries.append(runner.run(output_root, strategy="progressive_shared", order="PROJECT_MAJOR", root_budget=60, max_depth=2, fallback_expansion=True, limit=limit))
    typer.echo(json.dumps(summaries, indent=2))


@app.command("vf")
def vf(
    variants: Path = typer.Argument(..., exists=True), dataset: Path = typer.Option(DEFAULT_DATASET),
    output_root: Path = typer.Option(DEFAULT_RUNS), jarvis_root: Path = typer.Option(DEFAULT_JARVIS),
    limit: int = typer.Option(0),
) -> None:
    """Run frozen V0/V1/V2 VF manifests; each row has query_id, variant, vf_set."""
    source = read_parquet(variants) if variants.suffix == ".parquet" else [json.loads(line) for line in variants.read_text(encoding="utf-8").splitlines() if line.strip()]
    rq3_variants = any(str(row.get("variant") or "").startswith(("D_LEX", "D_SEM", "P_MODIFIED", "P_DUAL")) for row in source)
    if rq3_variants and limit == 0:
        binding_summary_path = variants.with_suffix(".summary.json")
        freeze_summary_path = DEFAULT_RQ3_MANIFEST.with_suffix(".summary.json")
        if binding_summary_path.is_file():
            binding_summary = json.loads(binding_summary_path.read_text(encoding="utf-8"))
            recorded_path = str(binding_summary.get("freeze_summary_path") or "").strip()
            if recorded_path:
                freeze_summary_path = Path(recorded_path)
        gate = _rq3_preflight(
            freeze_summary_path,
            REPO_ROOT / "experiments" / "dependency_build" / "current" / "build_summary.json",
            dataset,
        )
        if not gate["ready"]:
            raise typer.BadParameter("full RQ3 downstream run is gated; run `f-vra eval rq3-preflight` and fix failing checks: " + json.dumps(gate["checks"], sort_keys=True))
    runner = _runner(dataset, jarvis_root)
    by_variant: dict[str, dict[str, list[dict]]] = {}
    for row in source:
        by_variant.setdefault(str(row["variant"]), {})[str(row["query_id"])] = row["vf_set"]
    baseline_name = "V0_ORACLE" if "V0_ORACLE" in by_variant else ("V0" if "V0" in by_variant else "oracle")
    baseline = by_variant.get(baseline_name, {})
    original = runner.queries
    summaries = []
    for variant, anchors in sorted(by_variant.items()):
        runner.queries = []
        for query in original:
            if query["query_id"] not in anchors:
                continue
            selected = anchors[query["query_id"]]
            valid = bool(selected) and all(item.get("package_id") == query["affected_package_id"] and item.get("function_hash") and item.get("file") for item in selected)
            runner.queries.append(query | {"vf_set": selected, "eligibility_reason": "eligible" if valid else "UNKNOWN_VF_MISMATCH"})
        summary = runner.run(output_root, strategy="fresh", order="PROJECT_MAJOR", limit=limit, run_label=variant)
        input_metrics = {
            "variant": variant, "baseline": baseline_name,
            **vf_input_quality(baseline, anchors),
        }
        write_json(output_root / summary["run_id"] / "vf_input_metrics.json", input_metrics)
        summaries.append({"variant": variant, "vf_input_metrics": input_metrics, **summary})
    runner.queries = original
    typer.echo(json.dumps(summaries, indent=2))


@app.command("vf-build")
def vf_build(
    workbook: Path = typer.Argument(..., exists=True),
    dataset: Path = typer.Option(DEFAULT_DATASET),
    patch_source: Path = typer.Option(REPO_ROOT / "data" / "interim" / "current_cve_vf" / "current_candidate_functions.jsonl"),
    output: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "vf_variants.parquet"),
) -> None:
    typer.echo(json.dumps(build_vf_variants(dataset, workbook, patch_source, output), indent=2))


@app.command("report")
def report(dataset: Path = typer.Option(DEFAULT_DATASET), output_dir: Path = typer.Option(REPO_ROOT / "results" / "experiment_report"), run: list[Path] = typer.Option([], "--run")) -> None:
    runs = run or sorted(path for path in DEFAULT_RUNS.iterdir() if path.is_dir() and (path / "summary.json").is_file())
    typer.echo(json.dumps(generate_report(dataset, runs, output_dir), indent=2))


@app.command("rq3-audit")
def rq3_audit(
    benchmark: Path = typer.Option(DEFAULT_RQ3_BENCHMARK, exists=True),
    downstream: Path = typer.Option(REPO_ROOT / "data" / "benchmarks" / "f_vra_downstream_reachability_benchmark.jsonl"),
) -> None:
    """Offline evidence-acceptance and exact VF-group overlap audit; no batch is started."""
    typer.echo(json.dumps(audit_rq3_benchmark(benchmark, downstream), indent=2))


@app.command("rq3-freeze")
def rq3_freeze(
    benchmark: Path = typer.Option(DEFAULT_RQ3_BENCHMARK, exists=True),
    downstream: Path = typer.Option(REPO_ROOT / "data" / "benchmarks" / "f_vra_downstream_reachability_benchmark.jsonl"),
    output: Path = typer.Option(DEFAULT_RQ3_NEW_MANIFEST),
    snapshot_map: Path | None = typer.Option(None, help="Exact group/repo+commit to snapshot identity map"),
    snapshot_cache: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "source_cache"),
    patch_cache: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "patches"),
    snapshot_root: Path = typer.Option(DEFAULT_RQ3_SNAPSHOT_ROOT, help="Short path for exported source snapshots (prevents Windows MAX_PATH failures)"),
    materialize_sources: bool = typer.Option(False, help="Fetch and archive each exact vulnerable commit"),
    materialize_patches: bool = typer.Option(False, help="Fetch exact canonical fixing-commit diffs"),
    resolve_cwe: bool = typer.Option(True, "--resolve-cwe/--no-resolve-cwe"),
    adjudication: Path | None = typer.Option(None, help="Approved case-specific evidence decisions (JSON)"),
    reuse_manifest_from: Path | None = typer.Option(None, help="Reuse prior artifacts only when their source/patch identities match; permits a revised benchmark"),
) -> None:
    """Freeze accepted VF evidence and metadata; materialization is explicit because it fetches repositories."""
    summary = freeze_rq3_benchmark(
        benchmark, output, downstream=downstream, snapshot_map=snapshot_map,
        snapshot_cache=snapshot_cache, patch_cache=patch_cache,
        materialize_sources=materialize_sources, materialize_patches=materialize_patches,
        resolve_cwe=resolve_cwe, adjudication=adjudication,
        reuse_manifest_from=reuse_manifest_from,
        snapshot_root=snapshot_root,
    )
    typer.echo(json.dumps(summary, indent=2))


@app.command("rq3-prepare")
def rq3_prepare(
    benchmark: Path = typer.Option(DEFAULT_RQ3_BENCHMARK, exists=True),
    downstream: Path = typer.Option(REPO_ROOT / "data" / "benchmarks" / "f_vra_downstream_reachability_benchmark.jsonl"),
    output: Path = typer.Option(DEFAULT_RQ3_NEW_MANIFEST),
    snapshot_map: Path | None = typer.Option(None, help="Exact group/repo+commit to snapshot identity map"),
    snapshot_cache: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "source_cache"),
    patch_cache: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "patches"),
    snapshot_root: Path = typer.Option(DEFAULT_RQ3_SNAPSHOT_ROOT, help="Short path for exported source snapshots (prevents Windows MAX_PATH failures)"),
    materialize_sources: bool = typer.Option(False, help="Fetch exact vulnerable source snapshots"),
    materialize_patches: bool = typer.Option(False, help="Fetch canonical fixing-commit diffs"),
    resolve_cwe: bool = typer.Option(True, "--resolve-cwe/--no-resolve-cwe"),
    adjudication: Path | None = typer.Option(None, help="Approved case-specific evidence decisions (JSON)"),
    reuse_manifest_from: Path | None = typer.Option(None, help="Reuse prior artifacts only when their source/patch identities match; permits a revised benchmark"),
) -> None:
    """Audit and freeze one RQ3 benchmark in a single reproducible preparation step."""
    audit = audit_rq3_benchmark(benchmark, downstream)
    frozen = freeze_rq3_benchmark(
        benchmark,
        output,
        downstream=downstream,
        snapshot_map=snapshot_map,
        snapshot_cache=snapshot_cache,
        patch_cache=patch_cache,
        materialize_sources=materialize_sources,
        materialize_patches=materialize_patches,
        resolve_cwe=resolve_cwe,
        adjudication=adjudication,
        reuse_manifest_from=reuse_manifest_from,
        snapshot_root=snapshot_root,
    )
    typer.echo(json.dumps({"audit": audit, "freeze": frozen}, indent=2))
    if not frozen.get("full_batch_ready"):
        raise typer.Exit(2)


def _rq3_preflight(freeze_summary: Path, environment_summary: Path, dataset: Path) -> dict:
    frozen = json.loads(freeze_summary.read_text(encoding="utf-8")) if freeze_summary.is_file() else {}
    health = json.loads(environment_summary.read_text(encoding="utf-8")) if environment_summary.is_file() else {}
    projects = health.get("projects") or []
    ready = sum(str(row.get("status")) == "READY" for row in projects)
    dataset_ready = all((dataset / name).is_file() for name in ("dataset.json", "queries.parquet", "packages.parquet", "environments.parquet"))
    checks = {
        "accepted_benchmark_frozen": frozen.get("status") == "FROZEN",
        "accepted_sources_patches_and_cwe_frozen": bool(frozen.get("full_batch_ready")),
        "all_28_project_environments_ready": len(projects) == 28 and ready == 28,
        "downstream_dataset_materialized": dataset_ready,
    }
    return {
        "ready": all(checks.values()), "checks": checks,
        "accepted_cases": frozen.get("accepted_rows", 0),
        "eligible_source_cases": frozen.get("eligible_source_cases", 0),
        "unmatched_downstream_rows": frozen.get("downstream_rows_unmatched_exact_group"),
        "project_environments_ready": ready, "project_environments_total": len(projects),
        "failed_projects": [str(row.get("project_id")) for row in projects if str(row.get("status")) != "READY"],
        "freeze_summary": str(freeze_summary), "environment_summary": str(environment_summary),
        "dataset": str(dataset),
    }


@app.command("rq3-preflight")
def rq3_preflight(
    freeze_summary: Path = typer.Option(DEFAULT_RQ3_MANIFEST.with_suffix(".summary.json")),
    environment_summary: Path = typer.Option(REPO_ROOT / "experiments" / "dependency_build" / "current" / "build_summary.json"),
    dataset: Path = typer.Option(DEFAULT_DATASET),
) -> None:
    """Check gates before launching a full downstream batch; this command is read-only."""
    typer.echo(json.dumps(_rq3_preflight(freeze_summary, environment_summary, dataset), indent=2))


@app.command("rq3-localize")
def rq3_localize(
    cases: Path = typer.Argument(..., exists=True),
    config: str = typer.Option(..., "--config", help="D_LEX, D_SEM, P_MODIFIED, or P_DUAL"),
    output_root: Path = typer.Option(REPO_ROOT / "experiments" / "vf"),
    limit: int = typer.Option(0, min=0, help="Stable prefix limit; zero means all cases"),
    resume: bool = typer.Option(True, "--resume/--no-resume"),
) -> None:
    """Run a frozen RQ3 case manifest with durable case-level checkpoints."""
    try:
        summary = run_localization_batch(cases, config.upper(), output_root, limit=limit, resume=resume)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(summary, indent=2))
    if summary["failed"]:
        raise typer.Exit(2)


@app.command("vf-prepare")
def vf_prepare(
    cases: Path = typer.Option(DEFAULT_RQ3_MANIFEST, exists=True, help="Frozen VF manifest, normally prepared_manifest_v6.jsonl"),
    output_root: Path = typer.Option(DEFAULT_VF_INPUTS, help="Root for immutable mode inputs and FunctionCatalog artifacts"),
    limit: int = typer.Option(0, min=0, help="Stable prefix limit for a small preparation/smoke run; zero means all cases"),
    workers: int = typer.Option(2, min=1, help="Parallel source catalogs to prepare on this machine"),
) -> None:
    """Prepare role-preserving GT, FunctionCatalogs, and isolated inputs for each VF mode."""
    try:
        summary = prepare_vf_inputs(cases, output_root, limit=limit, workers=workers)
    except (ValueError, OSError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(summary, indent=2))


@app.command("vf-run")
def vf_run(
    mode: str = typer.Argument(..., help="D_LEX, D_SEM, P_DUAL_PRESENT, P_DUAL_HIDDEN, or ORACLE"),
    inputs_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    output_root: Path = typer.Option(DEFAULT_VF_RESULTS, help="Root for results/<run-id>/<MODE>.jsonl"),
    run_id: str | None = typer.Option(None, help="Shared run folder name; defaults to the immutable input ID"),
    workers: int = typer.Option(1, min=1, help="Concurrent cases within this machine"),
    case_limit: int = typer.Option(0, min=0, help="Run a stable prefix per mode; zero means all cases"),
    progress: bool = typer.Option(True, "--progress/--no-progress"),
) -> None:
    """Run one frozen VF mode and checkpoint every attempted record."""
    try:
        summary = dispatch_vf_mode(
            mode, inputs_dir, output_root, run_id=run_id, progress=progress,
            workers=workers, case_limit=case_limit,
        )
    except (ValueError, FileNotFoundError, OSError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(summary, indent=2))
    if summary.get("failed", 0):
        raise typer.Exit(2)


@app.command("vf-shard")
def vf_shard(
    inputs_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    shard_count: int = typer.Option(..., "--shard-count", min=1, max=64),
    output_root: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "shards"),
) -> None:
    """Create verified portable input bundles, one per machine."""
    try:
        summary = create_vf_machine_shards(inputs_dir, output_root, shard_count=shard_count)
    except (ValueError, FileNotFoundError, FileExistsError, OSError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(summary, indent=2))


@app.command("vf-shard-plan")
def vf_shard_plan(
    inputs_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    shard_count: int = typer.Option(..., "--shard-count", min=1, max=64),
    output_root: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "shard-plans"),
) -> None:
    """Create tiny per-machine case-ID plans; reuse locally installed source/catalog artifacts."""
    try:
        summary = create_vf_index_shards(inputs_dir, output_root, shard_count=shard_count)
    except (ValueError, FileNotFoundError, FileExistsError, OSError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(summary, indent=2))


@app.command("vf-run-index-shard")
def vf_run_index_shard(
    inputs_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    shard_plan: Path = typer.Argument(..., exists=True),
    output_root: Path = typer.Option(DEFAULT_VF_RESULTS, help="Root for results/<run-id>/<machine-id>/"),
    run_id: str | None = typer.Option(None, help="Use the same run ID on every machine"),
    workers: int = typer.Option(2, min=1, help="Concurrent cases on this machine"),
    case_limit: int = typer.Option(0, min=0, help="Canary prefix per mode; resume with zero for the full shard"),
    progress: bool = typer.Option(True, "--progress/--no-progress"),
) -> None:
    """Run a lightweight case-ID shard against source/catalog artifacts already on this machine."""
    try:
        summary = run_vf_index_shard(
            inputs_dir, shard_plan, output_root, run_id=run_id, workers=workers,
            case_limit=case_limit, progress=progress,
        )
    except (ValueError, FileNotFoundError, FileExistsError, OSError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(summary, indent=2))
    if any(mode.get("failed", 0) for mode in summary.get("modes", {}).values()):
        raise typer.Exit(2)


@app.command("vf-run-shard")
def vf_run_shard(
    inputs_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    output_root: Path = typer.Option(DEFAULT_VF_RESULTS, help="Root for results/<run-id>/<machine-id>/"),
    run_id: str | None = typer.Option(None, help="Use the same run ID on every machine; default is derived from parent input ID"),
    workers: int = typer.Option(2, min=1, help="Concurrent cases on this machine"),
    case_limit: int = typer.Option(0, min=0, help="Canary prefix per mode; resume with zero for the full shard"),
    progress: bool = typer.Option(True, "--progress/--no-progress"),
) -> None:
    """Run D_LEX, D_SEM, P_DUAL_PRESENT, and P_DUAL_HIDDEN on one shard."""
    try:
        summary = run_vf_machine_shard(
            inputs_dir, output_root, run_id=run_id, workers=workers,
            case_limit=case_limit, progress=progress,
        )
    except (ValueError, FileNotFoundError, FileExistsError, OSError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(summary, indent=2))
    if any(mode.get("failed", 0) for mode in summary.get("modes", {}).values()):
        raise typer.Exit(2)


@app.command("vf-merge")
def vf_merge(
    inputs_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    shard_run_dir: list[Path] = typer.Option(..., "--shard-run-dir", exists=True, file_okay=False, dir_okay=True),
    output_root: Path = typer.Option(DEFAULT_VF_RESULTS),
    run_id: str = typer.Option(..., help="Must match the --run-id used on every machine"),
) -> None:
    """Validate and merge machine results, then generate central ORACLE control."""
    if run_id in {".", ".."} or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-" for ch in run_id) or len(run_id) > 100:
        raise typer.BadParameter("run_id may contain only letters, digits, dot, underscore, and hyphen")
    try:
        summary = merge_vf_machine_shards(inputs_dir, shard_run_dir, output_root / run_id)
    except (ValueError, FileNotFoundError, FileExistsError, OSError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(summary, indent=2))


@app.command("vf-metrics")
def vf_metrics(
    inputs_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    results_dir: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    output_dir: Path | None = typer.Option(None, help="Defaults to <results-dir>/report; consumes artifacts only"),
) -> None:
    """Calculate VF metrics and reports offline from prepared inputs and persisted results."""
    try:
        summary = compute_vf_report(inputs_dir, results_dir, output_dir or results_dir / "report")
    except (ValueError, FileNotFoundError, OSError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(json.dumps(summary, indent=2))


@app.command("rq3-run")
def rq3_run(
    cases: Path = typer.Argument(..., exists=True),
    config: list[str] = typer.Option(..., "--config", help="Repeat for each family: D_LEX, D_SEM, P_MODIFIED, P_DUAL"),
    output_root: Path = typer.Option(REPO_ROOT / "experiments" / "vf"),
    limit: int = typer.Option(0, min=0, help="Stable prefix limit; zero means all frozen cases"),
    resume: bool = typer.Option(True, "--resume/--no-resume"),
    resume_from_summary: Path | None = typer.Option(
        None, "--resume-from-summary", exists=True, file_okay=True, dir_okay=False,
        help="Continue a prior partial run after a code/settings fingerprint change; provide its summary.json",
    ),
    resume_from_checkpoint: Path | None = typer.Option(
        None, "--resume-from-checkpoint", exists=True, file_okay=False, dir_okay=True,
        help="Continue a partial run from its run directory after changing execution settings",
    ),
    report: bool = typer.Option(True, "--report/--no-report"),
    report_dir: Path | None = typer.Option(None, help="Defaults to <output-root>/report"),
) -> None:
    """Run selected RQ3 families sequentially, resume checkpoints, and write a combined report."""
    normalized = [value.strip().upper() for value in config]
    supported = {"D_LEX", "D_SEM", "P_MODIFIED", "P_DUAL"}
    invalid = [value for value in normalized if value not in supported]
    if invalid:
        raise typer.BadParameter(f"unsupported RQ3 config(s): {', '.join(invalid)}")
    if len(normalized) != len(set(normalized)):
        raise typer.BadParameter("each RQ3 config may be supplied only once")
    if resume_from_summary is not None and resume_from_checkpoint is not None:
        raise typer.BadParameter("choose either --resume-from-summary or --resume-from-checkpoint")
    if (resume_from_summary is not None or resume_from_checkpoint is not None) and len(normalized) != 1:
        raise typer.BadParameter("compatibility resume can be used with exactly one --config")
    if (resume_from_summary is not None or resume_from_checkpoint is not None) and not resume:
        raise typer.BadParameter("compatibility resume requires --resume")

    freeze_summary_path = cases.with_name(f"{cases.stem}.summary.json")
    if not freeze_summary_path.is_file():
        raise typer.BadParameter(
            f"missing freeze summary {freeze_summary_path}; prepare the benchmark with rq3-prepare first"
        )
    frozen = json.loads(freeze_summary_path.read_text(encoding="utf-8"))
    if frozen.get("status") != "FROZEN":
        raise typer.BadParameter(f"case manifest is not frozen: {freeze_summary_path}")
    declared_cases_hash = str(frozen.get("cases_sha256") or "")
    actual_cases_hash = hashlib.sha256(cases.read_bytes()).hexdigest()
    if declared_cases_hash and declared_cases_hash != actual_cases_hash:
        raise typer.BadParameter("case manifest changed after freeze; rerun rq3-prepare")
    if limit == 0 and not frozen.get("full_batch_ready"):
        raise typer.BadParameter(
            "full localization requires full_batch_ready=true in the freeze summary; "
            "fix missing source, patch, or CWE artifacts, or use --limit for a smoke run"
        )

    if "P_DUAL" in normalized and limit == 0:
        typer.echo(
            "WARNING: P_DUAL full-batch ranking can make hundreds of pairwise LLM calls per case; "
            "check provider quota/cost before proceeding."
        )

    run_summaries = []
    failed_configs = []
    all_case_rows = _rq3_rows(cases)
    fingerprint_rows = all_case_rows[:limit] if limit else all_case_rows
    for config_id in normalized:
        reusable = None
        if resume and resume_from_summary is None and resume_from_checkpoint is None:
            run_fingerprint, input_hash = _fingerprint(
                fingerprint_rows, config_id, limit or None,
            )
            expected_run_id = f"rq3-{config_id.lower()}-{run_fingerprint[:16]}"
            expected_run_dir = output_root / expected_run_id
            expected_summary_path = expected_run_dir / "summary.json"
            expected_results_path = expected_run_dir / "case_results.jsonl"
            if expected_summary_path.is_file() and expected_results_path.is_file():
                try:
                    candidate = json.loads(expected_summary_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    candidate = {}
                counts_match = sum(
                    int(candidate.get(key) or 0)
                    for key in ("completed", "failed", "ineligible", "not_applicable")
                ) == len(fingerprint_rows)
                if (
                    candidate.get("run_id") == expected_run_id
                    and candidate.get("run_fingerprint") == run_fingerprint
                    and candidate.get("dataset_hash") == input_hash
                    and candidate.get("config_id") == config_id
                    and int(candidate.get("case_count") or 0) == len(fingerprint_rows)
                    and int(candidate.get("failed") or 0) == 0
                    and counts_match
                    and isinstance(candidate.get("localization_quality"), list)
                ):
                    reusable = candidate

        if reusable is not None:
            typer.echo(
                f"Reusing completed RQ3 family {config_id}: "
                f"{reusable['completed']} complete, {reusable['ineligible']} ineligible"
            )
            summary = reusable
        else:
            if resume_from_summary is not None:
                typer.echo(
                    f"Compatibility-resuming RQ3 family {config_id} from "
                    f"{resume_from_summary}; matching completed cases will be reused"
                )
            elif resume_from_checkpoint is not None:
                typer.echo(
                    f"Compatibility-resuming RQ3 family {config_id} from checkpoint "
                    f"{resume_from_checkpoint}; matching completed cases will be reused"
                )
            else:
                typer.echo(f"Starting RQ3 family {config_id}")
            try:
                resume_kwargs = {}
                if resume_from_summary is not None:
                    resume_kwargs["resume_from_summary"] = resume_from_summary
                elif resume_from_checkpoint is not None:
                    resume_kwargs["resume_from_checkpoint"] = resume_from_checkpoint
                summary = run_localization_batch(
                    cases, config_id, output_root, limit=limit, resume=resume,
                    **resume_kwargs,
                )
            except ValueError as exc:
                raise typer.BadParameter(str(exc)) from exc
        run_summaries.append(summary)
        if summary.get("failed", 0):
            failed_configs.append(config_id)

    resolved_report_dir = report_dir or output_root / "report"
    report_summary = None
    if report and run_summaries:
        quality_path = resolved_report_dir / "result_1_localization_quality.json"
        report_summary_path = resolved_report_dir / "summary.json"
        quality_rows = [
            metric
            for summary in run_summaries
            for metric in (summary.get("localization_quality") or [])
        ]
        report_summary = {
            "localization_cases": len(fingerprint_rows),
            "localization_result_rows": sum(
                int(summary.get("case_count") or 0) for summary in run_summaries
            ),
            "downstream_report_generated": False,
            "result_1": str(quality_path),
        }
        write_json(quality_path, quality_rows)
        write_json(report_summary_path, report_summary)

    batch_summary = {
        "cases": str(cases),
        "case_count": min(limit, int(frozen.get("accepted_rows", 0))) if limit else int(frozen.get("accepted_rows", 0)),
        "configs": run_summaries,
        "failed_configs": failed_configs,
        "resume_enabled": resume,
        "report": report_summary,
    }
    write_json(output_root / "batch_summary.json", batch_summary)
    typer.echo(json.dumps(batch_summary, indent=2))
    if failed_configs:
        raise typer.Exit(2)


def _rq3_rows(path: Path) -> list[dict]:
    if path.suffix.lower() == ".parquet":
        return read_parquet(path)
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


@app.command("rq3-report")
def rq3_report(
    cases: Path = typer.Argument(..., exists=True),
    localization_results: list[Path] = typer.Argument(..., exists=True),
    downstream_pairs: Path | None = typer.Option(None, help="Paired downstream rows with exact cve_vf_group_id, config, oracle_decision, decision"),
    output_dir: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "report"),
) -> None:
    """Write the localization, downstream-consequence, and error-propagation tables."""
    case_rows = _rq3_rows(cases)
    evaluation_cases = [parse_case(row) for row in case_rows]
    localized = [row for path in localization_results for row in _rq3_rows(path)]
    quality = localization_quality(evaluation_cases, localized)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "result_1_localization_quality.json", quality)
    downstream_table: list[dict] = []
    propagation_table: list[dict] = []
    unmatched_count = 0
    if downstream_pairs is not None:
        pairs, unmatched = exact_group_join(case_rows, _rq3_rows(downstream_pairs))
        unmatched_count = len(unmatched)
        grouped: dict[tuple[str, str], list[dict]] = {}
        for _, row in pairs:
            config_id = str(row.get("config_id") or row.get("config") or "UNKNOWN")
            if config_id == "P_DUAL" and row.get("runtime_mode"):
                config_id = f"P_DUAL/{row['runtime_mode']}"
            budget = "All" if config_id == "P_MODIFIED" else str(row.get("top_k") or row.get("budget") or "All")
            grouped.setdefault((config_id, budget), []).append(row)
        for (config_id, budget), records in sorted(grouped.items()):
            downstream_table.append({"Config": config_id, "Top-k": budget, **downstream_consequence(records)})
            propagation_table.append({"Config": config_id, "Top-k": budget, **error_propagation(records)})
    write_json(output_dir / "result_2_downstream_consequence.json", downstream_table)
    write_json(output_dir / "result_3_error_propagation.json", propagation_table)
    summary = {
        "localization_cases": len(case_rows),
        "localization_result_rows": len(localized),
        "downstream_rows_exactly_joined": sum(row["compared"] for row in downstream_table),
        "downstream_rows_unmatched_exact_group": unmatched_count,
        "result_1": str(output_dir / "result_1_localization_quality.json"),
        "result_2": str(output_dir / "result_2_downstream_consequence.json"),
        "result_3": str(output_dir / "result_3_error_propagation.json"),
    }
    write_json(output_dir / "summary.json", summary)
    typer.echo(json.dumps(summary, indent=2))


@app.command("rq3-vf-build")
def rq3_vf_build(
    cases: Path = typer.Option(DEFAULT_RQ3_MANIFEST, exists=True),
    localization_results: list[Path] = typer.Option(..., "--localization-results", exists=True),
    downstream: Path = typer.Option(REPO_ROOT / "data" / "benchmarks" / "f_vra_downstream_reachability_benchmark.jsonl", exists=True),
    dataset: Path = typer.Option(DEFAULT_DATASET),
    output: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "rq3_variants.parquet"),
    budget: list[int] = typer.Option([1, 5], "--budget", min=1),
    limit: int = typer.Option(0, min=0, help="Stable downstream prefix limit; zero means all"),
    resume: bool = typer.Option(True, "--resume/--no-resume"),
) -> None:
    """Exact-group join, bind selected functions, and write eval-vf manifests."""
    if limit == 0:
        freeze_summary = cases.with_name(f"{cases.stem}.summary.json")
        gate = _rq3_preflight(
            freeze_summary,
            REPO_ROOT / "experiments" / "dependency_build" / "current" / "build_summary.json",
            dataset,
        )
        if not gate["ready"]:
            raise typer.BadParameter("full RQ3 binding is gated; fix preflight checks first: " + json.dumps(gate["checks"], sort_keys=True))
    summary = build_rq3_vf_variants(
        cases, localization_results, downstream, dataset, output,
        budgets=tuple(sorted(set(budget))), limit=limit, resume=resume,
    )
    typer.echo(json.dumps(summary, indent=2))


@app.command("rq3-pair")
def rq3_pair(
    binding_audit: Path = typer.Argument(..., exists=True),
    downstream: Path = typer.Option(REPO_ROOT / "data" / "benchmarks" / "f_vra_downstream_reachability_benchmark.jsonl", exists=True),
    run: list[Path] = typer.Option(..., "--run", exists=True, help="One eval-vf run directory per config/budget"),
    output: Path = typer.Option(REPO_ROOT / "experiments" / "vf" / "rq3_downstream_pairs.parquet"),
) -> None:
    """Pair eval-vf decisions with benchmark labels via exact VF group IDs."""
    typer.echo(json.dumps(pair_rq3_downstream_runs(binding_audit, downstream, run, output), indent=2))


@app.command("reachability-benchmark")
def reachability_benchmark(
    dataset: Path = typer.Option(REPO_ROOT / "experiments" / "dataset" / "compose25_verified_v9", exists=True),
    jarvis_root: Path = typer.Option(DEFAULT_JARVIS, exists=True),
    output_dir: Path = typer.Option(REPO_ROOT / "experiments" / "vf"),
    query_id: list[str] = typer.Option([], "--query-id", help="Exact frozen query ID; repeat to select smoke cases."),
    limit: int = typer.Option(0, min=0, help="Stable query ID prefix limit; zero runs the selected population."),
    run_label: str = typer.Option("reachability", help="Output stem; results stay directly under experiments/vf."),
    adjudications: Path | None = typer.Option(None, exists=True, help="Manual eligibility exclusions bound to exact case snapshots."),
    resume: bool = typer.Option(True, "--resume/--no-resume"),
) -> None:
    """Run the direct binary reachability benchmark using its frozen VF sets."""
    from f_vra.evaluation.reachability_benchmark import run_reachability_benchmark

    result = run_reachability_benchmark(
        dataset,
        jarvis_root,
        output_dir,
        query_ids=set(query_id) if query_id else None,
        limit=limit,
        run_label=run_label,
        adjudications_path=adjudications,
        resume=resume,
    )
    typer.echo(json.dumps(result, indent=2))
