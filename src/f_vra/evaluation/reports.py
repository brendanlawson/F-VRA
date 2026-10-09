"""Produce reproducible tables and figures from event-level run outputs."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from f_vra.evaluation.io import read_json, read_parquet, write_json
from f_vra.evaluation.metrics import accuracy, agreement, cluster_bootstrap, cumulative, reuse_economics, vf_uncertainty, workload_overlap


def generate_report(dataset_dir: Path, run_dirs: list[Path], output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    oracle_path = dataset_dir / "oracle_labels.parquet"
    oracle = read_parquet(oracle_path) if oracle_path.exists() else []
    queries = read_parquet(dataset_dir / "queries.parquet")
    query_projects = {str(row["query_id"]): str(row["project_id"]) for row in queries}
    runs = []
    for path in run_dirs:
        config = __import__("yaml").safe_load((path / "config.yaml").read_text(encoding="utf-8"))
        result = [
            row | {"project_id": row.get("project_id") or query_projects.get(str(row["query_id"]), "")}
            for row in read_parquet(path / "query_results.parquet")
        ]
        vf_input_path = path / "vf_input_metrics.json"
        item = {
            "path": path, "config": config, "results": result, "summary": read_json(path / "summary.json"),
            "vf_input_metrics": read_json(vf_input_path) if vf_input_path.exists() else None,
        }
        runs.append(item)
    fresh_candidates = [run for run in runs if run["config"]["strategy"] == "fresh"]
    fresh = max(
        fresh_candidates,
        key=lambda run: (
            not bool(run["config"].get("run_label")),
            int(run["config"].get("limit") or 0) == 0,
            int(run["summary"].get("queries") or 0),
        ),
    ) if fresh_candidates else None
    report_rows = []
    accepted = {row["query_id"]: row["decision"] for row in oracle if row.get("review_status") == "accepted" and row.get("query_id")}
    for run in runs:
        agreement_rows = []
        correctness_rows = []
        fresh_by_id = {row["query_id"]: row["decision"] for row in (fresh["results"] if fresh else [])}
        for result in run["results"]:
            if result["query_id"] in fresh_by_id:
                agreement_rows.append({"project_id": result.get("project_id", ""), "value": float(result["decision"] == fresh_by_id[result["query_id"]])})
            truth = accepted.get(result["query_id"])
            if truth and truth != "UNKNOWN" and result["decision"] != "UNKNOWN":
                correctness_rows.append({"project_id": result.get("project_id", ""), "value": float(result["decision"] == truth)})
        row = {
            "run_id": run["summary"]["run_id"], "strategy": run["config"]["strategy"],
            "order": run["config"]["order"], "seed": run["config"]["seed"],
            "queries": run["summary"]["queries"],
            "cumulative_wall_clock_ms": run["summary"]["cumulative_wall_clock_ms"],
            "cumulative_cpu_time_ms": run["summary"].get("cumulative_cpu_time_ms", 0),
            "functions_analyzed": run["summary"]["functions_analyzed"],
            "unique_functions_analyzed": run["summary"].get("unique_functions_analyzed", 0),
            "call_edges_materialized": run["summary"].get("call_edges_materialized", 0),
            "peak_rss_mb": run["summary"].get("peak_rss_mb", 0),
            "artifact_bytes_written": run["summary"].get("artifact_bytes_written", 0),
            "project_graph_cost_ms": run["summary"].get("project_graph_cost_ms", 0),
            "oracle_accuracy": accuracy(run["results"], oracle),
            "fresh_agreement": agreement(run["results"], fresh["results"]) if fresh else None,
            "query_wall_ms_cluster_ci": cluster_bootstrap(run["results"], "wall_clock_ms", iterations=2000),
            "fresh_agreement_cluster_ci": cluster_bootstrap(agreement_rows, "value", iterations=2000),
            "oracle_accuracy_cluster_ci": cluster_bootstrap(correctness_rows, "value", iterations=2000),
        }
        report_rows.append(row)
    if fresh:
        for row, run in zip(report_rows, runs):
            row["reuse_economics"] = reuse_economics(run["path"], fresh["path"])
    overlap = workload_overlap(read_parquet(fresh["path"] / "artifact_events.parquet")) if fresh else None
    variants = {run["config"].get("run_label"): run for run in runs if run["config"].get("run_label")}
    v0 = variants.get("V0_ORACLE") or variants.get("V0") or variants.get("oracle")
    vf_metrics = {
        name: vf_uncertainty(v0["results"], run["results"]) | {"input": run.get("vf_input_metrics")}
        for name, run in variants.items() if v0 and run is not v0
    }
    package_rows = {row["package_id"]: row for row in read_parquet(dataset_dir / "packages.parquet")}
    project_graphs = {}
    usage_count = 0
    for query in queries:
        graph_path = dataset_dir / "project_graphs" / f"{query['env_id']}.json"
        if graph_path.exists():
            project_graphs.setdefault(query["env_id"], read_json(graph_path)["graph"])
            roots = set(package_rows.get(query["affected_package_id"], {}).get("import_roots") or [])
            if any(str(symbol).split(".", 1)[0] in roots for symbol in project_graphs[query["env_id"]].get("usage_index") or []):
                usage_count += 1
    fresh_reachable = sum(row["decision"] == "REACHABLE" for row in (fresh["results"] if fresh else []))
    funnel = {"package_exposed": len(queries), "used_or_imported": usage_count, "function_reachable": fresh_reachable}
    payload = {"runs": report_rows, "impact_funnel": funnel, "workload_overlap": overlap, "vf_uncertainty": vf_metrics, "oracle_accepted": sum(row.get("review_status") == "accepted" for row in oracle)}
    write_json(output_dir / "report.json", payload)
    with (output_dir / "run_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["run_id", "strategy", "order", "seed", "queries", "cumulative_wall_clock_ms", "cumulative_cpu_time_ms", "functions_analyzed", "unique_functions_analyzed", "call_edges_materialized", "peak_rss_mb", "artifact_bytes_written", "project_graph_cost_ms", "fresh_agreement_rate", "oracle_precision", "oracle_recall", "oracle_coverage"])
        writer.writeheader()
        for row in report_rows:
            oracle_metrics = row["oracle_accuracy"]
            writer.writerow({
                **{key: row[key] for key in ("run_id", "strategy", "order", "seed", "queries", "cumulative_wall_clock_ms", "cumulative_cpu_time_ms", "functions_analyzed", "unique_functions_analyzed", "call_edges_materialized", "peak_rss_mb", "artifact_bytes_written", "project_graph_cost_ms")},
                "fresh_agreement_rate": (row["fresh_agreement"] or {}).get("rate"),
                "oracle_precision": oracle_metrics["precision"], "oracle_recall": oracle_metrics["recall"], "oracle_coverage": oracle_metrics["coverage"],
            })
    lines = ["# F-VRA experiment report", "", f"Accepted oracle labels: {payload['oracle_accepted']}", "", "| Strategy | Order | Seed | Queries | Cumulative seconds | Functions analyzed | Agreement with Fresh |", "| --- | --- | ---: | ---: | ---: | ---: | ---: |"]
    for row in report_rows:
        agreement_rate = (row["fresh_agreement"] or {}).get("rate")
        lines.append(f"| {row['strategy']} | {row['order']} | {row['seed']} | {row['queries']} | {row['cumulative_wall_clock_ms'] / 1000:.2f} | {row['functions_analyzed']} | {agreement_rate:.3f} |" if agreement_rate is not None else f"| {row['strategy']} | {row['order']} | {row['seed']} | {row['queries']} | {row['cumulative_wall_clock_ms'] / 1000:.2f} | {row['functions_analyzed']} | n/a |")
    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(figsize=(8, 5))
        for run in runs:
            rows = cumulative(run["path"])
            ax.plot([item["queries_processed"] for item in rows], [item["cumulative_ms"] / 1000 for item in rows], label=f"{run['config']['strategy']} {run['config']['order']} {run['config']['seed']}")
        ax.set(xlabel="Queries processed", ylabel="Cumulative analysis seconds")
        ax.legend(fontsize=7)
        fig.tight_layout()
        fig.savefig(output_dir / "cumulative_cost.png", dpi=160)
        fig.savefig(output_dir / "cumulative_cost.svg")
        plt.close(fig)

        fig, ax = plt.subplots(figsize=(8, 5))
        for run in runs:
            rows = cumulative(run["path"])
            label = f"{run['config']['strategy']} {run['config']['order']} {run['config']['seed']}"
            ax.plot([item["queries_processed"] for item in rows], [item["cumulative_cpu_ms"] / 1000 for item in rows], label=label)
        ax.set(xlabel="Queries processed", ylabel="Cumulative CPU seconds")
        ax.legend(fontsize=7)
        fig.tight_layout()
        fig.savefig(output_dir / "cumulative_cpu_cost.png", dpi=160)
        plt.close(fig)

        fig, ax = plt.subplots(figsize=(8, 5))
        for run in runs:
            rows = cumulative(run["path"])
            label = f"{run['config']['strategy']} {run['config']['order']} {run['config']['seed']}"
            ax.plot([item["queries_processed"] for item in rows], [item["cumulative_functions"] for item in rows], label=label)
        ax.set(xlabel="Queries processed", ylabel="Cumulative function analyses")
        ax.legend(fontsize=7)
        fig.tight_layout()
        fig.savefig(output_dir / "cumulative_function_work.png", dpi=160)
        plt.close(fig)

        fig, ax = plt.subplots(figsize=(6, 4))
        funnel_names = ["Package exposed", "Used/imported", "Function reachable"]
        funnel_values = [funnel["package_exposed"], funnel["used_or_imported"], funnel["function_reachable"]]
        ax.bar(funnel_names, funnel_values)
        ax.set(ylabel="Queries")
        ax.tick_params(axis="x", rotation=18)
        fig.tight_layout()
        fig.savefig(output_dir / "impact_funnel.png", dpi=160)
        plt.close(fig)

        economics_rows = [(row["strategy"], row.get("reuse_economics") or {}) for row in report_rows]
        fig, ax = plt.subplots(figsize=(7, 4))
        ax.bar([name for name, _ in economics_rows], [float(values.get("work_saved") or 0) for _, values in economics_rows])
        ax.set(ylabel="Fraction of Fresh function work saved")
        ax.tick_params(axis="x", rotation=20)
        fig.tight_layout()
        fig.savefig(output_dir / "work_saved.png", dpi=160)
        plt.close(fig)

        fig, ax = plt.subplots(figsize=(7, 4))
        break_even = [values.get("break_even_query") for _, values in economics_rows]
        ax.bar([name for name, _ in economics_rows], [value if value is not None else 0 for value in break_even])
        ax.set(ylabel="Break-even query (0 = not reached)")
        ax.tick_params(axis="x", rotation=20)
        fig.tight_layout()
        fig.savefig(output_dir / "break_even.png", dpi=160)
        plt.close(fig)

        decisions = ["REACHABLE", "UNREACHABLE", "UNKNOWN"]
        transition_counts = [[0 for _ in decisions] for _ in decisions]
        for row in report_rows:
            for transition, count in (row.get("fresh_agreement") or {}).get("transitions", {}).items():
                left, right = transition.split("->", 1)
                transition_counts[decisions.index(left)][decisions.index(right)] += count
        fig, ax = plt.subplots(figsize=(5, 4))
        image = ax.imshow(transition_counts, cmap="Blues")
        ax.set_xticks(range(3), decisions, rotation=25, ha="right")
        ax.set_yticks(range(3), decisions)
        ax.set(xlabel="Policy verdict", ylabel="Fresh verdict")
        for i in range(3):
            for j in range(3):
                ax.text(j, i, str(transition_counts[i][j]), ha="center", va="center")
        fig.colorbar(image, ax=ax)
        fig.tight_layout()
        fig.savefig(output_dir / "verdict_transitions.png", dpi=160)
        plt.close(fig)

        multiplicity = (overlap or {}).get("root_multiplicity") or []
        top = sorted(multiplicity, key=lambda item: item["count"], reverse=True)[:20]
        fig, ax = plt.subplots(figsize=(8, max(4, len(top) * 0.25)))
        ax.barh([item["root"] for item in reversed(top)], [item["count"] for item in reversed(top)])
        ax.set(xlabel="Fresh fragment demands", ylabel="Root")
        fig.tight_layout()
        fig.savefig(output_dir / "workload_overlap.png", dpi=160)
        plt.close(fig)

        fig, ax = plt.subplots(figsize=(7, 4))
        if vf_metrics:
            ax.bar(list(vf_metrics), [float(values.get("decision_flip_rate") or 0) for values in vf_metrics.values()])
            ax.set(ylabel="Decision flip rate")
        else:
            ax.text(0.5, 0.5, "No VF variant runs supplied", ha="center", va="center", transform=ax.transAxes)
            ax.set_axis_off()
        fig.tight_layout()
        fig.savefig(output_dir / "vf_error_impact.png", dpi=160)
        plt.close(fig)
    except ImportError:
        pass
    return payload
