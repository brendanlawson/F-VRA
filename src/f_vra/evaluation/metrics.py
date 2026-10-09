"""Separated oracle accuracy, fresh agreement, and reuse economics."""

from __future__ import annotations

import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median
from typing import Any

from f_vra.evaluation.io import read_json, read_parquet


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> tuple[float, float] | None:
    if total <= 0:
        return None
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)


def accuracy(results: list[dict[str, Any]], oracle: list[dict[str, Any]]) -> dict[str, Any]:
    accepted = {row["query_id"]: row["decision"] for row in oracle if row.get("review_status") == "accepted"}
    matched = [(row["decision"], accepted[row["query_id"]]) for row in results if row["query_id"] in accepted]
    decisive = [(prediction, truth) for prediction, truth in matched if prediction != "UNKNOWN" and truth != "UNKNOWN"]
    tp = sum(prediction == truth == "REACHABLE" for prediction, truth in decisive)
    tn = sum(prediction == truth == "UNREACHABLE" for prediction, truth in decisive)
    fp = sum(prediction == "REACHABLE" and truth == "UNREACHABLE" for prediction, truth in decisive)
    fn = sum(prediction == "UNREACHABLE" and truth == "REACHABLE" for prediction, truth in decisive)
    ratio = lambda numerator, denominator: numerator / denominator if denominator else None
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    return {
        "oracle_accepted": len(accepted), "matched": len(matched), "decisive": len(decisive),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None,
        "fnr": ratio(fn, tp + fn), "coverage": ratio(len(decisive), len(matched)),
        "precision_ci": wilson_interval(tp, tp + fp), "recall_ci": wilson_interval(tp, tp + fn),
    }


def agreement(results: list[dict[str, Any]], fresh: list[dict[str, Any]]) -> dict[str, Any]:
    reference = {row["query_id"]: row["decision"] for row in fresh}
    pairs = [(reference[row["query_id"]], row["decision"]) for row in results if row["query_id"] in reference]
    flips = Counter(f"{a}->{b}" for a, b in pairs if a != b)
    equal = sum(a == b for a, b in pairs)
    return {"compared": len(pairs), "equal": equal, "rate": equal / len(pairs) if pairs else None, "transitions": dict(flips)}


def workload_overlap(fresh_events: list[dict[str, Any]]) -> dict[str, Any]:
    demands = [event for event in fresh_events if event.get("event") == "FRAGMENT_BUILD"]
    package_counts = Counter(str(event["package_id"]) for event in demands)
    root_counts = Counter((str(event["package_id"]), str(event["root"])) for event in demands)
    fresh_cost = sum(float(event.get("wall_clock_ms") or 0) for event in demands)
    unique_first = {}
    for event in demands:
        unique_first.setdefault((event["package_id"], event["root"]), float(event.get("wall_clock_ms") or 0))
    potential = 1 - sum(unique_first.values()) / fresh_cost if fresh_cost else None
    by_query: dict[str, set[str]] = defaultdict(set)
    for event in demands:
        by_query[str(event["query_id"])].update(str(value) for value in event.get("analyzed_functions") or [])
    query_ids = sorted(by_query)
    jaccards = []
    for i, left in enumerate(query_ids):
        for right in query_ids[i + 1:]:
            a, b = by_query[left], by_query[right]
            if a and b:
                union = a | b
                jaccards.append(len(a & b) / len(union))
    return {
        "total_fragment_demands": len(demands), "unique_fragment_demands": len(root_counts),
        "package_multiplicity": dict(package_counts),
        "root_multiplicity": [{"package_id": key[0], "root": key[1], "count": count} for key, count in sorted(root_counts.items())],
        "potential_reuse": potential, "median_function_jaccard": median(jaccards) if jaccards else None,
    }


def cumulative(run_dir: Path) -> list[dict[str, Any]]:
    summary = read_json(run_dir / "summary.json")
    cost = float(summary.get("precomputation_ms") or 0)
    events = read_parquet(run_dir / "artifact_events.parquet")
    functions = sum(int(event.get("functions_analyzed") or 0) for event in events if event.get("precomputation"))
    cpu = sum(float(event.get("cpu_time_ms") or 0) for event in events if event.get("precomputation"))
    rows = [{"queries_processed": 0, "cumulative_ms": cost, "cumulative_cpu_ms": cpu, "cumulative_functions": functions}]
    for index, item in enumerate(read_parquet(run_dir / "query_results.parquet"), 1):
        cost += float(item.get("wall_clock_ms") or 0)
        cpu += float(item.get("cpu_time_ms") or 0)
        functions += int(item.get("functions_analyzed") or 0)
        rows.append({"queries_processed": index, "cumulative_ms": cost, "cumulative_cpu_ms": cpu, "cumulative_functions": functions})
    return rows


def reuse_economics(run_dir: Path, fresh_dir: Path | None = None) -> dict[str, Any]:
    results = read_parquet(run_dir / "query_results.parquet")
    events = read_parquet(run_dir / "artifact_events.parquet")
    demands = sum(int(row.get("fragments_built") or 0) + int(row.get("fragments_reused") or 0) for row in results)
    reused = sum(int(row.get("fragments_reused") or 0) for row in results)
    summary = read_json(run_dir / "summary.json")
    metrics = {
        "reuse_rate": reused / demands if demands else 0.0,
        "cache_hit_rate": sum(int(row.get("cache_hit_count") or 0) for row in results) / sum(int(row.get("cache_lookup_count") or 0) for row in results) if sum(int(row.get("cache_lookup_count") or 0) for row in results) else 0.0,
        "artifact_bytes_written": sum(int(event.get("artifact_bytes_written") or 0) for event in events),
        "precomputation_ms": float(summary.get("precomputation_ms") or 0),
        "amortized_ms": float(summary.get("cumulative_wall_clock_ms") or 0) / len(results) if results else None,
    }
    if fresh_dir is not None:
        fresh_curve, curve = cumulative(fresh_dir), cumulative(run_dir)
        fresh_functions = fresh_curve[-1]["cumulative_functions"] if fresh_curve else 0
        functions = curve[-1]["cumulative_functions"] if curve else 0
        metrics["work_saved"] = 1 - functions / fresh_functions if fresh_functions else None
        by_n = {row["queries_processed"]: row["cumulative_ms"] for row in fresh_curve}
        metrics["break_even_query"] = next((row["queries_processed"] for row in curve if row["queries_processed"] and row["cumulative_ms"] <= by_n.get(row["queries_processed"], -1)), None)
    return metrics


def vf_uncertainty(oracle_results: list[dict[str, Any]], variant_results: list[dict[str, Any]]) -> dict[str, Any]:
    oracle = {row["query_id"]: row["decision"] for row in oracle_results}
    compared = [(oracle[row["query_id"]], row["decision"]) for row in variant_results if row["query_id"] in oracle]
    oracle_impact = {query_id for query_id, decision in oracle.items() if decision == "REACHABLE"}
    variant_impact = {row["query_id"] for row in variant_results if row["decision"] == "REACHABLE"}
    intersection = oracle_impact & variant_impact
    union = oracle_impact | variant_impact
    return {
        "compared": len(compared), "decision_flip_rate": sum(left != right for left, right in compared) / len(compared) if compared else None,
        "downstream_precision": len(intersection) / len(variant_impact) if variant_impact else None,
        "downstream_recall": len(intersection) / len(oracle_impact) if oracle_impact else None,
        "jaccard": len(intersection) / len(union) if union else 1.0,
        "transitions": dict(Counter(f"{left}->{right}" for left, right in compared if left != right)),
    }


def vf_input_quality(
    expected_by_query: dict[str, list[dict[str, Any]]],
    observed_by_query: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Compare source-bound VF identities for a frozen variant against V0."""
    identity = lambda query_id, item: (
        query_id, str(item.get("package_id") or ""),
        str(item.get("qualified_name") or ""), str(item.get("function_hash") or ""),
    )
    expected = {
        identity(query_id, item)
        for query_id, items in expected_by_query.items() for item in items
    }
    observed = {
        identity(query_id, item)
        for query_id, items in observed_by_query.items() for item in items
    }
    overlap = expected & observed
    return {
        "vf_true_positive": len(overlap), "vf_expected": len(expected), "vf_observed": len(observed),
        "vf_precision": len(overlap) / len(observed) if observed else None,
        "vf_recall": len(overlap) / len(expected) if expected else None,
    }


def cluster_bootstrap(records: list[dict[str, Any]], value_field: str, *, iterations: int = 1000, seed: int = 17) -> tuple[float, float] | None:
    grouped: dict[str, list[float]] = defaultdict(list)
    for row in records:
        value = row.get(value_field)
        project_id = row.get("project_id")
        if value is not None and project_id:
            grouped[str(project_id)].append(float(value))
    if not grouped:
        return None
    keys = sorted(grouped)
    generator = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        values = [value for key in (generator.choice(keys) for _ in keys) for value in grouped[key]]
        estimates.append(sum(values) / len(values))
    estimates.sort()
    return estimates[int(0.025 * iterations)], estimates[min(iterations - 1, int(0.975 * iterations))]
