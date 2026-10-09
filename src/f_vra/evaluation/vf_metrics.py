"""Offline CVE-to-vulnerable-function metrics over frozen run artifacts."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from f_vra.evaluation.io import write_json

SCOPES = ("root_cause_only", "all_valid_anchors")
RANK_CUTOFFS = (1, 3, 5, 10)
MODES = ("D_LEX", "D_SEM", "P_DUAL_PRESENT", "P_DUAL_HIDDEN", "ORACLE")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError(f"{path}:{line_number}: expected a JSON object")
                rows.append(value)
    return rows


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = list(dict.fromkeys(key for row in rows for key in row))
    if not columns:
        columns = ["mode", "gt_scope"]
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _write_markdown(path: Path, title: str, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = list(dict.fromkeys(key for row in rows for key in row))
    if not columns:
        path.write_text(f"# {title}\n\nNo data.\n", encoding="utf-8")
        return
    lines = [f"# {title}", "", "| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    for row in rows:
        values = []
        for column in columns:
            value = row.get(column)
            if isinstance(value, float):
                value = f"{value:.4f}"
            values.append(str(value if value is not None else "—").replace("|", "\\|"))
        lines.append("| " + " | ".join(values) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _path(value: Any) -> str:
    return str(value or "").replace("\\", "/").removeprefix("./")


def normalize_ground_truth(row: dict[str, Any]) -> dict[str, Any]:
    """Return role-preserving, deduplicated VF labels for one frozen case."""
    source = ""
    raw_value: Any = None
    for field in ("vulnerable_functions", "verified_vfs", "root_cause_functions"):
        candidate = row.get(field)
        if candidate:
            source, raw_value = field, candidate
            break
    if isinstance(raw_value, list):
        raw_labels = raw_value
    elif isinstance(raw_value, dict):
        role_map = {
            key: value for key, value in raw_value.items()
            if key in {"root_cause_vf", "root_cause_functions", "vulnerable_usage_site", "usage_sites"}
        }
        if role_map:
            raw_labels = []
            for role, values in role_map.items():
                role = "root_cause_vf" if role in {"root_cause_vf", "root_cause_functions"} else "vulnerable_usage_site"
                values = values if isinstance(values, list) else [values]
                for value in values:
                    if isinstance(value, dict):
                        raw_labels.append({**value, "role": value.get("role") or value.get("label") or role})
                    else:
                        raw_labels.append({"qualified_name": value, "role": role})
        else:
            raw_labels = [raw_value]
    elif isinstance(raw_value, str):
        raw_labels = [raw_value]
    elif raw_value is None:
        raw_labels = []
    else:
        raw_labels = [raw_value]

    normalized: dict[tuple[str, str, str], dict[str, Any]] = {}
    unresolved: list[dict[str, Any]] = []
    for raw in raw_labels:
        if isinstance(raw, str):
            file_path, qualified_name = "", raw.strip()
            role_value = "root_cause_vf" if source == "root_cause_functions" else "unknown"
        elif isinstance(raw, dict):
            file_path = _path(raw.get("file_path") or raw.get("file") or raw.get("path"))
            qualified_name = str(
                raw.get("qualified_name") or raw.get("qualname") or raw.get("function")
                or raw.get("function_name") or raw.get("name") or ""
            ).strip()
            role_value = str(raw.get("role") or raw.get("label") or raw.get("vf_role") or raw.get("ground_truth_role") or "").strip().lower()
            role_value = role_value.replace("-", "_").replace(" ", "_")
            if role_value in {"root_cause", "root_cause_function", "rootcause", "root_cause_vf"}:
                role_value = "root_cause_vf"
            elif role_value in {"usage_site", "vulnerable_usage", "vulnerable_usage_site"}:
                role_value = "vulnerable_usage_site"
            elif not role_value:
                role_value = "root_cause_vf" if source == "root_cause_functions" else "unknown"
        else:
            unresolved.append({"value": repr(raw), "reason": "unsupported_label_shape"})
            continue
        if not qualified_name:
            unresolved.append({"value": raw, "reason": "missing_qualified_name"})
            continue
        function_id = f"{file_path}:{qualified_name}" if file_path else qualified_name
        identity = (file_path, qualified_name, role_value)
        normalized[identity] = {
            "function_id": function_id,
            "file_path": file_path,
            "qualified_name": qualified_name,
            "role": role_value,
            "label_source": source,
        }
    anchors = [normalized[key] for key in sorted(normalized)]
    return {
        "schema_version": "f_vra.vf.ground-truth.v1",
        "case_id": str(row.get("case_id") or row.get("group_id") or row.get("cve_vf_group_id") or ""),
        "cve_vf_group_id": str(row.get("cve_vf_group_id") or row.get("group_id") or ""),
        "vulnerable_functions": anchors,
        "unresolved_labels": unresolved,
    }


def _anchors_for_scope(gt_row: dict[str, Any], scope: str) -> list[dict[str, Any]]:
    anchors = list(gt_row.get("vulnerable_functions") or [])
    if scope == "root_cause_only":
        return [anchor for anchor in anchors if anchor.get("role") == "root_cause_vf"]
    if scope == "all_valid_anchors":
        return anchors
    raise ValueError(f"unknown ground-truth scope: {scope}")


def _candidate_aliases(candidate: dict[str, Any]) -> set[str]:
    return {
        str(candidate.get(field) or "").strip()
        for field in ("qualified_name", "qualname", "module_qualified_name", "name")
        if str(candidate.get(field) or "").strip()
    }


def _matches(anchor: dict[str, Any], candidate: dict[str, Any]) -> bool:
    anchor_id = str(anchor.get("function_id") or "")
    candidate_id = str(candidate.get("function_id") or "")
    if anchor_id and candidate_id and anchor_id == candidate_id:
        return True
    anchor_path = _path(anchor.get("file_path"))
    candidate_path = _path(candidate.get("file_path"))
    anchor_name = str(anchor.get("qualified_name") or "").strip()
    aliases = _candidate_aliases(candidate)
    if anchor_name not in aliases:
        return False
    return not anchor_path or anchor_path == candidate_path


def _matched_anchor_indices(anchors: list[dict[str, Any]], candidates: Iterable[dict[str, Any]]) -> set[int]:
    matched = set()
    for candidate in candidates:
        for index, anchor in enumerate(anchors):
            if _matches(anchor, candidate):
                matched.add(index)
    return matched


def _latest_rows(path: Path) -> list[dict[str, Any]]:
    """Read the final result file, falling back to durable attempt checkpoints."""
    mode = path.stem.removesuffix(".checkpoint")
    checkpoint = path.with_name(f"{mode}.checkpoint.jsonl")
    source = checkpoint if checkpoint.exists() else path
    latest: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    if not source.exists():
        return []
    for row in _read_jsonl(source):
        case_id = str(row.get("case_id") or "")
        if not case_id:
            continue
        if case_id not in latest:
            order.append(case_id)
        latest[case_id] = row
    return [latest[case_id] for case_id in order]


def _usage(row: dict[str, Any]) -> dict[str, Any]:
    metadata = row.get("metadata") or {}
    return metadata.get("provider_usage") or {}


def _is_usable_extraction(row: dict[str, Any]) -> bool:
    metadata = row.get("metadata") or {}
    extraction = metadata.get("entity_extraction") or {}
    entities = extraction.get("entities") or metadata.get("entities") or {}
    return any(str(entities.get(key) or "").strip() for key in ("attack_vector", "root_cause"))


def _case_score(
    row: dict[str, Any] | None,
    anchors: list[dict[str, Any]],
) -> tuple[int | None, dict[str, Any]]:
    if row is None or row.get("status") != "complete" or row.get("output_type") != "ranked":
        return None, {"Hit@1": 0.0, "Hit@3": 0.0, "Hit@5": 0.0, "Hit@10": 0.0, "MRR": 0.0}
    predictions = row.get("predictions") or []
    best_rank = None
    for prediction in predictions:
        try:
            rank = int(prediction.get("rank"))
        except (TypeError, ValueError):
            continue
        if any(_matches(anchor, prediction) for anchor in anchors):
            best_rank = rank if best_rank is None else min(best_rank, rank)
    metrics = {f"Hit@{cutoff}": float(best_rank is not None and best_rank <= cutoff) for cutoff in RANK_CUTOFFS}
    metrics["MRR"] = 1.0 / best_rank if best_rank else 0.0
    return best_rank, metrics


def _metric_rows(
    inputs_by_mode: dict[str, list[dict[str, Any]]],
    gt_by_case: dict[str, dict[str, Any]],
    results_by_mode: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], dict[str, dict[str, dict[str, dict[str, float]]]]]:
    output: list[dict[str, Any]] = []
    score_lookup: dict[str, dict[str, dict[str, dict[str, float]]]] = defaultdict(lambda: defaultdict(dict))
    for mode, input_rows in inputs_by_mode.items():
        if mode == "ORACLE":
            continue
        result_by_case = {str(row.get("case_id")): row for row in results_by_mode.get(mode, [])}
        eligible_rows = [row for row in input_rows if bool(row.get("eligible", True))]
        ineligible_rows = [row for row in input_rows if not bool(row.get("eligible", True))]
        all_case_ids = [str(row.get("case_id") or "") for row in eligible_rows]
        result_statuses = [result_by_case.get(case_id) for case_id in all_case_ids]
        complete_count = sum(row is not None and row.get("status") == "complete" for row in result_statuses)
        failed_count = sum(row is not None and row.get("status") == "failed" for row in result_statuses)
        missing_count = sum(row is None for row in result_statuses)
        for scope in SCOPES:
            metric_cases: list[tuple[str, dict[str, Any], list[dict[str, Any]], dict[str, Any] | None]] = []
            for input_row in eligible_rows:
                case_id = str(input_row.get("case_id") or "")
                gt_row = gt_by_case.get(case_id, {})
                anchors = _anchors_for_scope(gt_row, scope)
                if anchors:
                    metric_cases.append((case_id, input_row, anchors, result_by_case.get(case_id)))
            per_case_scores: dict[str, dict[str, float]] = {}
            for case_id, _, anchors, result in metric_cases:
                _, score = _case_score(result, anchors)
                per_case_scores[case_id] = score
                score_lookup[mode][scope][case_id] = score
            denominator = len(metric_cases)
            averages = {
                metric: sum(values.get(metric, 0.0) for values in per_case_scores.values()) / denominator if denominator else None
                for metric in [*(f"Hit@{k}" for k in RANK_CUTOFFS), "MRR"]
            }
            candidate_recall = None
            candidate_anchor_recall = None
            candidate_recall_denominator = None
            candidate_anchor_denominator = None
            candidate_sizes = [int((result or {}).get("candidate_count") or 0) for _, _, _, result in metric_cases]
            raw_candidate_sizes = [int((result or {}).get("raw_candidate_count") or 0) for _, _, _, result in metric_cases]
            if mode.startswith("P_DUAL"):
                case_hits = []
                matched_anchor_count = 0
                ground_truth_anchor_count = 0
                for _, _, anchors, result in metric_cases:
                    candidate_rows = (result or {}).get("candidate_details") or []
                    matched = _matched_anchor_indices(anchors, candidate_rows[:100])
                    case_hits.append(bool(matched))
                    matched_anchor_count += len(matched)
                    ground_truth_anchor_count += len(anchors)
                candidate_recall_denominator = len(metric_cases)
                candidate_anchor_denominator = ground_truth_anchor_count
                candidate_recall = (
                    sum(case_hits) / len(case_hits) if case_hits else None
                )
                candidate_anchor_recall = (
                    matched_anchor_count / ground_truth_anchor_count
                    if ground_truth_anchor_count else None
                )

            runtime_values = [
                float(row["runtime_ms"])
                for row in result_statuses
                if row is not None and row.get("runtime_ms") is not None
            ]
            usages = [_usage(row or {}) for row in result_statuses]
            usage_records = sum(row is not None for row in result_statuses)
            sum_field = lambda field: sum(int(item.get(field) or 0) for item in usages)
            chat_unreported = sum_field("chat_usage_unreported_calls")
            embedding_unreported = sum_field("embedding_usage_unreported_calls")
            extraction_denominator = len(eligible_rows)
            extraction_coverage = None
            extraction_failure_rate = None
            fallback_rate = None
            if mode == "D_SEM":
                usable_count = sum(_is_usable_extraction(row or {}) for row in result_statuses)
                extraction_coverage = usable_count / extraction_denominator if extraction_denominator else None
                extraction_failure_count = sum(
                    bool(row and (row.get("metadata") or {}).get("entity_extraction", {}).get("failed"))
                    or bool(row and str(row.get("error") or "").startswith("SemanticEntityExtractionError:"))
                    for row in result_statuses
                )
                extraction_failure_rate = extraction_failure_count / extraction_denominator if extraction_denominator else None
                fallback_count = sum(bool(((row or {}).get("metadata") or {}).get("fallback_used")) for row in result_statuses)
                fallback_rate = fallback_count / extraction_denominator if extraction_denominator else 0.0

            output.append({
                "mode": mode,
                "gt_scope": scope,
                "applicable_cases": len(eligible_rows),
                "ineligible_records": len(ineligible_rows),
                "metric_cases": denominator,
                "RankMetricDenominatorCases": denominator,
                "completed_records": complete_count,
                "failed_records": failed_count,
                "missing_records": missing_count,
                **averages,
                "CandidateRecall@100": candidate_recall,
                "CandidateRecallDenominatorCases": candidate_recall_denominator,
                "CandidateAnchorRecall@100": candidate_anchor_recall,
                "CandidateAnchorRecallDenominatorAnchors": candidate_anchor_denominator,
                "AvgCandidatesBeforeRanking": sum(candidate_sizes) / len(candidate_sizes) if candidate_sizes else None,
                "AvgRawCandidates": sum(raw_candidate_sizes) / len(raw_candidate_sizes) if raw_candidate_sizes else None,
                "EntityExtractionCoverage": extraction_coverage,
                "ExtractionFailureRate": extraction_failure_rate,
                "FallbackRate": fallback_rate,
                "EntityExtractionDenominator": extraction_denominator if mode == "D_SEM" else None,
                "RuntimeMsTotal": sum(runtime_values) if runtime_values else 0.0,
                "RuntimeMsMean": sum(runtime_values) / len(runtime_values) if runtime_values else None,
                "RuntimeRecords": len(runtime_values),
                "UsageRecords": usage_records,
                "LLMCalls": sum_field("chat_calls"),
                "EmbeddingCalls": sum_field("embedding_calls"),
                "ChatPromptTokens": None if chat_unreported else sum_field("chat_prompt_tokens"),
                "ChatCompletionTokens": None if chat_unreported else sum_field("chat_completion_tokens"),
                "ChatTotalTokens": None if chat_unreported else sum_field("chat_total_tokens"),
                "EmbeddingInputTokens": None if embedding_unreported else sum_field("embedding_input_tokens"),
                "EmbeddingTotalTokens": None if embedding_unreported else sum_field("embedding_total_tokens"),
                "ChatUsageUnreportedCalls": chat_unreported,
                "EmbeddingUsageUnreportedCalls": embedding_unreported,
                "TokenCostUsd": None,
            })
    return output, score_lookup


def compute_vf_report(inputs_dir: Path, results_dir: Path, output_dir: Path) -> dict[str, Any]:
    """Calculate metrics only from prepared inputs and persisted result records."""
    manifest_path = inputs_dir / "manifest.json"
    gt_path = inputs_dir / "ground_truth.jsonl"
    if not manifest_path.is_file() or not gt_path.is_file():
        raise FileNotFoundError(f"not a prepared VF input directory: {inputs_dir}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    input_paths = manifest.get("mode_inputs") or {}
    gt_bytes = gt_path.read_bytes()
    if manifest.get("ground_truth_sha256") and hashlib.sha256(gt_bytes).hexdigest() != manifest["ground_truth_sha256"]:
        raise ValueError(f"ground-truth artifact changed after preparation: {gt_path}")
    inputs_by_mode = {
        mode: _read_jsonl(inputs_dir / input_paths[mode])
        for mode in MODES if mode in input_paths and (inputs_dir / input_paths[mode]).is_file()
    }
    for mode, mode_rows in inputs_by_mode.items():
        input_path = inputs_dir / input_paths[mode]
        expected_hash = (manifest.get("mode_input_sha256") or {}).get(mode)
        if expected_hash and hashlib.sha256(input_path.read_bytes()).hexdigest() != expected_hash:
            raise ValueError(f"prepared mode input changed after freezing: {input_path}")
        if any(row.get("mode") != mode for row in mode_rows):
            raise ValueError(f"prepared mode input contains records for another mode: {input_path}")
    gt_by_case = {str(row.get("case_id")): row for row in _read_jsonl(gt_path)}
    results_by_mode: dict[str, list[dict[str, Any]]] = {}
    for mode in inputs_by_mode:
        result_path = results_dir / f"{mode}.jsonl"
        if result_path.exists() or result_path.with_name(f"{mode}.checkpoint.jsonl").exists():
            results_by_mode[mode] = _latest_rows(result_path)
        else:
            results_by_mode[mode] = []
        for result in results_by_mode[mode]:
            if result.get("input_id") and result.get("input_id") != manifest.get("input_id"):
                raise ValueError(f"result row belongs to another prepared input: {mode}/{result.get('case_id')}")

    metric_rows, score_lookup = _metric_rows(inputs_by_mode, gt_by_case, results_by_mode)
    paired_rows = []
    for scope in SCOPES:
        present = score_lookup.get("P_DUAL_PRESENT", {}).get(scope, {})
        hidden = score_lookup.get("P_DUAL_HIDDEN", {}).get(scope, {})
        common = sorted(set(present) & set(hidden))
        results_by_case = {
            mode: {str(row.get("case_id")): row for row in results_by_mode.get(mode, [])}
            for mode in ("P_DUAL_PRESENT", "P_DUAL_HIDDEN")
        }
        present_statuses = [
            (results_by_case["P_DUAL_PRESENT"].get(case_id) or {}).get("status", "missing")
            for case_id in common
        ]
        hidden_statuses = [
            (results_by_case["P_DUAL_HIDDEN"].get(case_id) or {}).get("status", "missing")
            for case_id in common
        ]
        row: dict[str, Any] = {"gt_scope": scope, "paired_cases": len(common)}
        row.update({
            "paired_present_complete_records": sum(status == "complete" for status in present_statuses),
            "paired_hidden_complete_records": sum(status == "complete" for status in hidden_statuses),
            "paired_both_complete_records": sum(
                left == "complete" and right == "complete"
                for left, right in zip(present_statuses, hidden_statuses)
            ),
            "paired_present_failed_records": sum(status == "failed" for status in present_statuses),
            "paired_hidden_failed_records": sum(status == "failed" for status in hidden_statuses),
            "paired_present_missing_records": sum(status == "missing" for status in present_statuses),
            "paired_hidden_missing_records": sum(status == "missing" for status in hidden_statuses),
        })
        for metric in [*(f"Hit@{k}" for k in RANK_CUTOFFS), "MRR"]:
            row[f"Delta{metric}"] = (
                sum(present[case_id][metric] - hidden[case_id][metric] for case_id in common) / len(common)
                if common else None
            )
        paired_rows.append(row)

    oracle_rows = results_by_mode.get("ORACLE", [])
    oracle_summary = {
        "records": len(oracle_rows),
        "anchors": sum(len(row.get("vulnerable_functions") or []) for row in oracle_rows),
        "status_counts": {
            status: sum(row.get("status") == status for row in oracle_rows)
            for status in ("complete", "failed", "ineligible")
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    _write_csv(output_dir / "metrics.csv", metric_rows)
    _write_csv(output_dir / "paired_deltas.csv", paired_rows)
    _write_markdown(output_dir / "report.md", "CVE-to-VF Offline Metrics", metric_rows)
    _write_markdown(output_dir / "paired_deltas.md", "P_DUAL Paired Patch Benefit", paired_rows)
    payload = {
        "schema_version": "f_vra.vf.metrics-report.v1",
        "input_id": manifest.get("input_id"),
        "run_dir": str(results_dir.resolve()),
        "metrics": metric_rows,
        "paired_deltas": paired_rows,
        "metric_definitions": {
            "Hit@K_and_MRR": "For each case, rank is the earliest ranked valid ground-truth anchor; failed or missing records score zero. Rank metric denominator is eligible cases with at least one anchor in the selected GT scope.",
            "CandidateRecall@100": "Case-level recall: fraction of metric cases with at least one valid ground-truth anchor among the first 100 pre-ranking candidate details; missing candidates count as a miss.",
            "CandidateAnchorRecall@100": "Micro recall over all valid ground-truth anchors in the selected scope across metric cases.",
            "EntityExtractionCoverage": "Fraction of eligible D_SEM inputs with a usable attack-vector or root-cause entity; denominator is all eligible inputs, including missing or failed records.",
            "RuntimeMsMean": "Mean runtime over result records that contain runtime_ms; RuntimeRecords is its denominator. Failed records with runtime are included; missing records are excluded.",
            "paired_deltas": "PRESENT minus HIDDEN over common eligible case IDs with anchors in the selected GT scope; failed and missing records score zero and their counts are reported.",
        },
        "oracle_control": oracle_summary,
        "artifacts": {
            "metrics_csv": str((output_dir / "metrics.csv").resolve()),
            "paired_deltas_csv": str((output_dir / "paired_deltas.csv").resolve()),
            "report_markdown": str((output_dir / "report.md").resolve()),
            "paired_deltas_markdown": str((output_dir / "paired_deltas.md").resolve()),
        },
    }
    write_json(output_dir / "metrics.json", payload)
    return payload
