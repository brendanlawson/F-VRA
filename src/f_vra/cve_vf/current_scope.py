"""Build a CVE-level annotation scope from current CVE/package evidence.

The legacy ``docs/output_file`` pipeline works on ``CVE::package`` groups.
This module adds a current-run scope layer where each CVE is represented once
with one canonical package, while keeping dropped package aliases auditable.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from packaging.utils import canonicalize_name

STRONG_EVIDENCE_LEVELS = {"patch_verified", "poc_verified", "advisory_explicit"}
EVIDENCE_RANK = {
    "patch_verified": 5,
    "poc_verified": 4,
    "advisory_explicit": 3,
    "weak_or_uncertain": 1,
    "unknown": 0,
    "ambiguous": 0,
}
CANONICAL_TOOL_VERSION = "current_cve_scope_v1"
FALLBACK_TOOL_VERSION = "diff_hunk_candidate_fallback_v1"


@dataclass(frozen=True)
class AlertStats:
    row_count: int
    project_count: int
    projects: tuple[str, ...]


def normalize_package_name(name: str | None) -> str:
    if not name:
        return ""
    return canonicalize_name(str(name).strip()).replace("_", "-")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
    return records


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def write_json(path: Path, payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def read_valid_alert_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def build_alert_stats(valid_rows: Iterable[dict[str, str]]) -> dict[tuple[str, str], AlertStats]:
    row_counts: Counter[tuple[str, str]] = Counter()
    projects: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in valid_rows:
        cve_id = str(row.get("cve_id") or "").strip()
        package = normalize_package_name(row.get("package_normalized") or row.get("package"))
        if not cve_id or not package:
            continue
        key = (cve_id, package)
        row_counts[key] += 1
        project = str(row.get("project") or "").strip()
        if project:
            projects[key].add(project)
    return {
        key: AlertStats(
            row_count=count,
            project_count=len(projects.get(key, set())),
            projects=tuple(sorted(projects.get(key, set()))),
        )
        for key, count in row_counts.items()
    }


def load_candidate_group_ids(paths: Iterable[Path], extended_root: Path | None = None) -> set[str]:
    group_ids: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    group_id = json.loads(stripped).get("group_id")
                except json.JSONDecodeError:
                    continue
                if group_id:
                    group_ids.add(str(group_id))
    if extended_root and extended_root.exists():
        for child in extended_root.iterdir():
            if child.is_dir() and "__" in child.name and (child / "extended.jsonl").exists():
                cve_id, package = child.name.split("__", 1)
                group_ids.add(f"{cve_id}::{package}")
    return group_ids


def row_package_key(row: dict[str, Any]) -> tuple[str, str]:
    return (
        str(row.get("cve_id") or row.get("advisory_id") or "").strip(),
        normalize_package_name(row.get("package_normalized") or row.get("package")),
    )


def score_evidence_row(
    row: dict[str, Any],
    candidate_group_ids: set[str],
    alert_stats: dict[tuple[str, str], AlertStats],
) -> int:
    cve_id, package = row_package_key(row)
    stats = alert_stats.get((cve_id, package), AlertStats(0, 0, ()))
    evidence_score = EVIDENCE_RANK.get(str(row.get("evidence_level") or ""), 0) * 10000
    candidate_score = 5000 if str(row.get("group_id") or "") in candidate_group_ids else 0
    diff_score = 2000 if row.get("diff_paths") else 0
    fix_score = 1000 if row.get("fix_commits") else 0
    source_score = 500 if row.get("repo_url") and row.get("vulnerable_ref") else 0
    return evidence_score + candidate_score + diff_score + fix_score + source_score + stats.project_count * 100 + stats.row_count


def evidence_reasoning(row: dict[str, Any]) -> str:
    level = str(row.get("evidence_level") or "unknown")
    bits: list[str] = []
    if row.get("diff_paths"):
        bits.append("patch diff available")
    if row.get("fix_commits"):
        bits.append("fix commit reference available")
    if row.get("has_poc_reference"):
        bits.append("PoC/exploit reference available")
    if row.get("has_test_reference"):
        bits.append("test/regression reference available")
    if row.get("description_mentions_function"):
        bits.append("advisory mentions a function/component")
    if row.get("repo_url") and row.get("vulnerable_ref"):
        bits.append("source ref resolved")
    if not bits:
        bits.append("insufficient material evidence")
    return f"{level}: " + "; ".join(bits)


def _selected_reason(row: dict[str, Any], score: int, had_aliases: bool) -> str:
    package = row.get("package_normalized") or row.get("package")
    evidence = row.get("evidence_level") or "unknown"
    candidate_note = "candidate available" if row.get("candidate_available") else "candidate not yet available"
    if had_aliases:
        return (
            f"selected {package} by strongest evidence policy: "
            f"evidence={evidence}, score={score}, {candidate_note}"
        )
    return f"only package for CVE; evidence={evidence}, score={score}, {candidate_note}"


def select_canonical_scope(
    evidence_rows: Iterable[dict[str, Any]],
    valid_rows: Iterable[dict[str, str]],
    candidate_group_ids: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    alert_stats = build_alert_stats(valid_rows)
    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in evidence_rows:
        row = dict(raw)
        cve_id, package = row_package_key(row)
        if not cve_id or not package:
            continue
        row["cve_id"] = cve_id
        row["package_normalized"] = package
        row["candidate_available"] = str(row.get("group_id") or "") in candidate_group_ids
        row["package_selection_score"] = score_evidence_row(row, candidate_group_ids, alert_stats)
        stats = alert_stats.get((cve_id, package), AlertStats(0, 0, ()))
        row["valid_alert_row_count"] = int(row.get("valid_alert_row_count") or stats.row_count)
        row["valid_project_count"] = int(row.get("valid_project_count") or stats.project_count)
        row["valid_projects"] = list(stats.projects)
        by_cve[cve_id].append(row)

    selected: list[dict[str, Any]] = []
    package_audit: list[dict[str, Any]] = []
    for cve_id in sorted(by_cve):
        rows = sorted(
            by_cve[cve_id],
            key=lambda item: (
                -int(item["package_selection_score"]),
                -int(item.get("valid_project_count") or 0),
                -int(item.get("valid_alert_row_count") or 0),
                str(item.get("package_normalized") or item.get("package") or ""),
            ),
        )
        chosen = dict(rows[0])
        dropped = [row for row in rows[1:]]
        had_aliases = bool(dropped)
        chosen["canonical_unit"] = "cve"
        chosen["canonical_tool_version"] = CANONICAL_TOOL_VERSION
        chosen["selected_package_reason"] = _selected_reason(
            chosen,
            int(chosen["package_selection_score"]),
            had_aliases,
        )
        chosen["evidence_reasoning"] = evidence_reasoning(chosen)
        chosen["dropped_package_aliases"] = [
            {
                "group_id": row.get("group_id"),
                "package": row.get("package"),
                "package_normalized": row.get("package_normalized"),
                "evidence_level": row.get("evidence_level"),
                "candidate_available": row.get("candidate_available"),
                "package_selection_score": row.get("package_selection_score"),
                "valid_alert_row_count": row.get("valid_alert_row_count"),
                "valid_project_count": row.get("valid_project_count"),
            }
            for row in dropped
        ]
        selected.append(chosen)
        if had_aliases:
            package_audit.append(
                {
                    "cve_id": cve_id,
                    "selected_group_id": chosen.get("group_id"),
                    "selected_package": chosen.get("package"),
                    "selected_package_normalized": chosen.get("package_normalized"),
                    "selected_package_reason": chosen.get("selected_package_reason"),
                    "candidates": [
                        {
                            "group_id": row.get("group_id"),
                            "package": row.get("package"),
                            "package_normalized": row.get("package_normalized"),
                            "evidence_level": row.get("evidence_level"),
                            "candidate_available": row.get("candidate_available"),
                            "package_selection_score": row.get("package_selection_score"),
                            "valid_alert_row_count": row.get("valid_alert_row_count"),
                            "valid_project_count": row.get("valid_project_count"),
                        }
                        for row in rows
                    ],
                }
            )
    return selected, package_audit


def scope_audit(scope_rows: list[dict[str, Any]], original_rows: list[dict[str, Any]]) -> dict[str, Any]:
    cve_counts = Counter(str(row.get("cve_id") or "") for row in scope_rows)
    duplicate_cves = sorted(cve_id for cve_id, count in cve_counts.items() if count > 1)
    original_cves = {str(row.get("cve_id") or "") for row in original_rows if row.get("cve_id")}
    return {
        "tool_version": CANONICAL_TOOL_VERSION,
        "original_group_count": len(original_rows),
        "original_distinct_cve_count": len(original_cves),
        "row_count": len(scope_rows),
        "distinct_cve_count": len(cve_counts),
        "duplicate_cve_count": len(duplicate_cves),
        "duplicate_cves": duplicate_cves,
        "multi_package_cve_count": len(original_rows) - len(original_cves),
        "expected_row_count": len(original_cves),
        "passes_one_cve_one_package": len(scope_rows) == len(original_cves) and not duplicate_cves,
    }


def evidence_tier_audit(scope_rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(scope_rows)
    by_level = Counter(str(row.get("evidence_level") or "unknown") for row in rows)
    strong = sum(count for level, count in by_level.items() if level in STRONG_EVIDENCE_LEVELS)
    return {
        "tool_version": CANONICAL_TOOL_VERSION,
        "row_count": len(rows),
        "strong_evidence_count": strong,
        "counts": dict(sorted(by_level.items())),
    }


def _load_candidate_records(path: Path, source_name: str) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            group_id = str(record.get("group_id") or "")
            if not group_id:
                continue
            enriched = dict(record)
            enriched["_candidate_source"] = source_name
            records[group_id] = enriched
    return records


def load_candidate_records(paths: Iterable[tuple[Path, str]]) -> dict[str, dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for path, source_name in paths:
        for group_id, record in _load_candidate_records(path, source_name).items():
            merged.setdefault(group_id, record)
    return merged


def _candidate_count(record: dict[str, Any]) -> int:
    candidates = record.get("candidates") or {}
    if isinstance(candidates, dict):
        return len(candidates.get("patch_modified") or candidates.get("patch_extended") or [])
    if isinstance(candidates, list):
        return len(candidates)
    return 0


def _patch_modified_count(record: dict[str, Any]) -> int | None:
    if record.get("patch_modified_count") is not None:
        return int(record["patch_modified_count"])
    candidates = record.get("candidates") or {}
    if isinstance(candidates, dict) and candidates.get("patch_modified") is not None:
        return len(candidates.get("patch_modified") or [])
    if isinstance(candidates, list):
        return len(candidates)
    return None


def _extended_record(row: dict[str, Any], extended_root: Path) -> dict[str, Any] | None:
    group_id = str(row.get("group_id") or "")
    if "::" not in group_id:
        return None
    cve_id, package = group_id.split("::", 1)
    path = extended_root / f"{cve_id}__{package}" / "extended.jsonl"
    if not path.exists():
        return None
    funcs = read_jsonl(path)
    if not funcs:
        return None
    return {
        "group_id": group_id,
        "advisory_id": row.get("advisory_id") or row.get("cve_id"),
        "package": row.get("package"),
        "vulnerable_ref": row.get("vulnerable_ref"),
        "fixed_ref": row.get("fixed_ref"),
        "diff_sha_used": row.get("fixed_ref"),
        "candidates": {"patch_modified": funcs, "patch_extended": funcs},
        "patch_modified_count": len(funcs),
        "patch_extended_count": len(funcs),
        "full_corpus_count": None,
        "modified_files": sorted({func.get("file_path") for func in funcs if func.get("file_path")}),
        "needs_manual_diff_review": False,
        "build_tool_version": "current_scope_extended_candidates",
        "_candidate_source": "phase7b_patch_extended_candidates",
    }


def _diff_paths(row: dict[str, Any], repo_root: Path) -> list[Path]:
    paths: list[Path] = []
    for raw in row.get("diff_paths") or []:
        path = Path(str(raw))
        if not path.is_absolute():
            path = repo_root / path
        if path.exists():
            paths.append(path)
    return paths


def _module_prefix(file_path: str) -> str:
    without_ext = re.sub(r"\.py$", "", file_path.replace("\\", "/"))
    return ".".join(part for part in without_ext.split("/") if part and part != "__init__")


def _is_source_python_path(file_path: str) -> bool:
    normalized = file_path.replace("\\", "/").lower()
    if not normalized.endswith(".py"):
        return False
    return not (
        normalized.startswith("tests/")
        or "/tests/" in normalized
        or normalized.startswith("test/")
        or "/test/" in normalized
        or normalized.startswith("docs/")
        or "/docs/" in normalized
    )


def _parse_diff_fallback_candidates(row: dict[str, Any], repo_root: Path) -> list[dict[str, Any]]:
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    current_file = ""
    current_hunk: list[str] = []
    current_func = ""

    def flush_hunk() -> None:
        nonlocal current_hunk, current_func
        if not current_file or not _is_source_python_path(current_file):
            current_hunk = []
            current_func = ""
            return
        candidate_name = current_func or "__module__"
        source_lines: list[str] = []
        for line in current_hunk:
            if not line:
                continue
            prefix = line[0]
            if prefix in {" ", "-"}:
                source_lines.append(line[1:])
        source = "\n".join(source_lines).strip()
        key = (current_file, candidate_name)
        if key not in candidates:
            qname = f"{_module_prefix(current_file)}.{candidate_name}"
            candidates[key] = {
                "qualified_name": qname,
                "func_name": candidate_name,
                "class_name": None,
                "file_path": current_file,
                "start_line": None,
                "end_line": None,
                "source_hash": None,
                "is_method": False,
                "source": source or "[SOURCE_MISSING: diff hunk did not include vulnerable source context]",
                "candidate_source": FALLBACK_TOOL_VERSION,
            }
        current_hunk = []
        current_func = ""

    for diff_path in _diff_paths(row, repo_root):
        for raw_line in diff_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if raw_line.startswith("diff --git "):
                flush_hunk()
                match = re.match(r"diff --git a/(.+?) b/(.+)$", raw_line)
                current_file = match.group(2) if match else ""
                continue
            if raw_line.startswith("@@"):
                flush_hunk()
                current_hunk = []
                header_context = raw_line.rsplit("@@", 1)[-1].strip()
                match = re.search(r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", header_context)
                current_func = match.group(1) if match else ""
                continue
            if raw_line.startswith(("+", "-", " ")):
                current_hunk.append(raw_line)
                if not current_func:
                    match = re.search(r"^[ +\-]\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", raw_line)
                    if match:
                        current_func = match.group(1)
        flush_hunk()
    return list(candidates.values())


def _fallback_record(row: dict[str, Any], repo_root: Path) -> dict[str, Any] | None:
    funcs = _parse_diff_fallback_candidates(row, repo_root)
    if not funcs:
        return None
    group_id = str(row.get("group_id") or "")
    return {
        "group_id": group_id,
        "advisory_id": row.get("advisory_id") or row.get("cve_id"),
        "package": row.get("package"),
        "vulnerable_ref": row.get("vulnerable_ref"),
        "fixed_ref": row.get("fixed_ref"),
        "diff_sha_used": row.get("fixed_ref"),
        "candidates": {"patch_modified": funcs, "patch_extended": funcs},
        "patch_modified_count": len(funcs),
        "patch_extended_count": len(funcs),
        "full_corpus_count": None,
        "modified_files": sorted({func.get("file_path") for func in funcs if func.get("file_path")}),
        "files_still_missing": [],
        "needs_manual_diff_review": True,
        "patch_extended_scope_note": "fallback candidates parsed from Python diff hunk headers",
        "build_tool_version": FALLBACK_TOOL_VERSION,
        "_candidate_source": "diff_hunk_fallback",
    }


def _enrich_candidate_record(record: dict[str, Any], scope_row: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(record)
    for key in (
        "description",
        "references",
        "aliases",
        "affected_versions",
        "fixed_versions",
        "published_at",
        "repo_url",
        "evidence_level",
        "evidence_reasoning",
        "selected_package_reason",
        "dropped_package_aliases",
    ):
        if scope_row.get(key) not in (None, "", []):
            enriched[key] = scope_row[key]
    enriched["canonical_unit"] = "cve"
    enriched["canonical_tool_version"] = CANONICAL_TOOL_VERSION
    return enriched


def build_current_candidates(
    scope_rows: Iterable[dict[str, Any]],
    source_records: dict[str, dict[str, Any]],
    extended_root: Path,
    repo_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    scope_list = list(scope_rows)
    output: list[dict[str, Any]] = []
    coverage: list[dict[str, Any]] = []
    source_counts: Counter[str] = Counter()

    for scope_row in scope_list:
        group_id = str(scope_row.get("group_id") or "")
        source_name = "missing"
        record = source_records.get(group_id)
        if record is None:
            record = _extended_record(scope_row, extended_root)
        if record is None:
            record = _fallback_record(scope_row, repo_root)
        if record is not None:
            source_name = str(record.get("_candidate_source") or "unknown")
            record = _enrich_candidate_record(record, scope_row)
            output.append(record)
            source_counts[source_name] += 1

        coverage.append(
            {
                "cve_id": scope_row.get("cve_id"),
                "group_id": group_id,
                "package": scope_row.get("package"),
                "package_normalized": scope_row.get("package_normalized"),
                "evidence_level": scope_row.get("evidence_level"),
                "has_candidate": record is not None,
                "candidate_source": source_name,
                "candidate_count": _candidate_count(record) if record else 0,
                "patch_modified_count": _patch_modified_count(record) if record else None,
                "has_patch_material": bool(scope_row.get("diff_paths")),
                "has_source_ref": bool(scope_row.get("repo_url") and scope_row.get("vulnerable_ref")),
            }
        )

    summary = {
        "tool_version": CANONICAL_TOOL_VERSION,
        "scope_row_count": len(scope_list),
        "candidate_record_count": len(output),
        "missing_candidate_count": sum(1 for row in coverage if not row["has_candidate"]),
        "source_counts": dict(sorted(source_counts.items())),
        "missing_by_evidence_level": dict(
            sorted(Counter(row["evidence_level"] for row in coverage if not row["has_candidate"]).items())
        ),
        "available_by_evidence_level": dict(
            sorted(Counter(row["evidence_level"] for row in coverage if row["has_candidate"]).items())
        ),
    }
    return output, coverage, summary


def partition_annotation_buckets(
    scope_rows: Iterable[dict[str, Any]],
    candidate_records: Iterable[dict[str, Any]],
    tier1_max: int = 5,
    tier3_min: int = 100,
) -> dict[str, list[dict[str, Any]]]:
    candidates_by_gid = {str(record.get("group_id") or ""): record for record in candidate_records}
    buckets: dict[str, list[dict[str, Any]]] = {
        "tier1_ready": [],
        "tier2_needs_rank": [],
        "tier3_manual": [],
        "no_candidate": [],
        "weak_or_uncertain": [],
    }
    for scope_row in scope_rows:
        enriched = dict(scope_row)
        group_id = str(scope_row.get("group_id") or "")
        candidate = candidates_by_gid.get(group_id)
        evidence_level = str(scope_row.get("evidence_level") or "unknown")
        if evidence_level not in STRONG_EVIDENCE_LEVELS:
            enriched["annotation_bucket"] = "weak_or_uncertain"
            enriched["annotation_skip_reason"] = f"evidence_level:{evidence_level}"
            buckets["weak_or_uncertain"].append(enriched)
            continue
        if candidate is None:
            enriched["annotation_bucket"] = "no_candidate"
            enriched["annotation_skip_reason"] = "no_candidate_record"
            buckets["no_candidate"].append(enriched)
            continue
        pm = _patch_modified_count(candidate)
        enriched["patch_modified_count"] = pm
        enriched["patch_extended_count"] = candidate.get("patch_extended_count")
        enriched["full_corpus_count"] = candidate.get("full_corpus_count")
        enriched["candidate_count"] = _candidate_count(candidate)
        if pm is None or pm > tier3_min:
            bucket = "tier3_manual"
        elif pm > tier1_max:
            bucket = "tier2_needs_rank"
        else:
            bucket = "tier1_ready"
        enriched["annotation_bucket"] = bucket
        buckets[bucket].append(enriched)
    return buckets
