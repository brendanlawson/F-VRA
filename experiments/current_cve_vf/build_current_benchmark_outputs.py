from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parents[2]
ANNOTATIONS_FILE = BASE_DIR / "data" / "interim" / "annotations" / "vf_annotations.jsonl"
JUDGEMENTS_FILE = BASE_DIR / "data" / "interim" / "annotations" / "evidence_judgements.jsonl"
VALID_ALERTS_FILE = BASE_DIR / "data" / "interim" / "version_reconciliation" / "valid_alerts_for_annotation.csv"
FINAL_DIR = BASE_DIR / "data" / "final"
AUDIT_DIR = BASE_DIR / "data" / "interim" / "current_cve_vf" / "audits"

VF_LABELS = {"root_cause_vf", "vulnerable_usage_site"}
STRONG_EVIDENCE = {"patch_verified", "poc_verified", "advisory_explicit"}
ACCEPTED_CONFIDENCE = {"high", "medium"}
REVIEW_REASONS = {
    "review_ambiguous_mapping",
    "review_low_confidence",
    "review_vf_not_in_candidates",
    "review_no_vf",
    "review_weak_evidence",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_group_id(group_id: str) -> tuple[str, str]:
    if "::" not in group_id:
        return group_id, ""
    cve_id, package = group_id.split("::", 1)
    return cve_id, package


def target_vfs(annotation: dict[str, Any]) -> list[dict[str, Any]]:
    primary = annotation.get("vf_qualified_name")
    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in annotation.get("per_candidate") or []:
        label = str(candidate.get("label") or "")
        qualified_name = str(candidate.get("qualified_name") or "")
        if label not in VF_LABELS or not qualified_name:
            continue
        key = (qualified_name, label)
        if key in seen:
            continue
        seen.add(key)
        targets.append(
            {
                "qualified_name": qualified_name,
                "label": label,
                "reasoning": str(candidate.get("reasoning") or ""),
                "is_primary": bool(primary and qualified_name == primary),
            }
        )
    return targets


def classification(annotation: dict[str, Any]) -> str:
    targets = target_vfs(annotation)
    if annotation.get("vf_not_in_candidates"):
        return "review_vf_not_in_candidates"
    if annotation.get("mapping_type") == "ambiguous":
        return "review_ambiguous_mapping"
    if annotation.get("evidence_level") not in STRONG_EVIDENCE:
        return "review_weak_evidence"
    if annotation.get("confidence") not in ACCEPTED_CONFIDENCE:
        return "review_low_confidence"
    if not annotation.get("vf_qualified_name") or not targets:
        return "review_no_vf"
    return "accepted"


def load_valid_alerts(path: Path) -> dict[tuple[str, str], list[dict[str, str]]]:
    by_pair: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row.get("annotation_decision") != "valid_for_annotation":
                continue
            cve_id = str(row.get("cve_id") or row.get("advisory_id") or "")
            package = str(row.get("package_normalized") or row.get("package") or "").lower()
            if cve_id and package:
                by_pair[(cve_id, package)].append(row)
    return by_pair


def join_alerts(annotation: dict[str, Any], valid_by_pair: dict[tuple[str, str], list[dict[str, str]]]) -> list[dict[str, str]]:
    cve_id, package = parse_group_id(str(annotation.get("group_id") or ""))
    package_norm = package.lower().replace("_", "-")
    return valid_by_pair.get((cve_id, package_norm), [])


def benchmark_row(annotation: dict[str, Any], alerts: list[dict[str, str]]) -> dict[str, Any]:
    cve_id, package = parse_group_id(str(annotation.get("group_id") or ""))
    projects = sorted({row["project"] for row in alerts})
    scanners = sorted({row["scanner"] for row in alerts if row.get("scanner")})
    versions = sorted({row["resolved_version"] for row in alerts if row.get("resolved_version")})
    source_files = sorted({row["resolved_source_file"] for row in alerts if row.get("resolved_source_file")})
    return {
        "group_id": annotation.get("group_id"),
        "cve_id": cve_id,
        "package": package,
        "projects": projects,
        "project_count": len(projects),
        "scanners": scanners,
        "scanner_count": len(scanners),
        "resolved_versions": versions,
        "resolved_source_files": source_files,
        "mapping_type": annotation.get("mapping_type"),
        "evidence_level": annotation.get("evidence_level"),
        "confidence": annotation.get("confidence"),
        "vf_qualified_name": annotation.get("vf_qualified_name"),
        "target_vfs": target_vfs(annotation),
        "summary": annotation.get("summary"),
    }


def project_summary_rows(accepted_rows: list[dict[str, Any]], valid_by_pair: dict[tuple[str, str], list[dict[str, str]]]) -> list[dict[str, Any]]:
    by_project: dict[str, dict[str, Any]] = {}
    accepted_pairs = {(row["cve_id"], str(row["package"]).lower().replace("_", "-")) for row in accepted_rows}
    for cve_id, package in accepted_pairs:
        for alert in valid_by_pair.get((cve_id, package), []):
            project = alert["project"]
            item = by_project.setdefault(
                project,
                {
                    "project": project,
                    "cves": set(),
                    "packages": set(),
                    "scanners": set(),
                    "scanner_cve_pairs": defaultdict(set),
                },
            )
            item["cves"].add(cve_id)
            item["packages"].add(package)
            scanner = alert.get("scanner") or ""
            if scanner:
                item["scanners"].add(scanner)
                item["scanner_cve_pairs"][scanner].add(cve_id)

    rows: list[dict[str, Any]] = []
    for project, item in sorted(by_project.items()):
        scanner_counts = {
            scanner: len(cves)
            for scanner, cves in sorted(item["scanner_cve_pairs"].items())
        }
        rows.append(
            {
                "project": project,
                "cve_with_vf_count": len(item["cves"]),
                "cves_with_vf": ";".join(sorted(item["cves"])),
                "package_count": len(item["packages"]),
                "packages": ";".join(sorted(item["packages"])),
                "scanner_count": len(item["scanners"]),
                "scanners": ";".join(sorted(item["scanners"])),
                "scanner_cve_counts_json": json.dumps(scanner_counts, sort_keys=True),
            }
        )
    return rows


def main() -> int:
    annotations = load_jsonl(ANNOTATIONS_FILE)
    judgements = load_jsonl(JUDGEMENTS_FILE)
    valid_by_pair = load_valid_alerts(VALID_ALERTS_FILE)

    accepted: list[dict[str, Any]] = []
    review: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []

    for annotation in annotations:
        reason = classification(annotation)
        alerts = join_alerts(annotation, valid_by_pair)
        row = benchmark_row(annotation, alerts)
        row["benchmark_status"] = reason
        row["scan_alert_count"] = len(alerts)
        audit_rows.append(row)
        if reason == "accepted":
            accepted.append(row)
        elif reason in REVIEW_REASONS:
            review.append(row)
        else:
            rejected.append(row)

    project_rows = project_summary_rows(accepted, valid_by_pair)
    summary = {
        "judgement_count": len(judgements),
        "annotation_count": len(annotations),
        "accepted_count": len(accepted),
        "review_count": len(review),
        "rejected_count": len(rejected),
        "accepted_unique_cve_count": len({row["cve_id"] for row in accepted}),
        "accepted_project_count": len(project_rows),
        "status_counts": dict(Counter(row["benchmark_status"] for row in audit_rows)),
        "accepted_evidence_counts": dict(Counter(row["evidence_level"] for row in accepted)),
        "accepted_mapping_counts": dict(Counter(row["mapping_type"] for row in accepted)),
        "project_cve_rows": len(project_rows),
    }

    write_jsonl(FINAL_DIR / "cve_vf_benchmark_accepted.jsonl", accepted)
    write_jsonl(FINAL_DIR / "cve_vf_benchmark_review.jsonl", review)
    write_jsonl(FINAL_DIR / "cve_vf_benchmark_rejected.jsonl", rejected)
    write_jsonl(FINAL_DIR / "cve_vf_benchmark_audit.jsonl", audit_rows)
    write_csv(FINAL_DIR / "project_cve_vf_tool_summary.csv", project_rows)
    (FINAL_DIR / "cve_vf_benchmark_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    (AUDIT_DIR / "current_benchmark_final_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
