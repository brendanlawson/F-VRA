"""Build CVE-to-VF benchmark data from scan reports and VF annotations."""

from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from packaging.utils import canonicalize_name

VF_LABELS = {"root_cause_vf", "vulnerable_usage_site"}
STRONG_EVIDENCE_LEVELS = {"patch_verified", "poc_verified", "advisory_explicit"}
REJECTED_MAPPING_TYPES = {"ambiguous", "patch_variant_duplicate"}
VERSION_SPLIT_RE = re.compile(r"\s*(?:===|==|~=|!=|<=|>=|<|>|=|\s)\s*")


@dataclass(frozen=True)
class AnnotationRecord:
    source_path: str
    source_tier: str
    raw: dict[str, Any]
    cve_id: str
    package: str
    package_normalized: str

    @property
    def group_id(self) -> str:
        return str(self.raw.get("group_id") or "")

    @property
    def confidence(self) -> str:
        return str(self.raw.get("confidence") or "")

    @property
    def evidence_level(self) -> str:
        return str(self.raw.get("evidence_level") or "")

    @property
    def mapping_type(self) -> str:
        return str(self.raw.get("mapping_type") or "")

    @property
    def vf_qualified_name(self) -> str | None:
        value = self.raw.get("vf_qualified_name")
        return str(value) if value else None

    @property
    def vf_not_in_candidates(self) -> bool:
        return bool(self.raw.get("vf_not_in_candidates"))

    @property
    def summary(self) -> str:
        return str(self.raw.get("summary") or "")


@dataclass(frozen=True)
class ScanFinding:
    project: str
    repo_full_name: str
    cve_id: str
    package: str
    package_normalized: str
    version: str
    source: str


@dataclass
class ScanOccurrence:
    project: str
    repo_full_name: str
    cve_id: str
    package: str
    package_normalized: str
    sources: list[str]
    affected_package_versions: list[str]


def normalize_package_name(name: str | None) -> str:
    if not name:
        return ""
    cleaned = str(name).strip()
    if not cleaned:
        return ""
    return canonicalize_name(cleaned).replace("_", "-")


def package_from_requirement(value: str | None) -> str:
    if not value:
        return ""
    token = str(value).strip().split(";", 1)[0].strip()
    token = token.split("[", 1)[0].strip()
    parts = VERSION_SPLIT_RE.split(token, maxsplit=1)
    return parts[0].strip()


def parse_group_id(group_id: str) -> tuple[str, str]:
    if "::" not in group_id:
        return group_id.strip(), ""
    cve_id, package = group_id.split("::", 1)
    return cve_id.strip(), package.strip()


def infer_tier(path: Path) -> str:
    lower = path.name.lower()
    if "tier1" in lower:
        return "tier1"
    if "tier2" in lower:
        return "tier2"
    return "unknown"


def load_annotations(paths: Iterable[Path]) -> list[AnnotationRecord]:
    records: list[AnnotationRecord] = []
    for path in paths:
        tier = infer_tier(path)
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                raw = json.loads(stripped)
                cve_id, package = parse_group_id(str(raw.get("group_id") or ""))
                if not cve_id:
                    raise ValueError(f"Missing CVE in {path}:{line_no}")
                records.append(
                    AnnotationRecord(
                        source_path=str(path),
                        source_tier=tier,
                        raw=raw,
                        cve_id=cve_id,
                        package=package,
                        package_normalized=normalize_package_name(package),
                    )
                )
    return records


def split_semicolon_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in str(value).split(";") if item.strip()]


def repo_from_project(project: str) -> str:
    return project.replace("__", "/", 1)


def _occurrence_from_detail_row(row: dict[str, str], package_value: str) -> ScanOccurrence:
    package_name = package_from_requirement(package_value)
    return ScanOccurrence(
        project=row["project"],
        repo_full_name=repo_from_project(row["project"]),
        cve_id=row["cve_id"],
        package=package_name,
        package_normalized=normalize_package_name(package_name),
        sources=sorted(split_semicolon_values(row.get("sources"))),
        affected_package_versions=[package_value],
    )


def load_scan_occurrences(details_path: Path) -> list[ScanOccurrence]:
    occurrences: list[ScanOccurrence] = []
    with details_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            for package_value in split_semicolon_values(row.get("affected_packages")):
                occurrence = _occurrence_from_detail_row(row, package_value)
                if occurrence.package_normalized:
                    occurrences.append(occurrence)
    return merge_occurrences(occurrences)


def load_source_findings(path: Path) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            package = package_from_requirement(row.get("package"))
            if not package:
                continue
            findings.append(
                ScanFinding(
                    project=row["project"],
                    repo_full_name=repo_from_project(row["project"]),
                    cve_id=row["cve_id"],
                    package=package,
                    package_normalized=normalize_package_name(package),
                    version=str(row.get("version") or ""),
                    source=str(row.get("source") or ""),
                )
            )
    return findings


def merge_occurrences(occurrences: Iterable[ScanOccurrence]) -> list[ScanOccurrence]:
    merged: dict[tuple[str, str, str], ScanOccurrence] = {}
    for occurrence in occurrences:
        key = (occurrence.project, occurrence.cve_id, occurrence.package_normalized)
        existing = merged.get(key)
        if existing is None:
            merged[key] = ScanOccurrence(
                project=occurrence.project,
                repo_full_name=occurrence.repo_full_name,
                cve_id=occurrence.cve_id,
                package=occurrence.package,
                package_normalized=occurrence.package_normalized,
                sources=list(occurrence.sources),
                affected_package_versions=list(occurrence.affected_package_versions),
            )
            continue
        existing.sources = sorted(set(existing.sources).union(occurrence.sources))
        existing.affected_package_versions = sorted(
            set(existing.affected_package_versions).union(occurrence.affected_package_versions)
        )
    return sorted(merged.values(), key=lambda item: (item.project, item.cve_id, item.package_normalized))


def enrich_occurrences_with_source_findings(
    occurrences: list[ScanOccurrence], findings: Iterable[ScanFinding]
) -> list[ScanOccurrence]:
    by_key = {(item.project, item.cve_id, item.package_normalized): item for item in occurrences}
    for finding in findings:
        key = (finding.project, finding.cve_id, finding.package_normalized)
        occurrence = by_key.get(key)
        if occurrence is None:
            value = f"{finding.package}=={finding.version}" if finding.version else finding.package
            occurrence = ScanOccurrence(
                project=finding.project,
                repo_full_name=finding.repo_full_name,
                cve_id=finding.cve_id,
                package=finding.package,
                package_normalized=finding.package_normalized,
                sources=[],
                affected_package_versions=[value],
            )
            by_key[key] = occurrence
            occurrences.append(occurrence)
        if finding.source:
            occurrence.sources = sorted(set(occurrence.sources).union({finding.source}))
        if finding.version:
            value = f"{finding.package}=={finding.version}"
            occurrence.affected_package_versions = sorted(
                set(occurrence.affected_package_versions).union({value})
            )
    return sorted(occurrences, key=lambda item: (item.project, item.cve_id, item.package_normalized))


def target_vfs(annotation: AnnotationRecord) -> list[dict[str, Any]]:
    primary = annotation.vf_qualified_name
    targets: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in annotation.raw.get("per_candidate") or []:
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


def audit_reason(annotation: AnnotationRecord) -> str:
    targets = target_vfs(annotation)
    if annotation.mapping_type == "patch_variant_duplicate":
        return "review_duplicate"
    if annotation.mapping_type == "ambiguous":
        return "reject_ambiguous"
    if annotation.vf_not_in_candidates:
        return "reject_vf_missing"
    if annotation.confidence != "high" or annotation.evidence_level not in STRONG_EVIDENCE_LEVELS:
        return "reject_weak_evidence"
    if not annotation.vf_qualified_name or not targets:
        return "reject_no_vf"
    if annotation.mapping_type in REJECTED_MAPPING_TYPES:
        return "reject_ambiguous"
    return "accepted"


def benchmark_record(annotation: AnnotationRecord, occurrence: ScanOccurrence) -> dict[str, Any]:
    return {
        "benchmark_id": f"{occurrence.project}::{annotation.cve_id}::{annotation.package_normalized}",
        "project": occurrence.project,
        "repo_full_name": occurrence.repo_full_name,
        "cve_id": annotation.cve_id,
        "package": annotation.package,
        "package_normalized": annotation.package_normalized,
        "sources": occurrence.sources,
        "affected_package_versions": occurrence.affected_package_versions,
        "annotation_group_id": annotation.group_id,
        "mapping_type": annotation.mapping_type,
        "evidence_level": annotation.evidence_level,
        "confidence": annotation.confidence,
        "target_vfs": target_vfs(annotation),
        "annotation_summary": annotation.summary,
        "benchmark_status": "accepted",
    }


def aggregate_matches(matches: Iterable[ScanOccurrence]) -> ScanOccurrence:
    sorted_matches = sorted(matches, key=lambda item: item.project)
    if not sorted_matches:
        raise ValueError("Cannot aggregate empty scan matches")
    first = sorted_matches[0]
    return ScanOccurrence(
        project=first.project,
        repo_full_name=first.repo_full_name,
        cve_id=first.cve_id,
        package=first.package,
        package_normalized=first.package_normalized,
        sources=sorted({source for item in sorted_matches for source in item.sources}),
        affected_package_versions=sorted(
            {value for item in sorted_matches for value in item.affected_package_versions}
        ),
    )


def audit_record(
    annotation: AnnotationRecord,
    reason: str,
    occurrence: ScanOccurrence | None = None,
    scanned_projects: Iterable[str] | None = None,
    scanned_packages: Iterable[str] | None = None,
) -> dict[str, Any]:
    return {
        "annotation_group_id": annotation.group_id,
        "source_tier": annotation.source_tier,
        "source_path": annotation.source_path,
        "project": occurrence.project if occurrence else None,
        "repo_full_name": occurrence.repo_full_name if occurrence else None,
        "cve_id": annotation.cve_id,
        "annotation_package": annotation.package,
        "package": occurrence.package if occurrence else annotation.package,
        "package_normalized": occurrence.package_normalized if occurrence else annotation.package_normalized,
        "sources": occurrence.sources if occurrence else [],
        "affected_package_versions": occurrence.affected_package_versions if occurrence else [],
        "matched_projects": sorted(set(scanned_projects or ([occurrence.project] if occurrence else []))),
        "scanned_packages_for_cve": sorted(set(scanned_packages or [])),
        "mapping_type": annotation.mapping_type,
        "evidence_level": annotation.evidence_level,
        "confidence": annotation.confidence,
        "vf_not_in_candidates": annotation.vf_not_in_candidates,
        "vf_qualified_name": annotation.vf_qualified_name,
        "target_vfs": target_vfs(annotation),
        "annotation_summary": annotation.summary,
        "benchmark_status": "accepted" if reason == "accepted" else "rejected",
        "audit_reason": reason,
    }


def build_benchmark(
    annotations: list[AnnotationRecord],
    occurrences: list[ScanOccurrence],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    by_pair: dict[tuple[str, str], list[ScanOccurrence]] = defaultdict(list)
    by_cve: dict[str, list[ScanOccurrence]] = defaultdict(list)
    for occurrence in occurrences:
        by_pair[(occurrence.cve_id, occurrence.package_normalized)].append(occurrence)
        by_cve[occurrence.cve_id].append(occurrence)

    annotations_by_pair: dict[tuple[str, str], list[AnnotationRecord]] = defaultdict(list)
    benchmark_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []

    for annotation in annotations:
        if annotation.cve_id not in by_cve:
            continue
        annotations_by_pair[(annotation.cve_id, annotation.package_normalized)].append(annotation)
        matches = by_pair.get((annotation.cve_id, annotation.package_normalized), [])
        if not matches:
            audit_rows.append(
                audit_record(
                    annotation,
                    "reject_package_mismatch",
                    scanned_projects=[item.project for item in by_cve[annotation.cve_id]],
                    scanned_packages=[item.package_normalized for item in by_cve[annotation.cve_id]],
                )
            )
            continue
        reason = audit_reason(annotation)
        aggregated = aggregate_matches(matches)
        audit_rows.append(
            audit_record(
                annotation,
                reason,
                occurrence=aggregated,
                scanned_projects=[item.project for item in matches],
            )
        )
        if reason == "accepted":
            benchmark_rows.append(benchmark_record(annotation, aggregated))

    coverage_rows = coverage_records(occurrences, annotations_by_pair)
    summary = summary_counts(annotations, occurrences, benchmark_rows, audit_rows, coverage_rows)
    return benchmark_rows, audit_rows, coverage_rows, summary


def coverage_records(
    occurrences: list[ScanOccurrence],
    annotations_by_pair: dict[tuple[str, str], list[AnnotationRecord]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for occurrence in occurrences:
        annotations = annotations_by_pair.get((occurrence.cve_id, occurrence.package_normalized), [])
        if not annotations:
            rows.append(
                {
                    "project": occurrence.project,
                    "repo_full_name": occurrence.repo_full_name,
                    "cve_id": occurrence.cve_id,
                    "package": occurrence.package,
                    "package_normalized": occurrence.package_normalized,
                    "sources": ";".join(occurrence.sources),
                    "annotation_group_id": "",
                    "annotation_status": "unannotated",
                    "benchmark_status": "not_in_benchmark",
                    "audit_reason": "unannotated",
                    "target_vf_count": 0,
                }
            )
            continue
        for annotation in annotations:
            reason = audit_reason(annotation)
            rows.append(
                {
                    "project": occurrence.project,
                    "repo_full_name": occurrence.repo_full_name,
                    "cve_id": occurrence.cve_id,
                    "package": occurrence.package,
                    "package_normalized": occurrence.package_normalized,
                    "sources": ";".join(occurrence.sources),
                    "annotation_group_id": annotation.group_id,
                    "annotation_status": "annotated",
                    "benchmark_status": "accepted" if reason == "accepted" else "not_in_benchmark",
                    "audit_reason": reason,
                    "target_vf_count": len(target_vfs(annotation)),
                }
            )
    return rows


def summary_counts(
    annotations: list[AnnotationRecord],
    occurrences: list[ScanOccurrence],
    benchmark_rows: list[dict[str, Any]],
    audit_rows: list[dict[str, Any]],
    coverage_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    scan_cves = {item.cve_id for item in occurrences}
    annotation_cves = {item.cve_id for item in annotations}
    strict_pairs = {
        (row["cve_id"], row["package_normalized"])
        for row in audit_rows
        if row["audit_reason"] != "reject_package_mismatch"
    }
    return {
        "scan_unique_cves": len(scan_cves),
        "annotation_unique_cves": len(annotation_cves),
        "cve_only_intersection": len(scan_cves.intersection(annotation_cves)),
        "strict_annotation_records": sum(
            1 for row in audit_rows if row["audit_reason"] != "reject_package_mismatch"
        ),
        "strict_unique_cves": len(
            {row["cve_id"] for row in audit_rows if row["audit_reason"] != "reject_package_mismatch"}
        ),
        "strict_pairs": len(strict_pairs),
        "accepted_records": len(benchmark_rows),
        "accepted_unique_cves": len({row["cve_id"] for row in benchmark_rows}),
        "accepted_projects": len({row["project"] for row in benchmark_rows}),
        "audit_reason_counts": dict(Counter(row["audit_reason"] for row in audit_rows)),
        "coverage_rows": len(coverage_rows),
        "coverage_annotated_rows": sum(1 for row in coverage_rows if row["annotation_status"] == "annotated"),
    }


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
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


def summary_markdown(summary: dict[str, Any]) -> str:
    reason_counts = summary.get("audit_reason_counts", {})
    lines = [
        "# CVE-to-VF Annotation Coverage",
        "",
        "## Headline Counts",
        "",
        f"- Scan unique CVEs: {summary['scan_unique_cves']}",
        f"- Annotation unique CVEs: {summary['annotation_unique_cves']}",
        f"- CVE-only intersection: {summary['cve_only_intersection']}",
        f"- Strict annotation records (CVE + package): {summary['strict_annotation_records']}",
        f"- Strict unique CVEs: {summary['strict_unique_cves']}",
        f"- Accepted benchmark records: {summary['accepted_records']}",
        f"- Accepted unique CVEs: {summary['accepted_unique_cves']}",
        f"- Accepted projects: {summary['accepted_projects']}",
        "",
        "## Audit Reasons",
        "",
        "| reason | records |",
        "|---|---:|",
    ]
    for reason, count in sorted(reason_counts.items()):
        lines.append(f"| {reason} | {count} |")
    lines.extend(
        [
            "",
            "## Policy",
            "",
            "- Join policy: strict `CVE + package`; CVE-only matches are audit-only package mismatches.",
            "- Accepted records require high confidence, strong evidence (`patch_verified`, `poc_verified`, or `advisory_explicit`), a VF candidate label, and no missing/ambiguous VF flag.",
            "- Benchmark VF targets are read from `per_candidate` labels `root_cause_vf` and `vulnerable_usage_site`.",
        ]
    )
    return "\n".join(lines) + "\n"
