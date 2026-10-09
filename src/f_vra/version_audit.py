"""Version audit and reconciliation for SCA findings."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from f_vra.analysis.dependencies import parsers

VALID_FOR_ANNOTATION = {
    "consistent",
    "scanner_version_missing_but_env_affected",
    "mismatch_but_env_affected",
}

LOCKFILE_PRIORITY = {
    "uv.lock": 10,
    "poetry.lock": 20,
    "Pipfile.lock": 30,
    "requirements.txt": 40,
    "pyproject.toml": 50,
    "setup.py": 60,
}

MANIFEST_NAMES = {
    "uv.lock",
    "poetry.lock",
    "Pipfile.lock",
    "pyproject.toml",
    "setup.py",
}


@dataclass(frozen=True)
class ProjectRecord:
    project: str
    repo_full_name: str
    path: Path


@dataclass(frozen=True)
class ResolvedPackage:
    project: str
    package: str
    package_normalized: str
    version: str
    source_type: str
    source_file: str
    provenance: str
    priority: int


@dataclass(frozen=True)
class ScannerFinding:
    project: str
    source: str
    cve_id: str
    package: str
    package_normalized: str
    scanner_version: str
    fixed_versions: str
    severity: str
    title: str
    advisory_id: str


def normalize_package(name: str | None) -> str:
    if not name:
        return ""
    return canonicalize_name(str(name).strip()).replace("_", "-")


def normalize_version(value: str | None) -> str:
    value = str(value or "").strip()
    if not value:
        return ""
    try:
        return str(Version(value))
    except InvalidVersion:
        return value


def versions_equal(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    try:
        return Version(str(left)) == Version(str(right))
    except InvalidVersion:
        return str(left).strip() == str(right).strip()


def is_fixed_or_newer(version: str, fixed_versions: str) -> bool:
    if not version or not fixed_versions:
        return False
    parsed_version = Version(version)
    candidates: list[Version] = []
    for raw in fixed_versions.split(";"):
        raw = raw.strip()
        if not raw:
            continue
        if "==" in raw:
            raw = raw.rsplit("==", 1)[-1].strip()
        try:
            candidates.append(Version(raw))
        except InvalidVersion:
            continue
    return bool(candidates) and parsed_version >= min(candidates)


def project_slug(repo_full_name: str) -> str:
    return repo_full_name.replace("/", "__", 1)


def load_projects(projects_path: Path, projects_root: Path) -> list[ProjectRecord]:
    data = json.loads(projects_path.read_text(encoding="utf-8"))
    out: list[ProjectRecord] = []
    for item in data.get("projects", []) or []:
        repo = ((item.get("github") or {}).get("repository") or {}).get("full_name") or item.get("project")
        if not repo:
            continue
        slug = project_slug(str(repo))
        path = projects_root / slug
        if not path.exists():
            lowered = {child.name.lower(): child for child in projects_root.iterdir() if child.is_dir()}
            path = lowered.get(slug.lower(), path)
        out.append(ProjectRecord(project=slug, repo_full_name=str(repo), path=path))
    return out


def manifest_priority(path: Path) -> int:
    name = path.name
    if name.startswith("requirements") and name.endswith(".txt"):
        return 40
    return LOCKFILE_PRIORITY.get(name, 100)


def discover_manifests(project_path: Path) -> list[Path]:
    if not project_path.exists():
        return []
    paths: list[Path] = []
    for child in project_path.iterdir():
        if child.is_file() and (child.name in MANIFEST_NAMES or (child.name.startswith("requirements") and child.suffix == ".txt")):
            paths.append(child)
    return sorted(paths, key=lambda item: (manifest_priority(item), item.name.lower()))


def parse_manifest(path: Path, *, include_dev: bool = False) -> list[ResolvedPackage]:
    installed = {}
    direct_names: set[str] = set()
    if path.name == "pyproject.toml":
        direct_names = parsers.direct_names_from_pyproject(path, include_dev=include_dev)
    elif (path.parent / "pyproject.toml").exists():
        direct_names = parsers.direct_names_from_pyproject(path.parent / "pyproject.toml", include_dev=include_dev)

    if path.name == "uv.lock":
        records = parsers.parse_uv_lock(path, direct_names=direct_names, include_dev=include_dev, installed=installed)
    elif path.name == "poetry.lock":
        records = parsers.parse_poetry_lock(path, direct_names=direct_names, include_dev=include_dev, installed=installed)
    elif path.name == "Pipfile.lock":
        records = parsers.parse_pipfile_lock(path, include_dev=include_dev, installed=installed)
    elif path.name == "pyproject.toml":
        records = parsers.parse_pyproject(path, include_dev=include_dev, installed=installed)
    elif path.name == "setup.py":
        records = parsers.parse_setup_py(path, include_dev=include_dev, installed=installed)
    elif path.name.startswith("requirements") and path.suffix == ".txt":
        records = parsers.parse_requirements(path, include_dev=include_dev, installed=installed)
    else:
        records = []

    out: list[ResolvedPackage] = []
    for record in records:
        if not record.version:
            continue
        out.append(
            ResolvedPackage(
                project="",
                package=record.name,
                package_normalized=record.normalized_name,
                version=normalize_version(record.version),
                source_type=record.source_type,
                source_file=str(path),
                provenance="lockfile_or_manifest",
                priority=manifest_priority(path),
            )
        )
    return out


def collect_resolved_packages(projects: Iterable[ProjectRecord]) -> tuple[list[dict[str, str]], list[ResolvedPackage]]:
    env_rows: list[dict[str, str]] = []
    packages: list[ResolvedPackage] = []
    for project in projects:
        manifests = discover_manifests(project.path)
        parse_errors: list[str] = []
        project_packages: list[ResolvedPackage] = []
        for manifest in manifests:
            try:
                for package in parse_manifest(manifest):
                    project_packages.append(
                        ResolvedPackage(
                            project=project.project,
                            package=package.package,
                            package_normalized=package.package_normalized,
                            version=package.version,
                            source_type=package.source_type,
                            source_file=str(Path(package.source_file).relative_to(project.path)),
                            provenance=package.provenance,
                            priority=package.priority,
                        )
                    )
            except Exception as exc:
                parse_errors.append(f"{manifest.name}: {type(exc).__name__}: {exc}")
        env_status = "resolved_from_lockfile_or_manifest" if project_packages else "unresolved_environment"
        env_rows.append(
            {
                "project": project.project,
                "repo_full_name": project.repo_full_name,
                "project_path": str(project.path),
                "environment_status": env_status,
                "manifest_count": str(len(manifests)),
                "manifest_files": ";".join(str(path.relative_to(project.path)) for path in manifests),
                "resolved_package_count": str(len({item.package_normalized for item in project_packages})),
                "parse_errors": " | ".join(parse_errors),
                "version_source": "lockfile_or_manifest",
            }
        )
        packages.extend(project_packages)
    return env_rows, choose_best_versions(packages)


def choose_best_versions(packages: list[ResolvedPackage]) -> list[ResolvedPackage]:
    grouped: dict[tuple[str, str], list[ResolvedPackage]] = defaultdict(list)
    for package in packages:
        grouped[(package.project, package.package_normalized)].append(package)
    chosen: list[ResolvedPackage] = []
    for items in grouped.values():
        chosen.append(sorted(items, key=lambda item: (item.priority, item.source_file, item.version))[0])
    return sorted(chosen, key=lambda item: (item.project, item.package_normalized))


def load_scanner_findings(path: Path) -> list[ScannerFinding]:
    findings: list[ScannerFinding] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            package = str(row.get("package") or "").strip()
            if not package:
                continue
            findings.append(
                ScannerFinding(
                    project=str(row.get("project") or ""),
                    source=str(row.get("source") or ""),
                    cve_id=str(row.get("cve_id") or ""),
                    package=package,
                    package_normalized=normalize_package(package),
                    scanner_version=normalize_version(row.get("version")),
                    fixed_versions=str(row.get("fixed_versions") or ""),
                    severity=str(row.get("severity") or ""),
                    title=str(row.get("title") or ""),
                    advisory_id=str(row.get("advisory_id") or ""),
                )
            )
    return findings


def reconcile_status(finding: ScannerFinding, resolved: ResolvedPackage | None, project_resolved: bool) -> tuple[str, str, str]:
    if resolved is None:
        if not project_resolved:
            return "unresolved_environment", "exclude_unresolved_environment", "no resolved package manifest for project"
        return "scanner_only_manifest", "exclude_scanner_only_manifest", "package absent from resolved project manifests"
    if finding.scanner_version and versions_equal(finding.scanner_version, resolved.version):
        return "consistent", "valid_for_annotation", "scanner version matches resolved version"
    if not finding.scanner_version:
        return (
            "scanner_version_missing_but_env_affected",
            "valid_for_annotation",
            "scanner did not report a package version; using resolved version",
        )
    try:
        fixed_or_newer = is_fixed_or_newer(resolved.version, finding.fixed_versions)
    except InvalidVersion:
        fixed_or_newer = False
    if fixed_or_newer:
        return (
            "mismatch_not_applicable",
            "exclude_version_not_applicable",
            "resolved version is at or newer than known fixed version",
        )
    return (
        "mismatch_but_env_affected",
        "valid_for_annotation",
        "scanner version differs; resolved version is treated as applicable because no fixed-version exclusion matched",
    )


def reconcile_findings(
    findings: list[ScannerFinding],
    resolved_packages: list[ResolvedPackage],
    environment_rows: list[dict[str, str]],
) -> list[dict[str, str]]:
    resolved_by_pair = {(item.project, item.package_normalized): item for item in resolved_packages}
    project_resolved = {
        row["project"]: row["environment_status"] != "unresolved_environment"
        for row in environment_rows
    }
    rows: list[dict[str, str]] = []
    for finding in findings:
        resolved = resolved_by_pair.get((finding.project, finding.package_normalized))
        status, decision, reason = reconcile_status(finding, resolved, project_resolved.get(finding.project, False))
        rows.append(
            {
                "project": finding.project,
                "scanner": finding.source,
                "cve_id": finding.cve_id,
                "package": finding.package,
                "package_normalized": finding.package_normalized,
                "scanner_version": finding.scanner_version,
                "resolved_version": resolved.version if resolved else "",
                "resolved_source_type": resolved.source_type if resolved else "",
                "resolved_source_file": resolved.source_file if resolved else "",
                "resolved_provenance": resolved.provenance if resolved else "",
                "fixed_versions": finding.fixed_versions,
                "version_status": status,
                "annotation_decision": decision,
                "decision_reason": reason,
                "severity": finding.severity,
                "title": finding.title,
                "advisory_id": finding.advisory_id,
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def resolved_package_rows(packages: list[ResolvedPackage]) -> list[dict[str, str]]:
    return [
        {
            "project": item.project,
            "package": item.package,
            "package_normalized": item.package_normalized,
            "resolved_version": item.version,
            "source_type": item.source_type,
            "source_file": item.source_file,
            "provenance": item.provenance,
        }
        for item in packages
    ]


def valid_alerts(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [row for row in rows if row["version_status"] in VALID_FOR_ANNOTATION]


def summary_markdown(
    environment_rows: list[dict[str, str]],
    packages: list[ResolvedPackage],
    reconciliation_rows: list[dict[str, str]],
) -> str:
    status_counts = Counter(row["version_status"] for row in reconciliation_rows)
    decision_counts = Counter(row["annotation_decision"] for row in reconciliation_rows)
    unresolved_projects = [row["project"] for row in environment_rows if row["environment_status"] == "unresolved_environment"]
    conflict_counter = Counter(
        (row["project"], row["package_normalized"])
        for row in reconciliation_rows
        if row["version_status"].startswith("mismatch")
    )
    lines = [
        "# Version Audit Summary",
        "",
        "## Headline Counts",
        "",
        f"- Projects audited: {len(environment_rows)}",
        f"- Projects with resolved package evidence: {sum(1 for row in environment_rows if row['environment_status'] != 'unresolved_environment')}",
        f"- Projects unresolved: {len(unresolved_projects)}",
        f"- Resolved project/package pairs: {len(packages)}",
        f"- Scanner finding rows: {len(reconciliation_rows)}",
        f"- Valid alerts for annotation: {sum(decision_counts[key] for key in decision_counts if key == 'valid_for_annotation')}",
        "",
        "## Version Status",
        "",
        "| status | rows |",
        "|---|---:|",
    ]
    for status, count in sorted(status_counts.items()):
        lines.append(f"| {status} | {count} |")
    lines.extend(["", "## Annotation Decisions", "", "| decision | rows |", "|---|---:|"])
    for decision, count in sorted(decision_counts.items()):
        lines.append(f"| {decision} | {count} |")
    lines.extend(["", "## Top Version Conflicts", "", "| project | package | rows |", "|---|---|---:|"])
    for (project, package), count in conflict_counter.most_common(20):
        lines.append(f"| {project} | {package} | {count} |")
    lines.extend(["", "## Projects Needing Environment Build", ""])
    if unresolved_projects:
        for project in sorted(unresolved_projects):
            lines.append(f"- {project}")
    else:
        lines.append("- None")
    return "\n".join(lines) + "\n"
