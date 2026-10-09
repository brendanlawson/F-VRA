from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
SCANS = DATA / "_scans"
RESULTS = ROOT / "results" / "tables"

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))


def try_read_json(path: Path) -> Any | None:
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        return read_json(path)
    except json.JSONDecodeError:
        return None


def cves_from(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        return {m.upper() for m in CVE_RE.findall(value)}
    return {m.upper() for m in CVE_RE.findall(json.dumps(value, ensure_ascii=False))}


def project_key(repo_full_name: str) -> str:
    return repo_full_name.replace("/", "__")


def load_projects() -> list[dict[str, Any]]:
    raw = read_json(DATA / "projects.json")
    projects = []
    for item in raw["projects"]:
        repo = item["github"]["repository"]
        commit = item["github"].get("default_branch_commit", {})
        key = project_key(repo["full_name"])
        projects.append(
            {
                "project": key,
                "repo_full_name": repo["full_name"],
                "repo_url": repo["html_url"],
                "description": repo.get("description") or "",
                "language": repo.get("language") or "",
                "default_branch": repo.get("default_branch") or "",
                "snapshot_sha": (commit.get("sha") or "")[:12],
                "stars": repo.get("stargazers_count", 0),
                "forks": repo.get("forks_count", 0),
                "open_issues": repo.get("open_issues_count", 0),
                "size_kb": repo.get("size", 0),
            }
        )
    return projects


def load_snyk_summary() -> dict[str, dict[str, str]]:
    path = SCANS / "snyk" / "summary.combined.csv"
    if not path.exists():
        return {}
    with path.open(newline="", encoding="utf-8") as f:
        return {row["project"]: row for row in csv.DictReader(f)}


def load_csv_by_project(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}
    with path.open(newline="", encoding="utf-8-sig") as f:
        return {row["project"]: row for row in csv.DictReader(f)}


def add_finding(
    findings: list[dict[str, str]],
    project: str,
    source: str,
    cve: str,
    package: str = "",
    version: str = "",
    severity: str = "",
    title: str = "",
    fixed_versions: str = "",
    reachability: str = "",
    directness: str = "",
    advisory_id: str = "",
) -> None:
    findings.append(
        {
            "project": project,
            "source": source,
            "cve_id": cve.upper(),
            "package": package,
            "version": version,
            "severity": severity,
            "title": title.replace("\n", " ").strip(),
            "fixed_versions": fixed_versions,
            "reachability": reachability,
            "directness": directness,
            "advisory_id": advisory_id,
        }
    )


def parse_pip_audit(project: str, findings: list[dict[str, str]]) -> None:
    path = SCANS / "pip-audit" / f"{project}.json"
    data = try_read_json(path)
    if data is not None:
        _parse_pip_audit_doc(project, findings, data, "pip-audit")
    fallback_data = try_read_json(SCANS / "pip-audit-fallback" / f"{project}.json")
    if fallback_data is not None:
        _parse_pip_audit_doc(project, findings, fallback_data, "pip-audit-fallback")


def _parse_pip_audit_doc(
    project: str,
    findings: list[dict[str, str]],
    data: dict[str, Any],
    source: str,
) -> None:
    for dep in data.get("dependencies", []):
        pkg = dep.get("name", "")
        ver = dep.get("version", "")
        for vuln in dep.get("vulns", []) or []:
            ids = set()
            ids |= cves_from(vuln.get("id"))
            ids |= cves_from(vuln.get("aliases"))
            for cve in ids:
                add_finding(
                    findings,
                    project,
                    source,
                    cve,
                    package=pkg,
                    version=ver,
                    title=vuln.get("description", ""),
                    fixed_versions=";".join(vuln.get("fix_versions") or []),
                    advisory_id=vuln.get("id", ""),
                )


def parse_osv(project: str, findings: list[dict[str, str]]) -> None:
    path = SCANS / "osv-scanner" / f"{project}.json"
    data = try_read_json(path)
    if data is None:
        return
    for result in data.get("results") or []:
        for pkg_entry in result.get("packages") or []:
            pkg = pkg_entry.get("package") or {}
            name = pkg.get("name", "")
            version = pkg.get("version", "")
            for group in pkg_entry.get("groups") or []:
                ids = cves_from(group.get("ids")) | cves_from(group.get("aliases"))
                severity = str(group.get("max_severity") or "")
                advisory = ";".join(group.get("ids") or [])
                for cve in ids:
                    add_finding(
                        findings,
                        project,
                        "osv-scanner",
                        cve,
                        package=name,
                        version=version,
                        severity=severity,
                        advisory_id=advisory,
                    )


def parse_semgrep(project: str, findings: list[dict[str, str]]) -> None:
    path = SCANS / "semgrep-supply-chain" / f"{project}.json"
    data = try_read_json(path)
    if data is None:
        return
    for result in data.get("results") or []:
        extra = result.get("extra") or {}
        meta = extra.get("metadata") or {}
        ids = cves_from(meta.get("cve")) | cves_from(meta.get("sca-vuln-database-identifier"))
        if not ids:
            ids = cves_from(meta)
        pkg = ""
        ver = ""
        dep_match = meta.get("dependency_match") or {}
        if isinstance(dep_match, dict):
            pkg = dep_match.get("dependency_pattern", {}).get("package", "") or dep_match.get("found_dependency", {}).get("package", "")
            ver = dep_match.get("found_dependency", {}).get("version", "")
        if not pkg:
            fix_versions = meta.get("sca-fix-versions") or []
            if fix_versions and isinstance(fix_versions[0], dict):
                pkg = next(iter(fix_versions[0].keys()), "")
        fixed = []
        for item in meta.get("sca-fix-versions") or []:
            if isinstance(item, dict):
                fixed.extend(f"{k}=={v}" for k, v in item.items())
        for cve in ids:
            add_finding(
                findings,
                project,
                "semgrep-supply-chain",
                cve,
                package=pkg,
                version=ver,
                severity=str(meta.get("sca-severity") or ""),
                title=extra.get("message", ""),
                fixed_versions=";".join(fixed),
                reachability=str(meta.get("sca-kind") or ""),
                directness=str(meta.get("sca-dependency-kind") or ""),
                advisory_id=str(meta.get("ghsa") or meta.get("sca-vuln-database-identifier") or ""),
            )


def snyk_json_path(project: str) -> Path | None:
    for base in [
        SCANS / "snyk" / "pip-docker" / "json",
        SCANS / "snyk" / "pip-docker-recovered13" / "json",
    ]:
        path = base / f"{project}.json"
        if path.exists():
            return path
    return None


def parse_snyk(project: str, findings: list[dict[str, str]]) -> None:
    path = snyk_json_path(project)
    if not path:
        return
    data = try_read_json(path)
    if data is None:
        return
    docs = data if isinstance(data, list) else [data]
    for doc in docs:
        for vuln in doc.get("vulnerabilities") or []:
            identifiers = vuln.get("identifiers") or {}
            ids = cves_from(identifiers.get("CVE")) | cves_from(vuln)
            pkg = vuln.get("packageName") or vuln.get("moduleName") or vuln.get("name") or ""
            fixed = vuln.get("fixedIn") or []
            for cve in ids:
                add_finding(
                    findings,
                    project,
                    "snyk",
                    cve,
                    package=pkg,
                    version=str(vuln.get("version") or ""),
                    severity=str(vuln.get("severity") or ""),
                    title=vuln.get("title", ""),
                    fixed_versions=";".join(fixed),
                    advisory_id=vuln.get("id", ""),
                )


def collect_findings(projects: list[dict[str, Any]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for project in [p["project"] for p in projects]:
        parse_pip_audit(project, findings)
        parse_osv(project, findings)
        parse_semgrep(project, findings)
        parse_snyk(project, findings)
    # Exact duplicate rows can happen when a tool repeats the same advisory path.
    seen = set()
    deduped = []
    for row in findings:
        key = tuple(row.items())
        if key not in seen:
            seen.add(key)
            deduped.append(row)
    return deduped


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def build_reports() -> None:
    projects = load_projects()
    vuln_summary = load_csv_by_project(SCANS / "vuln_summary.csv")
    fallback_summary = load_csv_by_project(SCANS / "pip-audit-fallback" / "summary.csv")
    semgrep_summary = load_csv_by_project(SCANS / "semgrep_sc_summary.csv")
    snyk_summary = load_snyk_summary()
    findings = collect_findings(projects)

    by_project_source: dict[tuple[str, str], set[str]] = defaultdict(set)
    by_project_cve: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in findings:
        by_project_source[(row["project"], row["source"])].add(row["cve_id"])
        by_project_cve[(row["project"], row["cve_id"])].append(row)

    overview_rows = []
    for p in projects:
        project = p["project"]
        source_counts = {
            source: len(by_project_source.get((project, source), set()))
            for source in ["pip-audit", "osv-scanner", "semgrep-supply-chain", "snyk"]
        }
        pip_cves = set(by_project_source.get((project, "pip-audit"), set()))
        pip_cves.update(by_project_source.get((project, "pip-audit-fallback"), set()))
        source_counts["pip-audit"] = len(pip_cves)
        total_unique = len({cve for (proj, cve) in by_project_cve if proj == project})
        snyk = snyk_summary.get(project, {})
        vuln = vuln_summary.get(project, {})
        fallback = fallback_summary.get(project, {})
        semgrep = semgrep_summary.get(project, {})
        pip_status = vuln.get("pip_audit_status", "")
        if fallback and pip_status in {"", "error", "timeout", "skip"}:
            pip_status = f"fallback:{fallback.get('status', '')}"
        overview_rows.append(
            {
                **p,
                "pinned_pkgs": snyk.get("pinned", ""),
                "installed_pkgs": snyk.get("installed", ""),
                "install_fail": snyk.get("install_fail", ""),
                "pip_audit_status": pip_status,
                "pip_audit_fallback_status": fallback.get("status", ""),
                "pip_audit_fallback_failed": fallback.get("failed", ""),
                "pip_audit_fallback_dropped": fallback.get("dropped", ""),
                "pip_audit_cves": source_counts["pip-audit"],
                "osv_status": vuln.get("osv_status", ""),
                "osv_scanner_cves": source_counts["osv-scanner"],
                "semgrep_status": semgrep.get("status", ""),
                "semgrep_sc_cves": source_counts["semgrep-supply-chain"],
                "snyk_status": snyk.get("status", ""),
                "snyk_cves": source_counts["snyk"],
                "total_unique_cves": total_unique,
            }
        )

    detail_rows = []
    for (project, cve), rows in sorted(by_project_cve.items()):
        sources = sorted({r["source"] for r in rows})
        packages = sorted({f"{r['package']}=={r['version']}".strip("=") for r in rows if r["package"]})
        severities = sorted({f"{r['source']}:{r['severity']}" for r in rows if r["severity"]})
        reach = sorted({r["reachability"] for r in rows if r["reachability"]})
        titles = []
        for r in rows:
            if r["title"] and r["title"] not in titles:
                titles.append(r["title"])
        fixes = sorted({r["fixed_versions"] for r in rows if r["fixed_versions"]})
        detail_rows.append(
            {
                "project": project,
                "cve_id": cve,
                "sources": ";".join(sources),
                "source_count": len(sources),
                "affected_packages": ";".join(packages),
                "severity_by_source": ";".join(severities),
                "reachability": ";".join(reach),
                "fixed_versions": ";".join(fixes),
                "titles": " | ".join(titles[:3]),
                "finding_rows": len(rows),
            }
        )

    write_csv(
        RESULTS / "project_cve_overview.csv",
        overview_rows,
        [
            "project",
            "repo_full_name",
            "repo_url",
            "description",
            "language",
            "default_branch",
            "snapshot_sha",
            "stars",
            "forks",
            "open_issues",
            "size_kb",
            "pinned_pkgs",
            "installed_pkgs",
            "install_fail",
            "pip_audit_status",
            "pip_audit_fallback_status",
            "pip_audit_fallback_failed",
            "pip_audit_fallback_dropped",
            "pip_audit_cves",
            "osv_status",
            "osv_scanner_cves",
            "semgrep_status",
            "semgrep_sc_cves",
            "snyk_status",
            "snyk_cves",
            "total_unique_cves",
        ],
    )
    write_csv(
        RESULTS / "project_cve_details.csv",
        detail_rows,
        [
            "project",
            "cve_id",
            "sources",
            "source_count",
            "affected_packages",
            "severity_by_source",
            "reachability",
            "fixed_versions",
            "titles",
            "finding_rows",
        ],
    )
    write_csv(
        RESULTS / "project_cve_source_findings.csv",
        findings,
        [
            "project",
            "source",
            "cve_id",
            "package",
            "version",
            "severity",
            "title",
            "fixed_versions",
            "reachability",
            "directness",
            "advisory_id",
        ],
    )

    md = RESULTS / "project_cve_report.md"
    top = sorted(overview_rows, key=lambda r: int(r["total_unique_cves"]), reverse=True)[:10]
    lines = [
        "# Project CVE Report",
        "",
        "Generated from local GitHub snapshots and local scan artifacts in `data/_scans`.",
        "",
        f"- Projects: {len(projects)}",
        f"- Source finding rows: {len(findings)}",
        f"- Deduplicated project/CVE rows: {len(detail_rows)}",
        f"- Total unique CVEs across all projects: {len({r['cve_id'] for r in detail_rows})}",
        "",
        "## Top Projects By Deduplicated CVEs",
        "",
        "| project | pinned pkgs | pip-audit | osv | semgrep | snyk | dedup total |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for r in top:
        lines.append(
            f"| {r['project']} | {r['pinned_pkgs']} | {r['pip_audit_cves']} ({r['pip_audit_status']}) | "
            f"{r['osv_scanner_cves']} ({r['osv_status']}) | {r['semgrep_sc_cves']} ({r['semgrep_status']}) | "
            f"{r['snyk_cves']} ({r['snyk_status']}) | {r['total_unique_cves']} |"
        )
    lines.extend(
        [
            "",
            "## Methodology Notes",
            "",
            "- `size_kb` is the GitHub repository `size` field from `data/projects.json`.",
            "- `pinned_pkgs`, `installed_pkgs`, and `install_fail` come from the Snyk pip-docker pipeline summary.",
            "- CVE counts include only identifiers matching `CVE-YYYY-N...`; GHSA/PYSEC/SNYK IDs without a CVE alias are not counted in CVE columns.",
            "- Each source count is paired with a source status in `project_cve_overview.csv`; `0 (clean)` is different from `0 (error)` or `0 (timeout)`.",
            "- If one-shot pip-audit errors or times out, `pip_audit_cves` includes `pip-audit-fallback` batched Python 3.12 results when available.",
            "- `total_unique_cves` deduplicates by `(project, CVE)` across pip-audit, pip-audit-fallback, osv-scanner, Semgrep Supply Chain, and Snyk.",
            "- Empty or malformed JSON artifacts are skipped for that source only; other sources for the same project remain included.",
            "",
            "## Outputs",
            "",
            "- `project_cve_overview.csv`: project/link/size/package counts/CVE counts by source/dedup total.",
            "- `project_cve_details.csv`: one row per project and CVE after cross-source deduplication.",
            "- `project_cve_source_findings.csv`: source-level trace rows before project/CVE aggregation.",
        ]
    )
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"wrote {RESULTS / 'project_cve_overview.csv'} ({len(overview_rows)} rows)")
    print(f"wrote {RESULTS / 'project_cve_details.csv'} ({len(detail_rows)} rows)")
    print(f"wrote {RESULTS / 'project_cve_source_findings.csv'} ({len(findings)} rows)")
    print(f"wrote {md}")


if __name__ == "__main__":
    build_reports()
