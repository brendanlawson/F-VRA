"""Evidence enrichment for accepted CVE-to-VF records."""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import requests

from f_vra.cve_vf.benchmark import normalize_package_name

VALID_STATUSES = {
    "consistent",
    "scanner_version_missing_but_env_affected",
    "mismatch_but_env_affected",
}

EVIDENCE_PRIORITY = {
    "patch_verified": 0,
    "advisory_explicit": 1,
    "weak_or_uncertain": 2,
    "": 3,
}

GITHUB_COMMIT_RE = re.compile(r"https?://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{7,40}", re.I)
GITHUB_COMMIT_CAPTURE_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/\s]+)/(?P<repo>[^/\s#?]+)/(?:commit|commits)/(?P<sha>[0-9a-f]{7,40})",
    re.I,
)
GITHUB_PR_RE = re.compile(r"https?://github\.com/[^/]+/[^/]+/pull/\d+", re.I)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def pair_key(cve_id: str | None, package: str | None) -> tuple[str, str]:
    return (str(cve_id or "").strip(), normalize_package_name(package))


def group_id(cve_id: str | None, package: str | None) -> str:
    return f"{str(cve_id or '').strip()}::{normalize_package_name(package)}"


def parse_group_id(value: str | None) -> tuple[str, str]:
    raw = str(value or "")
    if "::" not in raw:
        return raw.strip(), ""
    cve_id, package = raw.split("::", 1)
    return cve_id.strip(), normalize_package_name(package)


def evidence_level_rank(value: str | None) -> int:
    return EVIDENCE_PRIORITY.get(str(value or ""), 3)


def merge_target_vfs(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        for target in row.get("target_vfs") or []:
            qualified_name = str(target.get("qualified_name") or "")
            label = str(target.get("label") or "")
            if not qualified_name:
                continue
            key = (qualified_name, label)
            if key not in merged:
                merged[key] = dict(target)
    return sorted(merged.values(), key=lambda item: (str(item.get("qualified_name") or ""), str(item.get("label") or "")))


def accepted_benchmark_rows(path: Path) -> list[dict[str, Any]]:
    return [row for row in read_jsonl(path) if row.get("benchmark_status") == "accepted"]


def valid_alert_rows(path: Path) -> list[dict[str, str]]:
    rows = read_csv(path)
    return [row for row in rows if row.get("version_status") in VALID_STATUSES]


def group_valid_alerts(rows: Iterable[dict[str, str]]) -> dict[tuple[str, str], list[dict[str, str]]]:
    grouped: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        grouped[pair_key(row.get("cve_id"), row.get("package_normalized") or row.get("package"))].append(row)
    return grouped


def build_target_pairs(
    accepted_rows: list[dict[str, Any]], valid_rows: list[dict[str, str]]
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], list[dict[str, str]]]]:
    valid_by_pair = group_valid_alerts(valid_rows)
    accepted_by_pair: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in accepted_rows:
        key = pair_key(row.get("cve_id"), row.get("package_normalized") or row.get("package"))
        if key in valid_by_pair:
            accepted_by_pair[key].append(row)

    pairs: list[dict[str, Any]] = []
    for key, rows in sorted(accepted_by_pair.items()):
        cve_id, package_normalized = key
        first = rows[0]
        alert_rows = valid_by_pair[key]
        levels = [str(row.get("evidence_level") or "") for row in rows]
        pairs.append(
            {
                "cve_id": cve_id,
                "package": first.get("package") or package_normalized,
                "package_normalized": package_normalized,
                "benchmark_ids": sorted(str(row.get("benchmark_id") or "") for row in rows),
                "accepted_record_count": len(rows),
                "valid_alert_row_count": len(alert_rows),
                "valid_project_count": len({row.get("project") for row in alert_rows}),
                "projects": sorted({str(row.get("project") or "") for row in alert_rows if row.get("project")}),
                "resolved_versions": sorted({str(row.get("resolved_version") or "") for row in alert_rows if row.get("resolved_version")}),
                "fixed_versions": "; ".join(
                    sorted({str(row.get("fixed_versions") or "") for row in alert_rows if row.get("fixed_versions")})
                ),
                "target_vfs": merge_target_vfs(rows),
                "annotation_summary": first.get("annotation_summary") or "",
                "benchmark_evidence_level": sorted(levels, key=evidence_level_rank)[0] if levels else "",
                "scanner_sources": sorted({str(row.get("scanner") or "") for row in alert_rows if row.get("scanner")}),
                "scanner_titles": sorted({str(row.get("title") or "") for row in alert_rows if row.get("title")}),
                "scanner_severities": sorted({str(row.get("severity") or "") for row in alert_rows if row.get("severity")}),
            }
        )
    return pairs, valid_by_pair


def build_alert_pairs(
    valid_rows: list[dict[str, str]],
    accepted_rows: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], list[dict[str, str]]]]:
    valid_by_pair = group_valid_alerts(valid_rows)

    pairs: list[dict[str, Any]] = []
    for key, alert_rows in sorted(valid_by_pair.items()):
        cve_id, package_normalized = key
        first = alert_rows[0]
        pairs.append(
            {
                "cve_id": cve_id,
                "package": first.get("package") or package_normalized,
                "package_normalized": package_normalized,
                "valid_alert_row_count": len(alert_rows),
                "valid_project_count": len({row.get("project") for row in alert_rows}),
                "projects": sorted({str(row.get("project") or "") for row in alert_rows if row.get("project")}),
                "resolved_versions": sorted({str(row.get("resolved_version") or "") for row in alert_rows if row.get("resolved_version")}),
                "fixed_versions": "; ".join(
                    sorted({str(row.get("fixed_versions") or "") for row in alert_rows if row.get("fixed_versions")})
                ),
                "annotation_summary": "",
                "benchmark_evidence_level": "",
                "scanner_sources": sorted({str(row.get("scanner") or "") for row in alert_rows if row.get("scanner")}),
                "scanner_titles": sorted({str(row.get("title") or "") for row in alert_rows if row.get("title")}),
                "scanner_severities": sorted({str(row.get("severity") or "") for row in alert_rows if row.get("severity")}),
            }
        )
    return pairs, valid_by_pair


def load_evidence_cache(path: Path) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in read_jsonl(path):
        key = pair_key(row.get("advisory_id") or row.get("cve_id"), row.get("package"))
        if key[0] and key[1]:
            out[key] = row
    return out


def load_advisory_groups(paths: Iterable[Path]) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for path in paths:
        for row in read_jsonl(path):
            package = row.get("package")
            package_name = package.get("name") if isinstance(package, dict) else package
            key = pair_key(row.get("advisory_id") or row.get("cve_id"), package_name)
            if key[0] and key[1] and key not in out:
                out[key] = row
    return out


def load_jsonl_by_pair(paths: Iterable[Path]) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for path in paths:
        for row in read_jsonl(path):
            cve_id, package = parse_group_id(row.get("group_id"))
            if not package:
                cve_id = str(row.get("advisory_id") or row.get("cve_id") or "")
                package = normalize_package_name(row.get("package"))
            key = pair_key(cve_id, package)
            if key[0] and key[1] and key not in out:
                out[key] = row
    return out


def reference_category(url: str | None, ref_type: str | None = None) -> str:
    url_l = str(url or "").lower()
    type_l = str(ref_type or "").lower()
    if type_l in {"poc", "proof_of_concept"} or "poc" in url_l:
        return "poc"
    if "exploit" in url_l:
        return "exploit"
    if type_l in {"test", "tests"} or "/test" in url_l or "test_" in url_l:
        return "test"
    if type_l in {"patch", "fix"} or ".patch" in url_l or ".diff" in url_l:
        return "patch"
    if type_l in {"commit", "commits"} or GITHUB_COMMIT_RE.search(str(url or "")):
        return "commit"
    if type_l in {"pr", "pull_request"} or GITHUB_PR_RE.search(str(url or "")):
        return "pull_request"
    if type_l in {"release", "tag"} or "/releases/" in url_l or "/tags/" in url_l:
        return "release"
    if type_l in {"issue", "bug"} or "/issues/" in url_l:
        return "issue"
    if type_l == "advisory" or "advisories" in url_l or "nvd.nist.gov" in url_l or "osv.dev" in url_l:
        return "advisory"
    return "other"


def normalize_references(references: Iterable[dict[str, Any]]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for ref in references:
        url = str(ref.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        ref_type = str(ref.get("type") or "")
        normalized.append({"url": url, "type": ref_type, "category": reference_category(url, ref_type)})
    return normalized


def fetched_metadata_to_advisory(cve_id: str, package: str, metadata: Any) -> dict[str, Any]:
    references = [{"url": url, "type": ""} for url in getattr(metadata, "references", []) or []]
    source = str(getattr(metadata, "source", "") or "").lower()
    provenance = f"fetched_{source}" if source and source != "unknown" else "fetched_metadata"
    return {
        "advisory_id": cve_id,
        "package": {"name": package},
        "description": getattr(metadata, "description", "") or "",
        "references": references,
        "aliases": {"cve": cve_id},
        "raw_sources": [getattr(metadata, "source", "") or "unknown"],
        "_provenance": provenance,
    }


def evidence_priority(level: str) -> str:
    if level == "patch_verified":
        return "Tier A"
    if level == "advisory_explicit":
        return "Tier B"
    return "Tier C"


def enrich_pair(
    pair: dict[str, Any],
    cache: dict[tuple[str, str], dict[str, Any]],
    advisory_groups: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    key = pair_key(pair.get("cve_id"), pair.get("package_normalized") or pair.get("package"))
    cached = cache.get(key, {})
    advisory = advisory_groups.get(key, {})
    references = normalize_references((advisory.get("references") or []) + (cached.get("references") or []))
    fix_commits = cached.get("fix_commits") or []
    patch_urls = sorted(
        {
            str(commit.get("url") or "")
            for commit in fix_commits
            if isinstance(commit, dict) and commit.get("url")
        }.union({ref["url"] for ref in references if ref["category"] in {"patch", "commit"}})
    )
    diff_paths = sorted(
        {
            str(commit.get("diff_path") or "")
            for commit in fix_commits
            if isinstance(commit, dict) and commit.get("diff_path")
        }
    )
    categories = Counter(ref["category"] for ref in references)
    evidence_level = str(cached.get("evidence_level") or pair.get("benchmark_evidence_level") or "weak_or_uncertain")
    provenance: list[str] = []
    if cached:
        provenance.append("imported_from_output_file")
    if advisory:
        provenance.append(str(advisory.get("_provenance") or "imported_advisory_group"))
    if not provenance:
        provenance.append("scanner_finding")

    return {
        **pair,
        "group_id": group_id(pair.get("cve_id"), pair.get("package_normalized") or pair.get("package")),
        "description": advisory.get("description") or pair.get("annotation_summary") or next(iter(pair.get("scanner_titles") or []), ""),
        "aliases": advisory.get("aliases") or {},
        "published_at": advisory.get("published_at") or "",
        "affected_versions": advisory.get("affected_versions") or "",
        "fixed_versions": advisory.get("fixed_versions") or pair.get("fixed_versions") or "",
        "references": references,
        "reference_category_counts": dict(sorted(categories.items())),
        "raw_sources": advisory.get("raw_sources") or [],
        "evidence_level": evidence_level,
        "suggested_priority": evidence_priority(evidence_level),
        "fix_commits": fix_commits,
        "patch_urls": patch_urls,
        "diff_paths": diff_paths,
        "repo_url": cached.get("repo_url") or "",
        "vulnerable_ref": cached.get("vulnerable_ref") or "",
        "fixed_ref": cached.get("fixed_ref") or "",
        "has_poc_reference": bool(cached.get("has_poc_reference")) or any(ref["category"] in {"poc", "exploit"} for ref in references),
        "has_pr_reference": bool(cached.get("has_pr_reference")) or any(ref["category"] == "pull_request" for ref in references),
        "has_test_reference": bool(cached.get("has_test_reference")) or any(ref["category"] == "test" for ref in references),
        "description_mentions_function": bool(cached.get("description_mentions_function")),
        "indexing_notes": cached.get("indexing_notes") or "",
        "evidence_provenance": provenance,
    }


def attach_snapshot_evidence(
    evidence_rows: list[dict[str, Any]],
    source_snapshots: dict[tuple[str, str], dict[str, Any]] | None = None,
    verified_snapshots: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    source_snapshots = source_snapshots or {}
    verified_snapshots = verified_snapshots or {}
    out: list[dict[str, Any]] = []
    for row in evidence_rows:
        key = pair_key(row.get("cve_id"), row.get("package_normalized") or row.get("package"))
        source = source_snapshots.get(key, {})
        verified = verified_snapshots.get(key, {})
        merged = dict(row)
        if source:
            merged["source_snapshot"] = source
        if verified:
            merged["verified_snapshot"] = verified
        merged["commit_verified"] = bool(verified.get("commit_verified", False))
        merged["tree_sha"] = verified.get("tree_sha") or ""
        merged["diff_files_py"] = int(verified.get("diff_files_py") or 0)
        merged["diff_total_files"] = int(verified.get("diff_total_files") or 0)
        merged["diff_insertions"] = int(verified.get("diff_insertions") or 0)
        merged["diff_deletions"] = int(verified.get("diff_deletions") or 0)
        merged["diff_py_files_list"] = verified.get("diff_py_files_list") or []
        if verified.get("fix_commits"):
            merged["verified_fix_commits"] = verified.get("fix_commits") or []
        if verified.get("repo_url") and not merged.get("repo_url"):
            merged["repo_url"] = verified["repo_url"]
        if verified.get("vulnerable_ref") and not merged.get("vulnerable_ref"):
            merged["vulnerable_ref"] = verified["vulnerable_ref"]
        if verified.get("fixed_ref") and not merged.get("fixed_ref"):
            merged["fixed_ref"] = verified["fixed_ref"]
        out.append(merged)
    return out


def advisory_group_rows(evidence_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in evidence_rows:
        rows.append(
            {
                "group_id": row.get("group_id") or group_id(row.get("cve_id"), row.get("package_normalized")),
                "advisory_id": row.get("cve_id"),
                "aliases": row.get("aliases") or {},
                "description": row.get("description") or "",
                "published_at": row.get("published_at") or "",
                "package": {
                    "ecosystem": "PyPI",
                    "name": row.get("package_normalized") or row.get("package"),
                    "purl": f"pkg:pypi/{row.get('package_normalized') or row.get('package')}",
                },
                "affected_versions": row.get("affected_versions") or "",
                "fixed_versions": row.get("fixed_versions") or "",
                "references": row.get("references") or [],
                "raw_sources": row.get("raw_sources") or [],
                "evidence_provenance": row.get("evidence_provenance") or [],
            }
        )
    return rows


def filtered_pair_rows(source_rows: dict[tuple[str, str], dict[str, Any]], evidence_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keys = {pair_key(row.get("cve_id"), row.get("package_normalized") or row.get("package")) for row in evidence_rows}
    return [source_rows[key] for key in sorted(keys) if key in source_rows]


def _patch_diff_relative_path(path_value: str | None) -> Path | None:
    if not path_value:
        return None
    raw = Path(str(path_value))
    parts = raw.parts
    lowered = [part.lower() for part in parts]
    if "patch_diffs" not in lowered:
        return None
    idx = lowered.index("patch_diffs")
    tail = parts[idx + 1 :]
    if not tail:
        return None
    return Path(*tail)


def _resolve_legacy_diff_path(path_value: str, source_patch_root: Path) -> Path | None:
    raw = Path(path_value)
    if raw.exists():
        return raw
    rel = _patch_diff_relative_path(path_value)
    if rel is None:
        return None
    candidate = source_patch_root / rel
    return candidate if candidate.exists() else None


def materialize_diff_paths(
    evidence_rows: list[dict[str, Any]],
    *,
    source_patch_root: Path,
    artifact_patch_root: Path,
    repo_root: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Copy referenced legacy patch diffs into this repo and rewrite diff paths."""
    artifact_patch_root.mkdir(parents=True, exist_ok=True)
    logs: list[dict[str, Any]] = []
    out: list[dict[str, Any]] = []
    for row in evidence_rows:
        updated = dict(row)
        fix_commits: list[dict[str, Any]] = []
        diff_paths: list[str] = []
        for commit in row.get("fix_commits") or []:
            if not isinstance(commit, dict):
                continue
            commit_out = dict(commit)
            old_path = str(commit.get("diff_path") or "")
            if old_path:
                source = _resolve_legacy_diff_path(old_path, source_patch_root)
                rel = _patch_diff_relative_path(old_path)
                if source and rel:
                    dest = artifact_patch_root / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    if not dest.exists() or dest.stat().st_size != source.stat().st_size:
                        shutil.copy2(source, dest)
                    try:
                        normalized = str(dest.relative_to(repo_root))
                    except ValueError:
                        normalized = str(dest)
                    commit_out["diff_path"] = normalized
                    commit_out["diff_path_provenance"] = "materialized_from_docs_output_file"
                    diff_paths.append(normalized)
                    logs.append(
                        {
                            "group_id": row.get("group_id"),
                            "cve_id": row.get("cve_id"),
                            "package": row.get("package"),
                            "action": "diff_materialized",
                            "source_path": str(source),
                            "artifact_path": normalized,
                        }
                    )
                else:
                    commit_out["diff_path_missing"] = old_path
                    logs.append(
                        {
                            "group_id": row.get("group_id"),
                            "cve_id": row.get("cve_id"),
                            "package": row.get("package"),
                            "action": "diff_missing",
                            "source_path": old_path,
                            "artifact_path": "",
                        }
                    )
            fix_commits.append(commit_out)
        updated["fix_commits"] = fix_commits
        updated["diff_paths"] = sorted(set(diff_paths))
        out.append(updated)
    return out, logs


def _safe_group_path(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)


def _display_path(path: Path, repo_root: Path) -> str:
    try:
        return str(path.resolve().relative_to(repo_root.resolve()))
    except ValueError:
        return str(path)


def _load_env_file() -> None:
    env_path = Path.cwd() / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _github_session() -> requests.Session:
    _load_env_file()
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    session = requests.Session()
    session.headers.update({"User-Agent": "f_vra-evidence-materializer"})
    if token:
        session.headers["Authorization"] = f"Bearer {token}"
    return session


def _github_commit_urls(row: dict[str, Any]) -> list[dict[str, str]]:
    urls: list[str] = []
    urls.extend(str(url) for url in row.get("patch_urls") or [] if url)
    for ref in row.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            urls.append(str(ref["url"]))
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for url in urls:
        match = GITHUB_COMMIT_CAPTURE_RE.search(url)
        if not match:
            continue
        owner = match.group("owner")
        repo = match.group("repo").removesuffix(".git")
        sha = match.group("sha")
        key = (owner.lower(), repo.lower(), sha.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "owner": owner,
                "repo": repo,
                "sha": sha,
                "url": f"https://github.com/{owner}/{repo}/commit/{sha}",
                "repo_url": f"https://github.com/{owner}/{repo}",
            }
        )
    return out


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def _nvd_payload_cve(payload: dict[str, Any]) -> dict[str, Any]:
    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return {}
    first = vulnerabilities[0] or {}
    return first.get("cve") or {}


def _nvd_cache_path(cache_dir: Path, cve_id: str) -> Path:
    return cache_dir / f"{cve_id.upper()}.json"


def _load_nvd_cached(cve_id: str, cache_dirs: list[Path]) -> tuple[dict[str, Any], str]:
    for cache_dir in cache_dirs:
        payload = _read_json(_nvd_cache_path(cache_dir, cve_id))
        if payload:
            return payload, "nvd_cache_hit"
    return {}, ""


def _fetch_nvd(cve_id: str, cache_dir: Path) -> tuple[dict[str, Any], str]:
    _load_env_file()
    cached = _read_json(_nvd_cache_path(cache_dir, cve_id))
    if cached:
        return cached, "nvd_cache_hit"
    headers = {"User-Agent": "f_vra-nvd-evidence-fetcher"}
    if key := os.getenv("NVD_API_KEY"):
        headers["apiKey"] = key
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers=headers,
            timeout=45,
        )
    except requests.RequestException as exc:
        return {"error": str(exc), "cve_id": cve_id}, "nvd_error"
    try:
        payload = response.json() if response.text else {}
    except json.JSONDecodeError:
        payload = {"text": response.text[:1000]}
    payload["_http_status"] = response.status_code
    if response.ok:
        _write_json(_nvd_cache_path(cache_dir, cve_id), payload)
        return payload, "nvd_fetched"
    return payload, f"nvd_http_{response.status_code}"


def _nvd_description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en" and item.get("value"):
            return str(item["value"])
    return ""


def _nvd_references(cve: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for item in cve.get("references") or []:
        url = str(item.get("url") or "").strip()
        if not url:
            continue
        tags = item.get("tags") or []
        ref_type = ""
        for tag in tags:
            tag_l = str(tag).lower()
            if tag_l in {"patch", "release notes", "vendor advisory", "third party advisory", "exploit"}:
                ref_type = str(tag)
                break
        refs.append({"url": url, "type": ref_type, "source": "NVD", "tags": tags})
    return refs


def _nvd_fixed_versions(cve: dict[str, Any]) -> list[str]:
    versions: set[str] = set()

    def visit_node(node: dict[str, Any]) -> None:
        for match in node.get("cpeMatch") or []:
            for key in ("versionEndExcluding", "versionEndIncluding"):
                value = match.get(key)
                if value and value not in {"*", "-"}:
                    versions.add(str(value))
        for child in node.get("nodes") or []:
            if isinstance(child, dict):
                visit_node(child)

    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            if isinstance(node, dict):
                visit_node(node)
    return sorted(versions)


def enrich_with_nvd_metadata(
    evidence_rows: list[dict[str, Any]],
    *,
    read_cache_dirs: list[Path],
    write_cache_dir: Path,
    delay_seconds: float = 0.65,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Merge NVD descriptions, references, tags, and versionEndExcluding metadata."""
    payload_by_cve: dict[str, tuple[dict[str, Any], str]] = {}
    out: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    for row in evidence_rows:
        cve_id = str(row.get("cve_id") or "").upper()
        if cve_id not in payload_by_cve:
            payload, status = _load_nvd_cached(cve_id, read_cache_dirs + [write_cache_dir])
            if not payload:
                payload, status = _fetch_nvd(cve_id, write_cache_dir)
                if status == "nvd_fetched":
                    time.sleep(delay_seconds)
            payload_by_cve[cve_id] = (payload, status or "nvd_miss")
        payload, status = payload_by_cve[cve_id]
        cve = _nvd_payload_cve(payload)
        updated = dict(row)
        refs = normalize_references((row.get("references") or []) + _nvd_references(cve))
        nvd_fixed_versions = _nvd_fixed_versions(cve)
        fixed_versions = str(updated.get("fixed_versions") or "").strip()
        if not fixed_versions and nvd_fixed_versions:
            fixed_versions = "; ".join(nvd_fixed_versions)
        patch_urls = {
            str(url)
            for url in (updated.get("patch_urls") or [])
            if url
        }.union({ref["url"] for ref in refs if ref["category"] in {"patch", "commit", "pull_request", "release"}})
        updated["description"] = updated.get("description") or _nvd_description(cve)
        updated["references"] = refs
        updated["reference_category_counts"] = dict(sorted(Counter(ref["category"] for ref in refs).items()))
        updated["fixed_versions"] = fixed_versions
        updated["nvd_fixed_version_candidates"] = nvd_fixed_versions
        updated["patch_urls"] = sorted(patch_urls)
        updated["raw_sources"] = sorted(set(updated.get("raw_sources") or []) | ({"NVD"} if cve else set()))
        provenance = list(updated.get("evidence_provenance") or [])
        if "fetched_nvd" not in provenance:
            provenance.append("fetched_nvd")
        updated["evidence_provenance"] = provenance
        updated["has_poc_reference"] = bool(updated.get("has_poc_reference")) or any(
            ref["category"] in {"poc", "exploit"} for ref in refs
        )
        updated["has_pr_reference"] = bool(updated.get("has_pr_reference")) or any(
            ref["category"] == "pull_request" for ref in refs
        )
        updated["has_test_reference"] = bool(updated.get("has_test_reference")) or any(
            ref["category"] == "test" for ref in refs
        )
        logs.append(
            {
                "group_id": row.get("group_id"),
                "cve_id": cve_id,
                "package": row.get("package"),
                "action": "nvd_enriched",
                "status": status,
                "reference_count": len(refs),
                "nvd_fixed_version_candidates": ";".join(nvd_fixed_versions),
            }
        )
        out.append(updated)
    return out, logs


def _fetch_github_commit_metadata(
    session: requests.Session,
    *,
    owner: str,
    repo: str,
    sha: str,
    cache_dir: Path,
) -> tuple[dict[str, Any], str]:
    cache_path = cache_dir / owner.lower() / repo.lower() / f"{sha}.json"
    cached = _read_json(cache_path)
    if cached:
        return cached, "metadata_cache_hit"
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
    try:
        response = session.get(url, headers={"Accept": "application/vnd.github+json"}, timeout=45)
    except requests.RequestException as exc:
        return {"error": str(exc), "url": url}, "metadata_error"
    payload: dict[str, Any]
    try:
        payload = response.json() if response.text else {}
    except json.JSONDecodeError:
        payload = {"text": response.text[:1000]}
    payload["_http_status"] = response.status_code
    payload["_url"] = url
    if response.ok:
        _write_json(cache_path, payload)
        return payload, "metadata_fetched"
    return payload, f"metadata_http_{response.status_code}"


def _fetch_commit_diff(
    session: requests.Session,
    *,
    owner: str,
    repo: str,
    sha: str,
    dest: Path,
) -> tuple[bool, str]:
    if dest.exists() and dest.stat().st_size > 0:
        return True, "diff_cache_hit"
    url = f"https://github.com/{owner}/{repo}/commit/{sha}.diff"
    try:
        response = session.get(url, headers={"Accept": "text/plain"}, timeout=45)
    except requests.RequestException:
        return False, "diff_error"
    if response.ok and "diff --git" in response.text[:5000]:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(response.text, encoding="utf-8", newline="\n")
        return True, "diff_fetched"
    return False, f"diff_http_{response.status_code}"


def materialize_github_commit_diffs(
    evidence_rows: list[dict[str, Any]],
    *,
    artifact_patch_root: Path,
    repo_root: Path,
    metadata_cache_dir: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fetch local diffs for GitHub commit references that were only URL-level signals."""
    session = _github_session()
    logs: list[dict[str, Any]] = []
    out: list[dict[str, Any]] = []
    for row in evidence_rows:
        updated = dict(row)
        group = str(row.get("group_id") or group_id(row.get("cve_id"), row.get("package_normalized") or row.get("package")))
        commits = _github_commit_urls(row)
        if not commits:
            out.append(updated)
            continue

        fix_commits = [dict(item) for item in row.get("fix_commits") or [] if isinstance(item, dict)]
        diff_paths = {str(path) for path in row.get("diff_paths") or [] if path}
        patch_urls = {str(url) for url in row.get("patch_urls") or [] if url}
        repo_urls = {str(url) for url in row.get("repo_urls") or [] if url}
        if row.get("repo_url"):
            repo_urls.add(str(row["repo_url"]))
        fixed_refs = {str(ref) for ref in row.get("fixed_refs") or [] if ref}
        vulnerable_refs = {str(ref) for ref in row.get("vulnerable_refs") or [] if ref}
        if row.get("fixed_ref"):
            fixed_refs.add(str(row["fixed_ref"]))
        if row.get("vulnerable_ref"):
            vulnerable_refs.add(str(row["vulnerable_ref"]))

        existing_commit_keys = {
            (str(item.get("url") or ""), str(item.get("sha") or ""))
            for item in fix_commits
            if isinstance(item, dict)
        }

        for commit in commits:
            owner, repo, sha = commit["owner"], commit["repo"], commit["sha"]
            patch_urls.add(commit["url"])
            repo_urls.add(commit["repo_url"])
            fixed_refs.add(sha)
            dest = artifact_patch_root / _safe_group_path(group) / f"{sha[:12]}.diff"
            diff_ok, diff_status = _fetch_commit_diff(session, owner=owner, repo=repo, sha=sha, dest=dest)
            metadata, metadata_status = _fetch_github_commit_metadata(
                session,
                owner=owner,
                repo=repo,
                sha=sha,
                cache_dir=metadata_cache_dir,
            )
            parents = metadata.get("parents") if isinstance(metadata, dict) else []
            parent_sha = ""
            if isinstance(parents, list) and parents:
                parent_sha = str((parents[0] or {}).get("sha") or "")
                if parent_sha:
                    vulnerable_refs.add(parent_sha)
            diff_path = ""
            if diff_ok:
                diff_path = _display_path(dest, repo_root)
                diff_paths.add(diff_path)
            item = {
                "url": commit["url"],
                "sha": sha,
                "repo_url": commit["repo_url"],
                "owner": owner,
                "repo": repo,
                "diff_path": diff_path,
                "parent_sha": parent_sha,
                "source": "github_commit_reference",
            }
            if (item["url"], item["sha"]) not in existing_commit_keys:
                fix_commits.append(item)
                existing_commit_keys.add((item["url"], item["sha"]))
            logs.append(
                {
                    "group_id": group,
                    "cve_id": row.get("cve_id"),
                    "package": row.get("package"),
                    "action": "github_commit_materialized",
                    "commit_url": commit["url"],
                    "diff_status": diff_status,
                    "metadata_status": metadata_status,
                    "diff_path": diff_path,
                    "parent_sha": parent_sha,
                }
            )

        updated["fix_commits"] = fix_commits
        updated["patch_urls"] = sorted(patch_urls)
        updated["diff_paths"] = sorted(diff_paths)
        updated["repo_urls"] = sorted(repo_urls)
        updated["fixed_refs"] = sorted(fixed_refs)
        updated["vulnerable_refs"] = sorted(vulnerable_refs)
        if not updated.get("repo_url") and repo_urls:
            updated["repo_url"] = sorted(repo_urls)[0]
        if not updated.get("fixed_ref") and fixed_refs:
            updated["fixed_ref"] = sorted(fixed_refs)[0]
        if not updated.get("vulnerable_ref") and vulnerable_refs:
            updated["vulnerable_ref"] = sorted(vulnerable_refs)[0]
        if "materialized_github_commit_diff" not in (updated.get("evidence_provenance") or []):
            updated["evidence_provenance"] = (updated.get("evidence_provenance") or []) + [
                "materialized_github_commit_diff"
            ]
        out.append(updated)
    return out, logs


def build_evidence_index(
    accepted_rows: list[dict[str, Any]],
    valid_rows: list[dict[str, str]],
    cache: dict[tuple[str, str], dict[str, Any]],
    advisory_groups: dict[tuple[str, str], dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], list[dict[str, str]]]]:
    target_pairs, valid_by_pair = build_target_pairs(accepted_rows, valid_rows)
    evidence_rows = [enrich_pair(pair, cache, advisory_groups) for pair in target_pairs]
    return evidence_rows, valid_by_pair


def build_alert_evidence_index(
    valid_rows: list[dict[str, str]],
    cache: dict[tuple[str, str], dict[str, Any]],
    advisory_groups: dict[tuple[str, str], dict[str, Any]],
    accepted_rows: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], dict[tuple[str, str], list[dict[str, str]]]]:
    target_pairs, valid_by_pair = build_alert_pairs(valid_rows, accepted_rows)
    evidence_rows = [enrich_pair(pair, cache, advisory_groups) for pair in target_pairs]
    return evidence_rows, valid_by_pair


def collapse_valid_alerts(rows: Iterable[dict[str, str]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        key = (
            str(row.get("project") or ""),
            str(row.get("cve_id") or ""),
            normalize_package_name(row.get("package_normalized") or row.get("package")),
        )
        grouped[key].append(row)

    out: list[dict[str, Any]] = []
    for (project, cve_id, package_normalized), items in sorted(grouped.items()):
        first = items[0]
        out.append(
            {
                "project": project,
                "cve_id": cve_id,
                "package": first.get("package") or package_normalized,
                "package_normalized": package_normalized,
                "resolved_versions": sorted({str(item.get("resolved_version") or "") for item in items if item.get("resolved_version")}),
                "version_statuses": sorted({str(item.get("version_status") or "") for item in items if item.get("version_status")}),
                "scanners": sorted({str(item.get("scanner") or "") for item in items if item.get("scanner")}),
                "severities": sorted({str(item.get("severity") or "") for item in items if item.get("severity")}),
                "titles": sorted({str(item.get("title") or "") for item in items if item.get("title")}),
                "fixed_versions": sorted({str(item.get("fixed_versions") or "") for item in items if item.get("fixed_versions")}),
                "scanner_row_count": len(items),
            }
        )
    return out


def build_annotation_queue(evidence_rows: list[dict[str, Any]], valid_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    evidence_by_pair = {pair_key(row.get("cve_id"), row.get("package_normalized") or row.get("package")): row for row in evidence_rows}
    valid_pairs = set(evidence_by_pair)
    collapsed = [
        row
        for row in collapse_valid_alerts(valid_rows)
        if pair_key(row.get("cve_id"), row.get("package_normalized") or row.get("package")) in valid_pairs
    ]

    queue: list[dict[str, Any]] = []
    for idx, alert in enumerate(collapsed, start=1):
        ev = evidence_by_pair[pair_key(alert.get("cve_id"), alert.get("package_normalized") or alert.get("package"))]
        resolved_versions = alert.get("resolved_versions") or []
        queue.append(
            {
                "queue_id": f"LLMQ-{idx:05d}",
                "group_id": ev.get("group_id") or group_id(alert["cve_id"], alert["package_normalized"]),
                "project": alert["project"],
                "cve_id": alert["cve_id"],
                "advisory_id": alert["cve_id"],
                "package": alert["package"],
                "package_normalized": alert["package_normalized"],
                "resolved_version": resolved_versions[0] if resolved_versions else "",
                "resolved_versions": resolved_versions,
                "version_statuses": alert["version_statuses"],
                "scanners": alert["scanners"],
                "scanner_row_count": alert["scanner_row_count"],
                "severities": alert["severities"],
                "titles": alert["titles"],
                "affected_versions": ev.get("affected_versions") or "",
                "fixed_versions": ev.get("fixed_versions") or ";".join(alert["fixed_versions"]),
                "aliases": ev.get("aliases") or {},
                "description": ev.get("description") or "",
                "annotation_summary": ev.get("annotation_summary") or "",
                "evidence_level": ev.get("evidence_level") or "",
                "suggested_priority": ev.get("suggested_priority") or "",
                "repo_url": ev.get("repo_url") or "",
                "vulnerable_ref": ev.get("vulnerable_ref") or "",
                "fixed_ref": ev.get("fixed_ref") or "",
                "fix_commits": ev.get("fix_commits") or [],
                "patch_urls": ev.get("patch_urls") or [],
                "diff_paths": ev.get("diff_paths") or [],
                "tree_sha": ev.get("tree_sha") or "",
                "commit_verified": ev.get("commit_verified", False),
                "diff_files_py": ev.get("diff_files_py", 0),
                "diff_total_files": ev.get("diff_total_files", 0),
                "diff_insertions": ev.get("diff_insertions", 0),
                "diff_deletions": ev.get("diff_deletions", 0),
                "diff_py_files_list": ev.get("diff_py_files_list") or [],
                "references": ev.get("references") or [],
                "reference_category_counts": ev.get("reference_category_counts") or {},
                "has_poc_reference": ev.get("has_poc_reference", False),
                "has_pr_reference": ev.get("has_pr_reference", False),
                "has_test_reference": ev.get("has_test_reference", False),
                "description_mentions_function": ev.get("description_mentions_function", False),
                "annotation_status": "pending",
                "llm_annotation_status": "pending",
                "annotation_goal": "identify vulnerable function(s)",
                "llm_prompt_context": {
                    "task": "Identify root-cause vulnerable function(s) for this CVE in the affected Python package.",
                    "use_patch_first": bool(ev.get("patch_urls") or ev.get("diff_paths") or ev.get("fix_commits")),
                    "do_not_infer_reachability": True,
                },
            }
        )
    return queue


def coverage_rows(evidence_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in evidence_rows:
        rows.append(
            {
                "cve_id": row["cve_id"],
                "package": row["package"],
                "package_normalized": row["package_normalized"],
                "valid_alert_row_count": row["valid_alert_row_count"],
                "valid_project_count": row["valid_project_count"],
                "evidence_level": row.get("evidence_level") or "",
                "suggested_priority": row.get("suggested_priority") or "",
                "has_patch": bool(row.get("patch_urls") or row.get("fix_commits")),
                "patch_url_count": len(row.get("patch_urls") or []),
                "fix_commit_count": len(row.get("fix_commits") or []),
                "diff_path_count": len(row.get("diff_paths") or []),
                "has_vulnerable_ref": bool(row.get("vulnerable_ref")),
                "has_fixed_ref": bool(row.get("fixed_ref")),
                "has_vulnerable_and_fixed_ref": bool(row.get("vulnerable_ref") and row.get("fixed_ref")),
                "has_fixed_versions": bool(row.get("fixed_versions")),
                "complete_for_requested_fields": all(
                    [
                        row.get("description"),
                        row.get("references"),
                        row.get("patch_urls") or row.get("fix_commits"),
                        row.get("fixed_versions"),
                        row.get("diff_paths"),
                        row.get("vulnerable_ref"),
                        row.get("fixed_ref"),
                        row.get("resolved_versions"),
                    ]
                ),
                "has_poc_reference": bool(row.get("has_poc_reference")),
                "has_pr_reference": bool(row.get("has_pr_reference")),
                "has_test_reference": bool(row.get("has_test_reference")),
                "reference_count": len(row.get("references") or []),
            }
        )
    return rows


def fetch_log_rows(evidence_rows: list[dict[str, Any]], cache: dict[tuple[str, str], dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in evidence_rows:
        key = pair_key(row.get("cve_id"), row.get("package_normalized") or row.get("package"))
        rows.append(
            {
                "cve_id": row.get("cve_id"),
                "package": row.get("package"),
                "package_normalized": row.get("package_normalized"),
                "action": "cache_hit" if key in cache else "cache_miss_not_fetched",
                "source": "docs/output_file/Phase 4b/evidence_index.jsonl" if key in cache else "",
                "message": "imported existing evidence" if key in cache else "no cached evidence; online fetch not required by default",
            }
        )
    return rows


def summary_counts(
    accepted_rows: list[dict[str, Any]],
    valid_rows: list[dict[str, str]],
    evidence_rows: list[dict[str, Any]],
    queue_rows: list[dict[str, Any]],
    cache: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    accepted_valid_pairs = {pair_key(row.get("cve_id"), row.get("package_normalized") or row.get("package")) for row in evidence_rows}
    cache_hits = sum(1 for key in accepted_valid_pairs if key in cache)
    level_counts = Counter(str(row.get("evidence_level") or "") for row in evidence_rows)
    package_counts = Counter(str(row.get("package_normalized") or "") for row in evidence_rows)
    return {
        "accepted_vf_records_total": len(accepted_rows),
        "accepted_version_valid_records": sum(int(row.get("accepted_record_count") or 0) for row in evidence_rows),
        "valid_alert_rows_total": len(valid_rows),
        "evidence_rows": len(evidence_rows),
        "unique_cves": len({row["cve_id"] for row in evidence_rows}),
        "unique_cve_package_pairs": len(accepted_valid_pairs),
        "cache_hits": cache_hits,
        "missing_evidence": len(accepted_valid_pairs) - cache_hits,
        "fetched_online": 0,
        "queue_rows": len(queue_rows),
        "queue_projects": len({row["project"] for row in queue_rows}),
        "patch_or_fix_commit": sum(1 for row in evidence_rows if row.get("patch_urls") or row.get("fix_commits")),
        "description_count": sum(1 for row in evidence_rows if row.get("description")),
        "references_count": sum(1 for row in evidence_rows if row.get("references")),
        "fix_commits_count": sum(1 for row in evidence_rows if row.get("fix_commits")),
        "diff_paths_count": sum(1 for row in evidence_rows if row.get("diff_paths")),
        "vulnerable_ref_count": sum(1 for row in evidence_rows if row.get("vulnerable_ref")),
        "fixed_ref_count": sum(1 for row in evidence_rows if row.get("fixed_ref")),
        "repo_url_count": sum(1 for row in evidence_rows if row.get("repo_url")),
        "complete_for_requested_fields": sum(
            1
            for row in evidence_rows
            if all(
                [
                    row.get("description"),
                    row.get("references"),
                    row.get("patch_urls") or row.get("fix_commits"),
                    row.get("fixed_versions"),
                    row.get("diff_paths"),
                    row.get("vulnerable_ref"),
                    row.get("fixed_ref"),
                    row.get("resolved_versions"),
                ]
            )
        ),
        "total_diff_path_refs": sum(len(row.get("diff_paths") or []) for row in evidence_rows),
        "total_fix_commit_refs": sum(len(row.get("fix_commits") or []) for row in evidence_rows),
        "poc_or_exploit_reference": sum(1 for row in evidence_rows if row.get("has_poc_reference")),
        "pr_reference": sum(1 for row in evidence_rows if row.get("has_pr_reference")),
        "test_reference": sum(1 for row in evidence_rows if row.get("has_test_reference")),
        "evidence_level_counts": dict(sorted(level_counts.items())),
        "top_packages": package_counts.most_common(15),
    }


def summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# CVE/VF Evidence Enrichment Summary",
        "",
        "## Headline Counts",
        "",
        f"- Accepted VF records input: {summary['accepted_vf_records_total']}",
        f"- Version-valid accepted VF records: {summary['accepted_version_valid_records']}",
        f"- Version-valid scanner rows input: {summary['valid_alert_rows_total']}",
        f"- Evidence rows (CVE + package): {summary['evidence_rows']}",
        f"- Unique CVEs with accepted VF evidence: {summary['unique_cves']}",
        f"- Unique CVE-package pairs: {summary['unique_cve_package_pairs']}",
        f"- Annotation queue rows (project + CVE + package): {summary['queue_rows']}",
        f"- Projects in annotation queue: {summary['queue_projects']}",
        "",
        "## Evidence Coverage",
        "",
        f"- Imported from existing cache: {summary['cache_hits']}",
        f"- Fetched online: {summary['fetched_online']}",
        f"- Missing evidence: {summary['missing_evidence']}",
        f"- Patch URL or fix commit signal available: {summary['patch_or_fix_commit']}",
        f"- PoC/exploit reference available: {summary['poc_or_exploit_reference']}",
        f"- PR reference available: {summary['pr_reference']}",
        f"- Test reference available: {summary['test_reference']}",
        "",
        "## Evidence Levels",
        "",
        "| evidence_level | pairs |",
        "|---|---:|",
    ]
    for level, count in summary["evidence_level_counts"].items():
        lines.append(f"| {level or '(missing)'} | {count} |")
    lines.extend(["", "## Top Packages", "", "| package | pairs |", "|---|---:|"])
    for package, count in summary["top_packages"]:
        lines.append(f"| {package} | {count} |")
    lines.extend(
        [
            "",
            "## Policy",
            "",
            "- Evidence enrichment is cache-first and does not rescan SCA tools.",
            "- Scanner findings remain CVE candidates; environment-resolved versions remain the source of truth.",
            "- Annotation queue rows are project-level tasks; evidence rows are deduplicated by `CVE + package`.",
            "- Online fetching is reserved for cache misses or missing evidence fields and is logged separately.",
        ]
    )
    return "\n".join(lines) + "\n"


def alert_summary_counts(
    valid_rows: list[dict[str, str]],
    evidence_rows: list[dict[str, Any]],
    queue_rows: list[dict[str, Any]],
    cache: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    pairs = {pair_key(row.get("cve_id"), row.get("package_normalized") or row.get("package")) for row in evidence_rows}
    cache_hits = sum(1 for key in pairs if key in cache)
    level_counts = Counter(str(row.get("evidence_level") or "") for row in evidence_rows)
    provenance_counts = Counter(
        provenance
        for row in evidence_rows
        for provenance in (row.get("evidence_provenance") or [])
    )
    package_counts = Counter(str(row.get("package_normalized") or "") for row in evidence_rows)
    return {
        "valid_alert_rows_total": len(valid_rows),
        "evidence_rows": len(evidence_rows),
        "unique_cves": len({row["cve_id"] for row in evidence_rows}),
        "unique_cve_package_pairs": len(pairs),
        "cache_hits": cache_hits,
        "missing_evidence": sum(1 for row in evidence_rows if not row.get("description") and not row.get("references")),
        "queue_rows": len(queue_rows),
        "queue_projects": len({row["project"] for row in queue_rows}),
        "patch_or_fix_commit": sum(1 for row in evidence_rows if row.get("patch_urls") or row.get("fix_commits")),
        "description_count": sum(1 for row in evidence_rows if row.get("description")),
        "references_count": sum(1 for row in evidence_rows if row.get("references")),
        "fix_commits_count": sum(1 for row in evidence_rows if row.get("fix_commits")),
        "diff_paths_count": sum(1 for row in evidence_rows if row.get("diff_paths")),
        "vulnerable_ref_count": sum(1 for row in evidence_rows if row.get("vulnerable_ref")),
        "fixed_ref_count": sum(1 for row in evidence_rows if row.get("fixed_ref")),
        "repo_url_count": sum(1 for row in evidence_rows if row.get("repo_url")),
        "complete_for_requested_fields": sum(
            1
            for row in evidence_rows
            if all(
                [
                    row.get("description"),
                    row.get("references"),
                    row.get("patch_urls") or row.get("fix_commits"),
                    row.get("fixed_versions"),
                    row.get("diff_paths"),
                    row.get("vulnerable_ref"),
                    row.get("fixed_ref"),
                    row.get("resolved_versions"),
                ]
            )
        ),
        "total_diff_path_refs": sum(len(row.get("diff_paths") or []) for row in evidence_rows),
        "total_fix_commit_refs": sum(len(row.get("fix_commits") or []) for row in evidence_rows),
        "poc_or_exploit_reference": sum(1 for row in evidence_rows if row.get("has_poc_reference")),
        "pr_reference": sum(1 for row in evidence_rows if row.get("has_pr_reference")),
        "test_reference": sum(1 for row in evidence_rows if row.get("has_test_reference")),
        "evidence_level_counts": dict(sorted(level_counts.items())),
        "provenance_counts": dict(sorted(provenance_counts.items())),
        "top_packages": package_counts.most_common(15),
    }


def alert_summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# All-Alert CVE Evidence Enrichment Summary",
        "",
        "## Headline Counts",
        "",
        f"- Version-valid scanner rows input: {summary['valid_alert_rows_total']}",
        f"- Evidence rows (CVE + package): {summary['evidence_rows']}",
        f"- Unique CVEs: {summary['unique_cves']}",
        f"- Unique CVE-package pairs: {summary['unique_cve_package_pairs']}",
        f"- Project alert evidence queue rows: {summary['queue_rows']}",
        f"- Projects in queue: {summary['queue_projects']}",
        "",
        "## Evidence Coverage",
        "",
        f"- Imported from Phase 4b cache: {summary['cache_hits']}",
        f"- Missing description and references: {summary['missing_evidence']}",
        f"- Description available: {summary['description_count']}",
        f"- References available: {summary['references_count']}",
        f"- Fix commits available: {summary['fix_commits_count']}",
        f"- Local diff paths available: {summary['diff_paths_count']}",
        f"- Vulnerable refs available: {summary['vulnerable_ref_count']}",
        f"- Fixed refs available: {summary['fixed_ref_count']}",
        f"- Repository URLs available: {summary['repo_url_count']}",
        f"- Complete for requested fields: {summary['complete_for_requested_fields']}",
        f"- Total local diff path references: {summary['total_diff_path_refs']}",
        f"- Total fix commit references: {summary['total_fix_commit_refs']}",
        f"- Patch URL or fix commit signal available: {summary['patch_or_fix_commit']}",
        f"- PoC/exploit reference available: {summary['poc_or_exploit_reference']}",
        f"- PR reference available: {summary['pr_reference']}",
        f"- Test reference available: {summary['test_reference']}",
    ]
    if summary["provenance_counts"]:
        lines.extend(["", "## Evidence Provenance", "", "| provenance | pairs |", "|---|---:|"])
        for provenance, count in summary["provenance_counts"].items():
            lines.append(f"| {provenance or '(missing)'} | {count} |")
    lines.extend(["", "## Evidence Levels", "", "| evidence_level | pairs |", "|---|---:|"])
    for level, count in summary["evidence_level_counts"].items():
        lines.append(f"| {level or '(missing)'} | {count} |")
    lines.extend(["", "## Top Packages", "", "| package | pairs |", "|---|---:|"])
    for package, count in summary["top_packages"]:
        lines.append(f"| {package} | {count} |")
    lines.extend(
        [
            "",
            "## Policy",
            "",
            "- Scope is all version-valid SCA alerts, not only accepted VF records.",
            "- Existing Phase 4b evidence is used first; advisory groups fill descriptions/references; optional metadata fetch fills remaining cache misses.",
            "- Scanner versions are not used as ground truth.",
        ]
    )
    return "\n".join(lines) + "\n"
