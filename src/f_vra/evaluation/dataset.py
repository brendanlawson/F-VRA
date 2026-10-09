"""Freeze repository and CVE inputs without trusting old result artifacts."""

from __future__ import annotations

import hashlib
import csv
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from packaging.utils import canonicalize_name

from f_vra.evaluation.contracts import ProjectSnapshot, digest
from f_vra.evaluation.io import read_json, write_json, write_parquet


def _git(project: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(project), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", check=True)
    return result.stdout.strip()


def _source_hash(project: Path) -> str:
    # Git's tree object is already a content-addressed snapshot of tracked
    # paths, modes, blobs and submodules. Re-hash its immutable ID with SHA-256
    # to keep the experiment contract independent of Git's object algorithm.
    tree_id = _git(project, "rev-parse", "HEAD^{tree}")
    return hashlib.sha256(f"git-tree:{tree_id}".encode("ascii")).hexdigest()


def freeze_projects(repo_root: Path, manifest_path: Path) -> tuple[list[ProjectSnapshot], list[dict[str, Any]]]:
    manifest = read_json(manifest_path)
    snapshots: list[ProjectSnapshot] = []
    audit: list[dict[str, Any]] = []
    for item in manifest["projects"]:
        project_id = str(item["id"])
        project = repo_root / "data" / "raw" / "projects" / project_id
        if not project.is_dir():
            audit.append({"project_id": project_id, "status": "MISSING_CHECKOUT", "path": str(project)})
            continue
        expected = str(item["commit"])
        actual = _git(project, "rev-parse", "HEAD")
        dirty = _git(project, "status", "--porcelain", "--untracked-files=no")
        if actual != expected or dirty:
            audit.append({"project_id": project_id, "status": "SNAPSHOT_MISMATCH", "expected": expected, "actual": actual, "dirty": bool(dirty)})
            continue
        snapshot = ProjectSnapshot(
            project_id=project_id,
            git_url=str(item["repo_url"]),
            commit_sha=actual,
            source_hash=_source_hash(project),
        )
        snapshots.append(snapshot)
        audit.append({"project_id": project_id, "snapshot_id": snapshot.snapshot_id, "status": "READY"})
    return snapshots, audit


def _benchmark_rows(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def freeze_dataset(
    repo_root: Path, output: Path, *, manifest: Path, benchmark: Path,
    protocol: Path | None = None, resolved_packages: Path | None = None,
) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    protocol_hash = hashlib.sha256(protocol.read_bytes()).hexdigest() if protocol else ""
    if protocol:
        shutil.copy2(protocol, output / "protocol.yaml")
    snapshots, audit = freeze_projects(repo_root, manifest)
    by_project = {item.project_id: item for item in snapshots}
    vulnerability_rows: list[dict[str, Any]] = []
    candidate_rows: list[dict[str, Any]] = []
    for record in _benchmark_rows(benchmark):
        cve_id = str(record["cve_id"])
        distribution = canonicalize_name(str(record["package"]))
        targets = [dict(item) for item in record.get("target_vfs") or []]
        vulnerability_rows.append({
            "vulnerability_id": digest((cve_id, distribution, record)),
            "cve_id": cve_id,
            "affected_distribution": distribution,
            "target_vfs": [str(item.get("qualified_name") or "") for item in targets],
            "vf_provenance": str(record.get("evidence_level") or ""),
            "metadata_snapshot_hash": digest(record),
            "metadata_json": json.dumps(record, sort_keys=True, ensure_ascii=False),
        })
        for project_id in record.get("projects") or []:
            snapshot = by_project.get(str(project_id))
            if snapshot is None:
                continue
            candidate_rows.append({
                "candidate_id": digest((snapshot.snapshot_id, cve_id)),
                "project_id": snapshot.project_id,
                "project_snapshot_id": snapshot.snapshot_id,
                "cve_id": cve_id,
                "affected_distribution": distribution,
                "target_vfs": [str(item.get("qualified_name") or "") for item in targets],
                "vf_provenance": str(record.get("evidence_level") or ""),
                "affected_versions_claimed": [str(x) for x in record.get("resolved_versions") or []],
            })
    candidate_rows.sort(key=lambda row: (row["project_id"], row["cve_id"]))
    if len({(row["project_snapshot_id"], row["cve_id"]) for row in candidate_rows}) != len(candidate_rows):
        raise ValueError("duplicate project snapshot/CVE candidate; inspect multi-distribution CVEs")
    write_parquet(output / "projects.parquet", [{**item.model_dump(), "snapshot_id": item.snapshot_id} for item in snapshots])
    write_parquet(output / "vulnerabilities.parquet", vulnerability_rows)
    write_parquet(output / "query_candidates.parquet", candidate_rows)
    expectation_rows: list[dict[str, Any]] = []
    resolved_hash = ""
    if resolved_packages is not None:
        resolved_hash = hashlib.sha256(resolved_packages.read_bytes()).hexdigest()
        with resolved_packages.open(encoding="utf-8-sig", newline="") as handle:
            resolved = {
                (str(row["project"]), canonicalize_name(str(row["package_normalized"]))): row
                for row in csv.DictReader(handle)
            }
        candidate_keys = {
            (str(row["project_id"]), canonicalize_name(str(row["affected_distribution"])))
            for row in candidate_rows
        }
        missing = sorted(candidate_keys - resolved.keys())
        if missing:
            raise ValueError(f"resolved package manifest is missing {len(missing)} candidate project/packages")
        for project_id, distribution in sorted(candidate_keys):
            source = resolved[(project_id, distribution)]
            version = str(source["resolved_version"])
            claims = {
                claimed
                for row in candidate_rows
                if row["project_id"] == project_id and row["affected_distribution"] == distribution
                for claimed in row["affected_versions_claimed"]
            }
            if version not in claims:
                raise ValueError(f"resolved version {project_id}/{distribution}=={version} is absent from candidate claims")
            expectation_rows.append({
                "expectation_id": digest((project_id, distribution, version, resolved_hash)),
                "project_id": project_id, "distribution": distribution, "version": version,
                "provenance": str(source.get("provenance") or ""),
                "source_file": str(source.get("source_file") or ""),
                "source_type": str(source.get("source_type") or ""),
            })
    # Historical scanner versions are an audit expectation only. Environment
    # materialization is derived exclusively from lockfiles in the frozen commit.
    write_parquet(output / "affected_package_expectations.parquet", expectation_rows)
    write_parquet(output / "snapshot_audit.parquet", audit)
    for name in ("environments", "packages", "queries", "environment_audit", "package_source_audit", "query_eligibility"):
        write_parquet(output / f"{name}.parquet", [])
    summary = {
        "schema_version": "f_vra.dataset.v1",
        "dataset_id": digest({
            "projects": [item.snapshot_id for item in snapshots],
            "benchmark": hashlib.sha256(benchmark.read_bytes()).hexdigest(),
            "protocol": protocol_hash,
            "resolved_packages": resolved_hash,
        }),
        "project_count": len(snapshots),
        "candidate_count": len(candidate_rows),
        "vulnerability_count": len(vulnerability_rows),
        "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "benchmark_sha256": hashlib.sha256(benchmark.read_bytes()).hexdigest(),
        "protocol_sha256": protocol_hash,
        "resolved_packages_sha256": resolved_hash,
        "affected_package_expectation_count": len(expectation_rows),
    }
    write_json(output / "dataset.json", summary)
    return summary
