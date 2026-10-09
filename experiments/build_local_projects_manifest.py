from __future__ import annotations

import argparse
import csv
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ENV_MANIFEST = REPO_ROOT / "data" / "interim" / "resolved_versions" / "project_environment_manifest.csv"
DEFAULT_BENCHMARK = REPO_ROOT / "data" / "final" / "cve_vf_benchmark_accepted.jsonl"
DEFAULT_OUTPUT = REPO_ROOT / "configs" / "local_projects.json"


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]


def _git_commit(path: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
            timeout=15,
        )
    except Exception:
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _repo_url(repo_full_name: str) -> str:
    return f"https://github.com/{repo_full_name}.git" if repo_full_name else ""


def _accepted_projects(benchmark_path: Path) -> set[str]:
    out: set[str] = set()
    for record in _load_jsonl(benchmark_path):
        if record.get("benchmark_status") != "accepted":
            continue
        out.update(str(project) for project in record.get("projects") or [] if project)
    return out


def build_manifest(args: argparse.Namespace) -> dict[str, Any]:
    wanted = _accepted_projects(args.benchmark)
    rows = list(csv.DictReader(args.environment_manifest.open(encoding="utf-8-sig")))
    projects: list[dict[str, Any]] = []
    missing: list[str] = []

    for row in rows:
        project_id = row.get("project", "")
        if wanted and project_id not in wanted:
            continue
        project_path = Path(row.get("project_path", ""))
        if not project_path.exists():
            missing.append(project_id)
            continue
        projects.append(
            {
                "id": project_id,
                "name": project_id,
                "repo_full_name": row.get("repo_full_name", ""),
                "repo_url": _repo_url(row.get("repo_full_name", "")),
                "commit": _git_commit(project_path),
                "path": str(project_path),
                "enabled": True,
                "environment_status": row.get("environment_status", ""),
                "version_source": row.get("version_source", ""),
                "manifest_files": [
                    item for item in str(row.get("manifest_files", "")).split(";") if item
                ],
                "resolved_package_count": int(row.get("resolved_package_count") or 0),
            }
        )

    projects.sort(key=lambda item: item["id"].lower())
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": {
            "environment_manifest": str(args.environment_manifest),
            "benchmark": str(args.benchmark),
        },
        "project_count": len(projects),
        "missing_project_count": len(missing),
        "missing_projects": sorted(missing),
        "projects": projects,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build configs/local_projects.json from resolved project metadata.")
    parser.add_argument("--environment-manifest", type=Path, default=DEFAULT_ENV_MANIFEST)
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    payload = build_manifest(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {args.output.relative_to(REPO_ROOT)} projects={payload['project_count']} missing={payload['missing_project_count']}")
    return 0 if not payload["missing_projects"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
