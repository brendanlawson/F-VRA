from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = REPO_ROOT / "data" / "projects.json"
DEFAULT_PROJECT_ROOT = REPO_ROOT / "data" / "raw" / "projects"

REPOS = [
    "alexferl/flask-simpleldap",
    "alerta/alerta",
    "Amm1rr/WebAI-to-API",
    "benavlabs/FastAPI-boilerplate",
    "Cinnamon/kotaemon",
    "djangostarter/web",
    "eightBEC/fastapi-ml-skeleton",
    "eosphoros-ai/DB-GPT",
    "evansd/whitenoise",
    "fastapi/asyncer",
    "iktakahiro/dddpy",
    "laurentS/slowapi",
    "marshmallow-code/flask-marshmallow",
    "marshmallow-code/flask-smorest",
    "Open-LLM-VTuber/Open-LLM-VTuber",
    "rtzll/flask-todolist",
    "sloria/environs",
    "spiral-project/ihatemoney",
    "sunscrapers/djoser",
    "teamhide/fastapi-boilerplate",
    "tinyfish-io/agentql",
    "tomasvotava/fastapi-sso",
    "tropicoo/yt-dlp-bot",
    "yezz123/authx",
    "reflex-dev/reflex",
    "benoitc/gunicorn",
    "Chainlit/chainlit",
    "Thysrael/Horizon",
    "AIDC-AI/Pixelle-MCP",
    "FuzzyGrim/Yamtrack",
    "LedFx/LedFx",
    "OWASP/Nettacker",
    "milesmcc/shynet",
    "sparckles/Robyn",
]

SCAN_TOOLS = ("pip-audit", "osv-scanner", "semgrep-supply-chain", "snyk")


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _repo_id(full_name: str) -> str:
    return full_name.replace("/", "__")


def _dedupe_repos(repos: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for repo in repos:
        repo = repo.strip()
        if not repo:
            continue
        key = repo.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(repo)
    return unique


def _github_json(path: str, token: str) -> dict:
    request = Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "f_vra-project-snapshot",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"GitHub API {path} returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"GitHub API {path} failed: {exc}") from exc


def _project_record(repo: str, token: str, project_root: Path, snapshot_at: str) -> dict:
    repository = _github_json(f"/repos/{repo}", token)
    default_branch = repository["default_branch"]
    default_branch_commit = _github_json(f"/repos/{repo}/commits/{default_branch}", token)
    full_name = repository["full_name"]
    project_id = _repo_id(full_name)
    return {
        "github": {
            "repository": repository,
            "default_branch_commit": default_branch_commit,
        }
    }


def _write_json_atomic(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=path.parent, suffix=".tmp") as tmp:
        json.dump(payload, tmp, indent=2, ensure_ascii=False)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def _run_git(args: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def _clone_or_update(project: dict) -> str:
    repository = project["github"]["repository"]
    commit = project["github"]["default_branch_commit"]
    project_id = _repo_id(repository["full_name"])
    dest = DEFAULT_PROJECT_ROOT / project_id
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        _run_git(["clone", "--no-checkout", repository["clone_url"], str(dest)])
        action = "cloned"
    else:
        action = "updated"
    _run_git(["fetch", "--all", "--prune"], cwd=dest)
    _run_git(["checkout", "--detach", commit["sha"]], cwd=dest)
    actual = _run_git(["rev-parse", "HEAD"], cwd=dest).stdout.strip()
    if actual != commit["sha"]:
        raise RuntimeError(f"{project_id} checkout mismatch: {actual} != {commit['sha']}")
    return action


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch GitHub project snapshots and optionally clone them.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--project-root", type=Path, default=DEFAULT_PROJECT_ROOT)
    parser.add_argument("--clone", action="store_true", help="Clone/fetch each project and checkout snapshot_sha.")
    parser.add_argument("--limit", type=int, default=0, help="Limit the number of projects to fetch.")
    args = parser.parse_args()

    _load_dotenv(REPO_ROOT / ".env")
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        raise RuntimeError("GITHUB_TOKEN is required in the environment or .env")

    repos = _dedupe_repos(REPOS)
    if args.limit:
        repos = repos[: args.limit]
    snapshot_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    projects: list[dict] = []
    failures: list[dict[str, str]] = []
    for index, repo in enumerate(repos, 1):
        print(f"[{index}/{len(repos)}] snapshot {repo}", flush=True)
        try:
            project = _project_record(repo, token, args.project_root, snapshot_at)
            projects.append(project)
        except Exception as exc:
            failures.append({"repo": repo, "error": str(exc)})
        time.sleep(0.2)

    payload = {
        "schema_version": 1,
        "snapshot_at": snapshot_at,
        "project_count": len(projects),
        "failed_count": len(failures),
        "source": "github_api",
        "projects": projects,
        "failures": failures,
    }
    _write_json_atomic(args.output, payload)
    print(f"wrote {args.output} ({len(projects)} projects, {len(failures)} failures)", flush=True)

    if failures:
        for failure in failures:
            print(f"FAILED {failure['repo']}: {failure['error']}", file=sys.stderr)
        return 1

    if args.clone:
        for index, project in enumerate(projects, 1):
            full_name = project["github"]["repository"]["full_name"]
            print(f"[{index}/{len(projects)}] clone {_repo_id(full_name)}", flush=True)
            _clone_or_update(project)
        print(f"cloned {len(projects)} projects", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
