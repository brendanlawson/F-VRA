from __future__ import annotations

import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from f_vra.core.config import settings


def _repo_name(url: str) -> str:
    name = url.rstrip("/").split("/")[-1]
    return re.sub(r"\.git$", "", name)


def github_repo_url_from_reference(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None

    owner, repo = parts[0], re.sub(r"\.git$", "", parts[1])
    if not owner or not repo:
        return None
    return f"https://github.com/{owner}/{repo}.git"


def github_repo_urls_from_references(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    repos: list[str] = []
    for url in urls:
        repo_url = github_repo_url_from_reference(url)
        if repo_url and repo_url not in seen:
            seen.add(repo_url)
            repos.append(repo_url)
    return repos


def github_commit_from_reference(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    try:
        commit_index = parts.index("commit")
    except ValueError:
        return None
    if commit_index + 1 >= len(parts):
        return None

    commit = re.sub(r"\.(patch|diff)$", "", parts[commit_index + 1], flags=re.I)
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", commit):
        return None
    return commit


def github_commit_from_references(urls: list[str]) -> str | None:
    for url in urls:
        commit = github_commit_from_reference(url)
        if commit:
            return commit
    return None


def clone_or_update(repo_url: str, commit: str | None = None) -> Path:
    name = _repo_name(repo_url)
    dest = settings.repo_cache_dir / name
    settings.repo_cache_dir.mkdir(parents=True, exist_ok=True)

    if not dest.exists():
        subprocess.run(
            ["git", "clone", "--progress", repo_url, str(dest)],
            check=True,
        )

    if commit:
        subprocess.run(["git", "-C", str(dest), "fetch", "--all", "--progress"], check=False)
        subprocess.run(
            ["git", "-C", str(dest), "checkout", commit],
            check=True,
        )

    return dest
