from __future__ import annotations

import os
from pathlib import Path


def find_workspace_root(start: Path | str | None = None) -> Path:
    """Find the F-VRA workspace root from the current process location."""
    configured = os.getenv("F_VRA_PROJECT_ROOT")
    if configured:
        root = Path(os.path.expandvars(os.path.expanduser(configured)))
        return root.resolve() if root.is_absolute() else (Path.cwd() / root).resolve()

    current = Path(start or Path.cwd()).resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").exists() and (
            (candidate / "packages").exists() or (candidate / "apps").exists()
        ):
            return candidate
    return Path.cwd().resolve()


def resolve_workspace_path(value: str | Path, *, base: Path | str | None = None) -> Path:
    """Resolve absolute or workspace-relative paths used in env configuration."""
    expanded = os.path.expandvars(os.path.expanduser(str(value)))
    if os.sep != "\\":
        expanded = expanded.replace("\\", os.sep)
    raw = Path(expanded)
    if raw.is_absolute():
        return raw.resolve()
    root = Path(base).resolve() if base is not None else find_workspace_root()
    return (root / raw).resolve()


def resolve_workspace_executable(value: str | Path) -> str:
    """Resolve path-like executables, while preserving PATH lookups such as python."""
    raw = os.path.expandvars(os.path.expanduser(str(value)))
    if not raw:
        return raw
    if "\\" in raw or "/" in raw or Path(raw).is_absolute():
        return str(resolve_workspace_path(raw))
    return raw
