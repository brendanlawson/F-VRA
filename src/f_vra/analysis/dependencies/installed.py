from __future__ import annotations

from importlib import metadata


def normalize_name(name: str) -> str:
    return name.replace("_", "-").lower()


def installed_distributions() -> dict[str, metadata.Distribution]:
    return {
        normalize_name(dist.metadata.get("Name", dist.name or "")): dist
        for dist in metadata.distributions()
        if dist.metadata.get("Name", dist.name or "")
    }


def distribution_source_path(dist: metadata.Distribution | None) -> str:
    if dist is None:
        return ""
    try:
        top_level = dist.read_text("top_level.txt") or ""
    except Exception:
        top_level = ""

    files = list(dist.files or [])
    for top in [line.strip() for line in top_level.splitlines() if line.strip()]:
        package_init = f"{top}/__init__.py"
        module_file = f"{top}.py"
        for file in files:
            posix = file.as_posix()
            if posix == package_init:
                return str(dist.locate_file(file).parent)
            if posix == module_file:
                return str(dist.locate_file(file))

    for file in files:
        posix = file.as_posix()
        if ".dist-info/" in posix or ".egg-info/" in posix:
            continue
        if posix.endswith("__init__.py"):
            return str(dist.locate_file(file).parent)
        if posix.endswith(".py"):
            return str(dist.locate_file(file))
    return ""
