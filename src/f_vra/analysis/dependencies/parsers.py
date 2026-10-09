from __future__ import annotations

import ast
import json
import re
import tomllib
from importlib import metadata
from pathlib import Path
from typing import Any

from f_vra.analysis.dependencies.installed import distribution_source_path, normalize_name
from f_vra.core.models import DependencyRecord

LOCKFILE_NAMES = ("uv.lock", "poetry.lock", "Pipfile.lock")
MANIFEST_NAMES = ("pyproject.toml", "requirements.txt", "setup.py")
REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(.*)$")
SPEC_START_RE = re.compile(r"\s*(===|==|~=|!=|<=|>=|<|>|@)\s*")


def purl(name: str, version: str) -> str:
    norm = normalize_name(name)
    return f"pkg:pypi/{norm}@{version}" if version else f"pkg:pypi/{norm}"


def requirement_parts(requirement: str) -> tuple[str, str, str] | None:
    line = requirement.strip()
    if not line or line.startswith("#"):
        return None
    line = line.split(";", 1)[0].strip()
    if " #" in line:
        line = line.split(" #", 1)[0].strip()
    if line.startswith(("-e ", "--editable ")):
        line = line.split(maxsplit=1)[1].strip()
    if line.startswith(("-", "--")):
        return None
    match = REQ_NAME_RE.match(line)
    if not match:
        return None
    name, rest = match.group(1), match.group(2).strip()
    specifier = rest if SPEC_START_RE.match(rest) else ""
    version = ""
    if specifier.startswith("==") and "," not in specifier:
        version = specifier[2:].strip()
    elif specifier.startswith("===") and "," not in specifier:
        version = specifier[3:].strip()
    return name, version, specifier


def dependency_record(
    name: str,
    *,
    version: str = "",
    specifier: str = "",
    direct: bool = False,
    dev: bool = False,
    source_file: Path,
    source_type: str,
    dependencies: list[str] | None = None,
    dependency_edges: list[dict[str, str]] | None = None,
    marker: str = "",
    source: str = "",
    installed: dict[str, metadata.Distribution],
) -> DependencyRecord | None:
    clean_name = str(name or "").strip()
    if not clean_name or clean_name.lower() == "python":
        return None
    norm = normalize_name(clean_name)
    dist = installed.get(norm)
    return DependencyRecord(
        name=clean_name,
        normalized_name=norm,
        version=str(version or ""),
        specifier=str(specifier or ""),
        direct=direct,
        dev=dev,
        source_file=str(source_file),
        source_type=source_type,
        marker=str(marker or ""),
        source=str(source or ""),
        source_path=distribution_source_path(dist),
        dependencies=sorted({normalize_name(item) for item in dependencies or [] if item}),
        dependency_edges=list(dependency_edges or []),
        purl=purl(clean_name, str(version or "")),
    )


def dependency_names_from_poetry_table(table: dict[str, Any], *, include_dev: bool) -> set[str]:
    names: set[str] = set()
    for name in table.get("dependencies", {}) or {}:
        if str(name).lower() != "python":
            names.add(normalize_name(str(name)))
    if include_dev:
        for name in table.get("dev-dependencies", {}) or {}:
            if str(name).lower() != "python":
                names.add(normalize_name(str(name)))
        for group in (table.get("group", {}) or {}).values():
            if isinstance(group, dict):
                for name in (group.get("dependencies", {}) or {}):
                    if str(name).lower() != "python":
                        names.add(normalize_name(str(name)))
    return names


def direct_names_from_pyproject(path: Path, *, include_dev: bool) -> set[str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return set()
    names: set[str] = set()
    project = data.get("project", {}) or {}
    for requirement in project.get("dependencies", []) or []:
        parts = requirement_parts(str(requirement))
        if parts:
            names.add(normalize_name(parts[0]))
    if include_dev:
        optional = project.get("optional-dependencies", {}) or {}
        for requirements in optional.values():
            for requirement in requirements or []:
                parts = requirement_parts(str(requirement))
                if parts:
                    names.add(normalize_name(parts[0]))
    poetry = ((data.get("tool", {}) or {}).get("poetry", {}) or {})
    names.update(dependency_names_from_poetry_table(poetry, include_dev=include_dev))
    return names


def parse_pyproject(
    path: Path,
    *,
    include_dev: bool,
    installed: dict[str, metadata.Distribution],
) -> list[DependencyRecord]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    records: list[DependencyRecord] = []
    project = data.get("project", {}) or {}
    for requirement in project.get("dependencies", []) or []:
        parts = requirement_parts(str(requirement))
        if parts:
            name, version, specifier = parts
            record = dependency_record(
                name,
                version=version,
                specifier=specifier,
                direct=True,
                source_file=path,
                source_type="pyproject.toml",
                installed=installed,
            )
            if record:
                records.append(record)

    if include_dev:
        for requirements in (project.get("optional-dependencies", {}) or {}).values():
            for requirement in requirements or []:
                parts = requirement_parts(str(requirement))
                if parts:
                    name, version, specifier = parts
                    record = dependency_record(
                        name,
                        version=version,
                        specifier=specifier,
                        direct=True,
                        dev=True,
                        source_file=path,
                        source_type="pyproject.toml",
                        installed=installed,
                    )
                    if record:
                        records.append(record)

    poetry = ((data.get("tool", {}) or {}).get("poetry", {}) or {})
    for name, value in (poetry.get("dependencies", {}) or {}).items():
        if str(name).lower() == "python":
            continue
        specifier = value if isinstance(value, str) else str(value.get("version", "")) if isinstance(value, dict) else ""
        record = dependency_record(
            str(name),
            specifier=specifier,
            direct=True,
            source_file=path,
            source_type="pyproject.toml",
            installed=installed,
        )
        if record:
            records.append(record)

    if include_dev:
        groups: list[dict[str, Any]] = [poetry]
        groups.extend(group for group in (poetry.get("group", {}) or {}).values() if isinstance(group, dict))
        for group in groups:
            for name, value in (group.get("dev-dependencies", {}) or {}).items():
                specifier = value if isinstance(value, str) else str(value.get("version", "")) if isinstance(value, dict) else ""
                record = dependency_record(
                    str(name),
                    specifier=specifier,
                    direct=True,
                    dev=True,
                    source_file=path,
                    source_type="pyproject.toml",
                    installed=installed,
                )
                if record:
                    records.append(record)
            for name, value in (group.get("dependencies", {}) or {}).items():
                specifier = value if isinstance(value, str) else str(value.get("version", "")) if isinstance(value, dict) else ""
                record = dependency_record(
                    str(name),
                    specifier=specifier,
                    direct=True,
                    dev=True,
                    source_file=path,
                    source_type="pyproject.toml",
                    installed=installed,
                )
                if record:
                    records.append(record)
    return records


def parse_poetry_lock(
    path: Path,
    *,
    direct_names: set[str],
    include_dev: bool,
    installed: dict[str, metadata.Distribution],
) -> list[DependencyRecord]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    records: list[DependencyRecord] = []
    for package in data.get("package", []) or []:
        if not isinstance(package, dict):
            continue
        category = str(package.get("category") or "")
        groups = {str(item) for item in package.get("groups", []) or []}
        dev = category == "dev" or "dev" in groups
        if dev and not include_dev:
            continue
        deps = []
        raw_deps = package.get("dependencies", {}) or {}
        dependency_edges = []
        if isinstance(raw_deps, dict):
            deps = [str(name) for name in raw_deps]
            dependency_edges = [
                {
                    "name": normalize_name(str(name)),
                    "specifier": str(value.get("version") or "") if isinstance(value, dict) else str(value or ""),
                    "marker": str(value.get("markers") or "") if isinstance(value, dict) else "",
                }
                for name, value in raw_deps.items()
                if str(name).strip()
            ]
        record = dependency_record(
            str(package.get("name") or ""),
            version=str(package.get("version") or ""),
            direct=normalize_name(str(package.get("name") or "")) in direct_names,
            dev=dev,
            source_file=path,
            source_type="poetry.lock",
            dependencies=deps,
            dependency_edges=dependency_edges,
            installed=installed,
        )
        if record:
            records.append(record)
    return records


def parse_uv_lock(
    path: Path,
    *,
    direct_names: set[str],
    include_dev: bool,
    installed: dict[str, metadata.Distribution],
) -> list[DependencyRecord]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    records: list[DependencyRecord] = []
    for package in data.get("package", []) or []:
        if not isinstance(package, dict):
            continue
        raw_deps = package.get("dependencies", []) or []
        dependency_edges = [
            {
                "name": normalize_name(str(dep.get("name"))),
                "specifier": str(dep.get("version") or ""),
                "marker": str(dep.get("marker") or ""),
                "source": str((dep.get("source") or {}).get("registry") or "") if isinstance(dep.get("source"), dict) else "",
            }
            for dep in raw_deps
            if isinstance(dep, dict) and dep.get("name")
        ]
        deps = [edge["name"] for edge in dependency_edges]
        dev = bool(package.get("dev", False))
        if dev and not include_dev:
            continue
        record = dependency_record(
            str(package.get("name") or ""),
            version=str(package.get("version") or ""),
            direct=normalize_name(str(package.get("name") or "")) in direct_names,
            dev=dev,
            source_file=path,
            source_type="uv.lock",
            dependencies=deps,
            dependency_edges=dependency_edges,
            marker="; ".join(str(item) for item in package.get("resolution-markers", []) or []),
            source=str((package.get("source") or {}).get("registry") or "") if isinstance(package.get("source"), dict) else "",
            installed=installed,
        )
        if record:
            records.append(record)
    return records


def parse_pipfile_lock(
    path: Path,
    *,
    include_dev: bool,
    installed: dict[str, metadata.Distribution],
) -> list[DependencyRecord]:
    data = json.loads(path.read_text(encoding="utf-8"))
    records: list[DependencyRecord] = []
    sections = [("default", False)]
    if include_dev:
        sections.append(("develop", True))
    for section, dev in sections:
        for name, value in (data.get(section, {}) or {}).items():
            specifier = str((value or {}).get("version") or "") if isinstance(value, dict) else str(value or "")
            version = specifier[2:].strip() if specifier.startswith("==") else ""
            record = dependency_record(
                str(name),
                version=version,
                specifier=specifier,
                direct=True,
                dev=dev,
                source_file=path,
                source_type="Pipfile.lock",
                installed=installed,
            )
            if record:
                records.append(record)
    return records


def parse_requirements(
    path: Path,
    *,
    include_dev: bool,
    installed: dict[str, metadata.Distribution],
    seen: set[Path] | None = None,
) -> list[DependencyRecord]:
    _ = include_dev
    seen = seen or set()
    resolved = path.resolve()
    if resolved in seen:
        return []
    seen.add(resolved)
    records: list[DependencyRecord] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith(("-r ", "--requirement ")):
            nested = path.parent / line.split(maxsplit=1)[1]
            if nested.exists():
                records.extend(parse_requirements(nested, include_dev=include_dev, installed=installed, seen=seen))
            continue
        parts = requirement_parts(line)
        if not parts:
            continue
        name, version, specifier = parts
        record = dependency_record(
            name,
            version=version,
            specifier=specifier,
            direct=True,
            source_file=path,
            source_type="requirements.txt",
            installed=installed,
        )
        if record:
            records.append(record)
    return records


def literal_string_list(node: ast.AST) -> list[str]:
    if not isinstance(node, (ast.List, ast.Tuple)):
        return []
    out: list[str] = []
    for item in node.elts:
        if isinstance(item, ast.Constant) and isinstance(item.value, str):
            out.append(item.value)
    return out


def parse_setup_py(
    path: Path,
    *,
    include_dev: bool,
    installed: dict[str, metadata.Distribution],
) -> list[DependencyRecord]:
    _ = include_dev
    tree = ast.parse(path.read_text(encoding="utf-8"))
    records: list[DependencyRecord] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = getattr(node.func, "id", "") or getattr(node.func, "attr", "")
        if func_name != "setup":
            continue
        for keyword in node.keywords:
            if keyword.arg != "install_requires":
                continue
            for requirement in literal_string_list(keyword.value):
                parts = requirement_parts(requirement)
                if not parts:
                    continue
                name, version, specifier = parts
                record = dependency_record(
                    name,
                    version=version,
                    specifier=specifier,
                    direct=True,
                    source_file=path,
                    source_type="setup.py",
                    installed=installed,
                )
                if record:
                    records.append(record)
    return records
