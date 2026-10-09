from __future__ import annotations

import hashlib
import json
import platform
import re
import tomllib
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from packaging.markers import Marker


def normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", str(value or "").strip()).lower()


def _fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _marker_environment(python_version: str) -> dict[str, str]:
    major_minor = ".".join(str(python_version).split(".")[:2])
    return {
        "implementation_name": "cpython",
        "implementation_version": str(python_version),
        "os_name": "nt" if platform.system().lower() == "windows" else "posix",
        "platform_machine": platform.machine().lower(),
        "platform_python_implementation": "CPython",
        "platform_release": platform.release(),
        "platform_system": platform.system(),
        "platform_version": platform.version(),
        "python_full_version": str(python_version),
        "python_version": major_minor,
        "sys_platform": "win32" if platform.system().lower() == "windows" else platform.system().lower(),
        "extra": "",
    }


def marker_matches(expression: str | None, environment: dict[str, str]) -> bool:
    if not expression:
        return True
    try:
        return bool(Marker(str(expression)).evaluate(environment))
    except Exception as exc:
        raise ValueError(f"invalid lockfile marker {expression!r}: {exc}") from exc


@dataclass(frozen=True)
class LockPackage:
    name: str
    normalized_name: str
    version: str
    dependencies: tuple[str, ...] = ()
    source_type: str = ""
    source: dict[str, Any] = field(default_factory=dict)
    resolution_markers: tuple[str, ...] = ()
    selected_markers: tuple[str, ...] = ()

    @property
    def is_local(self) -> bool:
        return bool(self.source.get("editable") or self.source.get("directory") or self.source.get("path"))


@dataclass(frozen=True)
class DependencyClosure:
    project_id: str
    project_path: str
    roots: tuple[str, ...]
    target_import_roots: tuple[str, ...]
    packages: tuple[LockPackage, ...]
    omitted: tuple[dict[str, Any], ...]
    lockfile: str
    lockfile_fingerprint: str
    resolver: str
    python_version: str
    marker_environment: dict[str, str]
    install_requirements: tuple[str, ...]
    install_project_editable: bool = False

    @property
    def package_names(self) -> set[str]:
        return {package.normalized_name for package in self.packages if not package.is_local}

    def to_json(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["packages"] = [asdict(package) for package in self.packages]
        payload["package_count"] = len(self.packages)
        payload["install_package_names"] = sorted(self.package_names)
        return payload


def _select_uv_records(data: dict[str, Any], environment: dict[str, str]) -> dict[str, LockPackage]:
    candidates: dict[str, list[LockPackage]] = {}
    for raw in data.get("package", []) or []:
        if not isinstance(raw, dict) or not raw.get("name"):
            continue
        dependencies = []
        for dependency in raw.get("dependencies", []) or []:
            if not isinstance(dependency, dict) or not dependency.get("name"):
                continue
            if marker_matches(dependency.get("marker"), environment):
                dependencies.append(normalize_name(str(dependency["name"])))
        resolution_markers = tuple(str(item) for item in raw.get("resolution-markers", []) or [])
        if resolution_markers and not any(marker_matches(marker, environment) for marker in resolution_markers):
            continue
        package = LockPackage(
            name=str(raw["name"]),
            normalized_name=normalize_name(str(raw["name"])),
            version=str(raw.get("version") or ""),
            dependencies=tuple(sorted(set(dependencies))),
            source_type="uv.lock",
            source=dict(raw.get("source") or {}),
            resolution_markers=resolution_markers,
            selected_markers=tuple(marker for marker in resolution_markers if marker_matches(marker, environment)),
        )
        candidates.setdefault(package.normalized_name, []).append(package)

    selected: dict[str, LockPackage] = {}
    for name, values in candidates.items():
        versions = {value.version for value in values}
        if len(values) > 1 and len(versions) > 1:
            # uv can retain package records for mutually exclusive indexes
            # (notably PyTorch CUDA extras) in the same lockfile.  When the
            # benchmark selects a distribution directly, no optional extra
            # is activated.  In that case the lock's default PyPI record is
            # the only non-extra interpretation we can prove.  Do not pick a
            # CUDA/index-specific version merely because it sorts first.
            default_registry = [
                value
                for value in values
                if str(value.source.get("registry") or "").rstrip("/")
                in {"https://pypi.org/simple", "https://pypi.python.org/simple"}
            ]
            default_versions = {value.version for value in default_registry}
            if len(default_versions) == 1:
                values = default_registry
                versions = default_versions
            else:
                candidates_text = sorted(
                    f"{value.version} @ {value.source.get('registry') or value.source_type}"
                    for value in values
                )
                raise ValueError(
                    f"ambiguous lockfile versions for {name}; no unique default-index "
                    f"record: {candidates_text}"
                )
        merged = values[0]
        if len(values) > 1:
            merged = LockPackage(
                name=merged.name,
                normalized_name=merged.normalized_name,
                version=merged.version,
                dependencies=tuple(sorted({dep for value in values for dep in value.dependencies})),
                source_type=merged.source_type,
                source=merged.source,
                resolution_markers=tuple(sorted({marker for value in values for marker in value.resolution_markers})),
                selected_markers=tuple(sorted({marker for value in values for marker in value.selected_markers})),
            )
        selected[name] = merged
    return selected


def _select_poetry_records(data: dict[str, Any], environment: dict[str, str]) -> dict[str, LockPackage]:
    selected: dict[str, LockPackage] = {}
    for raw in data.get("package", []) or []:
        if not isinstance(raw, dict) or not raw.get("name"):
            continue
        dependencies = []
        for name, spec in (raw.get("dependencies") or {}).items():
            marker = ""
            if isinstance(spec, dict):
                marker = str(spec.get("markers") or "")
            if marker_matches(marker, environment):
                dependencies.append(normalize_name(str(name)))
        package = LockPackage(
            name=str(raw["name"]),
            normalized_name=normalize_name(str(raw["name"])),
            version=str(raw.get("version") or ""),
            dependencies=tuple(sorted(set(dependencies))),
            source_type="poetry.lock",
            source=dict(raw.get("source") or {}),
        )
        existing = selected.get(package.normalized_name)
        if existing and existing.version != package.version:
            raise ValueError(f"ambiguous lockfile versions for {package.normalized_name}: {existing.version}, {package.version}")
        selected[package.normalized_name] = package
    return selected


def _select_pipfile_records(data: dict[str, Any]) -> dict[str, LockPackage]:
    selected: dict[str, LockPackage] = {}
    for section in ("default", "develop"):
        for name, raw in (data.get(section) or {}).items():
            if not isinstance(raw, dict):
                continue
            version = str(raw.get("version") or "").lstrip("=").strip()
            normalized = normalize_name(str(name))
            dependencies = tuple(sorted(normalize_name(str(dep)) for dep in (raw.get("dependencies") or {}) if dep))
            selected[normalized] = LockPackage(
                name=str(name),
                normalized_name=normalized,
                version=version,
                dependencies=dependencies,
                source_type="Pipfile.lock",
            )
    return selected


def build_dependency_closure(
    project_id: str,
    project_path: Path,
    roots: Iterable[str],
    *,
    python_version: str,
    target_import_roots: Iterable[str] = (),
) -> DependencyClosure:
    environment = _marker_environment(python_version)
    lock_path: Path | None = None
    resolver = ""
    records: dict[str, LockPackage] = {}
    if (project_path / "uv.lock").exists():
        lock_path = project_path / "uv.lock"
        resolver = "uv.lock"
        records = _select_uv_records(tomllib.loads(lock_path.read_text(encoding="utf-8")), environment)
    elif (project_path / "poetry.lock").exists():
        lock_path = project_path / "poetry.lock"
        resolver = "poetry.lock"
        records = _select_poetry_records(tomllib.loads(lock_path.read_text(encoding="utf-8")), environment)
    elif (project_path / "Pipfile.lock").exists():
        lock_path = project_path / "Pipfile.lock"
        resolver = "Pipfile.lock"
        records = _select_pipfile_records(json.loads(lock_path.read_text(encoding="utf-8")))
    else:
        requirements = sorted(project_path.glob("requirements*.txt"))
        if requirements:
            lock_path = requirements[0]
            resolver = "requirements-manifest"
            for line in lock_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.split("#", 1)[0].strip()
                if not line or line.startswith(("-", "git+", "http:" , "https:")):
                    continue
                match = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([^;\s]+)", line)
                if match:
                    name, version = match.groups()
                    normalized = normalize_name(name)
                    records[normalized] = LockPackage(name=name, normalized_name=normalized, version=version, source_type=resolver)

    normalized_roots = tuple(sorted({normalize_name(root) for root in roots if str(root).strip()}))
    selected: dict[str, LockPackage] = {}
    omitted: list[dict[str, Any]] = []
    queue = deque(normalized_roots)
    while queue:
        name = queue.popleft()
        if name in selected:
            continue
        package = records.get(name)
        if package is None:
            omitted.append({"name": name, "reason": "not_in_lockfile"})
            continue
        selected[name] = package
        queue.extend(dependency for dependency in package.dependencies if dependency not in selected)

    requirements = tuple(
        f"{package.name}=={package.version}"
        for package in sorted(selected.values(), key=lambda item: item.normalized_name)
        if package.version and not package.is_local
    )
    install_project = any(package.is_local for package in selected.values())
    return DependencyClosure(
        project_id=project_id,
        project_path=str(project_path.resolve()),
        roots=normalized_roots,
        target_import_roots=tuple(sorted({str(root).split(".", 1)[0] for root in target_import_roots if str(root).strip()})),
        packages=tuple(sorted(selected.values(), key=lambda item: item.normalized_name)),
        omitted=tuple(omitted),
        lockfile=str(lock_path.resolve()) if lock_path else "",
        lockfile_fingerprint=_fingerprint(lock_path) if lock_path else "",
        resolver=resolver or "no-supported-lockfile",
        python_version=python_version,
        marker_environment=environment,
        install_requirements=requirements,
        install_project_editable=install_project,
    )
