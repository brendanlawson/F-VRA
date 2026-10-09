from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from f_vra.analysis.dependencies.installed import installed_distributions
from f_vra.analysis.dependencies.parsers import (
    LOCKFILE_NAMES,
    MANIFEST_NAMES,
    direct_names_from_pyproject,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_pyproject,
    parse_requirements,
    parse_setup_py,
    parse_uv_lock,
    purl,
    requirement_parts,
)
from f_vra.core.models import (
    AnalysisFingerprint,
    DependencyGraphArtifact,
    DependencyRecord,
    ProjectIdentity,
)
from f_vra.runtime.conda import RuntimeEnvironment


def project_fingerprint(project: Path, files: list[Path]) -> str:
    digest = hashlib.sha256()
    digest.update(str(project.resolve()).encode("utf-8", errors="ignore"))
    for path in sorted(files, key=lambda item: item.as_posix()):
        digest.update(path.as_posix().encode("utf-8", errors="ignore"))
        try:
            digest.update(path.read_bytes())
        except OSError:
            continue
    return digest.hexdigest()[:16]


def discover_dependency_files(project: Path) -> list[Path]:
    files: list[Path] = []
    for name in LOCKFILE_NAMES + MANIFEST_NAMES:
        path = project / name
        if path.exists():
            files.append(path)
    files.extend(sorted(project.glob("requirements*.txt")))
    return list(dict.fromkeys(files))


def dedupe_records(records: list[DependencyRecord]) -> list[DependencyRecord]:
    merged: dict[tuple[str, str, str, str], DependencyRecord] = {}
    for record in records:
        key = (
            record.normalized_name,
            record.version or record.specifier,
            record.marker,
            record.source,
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = record
            continue
        merged[key] = existing.model_copy(
            update={
                "direct": existing.direct or record.direct,
                "dev": existing.dev and record.dev,
                "source_file": existing.source_file if existing.version else record.source_file,
                "source_type": existing.source_type if existing.version else record.source_type,
                "marker": existing.marker or record.marker,
                "source": existing.source or record.source,
                "source_path": existing.source_path or record.source_path,
                "dependencies": sorted(set(existing.dependencies) | set(record.dependencies)),
                "dependency_edges": [*existing.dependency_edges, *record.dependency_edges],
            }
        )
    return sorted(merged.values(), key=lambda item: (not item.direct, item.normalized_name, item.version, item.specifier))


def _pip_report_requirements(project: Path, selected_files: list[Path]) -> list[str]:
    requirements: list[str] = []
    for path in selected_files:
        if path.name.startswith("requirements") and path.suffix == ".txt":
            requirements.extend(["-r", str(path)])
        elif path.name == "pyproject.toml":
            requirements.append(str(project))
        elif path.name == "setup.py":
            requirements.append(str(project))
    return requirements


def _caret_to_pep440(specifier: str) -> str:
    version_text = specifier[1:].strip()
    try:
        version = Version(version_text)
    except InvalidVersion:
        return specifier
    parts = list(version.release)
    while len(parts) < 3:
        parts.append(0)
    major, minor, patch = parts[:3]
    if major > 0:
        upper = f"{major + 1}.0.0"
    elif minor > 0:
        upper = f"0.{minor + 1}.0"
    else:
        upper = f"0.0.{patch + 1}"
    return f">={version_text},<{upper}"


def _poetry_specifier_to_pep440(specifier: str) -> str:
    specifier = str(specifier or "").strip()
    if not specifier or specifier == "*":
        return ""
    if specifier.startswith("^"):
        return _caret_to_pep440(specifier)
    return specifier


def _pyproject_requirement_lines(path: Path, *, include_dev: bool = False) -> list[str]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    requirements: list[str] = []
    project = data.get("project", {}) or {}
    requirements.extend(str(item) for item in project.get("dependencies", []) or [] if str(item).strip())
    if include_dev:
        for optional_requirements in (project.get("optional-dependencies", {}) or {}).values():
            requirements.extend(str(item) for item in optional_requirements or [] if str(item).strip())

    def add_poetry_items(items: dict[str, object], *, dev: bool = False) -> None:
        if dev and not include_dev:
            return
        for name, value in (items or {}).items():
            if str(name).lower() == "python":
                continue
            extras: list[str] = []
            specifier = ""
            if isinstance(value, str):
                specifier = value
            elif isinstance(value, dict):
                specifier = str(value.get("version", "") or "")
                raw_extras = value.get("extras", []) or []
                if isinstance(raw_extras, list):
                    extras = [str(item) for item in raw_extras if str(item)]
            converted = _poetry_specifier_to_pep440(specifier)
            extras_text = f"[{','.join(extras)}]" if extras else ""
            if converted.startswith("@"):
                requirements.append(f"{name}{extras_text} {converted}")
            else:
                requirements.append(f"{name}{extras_text}{converted}")

    poetry = ((data.get("tool", {}) or {}).get("poetry", {}) or {})
    add_poetry_items(poetry.get("dependencies", {}) or {})
    if include_dev:
        add_poetry_items(poetry.get("dev-dependencies", {}) or {}, dev=True)
        for group in (poetry.get("group", {}) or {}).values():
            if isinstance(group, dict):
                add_poetry_items(group.get("dependencies", {}) or {}, dev=True)
    return list(dict.fromkeys(requirements))


def _python_version_for_specifier(specifier_text: str) -> str:
    specifier_text = str(specifier_text or "").strip()
    if not specifier_text or specifier_text == "*":
        return ""
    try:
        specifier = SpecifierSet(_poetry_specifier_to_pep440(specifier_text))
    except InvalidSpecifier:
        return ""
    current = Version(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    if specifier.contains(current, prereleases=True):
        return str(current)
    for candidate_text in ("3.13.0", "3.12.0", "3.11.0", "3.10.0", "3.9.0", "3.8.0", "3.7.0"):
        candidate = Version(candidate_text)
        if specifier.contains(candidate, prereleases=True):
            return candidate_text
    return ""


def _project_python_version_hint(project: Path) -> str:
    pyproject = project / "pyproject.toml"
    if not pyproject.exists():
        return ""
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except Exception:
        return ""
    project_metadata = data.get("project", {}) or {}
    requires_python = str(project_metadata.get("requires-python") or "").strip()
    if requires_python:
        return _python_version_for_specifier(requires_python)
    poetry_dependencies = (((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
    poetry_python = poetry_dependencies.get("python") if isinstance(poetry_dependencies, dict) else None
    if isinstance(poetry_python, str):
        return _python_version_for_specifier(poetry_python)
    if isinstance(poetry_python, dict):
        return _python_version_for_specifier(str(poetry_python.get("version") or ""))
    return ""


def _pip_report_requirements_file(project: Path, selected_files: list[Path], tmp: Path) -> Path | None:
    if not any(path.name == "pyproject.toml" for path in selected_files):
        return None
    lines: list[str] = []
    for path in selected_files:
        if path.name == "pyproject.toml":
            lines.extend(_pyproject_requirement_lines(path))
    if not lines:
        return None
    requirements = tmp / "pyproject-requirements.txt"
    requirements.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return requirements


def _project_distribution_name(project: Path) -> str:
    pyproject = project / "pyproject.toml"
    if pyproject.exists():
        try:
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        name = str((data.get("project") or {}).get("name") or "").strip()
        if name:
            return name.replace("_", "-").lower()
        poetry_name = str((((data.get("tool") or {}).get("poetry") or {}).get("name")) or "").strip()
        if poetry_name:
            return poetry_name.replace("_", "-").lower()
    return ""


def _imported_top_level_modules(project: Path) -> set[str]:
    modules: set[str] = set()
    skipped_dirs = {".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__", "node_modules"}
    for path in project.rglob("*.py"):
        if any(part in skipped_dirs for part in path.relative_to(project).parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0].strip()
                    if root:
                        modules.add(root.replace("_", "-").lower())
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                root = node.module.split(".", 1)[0].strip()
                if root:
                    modules.add(root.replace("_", "-").lower())
    return modules


def _looks_like_imported_package(normalized_name: str, imports: set[str]) -> bool:
    candidates = {normalized_name, normalized_name.replace("-", "_").lower()}
    if "-" in normalized_name:
        candidates.add(normalized_name.split("-", 1)[0])
    normalized_imports = {item.replace("_", "-").lower() for item in imports}
    return bool(candidates & normalized_imports)


def _infer_direct_from_requirements_freeze(project: Path, records: list[DependencyRecord]) -> list[DependencyRecord]:
    names = {record.normalized_name for record in records}
    referenced = {
        dependency
        for record in records
        for dependency in record.dependencies
        if dependency in names
    }
    imports = _imported_top_level_modules(project)
    inferred: list[DependencyRecord] = []
    for record in records:
        direct = record.normalized_name not in referenced or _looks_like_imported_package(record.normalized_name, imports)
        inferred.append(record.model_copy(update={"direct": direct}))
    return inferred


def _requires_dist_names(requirements: list[str]) -> list[str]:
    names: list[str] = []
    for requirement in requirements:
        try:
            parsed = Requirement(str(requirement))
        except InvalidRequirement:
            parts = requirement_parts(str(requirement))
            if parts:
                names.append(parts[0])
            continue
        if parsed.marker is not None and "extra" in str(parsed.marker).lower():
            try:
                if not parsed.marker.evaluate({"extra": ""}):
                    continue
            except Exception:
                continue
        names.append(parsed.name)
    return sorted({name.replace("_", "-").lower() for name in names})


def _python_version_satisfies(requires_python: str, python_version: str = "") -> bool:
    if not requires_python:
        return True
    try:
        specifier = SpecifierSet(str(requires_python))
    except InvalidSpecifier:
        return True
    try:
        current = Version(python_version) if python_version else Version(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    except InvalidVersion:
        current = Version(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")
    return specifier.contains(current, prereleases=True)


def _best_pypi_release(name: str, specifier: str, warnings: list[str], python_version: str = "") -> str:
    converted = _poetry_specifier_to_pep440(specifier)
    try:
        spec = SpecifierSet(converted) if converted else SpecifierSet("")
    except InvalidSpecifier:
        warnings.append(f"unsupported version specifier for {name}: {specifier}")
        return ""
    quoted_name = urllib.parse.quote(name)
    url = f"https://pypi.org/pypi/{quoted_name}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        warnings.append(f"PyPI version lookup failed for {name}{specifier}: {exc}")
        return ""
    candidates: list[Version] = []
    for raw_version, files in (payload.get("releases") or {}).items():
        try:
            parsed = Version(str(raw_version))
        except InvalidVersion:
            continue
        if parsed.is_prerelease and not spec.prereleases:
            continue
        if not spec.contains(parsed, prereleases=bool(spec.prereleases)):
            continue
        if files and not any(_python_version_satisfies(str(file.get("requires_python") or ""), python_version) for file in files if isinstance(file, dict)):
            continue
        candidates.append(parsed)
    if not candidates:
        warnings.append(f"no PyPI release satisfies {name}{specifier}")
        return ""
    return str(sorted(candidates)[-1])


def _resolve_missing_versions_from_pypi(records: list[DependencyRecord], warnings: list[str], python_version: str = "") -> list[DependencyRecord]:
    resolved: list[DependencyRecord] = []
    for record in records:
        if record.version or not record.specifier:
            resolved.append(record)
            continue
        version = _best_pypi_release(record.normalized_name, record.specifier, warnings, python_version)
        if not version:
            resolved.append(record)
            continue
        converted_specifier = _poetry_specifier_to_pep440(record.specifier)
        resolved.append(
            record.model_copy(
                update={
                    "version": version,
                    "specifier": converted_specifier or record.specifier,
                    "purl": purl(record.name, version),
                }
            )
        )
    return resolved


def _enrich_records_from_pypi_metadata(records: list[DependencyRecord], warnings: list[str]) -> list[DependencyRecord]:
    if os.getenv("F_VRA_PYPI_METADATA", "1").lower() in {"0", "false", "no"}:
        warnings.append("PyPI metadata enrichment disabled by F_VRA_PYPI_METADATA")
        return records

    enriched: list[DependencyRecord] = []
    for record in records:
        if record.dependencies or not record.version:
            enriched.append(record)
            continue
        quoted_name = urllib.parse.quote(record.normalized_name)
        quoted_version = urllib.parse.quote(record.version)
        url = f"https://pypi.org/pypi/{quoted_name}/{quoted_version}/json"
        try:
            with urllib.request.urlopen(url, timeout=10) as response:
                payload = json.loads(response.read().decode("utf-8"))
            requires_dist = (payload.get("info") or {}).get("requires_dist") or []
        except Exception as exc:
            warnings.append(f"PyPI metadata lookup failed for {record.normalized_name}=={record.version}: {exc}")
            enriched.append(record)
            continue
        enriched.append(record.model_copy(update={"dependencies": _requires_dist_names(requires_dist)}))
    return enriched


def _resolve_with_pip_report(project: Path, selected_files: list[Path], direct_names: set[str]) -> tuple[list[DependencyRecord], list[str]]:
    if os.getenv("F_VRA_PIP_RESOLVE", "1").lower() in {"0", "false", "no"}:
        return [], ["pip resolver disabled by F_VRA_PIP_RESOLVE"]
    requirements = _pip_report_requirements(project, selected_files)
    if not requirements:
        return [], []
    with tempfile.TemporaryDirectory(prefix="fvra-pip-report-") as tmp:
        tmp_path = Path(tmp)
        report_path = tmp_path / "report.json"
        manifest_requirements = _pip_report_requirements_file(project, selected_files, tmp_path)
        if manifest_requirements is not None:
            requirements = ["-r", str(manifest_requirements)]
        command = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--report",
            str(report_path),
            *requirements,
        ]
        try:
            subprocess.run(
                command,
                cwd=project,
                text=True,
                capture_output=True,
                check=True,
            )
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return [], [f"pip dependency resolution failed: {exc}"]

    records: list[DependencyRecord] = []
    project_name = _project_distribution_name(project)
    for item in payload.get("install") or []:
        metadata = item.get("metadata") or {}
        name = str(metadata.get("name") or "")
        version = str(metadata.get("version") or "")
        if not name or name.lower() == "python":
            continue
        norm = name.replace("_", "-").lower()
        if project_name and norm == project_name:
            continue
        dependencies = _requires_dist_names([str(requirement) for requirement in metadata.get("requires_dist") or []])
        records.append(
            DependencyRecord(
                name=name,
                normalized_name=norm,
                version=version,
                specifier=f"=={version}" if version else "",
                direct=norm in direct_names or bool(item.get("requested")),
                dev=False,
                source_file=str(selected_files[0]) if selected_files else "",
                source_type="pip-report",
                source_path="",
                dependencies=dependencies,
                purl=purl(name, version),
            )
        )
    requirements_only = selected_files and all(path.name.startswith("requirements") and path.suffix == ".txt" for path in selected_files)
    if requirements_only and not direct_names:
        records = _infer_direct_from_requirements_freeze(project, records)
    return records, []


def resolve_dependency_graph(
    project: Path,
    *,
    files: list[Path] | None = None,
    include_dev: bool = False,
) -> DependencyGraphArtifact:
    project = project.resolve()
    selected_files = [path.resolve() for path in (files or discover_dependency_files(project))]
    installed = installed_distributions()
    direct_names: set[str] = set()
    pyproject = project / "pyproject.toml"
    if pyproject.exists():
        direct_names = direct_names_from_pyproject(pyproject, include_dev=include_dev)

    records: list[DependencyRecord] = []
    warnings: list[str] = []
    has_lockfile = any(path.name in LOCKFILE_NAMES for path in selected_files)
    for path in selected_files:
        if not path.exists():
            warnings.append(f"missing dependency file: {path}")
            continue
        try:
            if path.name == "poetry.lock":
                records.extend(
                    parse_poetry_lock(path, direct_names=direct_names, include_dev=include_dev, installed=installed)
                )
            elif path.name == "uv.lock":
                records.extend(parse_uv_lock(path, direct_names=direct_names, include_dev=include_dev, installed=installed))
            elif path.name == "Pipfile.lock":
                records.extend(parse_pipfile_lock(path, include_dev=include_dev, installed=installed))
            elif path.name == "pyproject.toml":
                if not has_lockfile:
                    records.extend(parse_pyproject(path, include_dev=include_dev, installed=installed))
            elif path.name == "setup.py":
                records.extend(parse_setup_py(path, include_dev=include_dev, installed=installed))
            elif path.name.startswith("requirements") and path.suffix == ".txt":
                records.extend(parse_requirements(path, include_dev=include_dev, installed=installed))
        except Exception as exc:
            warnings.append(f"failed to parse {path}: {exc}")

    if not has_lockfile:
        manifest_direct_names = {record.normalized_name for record in records if record.direct}
        pip_records, pip_warnings = _resolve_with_pip_report(project, selected_files, direct_names | manifest_direct_names)
        warnings.extend(pip_warnings)
        if pip_records:
            records = pip_records
        elif records:
            records = _resolve_missing_versions_from_pypi(records, warnings, _project_python_version_hint(project))
            records = _enrich_records_from_pypi_metadata(records, warnings)
            if all(path.name.startswith("requirements") and path.suffix == ".txt" for path in selected_files):
                records = _infer_direct_from_requirements_freeze(project, records)

    return DependencyGraphArtifact(
        project=ProjectIdentity(root=str(project), fingerprint=project_fingerprint(project, selected_files)),
        fingerprint=AnalysisFingerprint(python_version=f"{sys.version_info.major}.{sys.version_info.minor}"),
        source_files=[str(path) for path in selected_files if path.exists()],
        dependencies=dedupe_records(records),
        analysis_warnings={"warnings": warnings} if warnings else {},
    )


def resolve_dependency_graph_from_runtime(
    project: Path,
    runtime: RuntimeEnvironment,
    *,
    runtime_manifest: Path | None = None,
) -> DependencyGraphArtifact:
    """Create the dependency graph from one project's captured interpreter.

    Unlike the static resolver above, this function has exactly one record per
    distribution/version observed by ``importlib.metadata`` in the project's
    own Conda prefix.  It never consults the f_vra environment or selects a
    version from a lockfile after installation.
    """
    project = project.resolve()
    selected_files = [path for path in discover_dependency_files(project) if path.exists()]
    direct_names: set[str] = set()
    pyproject = project / "pyproject.toml"
    if pyproject.exists():
        direct_names = direct_names_from_pyproject(pyproject, include_dev=True)
    source_file = str(runtime_manifest or (project / "runtime_environment.json"))
    records: list[DependencyRecord] = []
    for package in runtime.packages:
        dependencies = _requires_dist_names(list(package.requires_dist))
        records.append(
            DependencyRecord(
                name=package.name,
                normalized_name=package.normalized_name,
                version=package.version,
                specifier=f"=={package.version}" if package.version else "",
                direct=package.normalized_name in direct_names,
                source_file=source_file,
                source_type="conda-runtime",
                source_path=package.source_path,
                dependencies=dependencies,
                purl=purl(package.name, package.version),
            )
        )
    return DependencyGraphArtifact(
        project=ProjectIdentity(root=str(project), fingerprint=project_fingerprint(project, selected_files)),
        fingerprint=AnalysisFingerprint(
            python_version=runtime.python_version,
            config_hash=runtime.fingerprint,
        ),
        source_files=[str(path) for path in selected_files] + [source_file],
        resolver="conda-runtime",
        dependencies=sorted(records, key=lambda item: (item.normalized_name, item.version)),
        analysis_warnings={},
    )
