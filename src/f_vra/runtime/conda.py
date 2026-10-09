from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import textwrap
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable


ProgressCallback = Callable[[dict[str, Any]], None]


def _find_msvc_devcmd() -> Path | None:
    """Locate the Visual Studio developer command script when installed."""

    candidates: list[Path] = []
    for value in (os.environ.get("VSINSTALLDIR", ""), os.environ.get("VS170COMNTOOLS", "")):
        if value:
            base = Path(value)
            candidates.extend([base / "Common7" / "Tools" / "VsDevCmd.bat", base / "VsDevCmd.bat"])
    candidates.extend(
        [
            Path(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"),
            Path(r"C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"),
        ]
    )
    for root in (Path(r"C:\Program Files\Microsoft Visual Studio"), Path(r"C:\Program Files (x86)\Microsoft Visual Studio")):
        if root.is_dir():
            candidates.extend(root.glob("*/Community/Common7/Tools/VsDevCmd.bat"))
            candidates.extend(root.glob("*/Professional/Common7/Tools/VsDevCmd.bat"))
            candidates.extend(root.glob("*/Enterprise/Common7/Tools/VsDevCmd.bat"))
            candidates.extend(root.glob("*/BuildTools/Common7/Tools/VsDevCmd.bat"))
    for vswhere in candidates:
        if not vswhere.is_file() or vswhere.name.lower() != "vswhere.exe":
            continue
        try:
            result = subprocess.run(
                [
                    str(vswhere),
                    "-latest",
                    "-products",
                    "*",
                    "-requires",
                    "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                    "-property",
                    "installationPath",
                ],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            continue
        installation = result.stdout.strip().splitlines()[0].strip() if result.stdout.strip() else ""
        if installation:
            candidates.append(Path(installation) / "Common7" / "Tools" / "VsDevCmd.bat")
    for candidate in candidates:
        if candidate.is_file() and candidate.name.lower() == "vsdevcmd.bat":
            return candidate.resolve()
    return None


def _load_msvc_environment() -> dict[str, str]:
    """Import the x64 MSVC toolchain environment for child build processes."""

    devcmd = _find_msvc_devcmd()
    if devcmd is None or os.name != "nt":
        return {}
    try:
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", "call", str(devcmd), "-arch=x64", "-host_arch=x64", "&&", "set"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return {}
    if result.returncode != 0:
        return {}
    environment: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line or line.startswith("="):
            continue
        key, value = line.split("=", 1)
        environment[key] = value
    path_value = environment.get("Path", environment.get("PATH", ""))
    if not shutil.which("cl.exe", path=path_value) or not shutil.which("nmake.exe", path=path_value):
        return {}
    return environment


class RuntimeCommandError(RuntimeError):
    """A non-zero command result from a runtime/environment operation."""

    def __init__(self, command: list[str], returncode: int, log_path: Path):
        self.command = command
        self.returncode = returncode
        self.log_path = log_path
        super().__init__(f"command failed with exit code {returncode}: {' '.join(command)}; log={log_path}")


@dataclass(frozen=True)
class RuntimePackage:
    name: str
    normalized_name: str
    version: str
    source_path: str = ""
    import_roots: tuple[str, ...] = ()
    python_source: bool = False
    source_fingerprint: str = ""
    requires_dist: tuple[str, ...] = ()
    import_root_paths: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeEnvironment:
    project_id: str
    project_path: str
    prefix: str
    python_executable: str
    python_version: str
    fingerprint: str
    packages: tuple[RuntimePackage, ...]
    sys_path: tuple[str, ...] = ()
    conda_packages: tuple[dict[str, Any], ...] = ()
    pip_inspect: dict[str, Any] = field(default_factory=dict)
    install_commands: tuple[str, ...] = ()
    bootstrap_tools: tuple[str, ...] = ()

    def package_by_root(self) -> dict[str, RuntimePackage]:
        result: dict[str, RuntimePackage] = {}
        for package in self.packages:
            for root in package.import_roots:
                result.setdefault(root, package)
        return result

    def to_json(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["packages"] = [asdict(item) for item in self.packages]
        payload["pip_inspect"] = self.pip_inspect or {}
        return payload

    @classmethod
    def from_json(cls, payload: dict[str, Any]) -> "RuntimeEnvironment":
        return cls(
            project_id=str(payload.get("project_id", "")),
            project_path=str(payload.get("project_path", "")),
            prefix=str(payload.get("prefix", "")),
            python_executable=str(payload.get("python_executable", "")),
            python_version=str(payload.get("python_version", "")),
            fingerprint=str(payload.get("fingerprint", "")),
            packages=tuple(RuntimePackage(**item) for item in payload.get("packages", [])),
            sys_path=tuple(str(item) for item in payload.get("sys_path", [])),
            conda_packages=tuple(payload.get("conda_packages", [])),
            pip_inspect=payload.get("pip_inspect") or {},
            install_commands=tuple(str(item) for item in payload.get("install_commands", [])),
            bootstrap_tools=tuple(str(item) for item in payload.get("bootstrap_tools", [])),
        )


def _normalize_name(name: str) -> str:
    return name.replace("_", "-").lower()


def _stable_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-").lower() or "project"


def _version_tuple(value: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", value)
    parsed = [int(item) for item in numbers[:4]]
    return tuple(parsed + [0] * (4 - len(parsed))) if parsed else (0, 0, 0, 0)


def _satisfies(version: str, specifier: str) -> bool:
    """Small dependency-free Python-version constraint matcher."""
    if not specifier:
        return True
    current = _version_tuple(version)
    for raw in re.split(r"[,;\s]+", specifier.replace("^", ">=")):
        token = raw.strip()
        if not token or token in {"and", "or"}:
            continue
        match = re.match(r"(===|==|!=|<=|>=|<|>)([0-9][0-9.*]*)", token)
        if not match:
            continue
        operator, wanted = match.groups()
        if wanted.endswith(".*"):
            prefix = _version_tuple(wanted[:-2])
            actual = current[: len(prefix)]
            matches = actual == prefix
            result = (not matches) if operator == "!=" else matches
        else:
            target = _version_tuple(wanted)
            result = {
                "===": current == target,
                "==": current == target,
                "!=": current != target,
                "<=": current <= target,
                ">=": current >= target,
                "<": current < target,
                ">": current > target,
            }[operator]
        if not result:
            return False
    return True


def python_version_candidates(
    project_path: Path,
    available: Iterable[str] = ("3.14", "3.13", "3.12", "3.11", "3.10"),
    *,
    distribution_names: Iterable[str] = (),
) -> list[str]:
    """Return available interpreters satisfying every project constraint.

    Poetry projects keep the Python constraint under
    ``tool.poetry.dependencies.python`` rather than ``requires-python``.
    Reading only the latter was the reason old Poetry projects were assigned
    Python 3.14 even when their lock/build chain was authored for older
    interpreters.
    """
    exact = project_path / ".python-version"
    preferred = ""
    if exact.exists():
        value = exact.read_text(encoding="utf-8", errors="replace").splitlines()[0].strip()
        if value and not value.startswith("#"):
            preferred = value

    candidates = list(available)
    metadata_values: list[str] = []
    try:
        import tomllib

        pyproject_payload = tomllib.loads((project_path / "pyproject.toml").read_text(encoding="utf-8")) if (project_path / "pyproject.toml").exists() else {}
    except Exception:
        pyproject_payload = {}
    project_metadata = pyproject_payload.get("project", {}) or {}
    if project_metadata.get("requires-python"):
        metadata_values.append(str(project_metadata["requires-python"]))
    poetry_dependencies = (((pyproject_payload.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
    poetry_python = poetry_dependencies.get("python") if isinstance(poetry_dependencies, dict) else None
    if isinstance(poetry_python, str) and poetry_python.strip():
        metadata_values.append(poetry_python.strip())
    elif isinstance(poetry_python, dict) and poetry_python.get("version"):
        metadata_values.append(str(poetry_python["version"]))
    for name in ("pyproject.toml",):
        path = project_path / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        metadata_values.extend(re.findall(r"(?im)^\s*requires-python\s*=\s*[\"']([^\"']+)", text))
        metadata_values.extend(re.findall(r"(?im)^\s*python_requires\s*=\s*[\"']([^\"']+)", text))
    for name in ("setup.py", "setup.cfg"):
        path = project_path / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        metadata_values.extend(re.findall(r"(?im)^\s*python_requires\s*=\s*[\"']([^\"']+)", text))

    lock = project_path / "uv.lock"
    wheel_abi3_min: dict[str, int] = {}
    if lock.exists():
        text = lock.read_text(encoding="utf-8", errors="replace")
        metadata_values.extend(re.findall(r"(?im)^\s*requires-python\s*=\s*[\"']([^\"']+)", text)[:1])

        # A lock can prove that a benchmark root has no wheel for the
        # selected interpreter even when its Python constraint is broad.  Use
        # this only for explicitly selected benchmark roots; unrelated lock
        # packages may legitimately build from source and must not constrain
        # the whole project.
        try:
            import tomllib

            lock_payload = tomllib.loads(text)
            selected_names = {
                re.sub(r"[-_.]+", "-", str(name).strip()).lower()
                for name in distribution_names
                if str(name).strip()
            }
            wheel_python_tags: dict[str, set[str]] = {}
            for package in lock_payload.get("package", []) or []:
                if not isinstance(package, dict):
                    continue
                normalized = re.sub(r"[-_.]+", "-", str(package.get("name") or "").strip()).lower()
                if normalized not in selected_names:
                    continue
                tags: set[str] = set()
                for wheel in package.get("wheels", []) or []:
                    filename = str((wheel or {}).get("url") or "").rsplit("/", 1)[-1].lower()
                    tags.update(re.findall(r"cp(\d{2,3})", filename))
                    if "abi3" in filename:
                        abi3_tags = [int(item) for item in re.findall(r"cp(\d{2,3})", filename)]
                        if abi3_tags:
                            wheel_abi3_min[normalized] = min(wheel_abi3_min.get(normalized, abi3_tags[0]), min(abi3_tags))
                if tags:
                    wheel_python_tags[normalized] = tags
        except Exception:
            wheel_python_tags = {}
    else:
        wheel_python_tags = {}
        try:
            import tomllib

            poetry_payload = tomllib.loads((project_path / "poetry.lock").read_text(encoding="utf-8")) if (project_path / "poetry.lock").exists() else {}
            selected_names = {
                re.sub(r"[-_.]+", "-", str(name).strip()).lower()
                for name in distribution_names
                if str(name).strip()
            }
            for package in poetry_payload.get("package", []) or []:
                normalized = re.sub(r"[-_.]+", "-", str(package.get("name") or "").strip()).lower()
                if normalized in selected_names and package.get("python-versions") and str(package["python-versions"]) not in {"*", ""}:
                    metadata_values.append(str(package["python-versions"]))
                if normalized not in selected_names:
                    continue
                tags: set[str] = set()
                for file_entry in package.get("files", []) or []:
                    filename = str((file_entry or {}).get("file") or "").lower()
                    tags.update(re.findall(r"cp(\d{2,3})", filename))
                    if "abi3" in filename:
                        abi3_tags = [int(item) for item in re.findall(r"cp(\d{2,3})", filename)]
                        if abi3_tags:
                            wheel_abi3_min[normalized] = min(wheel_abi3_min.get(normalized, abi3_tags[0]), min(abi3_tags))
                if tags:
                    wheel_python_tags[normalized] = tags
        except Exception:
            pass

    # All declared constraints must hold.  The previous implementation used
    # only the first value, which allowed a project with ``>=3.11`` in
    # pyproject.toml and ``<3.14`` in uv.lock to select Python 3.14.
    ordered = ([preferred] if preferred else []) + [candidate for candidate in candidates if candidate != preferred]
    compatible = [
        candidate
        for candidate in ordered
        if all(_satisfies(candidate, constraint) for constraint in metadata_values)
        and all(
            not tags
            or f"{candidate.split('.')[0]}{candidate.split('.')[1]}" in tags
            or (name in wheel_abi3_min and int(f"{candidate.split('.')[0]}{candidate.split('.')[1]}") >= wheel_abi3_min[name])
            for name, tags in wheel_python_tags.items()
        )
    ]
    if not compatible and candidates:
        raise ValueError(f"no available Python version satisfies project constraints: {metadata_values!r}")
    return compatible


def select_python_version(
    project_path: Path,
    available: Iterable[str] = ("3.14", "3.13", "3.12", "3.11", "3.10"),
    *,
    distribution_names: Iterable[str] = (),
) -> str:
    """Select the highest available interpreter satisfying project metadata."""
    candidates = list(available)
    compatible = python_version_candidates(project_path, candidates, distribution_names=distribution_names)
    if compatible:
        return compatible[0]
    if candidates:
        raise ValueError(f"no available Python version satisfies project constraints")
    return "3.12"


def _source_fingerprint(path: Path) -> str:
    if not path.exists():
        return ""
    if path.is_file():
        stat = path.stat()
        return _stable_hash([path.name, stat.st_size, stat.st_mtime_ns])
    rows: list[tuple[str, int, int]] = []
    for child in sorted(path.rglob("*.py")):
        try:
            stat = child.stat()
        except OSError:
            continue
        rows.append((str(child.relative_to(path)), stat.st_size, stat.st_mtime_ns))
    return _stable_hash(rows)


def _source_path_from_distribution(dist: Any) -> str:
    try:
        top_level = dist.read_text("top_level.txt") or ""
    except Exception:
        top_level = ""
    files = list(dist.files or [])
    tops = [line.strip() for line in top_level.splitlines() if line.strip()]
    for top in tops:
        for file in files:
            posix = file.as_posix()
            if posix == f"{top}/__init__.py":
                return str(dist.locate_file(file).parent)
            if posix == f"{top}.py":
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


def capture_runtime_snapshot(
    project_id: str,
    project_path: Path,
    prefix: Path,
    *,
    command_runner: Callable[..., Any],
    log_dir: Path,
    progress: ProgressCallback | None = None,
    install_commands: Iterable[str] = (),
    bootstrap_tools: Iterable[str] = (),
    conda_packages: Iterable[dict[str, Any]] = (),
    pip_inspect: dict[str, Any] | None = None,
) -> RuntimeEnvironment:
    """Capture distribution metadata from the project interpreter itself."""
    conda_package_rows = tuple(conda_packages)
    pip_inspect_payload = pip_inspect or {}
    python_executable = prefix / ("python.exe" if os.name == "nt" else "bin/python")
    # Keep the probe self-contained so it does not import f_vra or project code.
    probe = textwrap.dedent(
        """
        import importlib.metadata as m
        import importlib.util
        import json
        import pathlib
        import platform
        import sys
        import sysconfig

        rows = []
        for d in m.distributions():
            name = d.metadata.get("Name") or d.name or ""
            if not name:
                continue
            try:
                tops = [x.strip() for x in (d.read_text("top_level.txt") or "").splitlines() if x.strip()]
            except Exception:
                tops = []
            # ``top_level.txt`` is optional and frequently wrong for modern
            # wheels (for example yt-dlp, black, protobuf and llama-index).
            # Ask importlib which distributions own each import root, then
            # prefer those roots while retaining the raw metadata for audit.
            try:
                owned_tops = [
                    str(top).strip()
                    for top, owners in m.packages_distributions().items()
                    if any(str(owner).replace("_", "-").lower() == str(name).replace("_", "-").lower() for owner in owners)
                ]
            except Exception:
                owned_tops = []
            tops = list(dict.fromkeys([*owned_tops, *tops]))
            files = [x.as_posix() for x in (d.files or [])]
            source = ""
            root_sources = {}
            preferred = []
            for top in tops:
                preferred.extend([f"{top}/__init__.py", f"{top}.py"])
                for f in (f"{top}/__init__.py", f"{top}.py"):
                    if f not in files:
                        continue
                    located = d.locate_file(f)
                    if located.exists():
                        root_sources[top] = str(located.parent if f.endswith("__init__.py") else located)
                        if not source:
                            source = root_sources[top]
                        break
                if top not in root_sources:
                    try:
                        spec = importlib.util.find_spec(top)
                    except Exception:
                        spec = None
                    if spec is not None:
                        locations = list(spec.submodule_search_locations or [])
                        origin = str(spec.origin or "")
                        if locations:
                            root_sources[top] = str(pathlib.Path(locations[0]))
                        elif origin and origin != "built-in":
                            root_sources[top] = origin
                        if top in root_sources and not source:
                            source = root_sources[top]
            if not source:
                for f in files:
                    if ".dist-info/" in f or ".egg-info/" in f:
                        continue
                    if f.endswith("__init__.py") or f.endswith(".py"):
                        located = d.locate_file(f)
                        if located.exists():
                            source = str(located.parent if f.endswith("__init__.py") else located)
                            break
            if not tops and source:
                source_path = pathlib.Path(source)
                tops = [source_path.stem if source_path.suffix == ".py" else source_path.name]
            rows.append(
                {
                    "name": name,
                    "normalized_name": name.replace("_", "-").lower(),
                    "version": d.version or "",
                    "source_path": source,
                    "import_roots": tops,
                    "python_source": bool(source),
                    "import_root_paths": root_sources,
                    "requires_dist": list(d.requires or []),
                }
            )
        print(json.dumps({"python_version": platform.python_version(), "sys_path": sys.path, "sysconfig": sysconfig.get_paths(), "packages": rows}))
        """
    ).strip()
    result = command_runner(
        [str(python_executable), "-c", probe],
        cwd=project_path,
        log_dir=log_dir,
        label="runtime_probe",
        progress=progress,
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    payload = json.loads(lines[-1])
    packages: list[RuntimePackage] = []
    for item in payload.get("packages", []):
        source = Path(str(item.get("source_path", ""))) if item.get("source_path") else None
        packages.append(
            RuntimePackage(
                name=str(item.get("name", "")),
                normalized_name=str(item.get("normalized_name", "")),
                version=str(item.get("version", "")),
                source_path=str(item.get("source_path", "")),
                import_roots=tuple(str(x) for x in item.get("import_roots", [])),
                python_source=bool(item.get("python_source")),
                source_fingerprint=_source_fingerprint(source) if source else "",
                requires_dist=tuple(str(x) for x in item.get("requires_dist", [])),
                import_root_paths={str(k): str(v) for k, v in (item.get("import_root_paths") or {}).items()},
            )
        )
    # Native lock installers commonly install the project itself in editable
    # mode.  Its dist-info RECORD then contains no source files, so recover the
    # source from the project's own import layout without consulting the
    # f_vra environment.
    project_distribution = ""
    try:
        import tomllib

        pyproject = project_path / "pyproject.toml"
        if pyproject.exists():
            metadata_payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            project_distribution = str((metadata_payload.get("project") or {}).get("name") or "")
            if not project_distribution:
                project_distribution = str((((metadata_payload.get("tool") or {}).get("poetry") or {}).get("name")) or "")
    except Exception:
        project_distribution = ""
    if project_distribution:
        normalized_project = _normalize_name(project_distribution)
        package_root = normalized_project.replace("-", "_")
        candidates = [project_path / "src" / package_root, project_path / package_root, project_path / "src" / f"{package_root}.py", project_path / f"{package_root}.py"]
        editable_source = next((candidate for candidate in candidates if candidate.exists()), None)
        if editable_source is not None:
            updated: list[RuntimePackage] = []
            for package in packages:
                if package.normalized_name == normalized_project and (
                    not package.source_path or not Path(package.source_path).exists()
                ):
                    updated.append(
                        RuntimePackage(
                            name=package.name,
                            normalized_name=package.normalized_name,
                            version=package.version,
                            source_path=str(editable_source.resolve()),
                            import_roots=package.import_roots or (package_root,),
                            python_source=True,
                            source_fingerprint=_source_fingerprint(editable_source),
                            requires_dist=package.requires_dist,
                            import_root_paths=package.import_root_paths,
                        )
                    )
                else:
                    updated.append(package)
            packages = updated
    fingerprint = _stable_hash(
        {
            "python_version": payload.get("python_version", ""),
            "prefix": str(prefix.resolve()),
            "packages": [(p.normalized_name, p.version, p.source_fingerprint) for p in packages],
            "conda_packages": list(conda_package_rows),
            "pip_inspect": pip_inspect_payload,
        }
    )
    return RuntimeEnvironment(
        project_id=project_id,
        project_path=str(project_path.resolve()),
        prefix=str(prefix.resolve()),
        python_executable=str(python_executable.resolve()),
        python_version=str(payload.get("python_version", "")),
        fingerprint=fingerprint,
        packages=tuple(packages),
        sys_path=tuple(str(x) for x in payload.get("sys_path", [])),
        conda_packages=conda_package_rows,
        pip_inspect=pip_inspect_payload,
        install_commands=tuple(str(x) for x in install_commands),
        bootstrap_tools=tuple(str(x) for x in bootstrap_tools),
    )


class CondaEnvironmentManager:
    def __init__(self, prefix_root: Path, *, conda_executable: Path | None = None):
        self.prefix_root = prefix_root.resolve()
        self.conda_executable = self._resolve_conda(conda_executable)
        self.msvc_environment = _load_msvc_environment()
        # Summary workers are spawned after the manager is constructed. Keep
        # the discovered developer environment in the parent so multiprocessing
        # workers inherit cl.exe/nmake/CMake as well as installer subprocesses.
        if self.msvc_environment:
            os.environ.update(self.msvc_environment)
        self.prefix_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _resolve_conda(candidate: Path | None) -> Path:
        values = [candidate] if candidate else []
        env_value = os.environ.get("F_VRA_CONDA_EXE", "").strip()
        if env_value:
            values.append(Path(env_value))
        values.extend(
            [
                Path(r"C:\Users\iamwu\miniconda3\Scripts\conda.exe"),
                Path(r"C:\Users\iamwu\miniconda3\condabin\conda.bat"),
            ]
        )
        which = shutil.which("conda")
        if which:
            values.append(Path(which))
        for value in values:
            if value and value.exists():
                return value.resolve()
        raise FileNotFoundError("Conda executable not found; set F_VRA_CONDA_EXE")

    def prefix_for(self, project_id: str, config_hash: str) -> Path:
        return self.prefix_root / f"{_slug(project_id)}-{config_hash[:12]}"

    @staticmethod
    def _python(prefix: Path) -> Path:
        return prefix / ("python.exe" if os.name == "nt" else "bin/python")

    @staticmethod
    def _poetry_groups(project_path: Path) -> list[str]:
        try:
            import tomllib

            payload = tomllib.loads((project_path / "pyproject.toml").read_text(encoding="utf-8"))
        except Exception:
            return []
        groups = ((payload.get("tool") or {}).get("poetry") or {}).get("group") or {}
        return sorted(str(name) for name in groups if str(name).strip())

    @staticmethod
    def _pyproject_dependency_groups(project_path: Path) -> list[str]:
        try:
            import tomllib

            payload = tomllib.loads((project_path / "pyproject.toml").read_text(encoding="utf-8"))
        except Exception:
            return []
        groups = payload.get("dependency-groups") or {}
        flattened: list[str] = []
        visiting: set[str] = set()

        def visit(name: str) -> None:
            if name in visiting:
                return
            visiting.add(name)
            for item in groups.get(name, []) or []:
                if isinstance(item, str):
                    flattened.append(item)
                elif isinstance(item, dict) and item.get("include-group"):
                    visit(str(item["include-group"]))
            visiting.remove(name)

        for name in groups:
            visit(str(name))
        return list(dict.fromkeys(flattened))

    @staticmethod
    def _pyproject_optional_extras(project_path: Path) -> list[str]:
        try:
            import tomllib

            payload = tomllib.loads((project_path / "pyproject.toml").read_text(encoding="utf-8"))
        except Exception:
            return []
        optional = ((payload.get("project") or {}).get("optional-dependencies") or {})
        return sorted(str(name) for name in optional if str(name).strip())

    def install(
        self,
        project_id: str,
        project_path: Path,
        prefix: Path,
        *,
        log_dir: Path,
        progress: ProgressCallback | None = None,
        selected_requirements: Path | None = None,
        install_project_editable: bool = False,
        build_constraints: Path | None = None,
    ) -> tuple[list[str], list[str]]:
        """Install either a targeted lock closure or the legacy full manifest.

        There is deliberately no timeout and no version fallback here.  A
        non-zero installer command must be surfaced to the orchestrator as an
        install failure with its log preserved.
        """
        python = self._python(prefix)
        commands: list[str] = []
        bootstrap: list[str] = []

        def run(
            command: list[str],
            label: str,
            *,
            env: dict[str, str] | None = None,
            allow_failure: bool = False,
        ) -> Any:
            commands.append(" ".join(command))
            try:
                return self.run(
                    command,
                    cwd=project_path,
                    log_dir=log_dir,
                    label=label,
                    progress=progress,
                    prefix=prefix,
                    env=env,
                )
            except RuntimeCommandError as exc:
                if not allow_failure:
                    raise
                if progress:
                    progress(
                        {
                            "phase": "command_warning",
                            "project": project_id,
                            "label": label,
                            "error": str(exc),
                            "log_path": str(log_dir / f"{label}.log"),
                        }
                    )
                return None

        if selected_requirements is not None:
            run([str(python), "-m", "pip", "install", "uv"], "bootstrap_uv")
            bootstrap.append("uv")
            if selected_requirements.exists():
                targeted_command = [
                    str(python),
                    "-m",
                    "uv",
                    "pip",
                    "install",
                    "--python",
                    str(python),
                    "--no-deps",
                ]
                if build_constraints is not None and build_constraints.exists():
                    targeted_command.extend(["--build-constraints", str(build_constraints)])
                targeted_command.extend(["-r", str(selected_requirements)])
                run(
                    targeted_command,
                    "install_targeted_closure",
                    env={"UV_NO_PROGRESS": "1", "VIRTUAL_ENV": None},
                )
            if install_project_editable and (project_path / "pyproject.toml").exists():
                run(
                    [str(python), "-m", "pip", "install", "--no-deps", "-e", str(project_path)],
                    "install_project_editable_no_deps",
                )
        elif (project_path / "uv.lock").exists():
            run([str(python), "-m", "pip", "install", "uv"], "bootstrap_uv")
            bootstrap.append("uv")
            uv_requirements = log_dir / "uv_export_requirements.txt"
            run(
                [
                    str(python),
                    "-m",
                    "uv",
                    "export",
                    "--frozen",
                    "--format",
                    "requirements.txt",
                    "--output-file",
                    str(uv_requirements),
                ],
                "export_uv_lock",
                # uv sync manages a PEP 405 virtualenv and cannot treat a
                # Conda prefix as that virtualenv. Export the native lockfile
                # first, then use uv pip sync with the explicit Conda Python.
                env={"UV_NO_PROGRESS": "1", "VIRTUAL_ENV": None},
            )
            run(
                [str(python), "-m", "uv", "pip", "sync", "--python", str(python), str(uv_requirements)],
                "install_uv_lock",
                env={"UV_NO_PROGRESS": "1", "VIRTUAL_ENV": None},
            )
        elif (project_path / "poetry.lock").exists():
            run([str(python), "-m", "pip", "install", "poetry"], "bootstrap_poetry")
            bootstrap.append("poetry")
            run(
                [str(python), "-m", "poetry", "install", "--no-interaction", "--no-ansi", "--no-root"],
                "install_poetry_lock",
                env={"POETRY_VIRTUALENVS_CREATE": "false"},
            )
        elif (project_path / "Pipfile.lock").exists():
            run([str(python), "-m", "pip", "install", "pipenv"], "bootstrap_pipenv")
            bootstrap.append("pipenv")
            run(
                [str(python), "-m", "pipenv", "sync"],
                "install_pipfile_lock",
                env={
                    "PIPENV_IGNORE_VIRTUALENVS": "0",
                    "PIPENV_VENV_IN_PROJECT": "0",
                    "PIPENV_ACTIVE": "1",
                    "VIRTUAL_ENV": str(prefix),
                    "PATH": str(prefix / "Scripts") + os.pathsep + os.environ.get("PATH", ""),
                },
            )
        else:
            requirement_files = sorted(project_path.glob("requirements*.txt"))
            for index, requirement_file in enumerate(requirement_files, 1):
                run(
                    [str(python), "-m", "pip", "install", "-r", str(requirement_file)],
                    f"install_requirements_{index:03d}",
                )
            if not requirement_files and not ((project_path / "pyproject.toml").exists() or (project_path / "setup.py").exists()):
                raise RuntimeError(f"no supported dependency manifest found for {project_id}")
            if (project_path / "pyproject.toml").exists() or (project_path / "setup.py").exists():
                run([str(python), "-m", "pip", "install", "--no-deps", "-e", str(project_path)], "install_project_editable_no_deps")

        pip_check = run([str(python), "-m", "pip", "check"], "pip_check", allow_failure=True)
        if pip_check is None:
            # pip check is a post-install diagnostic. Preserve its log as an
            # explicit warning and continue with the real runtime snapshot;
            # dependency installation failures above still raise.
            bootstrap.append("pip_check_warning")
        if progress:
            progress({"phase": "installed", "project": project_id, "commands": len(commands)})
        return commands, bootstrap

    def create(
        self,
        project_id: str,
        project_path: Path,
        *,
        python_version: str,
        config_hash: str,
        log_dir: Path,
        progress: ProgressCallback | None = None,
    ) -> tuple[Path, list[str]]:
        prefix = self.prefix_for(project_id, config_hash)
        commands: list[str] = []
        marker = prefix / "conda-meta" / "history"
        if not marker.exists():
            command = [str(self.conda_executable), "create", "--prefix", str(prefix), f"python={python_version}", "pip", "--yes", "--no-default-packages"]
            commands.append(" ".join(command))
            self.run(command, cwd=project_path, log_dir=log_dir, label="conda_create", progress=progress)
        if progress:
            progress({"phase": "env_created", "project": project_id, "prefix": str(prefix), "python_version": python_version})
        return prefix, commands

    def run(
        self,
        command: list[str],
        *,
        cwd: Path,
        log_dir: Path,
        label: str,
        progress: ProgressCallback | None = None,
        prefix: Path | None = None,
        env: dict[str, str | None] | None = None,
    ) -> Any:
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"{label}.log"
        started = time.perf_counter()
        process_env = os.environ.copy()
        if prefix is not None:
            # The orchestrator itself runs from the ``f_vra`` Conda env.
            # Poetry/Pipenv otherwise inherit that environment and can install
            # into it even when the command uses the project interpreter.
            target_prefix = str(prefix.resolve())
            scripts = prefix / ("Scripts" if os.name == "nt" else "bin")
            inherited_path = process_env.get("PATH", "")
            process_env["PATH"] = os.pathsep.join(
                part for part in (str(scripts), target_prefix, inherited_path) if part
            )
            process_env["VIRTUAL_ENV"] = target_prefix
            process_env["CONDA_PREFIX"] = target_prefix
            process_env["CONDA_DEFAULT_ENV"] = target_prefix
            process_env["CONDA_PROMPT_MODIFIER"] = ""
            process_env["PYTHONNOUSERSITE"] = "1"
            process_env.pop("PYTHONHOME", None)
        if env:
            for key, value in env.items():
                if value is None:
                    process_env.pop(key, None)
                else:
                    process_env[key] = value
        process_env.setdefault("PYTHONUNBUFFERED", "1")
        process_env.setdefault("PYTHONIOENCODING", "utf-8")
        with log_path.open("w", encoding="utf-8", errors="replace") as handle:
            completed = subprocess.Popen(
                command,
                cwd=str(cwd),
                env=process_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            output: list[str] = []
            assert completed.stdout is not None

            stop_heartbeat = threading.Event()

            def heartbeat() -> None:
                while not stop_heartbeat.wait(10):
                    if completed.poll() is not None:
                        return
                    if progress:
                        progress(
                            {
                                "phase": "process_live",
                                "label": label,
                                "pid": completed.pid,
                                "elapsed_s": round(time.perf_counter() - started, 1),
                            }
                        )

            heartbeat_thread = threading.Thread(target=heartbeat, name=f"f_vra-heartbeat-{label}", daemon=True)
            heartbeat_thread.start()
            last_progress_line = ""
            last_progress_at = 0.0
            for line in completed.stdout:
                handle.write(line)
                handle.flush()
                output.append(line)
                if progress:
                    display_line = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", line).replace("\r", " ").replace("\b", "")
                    now = time.perf_counter()
                    if display_line.strip() and (display_line != last_progress_line or now - last_progress_at >= 1.0):
                        progress({"phase": "command_output", "label": label, "line": display_line.rstrip()[-500:]})
                        last_progress_line = display_line
                        last_progress_at = now
            returncode = completed.wait()
            stop_heartbeat.set()
            heartbeat_thread.join(timeout=1)
        result = type("CommandResult", (), {})()
        result.returncode = returncode
        result.stdout = "".join(output)
        result.elapsed_s = round(time.perf_counter() - started, 3)
        result.log_path = str(log_path)
        if returncode != 0:
            raise RuntimeCommandError(command, returncode, log_path)
        return result

    def capture(
        self,
        project_id: str,
        project_path: Path,
        prefix: Path,
        *,
        log_dir: Path,
        progress: ProgressCallback | None = None,
        install_commands: Iterable[str] = (),
        bootstrap_tools: Iterable[str] = (),
    ) -> RuntimeEnvironment:
        conda_result = self.run(
            [str(self.conda_executable), "list", "--prefix", str(prefix), "--json"],
            cwd=project_path,
            log_dir=log_dir,
            label="conda_list",
            progress=progress,
            prefix=prefix,
        )
        pip_result = self.run(
            [str(self._python(prefix)), "-m", "pip", "inspect"],
            cwd=project_path,
            log_dir=log_dir,
            label="pip_inspect",
            progress=progress,
            prefix=prefix,
        )

        def parse_json(output: str, label: str) -> Any:
            lines = [line for line in output.splitlines() if line.strip()]
            if not lines:
                raise RuntimeError(f"{label} returned no JSON")
            try:
                candidate = "\n".join(lines)
                start = min((index for index in (candidate.find("{"), candidate.find("[")) if index >= 0), default=0)
                end = max(candidate.rfind("}"), candidate.rfind("]"))
                return json.loads(candidate[start : end + 1])
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"{label} returned invalid JSON: {exc}") from exc

        runtime = capture_runtime_snapshot(
            project_id,
            project_path,
            prefix,
            command_runner=lambda command, **kwargs: self.run(command, prefix=prefix, **kwargs),
            log_dir=log_dir,
            progress=progress,
            install_commands=install_commands,
            bootstrap_tools=bootstrap_tools,
            conda_packages=(
                parse_json(conda_result.stdout, "conda list").get("packages", [])
                if isinstance(parse_json(conda_result.stdout, "conda list"), dict)
                else parse_json(conda_result.stdout, "conda list")
            ),
            pip_inspect=parse_json(pip_result.stdout, "pip inspect"),
        )
        return runtime
