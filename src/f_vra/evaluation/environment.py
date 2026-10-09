"""Build immutable Docker environments and derive actual installed identities."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packaging.markers import Marker, default_environment
from packaging.requirements import Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version

from f_vra.analysis.dependencies.resolver import discover_dependency_files
from f_vra.evaluation.contracts import EnvironmentSnapshot, PackageID, VFAnchor, digest
from f_vra.evaluation.io import read_json, read_parquet, write_json, write_parquet
from f_vra.evaluation.environment_probe import PROBE_SCHEMA_VERSION


PROBE = Path(__file__).with_name("environment_probe.py")
AST_ADAPTER_VERSION = "ast-boundary-v7-source-layout-symbol-resolution"
RESOLVER_VERSION = "docker-lock-universe-v16-normalized-wheel-metadata"
BUILD_SYSTEM_PACKAGES = (
    "build-essential", "gcc", "g++", "pkg-config", "git", "libpq-dev", "libldap2-dev",
    "libsasl2-dev", "libssl-dev", "libffi-dev", "libxml2-dev", "libxslt1-dev",
    "zlib1g-dev", "libjpeg-dev", "default-libmysqlclient-dev", "portaudio19-dev",
    "libasound2-dev", "libsndfile1-dev",
)


def _run(args: list[str], *, cwd: Path | None = None, timeout: int = 1800) -> str:
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args[:3])} failed: {(result.stderr or result.stdout)[-2000:]}")
    return result.stdout.strip()


def _pinned_base(tag: str) -> str:
    inspect = subprocess.run(
        ["docker", "image", "inspect", tag, "--format", "{{index .RepoDigests 0}}"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    reference = inspect.stdout.strip() if inspect.returncode == 0 else ""
    if "@sha256:" not in reference:
        _run(["docker", "pull", tag], timeout=1200)
        reference = _run(["docker", "image", "inspect", tag, "--format", "{{index .RepoDigests 0}}"])
    if "@sha256:" not in reference:
        raise RuntimeError(f"image {tag} has no immutable registry digest")
    return reference


def _poetry_constraint_allows(constraint: str, python_version: str) -> bool:
    """Evaluate the Python subset of Poetry constraints without rewriting the lock."""
    raw = constraint.strip()
    if not raw or raw == "*":
        return True
    version = Version(python_version if python_version.count(".") == 2 else f"{python_version}.0")
    for alternative in raw.split("||"):
        value = alternative.strip()
        if not value:
            continue
        parts: list[str] = []
        for item in (piece.strip() for piece in value.split(",")):
            if not item or item == "*":
                continue
            if item.startswith("^"):
                base = Version(item[1:])
                release = base.release + (0,) * (3 - len(base.release))
                if release[0] > 0:
                    upper = f"{release[0] + 1}.0"
                elif release[1] > 0:
                    upper = f"0.{release[1] + 1}"
                else:
                    upper = f"0.0.{release[2] + 1}"
                parts.extend((f">={base}", f"<{upper}"))
            elif item.startswith("~") and not item.startswith("~="):
                base = Version(item[1:])
                release = base.release + (0,) * (2 - len(base.release))
                parts.extend((f">={base}", f"<{release[0]}.{release[1] + 1}"))
            elif item.endswith(".*") and item[0].isdigit():
                release = tuple(int(piece) for piece in item[:-2].split("."))
                if len(release) == 1:
                    upper = f"{release[0] + 1}"
                else:
                    upper = ".".join(map(str, release[:-1] + (release[-1] + 1,)))
                parts.extend((f">={item[:-2]}", f"<{upper}"))
            elif item[0].isdigit():
                parts.append(f"=={item}")
            else:
                parts.append(item)
        try:
            if version in SpecifierSet(",".join(parts)):
                return True
        except InvalidSpecifier:
            # Keep the package when an old Poetry constraint cannot be represented
            # in PEP 440. The package's own wheel/sdist metadata remains a second gate.
            return True
    return False


def _poetry_lock_pins(project: Path, python_version: str) -> list[str]:
    """Select exact pins from the original lock for the target runtime."""
    lock = tomllib.loads((project / "poetry.lock").read_text(encoding="utf-8"))
    pyproject = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    poetry = ((pyproject.get("tool") or {}).get("poetry") or {})
    extras = set((poetry.get("extras") or {}).keys())
    extras.update(((pyproject.get("project") or {}).get("optional-dependencies") or {}).keys())
    marker_env = default_environment()
    major_minor = ".".join(python_version.split(".")[:2])
    marker_env.update({
        "implementation_name": "cpython", "platform_machine": "x86_64",
        "platform_python_implementation": "CPython", "platform_system": "Linux",
        "python_full_version": python_version if python_version.count(".") == 2 else f"{python_version}.0",
        "python_version": major_minor, "sys_platform": "linux",
    })
    selected: dict[str, str] = {}
    for package in lock.get("package") or []:
        name = str(package.get("name") or "")
        version = str(package.get("version") or "")
        if not name or not version or not _poetry_constraint_allows(str(package.get("python-versions") or "*"), python_version):
            continue
        marker_values = package.get("markers")
        if isinstance(marker_values, dict):
            marker_values = list(marker_values.values())
        elif marker_values:
            marker_values = [marker_values]
        else:
            marker_values = []
        if marker_values:
            applicable = False
            for marker_text in marker_values:
                marker = Marker(str(marker_text))
                for extra in [""] + sorted(extras):
                    if marker.evaluate(marker_env | {"extra": extra}):
                        applicable = True
                        break
                if applicable:
                    break
            if not applicable:
                continue
        normalized = canonicalize_name(name)
        previous = selected.get(normalized)
        if previous and previous != version:
            raise ValueError(f"multiple applicable Poetry lock versions for {name}: {previous}, {version}")
        selected[normalized] = version
    return [f"'{name}=={version}'" for name, version in sorted(selected.items())]


def _dockerfile(
    project: Path, python_version: str, *, prior_lock: dict[str, Any] | None = None,
) -> tuple[str, str, str]:
    files = {path.name: path for path in discover_dependency_files(project)}
    if "uv.lock" in files:
        lock_type = "uv.lock"
        pyproject_payload = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8")) if (project / "pyproject.toml").is_file() else {}
        uv_config = ((pyproject_payload.get("tool") or {}).get("uv") or {})
        workspace = bool((uv_config.get("workspace") or {}).get("members"))
        # uv refuses --all-extras when the project declares mutually exclusive
        # extras. In that case, all groups remain materialized and extras stay
        # disabled so the single environment is one valid project profile.
        declared_conflicts = bool(uv_config.get("conflicts"))
        if workspace and not declared_conflicts:
            for member_pyproject in project.glob("packages/**/pyproject.toml"):
                member = tomllib.loads(member_pyproject.read_text(encoding="utf-8"))
                if (((member.get("tool") or {}).get("uv") or {}).get("conflicts")):
                    declared_conflicts = True
                    break
        extras = "" if declared_conflicts else "--all-extras "
        groups = "--no-dev " if declared_conflicts else "--all-groups "
        scope = "--all-packages --no-install-workspace" if workspace else "--no-install-project"
        install = f"RUN python -m pip install 'uv==0.8.22' && uv sync --frozen {groups}{extras}{scope}"
        target_python = "/app/.venv/bin/python"
    elif "poetry.lock" in files:
        lock_type = "poetry.lock"
        pins = _poetry_lock_pins(project, python_version)
        locked = {
            canonicalize_name(pin.split("==", 1)[0].strip("'")): pin.rsplit("==", 1)[1].strip("'")
            for pin in pins
        }
        bootstrap = ["python -m venv /opt/f_vra-uv", "/opt/f_vra-uv/bin/pip install 'uv==0.8.22'"]
        if locked.get("django-allauth") == "0.45.0":
            bootstrap.extend([
                "python -m pip install 'wheel<0.46' 'setuptools<70'",
                "python -m pip install --no-use-pep517 --no-deps 'django-allauth==0.45.0'",
            ])
            pins.remove("'django-allauth==0.45.0'")
        if locked.get("pyyaml") == "5.4.1":
            bootstrap.extend([
                "printf 'Cython<3\\n' > /tmp/build-constraints.txt",
                "PIP_CONSTRAINT=/tmp/build-constraints.txt python -m pip install --no-deps 'PyYAML==5.4.1'",
            ])
            pins.remove("'pyyaml==5.4.1'")
        install_lines = ["RUN " + " && ".join(bootstrap)]
        for start in range(0, len(pins), 30):
            install_lines.append(
                "RUN /opt/f_vra-uv/bin/uv pip install --python /usr/local/bin/python --no-deps "
                + " ".join(pins[start:start + 30])
            )
        install = "\n".join(install_lines)
        target_python = "python"
    elif "Pipfile.lock" in files:
        lock_type = "Pipfile.lock"
        install = "RUN python -m pip install 'pipenv==2025.0.4' && pipenv sync --system --deploy --dev"
        target_python = "python"
    else:
        requirements = files.get("requirements.txt")
        if requirements is not None:
            lock_type = "requirements.txt"
            install = "RUN python -m pip install -r requirements.txt"
        else:
            lock_type = "project-metadata"
            install = "RUN python -m pip install -e ."
        target_python = "python"
    # Both stages use bookworm, so the copied CPython 3.8 runtime has matching libc.
    jarvis_base = _pinned_base("python:3.8-slim-bookworm")
    target_base = _pinned_base(f"python:{python_version}-slim-bookworm")
    lines = [
        f"FROM {jarvis_base} AS jarvis-runtime",
        f"FROM {target_base}",
        "COPY --from=jarvis-runtime /usr/local /opt/jarvis-python",
        "COPY --from=jarvis-runtime /usr/lib/x86_64-linux-gnu/libexpat.so.1* /opt/jarvis-libs/",
        'ENV LD_LIBRARY_PATH="/opt/jarvis-libs"',
        "RUN apt-get update && apt-get install -y --no-install-recommends "
        + " ".join(BUILD_SYSTEM_PACKAGES)
        + " && rm -rf /var/lib/apt/lists/*",
        "WORKDIR /app",
        "COPY . /app",
    ]
    if prior_lock:
        if target_python.startswith("/app/.venv"):
            lines.append("RUN python -m venv --without-pip /app/.venv")
        install_python = target_python if target_python.startswith("/") else "/usr/local/bin/python"
        lines.append("RUN python -m venv /opt/uv-tool && /opt/uv-tool/bin/pip install 'uv==0.8.22'")
        pins = []
        local_distribution = ""
        pyproject = project / "pyproject.toml"
        if pyproject.is_file():
            metadata = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            local_distribution = canonicalize_name(str(
                (metadata.get("project") or {}).get("name")
                or ((metadata.get("tool") or {}).get("poetry") or {}).get("name")
                or ""
            ))
        for package in prior_lock.get("packages") or []:
            name, version = str(package.get("name") or ""), str(package.get("version") or "")
            if not name or not version:
                continue
            if local_distribution and canonicalize_name(name) == local_distribution:
                continue
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or not re.fullmatch(r"[A-Za-z0-9_.!+*-]+", version):
                raise ValueError(f"unsafe generated lock requirement: {name!r} {version!r}")
            pins.append(f"'{name}=={version}'")
        for start in range(0, len(pins), 30):
            lines.append(f"RUN /opt/uv-tool/bin/uv pip install --python {install_python} --no-deps " + " ".join(pins[start:start + 30]))
    else:
        lines.append(install)
    lines.extend([
        f'ENV F_VRA_TARGET_PYTHON="{target_python}"',
        'ENV F_VRA_JARVIS_PYTHON="/opt/jarvis-python/bin/python3.8"',
    ])
    dockerfile = "\n".join(lines) + "\n"
    lock_path = files.get(lock_type)
    lock_hash = hashlib.sha256(lock_path.read_bytes()).hexdigest() if lock_path else digest({"metadata": sorted(files)})
    return dockerfile, lock_type, lock_hash


def _python_version(project: Path) -> str:
    from f_vra.runtime.conda import select_python_version

    pyproject = project / "pyproject.toml"
    if pyproject.is_file():
        metadata = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        poetry = (((metadata.get("tool") or {}).get("poetry") or {}).get("dependencies") or {})
        raw = poetry.get("python") if isinstance(poetry, dict) else None
        constraint = str(raw.get("version") if isinstance(raw, dict) else raw or "").strip()
        exact = re.fullmatch(r"(\d+\.\d+(?:\.\d+)?)", constraint)
        lower = re.fullmatch(r"[\^~](\d+\.\d+)(?:\.\d+)?", constraint)
        if exact:
            return exact.group(1)
        if lower:
            return lower.group(1)
    return select_python_version(project, ["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"])


def _jarvis_version(jarvis_root: Path) -> str:
    result = subprocess.run(["git", "-C", str(jarvis_root), "rev-parse", "HEAD"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    return hashlib.sha256((jarvis_root / "tool" / "Jarvis" / "jarvis_cli.py").read_bytes()).hexdigest()


def _source_reason(package: dict[str, Any]) -> str:
    if package["has_python"]:
        return "SOURCE_AVAILABLE"
    if package["has_native"]:
        return "NATIVE_ONLY"
    if package["import_roots"]:
        return "SOURCE_NOT_INSTALLED"
    return "PACKAGE_MAPPING_FAILED"


def _locked_versions(project: Path, distribution: str) -> set[str]:
    """Return every version variant recorded for a distribution in the frozen lock."""
    normalized = canonicalize_name(distribution)
    uv_lock = project / "uv.lock"
    poetry_lock = project / "poetry.lock"
    if uv_lock.is_file():
        payload = tomllib.loads(uv_lock.read_text(encoding="utf-8"))
        return {
            str(row.get("version") or "") for row in payload.get("package") or []
            if canonicalize_name(str(row.get("name") or "")) == normalized
        }
    if poetry_lock.is_file():
        payload = tomllib.loads(poetry_lock.read_text(encoding="utf-8"))
        return {
            str(row.get("version") or "") for row in payload.get("package") or []
            if canonicalize_name(str(row.get("name") or "")) == normalized
        }
    return set()


def _function_anchor(package_id: str, qualified_name: str, provenance: str, bound: dict[str, Any]) -> tuple[VFAnchor | None, str]:
    status = str(bound.get("status") or "UNKNOWN_VF_MISMATCH")
    if status != "BOUND":
        return None, status
    return VFAnchor(
        package_id=package_id, module=str(bound["module"]),
        qualified_name=str(bound.get("qualified_name") or qualified_name),
        file=str(bound["file"]), start_line=int(bound["start_line"]),
        end_line=int(bound["end_line"]), function_hash=str(bound["function_hash"]),
        provenance=provenance,
    ), "BOUND"


class EnvironmentResolver:
    def __init__(self, repo_root: Path, dataset_dir: Path, jarvis_root: Path) -> None:
        self.repo_root = repo_root.resolve()
        self.dataset_dir = dataset_dir.resolve()
        self.jarvis_root = jarvis_root.resolve()
        self.backend_version = _jarvis_version(self.jarvis_root)
        self.protocol_sha256 = str(read_json(self.dataset_dir / "dataset.json").get("protocol_sha256") or "")

    def freeze(
        self, project: dict[str, Any], anchor_requests: list[dict[str, str]] | None = None,
        *, force_rebuild: bool = False,
    ) -> tuple[EnvironmentSnapshot, list[dict[str, Any]], dict[str, Any]]:
        project_root = self.repo_root / "data" / "raw" / "projects" / str(project["project_id"])
        python_version = _python_version(project_root)
        build_dir = self.dataset_dir / "images" / str(project["project_id"])
        build_dir.mkdir(parents=True, exist_ok=True)
        lock_path = build_dir / "experiment_lock.json"
        raw_prior_lock = read_json(lock_path) if lock_path.is_file() else None
        prior_lock = raw_prior_lock
        if prior_lock and (
            prior_lock.get("protocol_sha256") != self.protocol_sha256
            or prior_lock.get("resolver_version") != RESOLVER_VERSION
        ):
            prior_lock = None
        protocol_tag = (self.protocol_sha256 or "unversioned")[:8]
        tag = f"f_vra-exp:{str(project['snapshot_id'])[:12]}-{protocol_tag}"
        installed_path = build_dir / "installed_manifest.json"
        environment_path = build_dir / "environment.json"
        if prior_lock and not force_rebuild and installed_path.is_file() and environment_path.is_file():
            probe = read_json(installed_path)
            environment_payload = read_json(environment_path)
            image = subprocess.run(
                ["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
            if (
                image.returncode == 0
                and image.stdout.strip() == environment_payload.get("docker_image_digest")
                and prior_lock.get("probe_schema_version") == PROBE_SCHEMA_VERSION
                and digest(probe.get("packages") or []) == prior_lock.get("installed_distribution_manifest_hash")
            ):
                environment_payload.pop("env_id", None)
                environment = EnvironmentSnapshot(**environment_payload)
                write_json(build_dir / "image_build_event.json", {
                    "status": "RESUMED_FROZEN_ENVIRONMENT", "docker_image_digest": image.stdout.strip(),
                })
                return environment, probe["packages"], probe
        old_dockerfile = (build_dir / "Dockerfile").read_text(encoding="utf-8") if (build_dir / "Dockerfile").is_file() else ""
        dockerfile, lock_type, lock_hash = _dockerfile(project_root, python_version, prior_lock=prior_lock)
        dockerfile_path = build_dir / "Dockerfile"
        dockerfile_path.write_text(dockerfile, encoding="utf-8")
        (build_dir / "Dockerfile.dockerignore").write_text(".git\n.venv\n__pycache__\n*.pyc\n", encoding="utf-8")
        existing_image = subprocess.run(
            ["docker", "image", "inspect", tag, "--format", "{{.Id}}"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        reuse_identical_recipe = (
            not force_rebuild and prior_lock is None
            and old_dockerfile == dockerfile and existing_image.returncode == 0
            and bool(existing_image.stdout.strip())
        )
        if not reuse_identical_recipe:
            _run(["docker", "build", "--progress=plain", "--network", "default", "-f", str(dockerfile_path), "-t", tag, str(project_root)], timeout=7200)
        image_digest = _run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"])
        write_json(build_dir / "image_build_event.json", {
            "status": "REUSED_IDENTICAL_RECIPE" if reuse_identical_recipe else "BUILT",
            "docker_image_digest": image_digest,
            "dockerfile_sha256": hashlib.sha256(dockerfile.encode("utf-8")).hexdigest(),
        })
        requests_path = build_dir / "anchor_requests.json"
        write_json(requests_path, anchor_requests or [])
        target_python = _run(["docker", "run", "--rm", "--network=none", image_digest, "sh", "-c", 'printf "%s" "$F_VRA_TARGET_PYTHON"'])
        probe = json.loads(_run([
            "docker", "run", "--rm", "--network=none", "--cpus=8", "--memory=16g",
            "-v", f"{PROBE.resolve().as_posix()}:/probe.py:ro",
            "-v", f"{requests_path.resolve().as_posix()}:/anchors.json:ro", image_digest,
            "sh", "-c", f"{target_python} /probe.py /anchors.json",
        ]))
        if not probe.get("packages"):
            raise RuntimeError("target runtime contains no installed distributions")
        installed_hash = digest(probe["packages"])
        if prior_lock and prior_lock["installed_distribution_manifest_hash"] != installed_hash:
            old = {canonicalize_name(row["name"]): row for row in prior_lock.get("packages") or []}
            new = {canonicalize_name(row["name"]): row for row in probe["packages"]}
            changed = sorted(name for name in old.keys() | new.keys() if old.get(name) != new.get(name))
            write_json(build_dir / "manifest_diff.json", {
                "reason": "installed manifest changed for the same frozen project snapshot",
                "previous_hash": prior_lock["installed_distribution_manifest_hash"],
                "current_hash": installed_hash,
                "changed_distributions": changed,
                "probe_schema_version": probe.get("probe_schema_version", "unknown"),
            })
            raise RuntimeError("rebuild differs from frozen installed manifest; inspect manifest_diff.json")
        manifest_diff = build_dir / "manifest_diff.json"
        if manifest_diff.exists():
            manifest_diff.unlink()
        if not prior_lock:
            write_json(lock_path, {
                "installed_distribution_manifest_hash": installed_hash,
                "packages": probe["packages"], "lockfile_type": lock_type, "lockfile_hash": lock_hash,
                "probe_schema_version": probe.get("probe_schema_version", "unknown"),
                "protocol_sha256": self.protocol_sha256, "resolver_version": RESOLVER_VERSION,
            })
        environment = EnvironmentSnapshot(
            project_snapshot_id=str(project["snapshot_id"]), lockfile_type=lock_type,
            lockfile_hash=lock_hash, python_version=str(probe["python_version"]),
            platform=str(probe["platform"]), docker_image_digest=image_digest,
            installed_distribution_manifest_hash=installed_hash,
            generated_lock=lock_type in {"requirements.txt", "project-metadata"},
            resolver_version=RESOLVER_VERSION, resolution_date=datetime.now(timezone.utc).isoformat(),
        )
        write_json(build_dir / "installed_manifest.json", probe)
        write_json(build_dir / "environment.json", environment.model_dump(mode="json") | {"env_id": environment.env_id})
        return environment, probe["packages"], probe


def build_environments(
    resolver: EnvironmentResolver, *, project_ids: set[str] | None = None, limit: int = 0,
    force_rebuild: bool = False,
) -> dict[str, Any]:
    projects = read_parquet(resolver.dataset_dir / "projects.parquet")
    candidates = read_parquet(resolver.dataset_dir / "query_candidates.parquet")
    if project_ids:
        projects = [row for row in projects if row["project_id"] in project_ids]
    if limit:
        projects = projects[:limit]
    environment_rows: list[dict[str, Any]] = []
    package_rows: list[dict[str, Any]] = []
    query_rows: list[dict[str, Any]] = []
    environment_audit: list[dict[str, Any]] = []
    source_audit: list[dict[str, Any]] = []
    eligibility: list[dict[str, Any]] = []
    previous_eligibility = read_parquet(resolver.dataset_dir / "query_eligibility.parquet") if (resolver.dataset_dir / "query_eligibility.parquet").exists() else []
    expectation_path = resolver.dataset_dir / "affected_package_expectations.parquet"
    expectations = {
        (str(row["project_id"]), canonicalize_name(str(row["distribution"]))): row
        for row in (read_parquet(expectation_path) if expectation_path.exists() else [])
    }
    projects_with_previous_eligibility = {str(row.get("project_id")) for row in previous_eligibility}
    dataset_meta = read_json(resolver.dataset_dir / "dataset.json")
    config_hash = digest({
        "jarvis_mode": "EA", "precision": True, "ast_adapter": AST_ADAPTER_VERSION,
        "resolver_version": RESOLVER_VERSION, "build_system_packages": BUILD_SYSTEM_PACKAGES,
        "protocol_sha256": dataset_meta.get("protocol_sha256", ""),
    })
    for project in projects:
        project_candidates = [row for row in candidates if row["project_id"] == project["project_id"]]
        anchor_requests = [
            {"distribution": canonicalize_name(row["affected_distribution"]), "qualified_name": target}
            for row in project_candidates for target in row["target_vfs"]
        ]
        try:
            environment, packages, probe = resolver.freeze(project, anchor_requests, force_rebuild=force_rebuild)
        except Exception as exc:
            environment_audit.append({"project_id": project["project_id"], "status": "INSTALL_FAILURE", "detail": str(exc)})
            if str(project["project_id"]) not in projects_with_previous_eligibility:
                eligibility.extend({
                    "project_id": project["project_id"], "cve_id": candidate["cve_id"],
                    "candidate_id": candidate["candidate_id"], "env_id": "",
                    "package_installed": False, "affected_version": False,
                    "source_available": False, "vf_bound": False, "query_eligible": False,
                    "status": "ENVIRONMENT_NOT_READY",
                } for candidate in project_candidates)
            continue
        environment_rows.append(environment.model_dump(mode="json") | {"env_id": environment.env_id, "project_id": project["project_id"]})
        environment_audit.append({"project_id": project["project_id"], "env_id": environment.env_id, "status": "READY", "distribution_count": len(packages)})
        installed = {canonicalize_name(item["name"]): item for item in packages}
        direct_names = set()
        project_root = resolver.repo_root / "data" / "raw" / "projects" / str(project["project_id"])
        pyproject = project_root / "pyproject.toml"
        if pyproject.is_file():
            from f_vra.analysis.dependencies.parsers import direct_names_from_pyproject

            direct_names.update(direct_names_from_pyproject(pyproject, include_dev=False))
        for requirement_file in project_root.glob("requirements*.txt"):
            for line in requirement_file.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    direct_names.add(canonicalize_name(Requirement(line).name))
                except Exception:
                    continue
        id_by_name = {}
        for package in packages:
            name = canonicalize_name(package["name"])
            identity = PackageID(
                distribution=name, version=str(package["version"]), source_hash=str(package["source_hash"]),
                python_abi=str(probe["python_abi"]), platform_tag=",".join(package.get("wheel_tags") or []) or str(probe["platform"]),
                wheel_hash=str(package.get("wheel_hash") or ""),
                backend_version=resolver.backend_version, ast_adapter_version=AST_ADAPTER_VERSION,
                analysis_config_hash=config_hash,
            )
            id_by_name[name] = identity.package_id
            dependencies = []
            for raw in package["requires_dist"]:
                try:
                    dependencies.append(canonicalize_name(Requirement(raw).name))
                except Exception:
                    continue
            package_rows.append(package | identity.model_dump() | {
                "package_id": identity.package_id, "env_id": environment.env_id,
                "project_id": project["project_id"], "direct": name in direct_names,
                "dependencies": sorted(set(dependencies)), "source_status": _source_reason(package),
            })
            source_audit.append({"project_id": project["project_id"], "env_id": environment.env_id, "package_id": identity.package_id, "distribution": name, "status": _source_reason(package)})
        for candidate in project_candidates:
            name = canonicalize_name(candidate["affected_distribution"])
            package = installed.get(name)
            eligibility_row = {
                "project_id": project["project_id"], "cve_id": candidate["cve_id"],
                "candidate_id": candidate["candidate_id"],
                "env_id": environment.env_id,
                "package_installed": package is not None,
                "affected_version": False, "source_available": False,
                "vf_bound": False, "query_eligible": False,
                "annotated_version": str(expectations.get((str(project["project_id"]), name), {}).get("version") or ""),
                "installed_version": str(package.get("version") or "") if package else "",
            }
            if package is None:
                status = "AFFECTED_PACKAGE_NOT_INSTALLED"
            elif package["version"] not in candidate["affected_versions_claimed"]:
                expected = eligibility_row["annotated_version"]
                variants = _locked_versions(project_root, name)
                status = (
                    "ENVIRONMENT_LOCK_VARIANT_MISMATCH"
                    if expected in variants and str(package["version"]) in variants
                    else "ENVIRONMENT_VERSION_MISMATCH"
                )
            else:
                status = "eligible"
                eligibility_row["affected_version"] = True
                eligibility_row["source_available"] = _source_reason(package) == "SOURCE_AVAILABLE"
            if package is None or status != "eligible":
                eligibility.append(eligibility_row | {"status": status})
                continue
            anchors = []
            if not eligibility_row["source_available"]:
                status = _source_reason(package)
            for qualified in candidate["target_vfs"]:
                anchor_key = name + "|" + qualified
                anchor, anchor_status = _function_anchor(id_by_name[name], qualified, candidate["vf_provenance"], probe["anchors"].get(anchor_key, {}))
                if anchor is not None:
                    anchors.append(anchor.model_dump(mode="json"))
                if anchor_status != "BOUND":
                    status = anchor_status
            eligibility_row["vf_bound"] = bool(anchors) and len(anchors) == len(candidate["target_vfs"])
            eligibility_row["query_eligible"] = status == "eligible" and eligibility_row["source_available"]
            query_id = digest((project["snapshot_id"], environment.env_id, candidate["cve_id"]))
            query_rows.append({
                "query_id": query_id, "project_id": project["project_id"],
                "candidate_id": candidate["candidate_id"],
                "project_snapshot_id": project["snapshot_id"], "env_id": environment.env_id,
                "cve_id": candidate["cve_id"], "affected_package_id": id_by_name[name],
                "affected_distribution": name, "affected_version": package["version"],
                "dependency_type": "direct" if name in direct_names else "transitive",
                "vf_set": anchors, "eligibility_reason": status,
            })
            eligibility.append(eligibility_row | {"query_id": query_id, "status": status})
    successful_projects = {row["project_id"] for row in environment_rows}
    selected_projects = {row["project_id"] for row in projects}
    for name, rows in (
        ("environments", environment_rows), ("packages", package_rows), ("queries", query_rows),
        ("environment_audit", environment_audit), ("package_source_audit", source_audit), ("query_eligibility", eligibility),
    ):
        path = resolver.dataset_dir / f"{name}.parquet"
        if (project_ids or limit) and path.exists():
            previous = read_parquet(path)
            touched = selected_projects if name == "environment_audit" else successful_projects
            rows = [row for row in previous if row.get("project_id") not in touched] + rows
        write_parquet(path, rows)
    return {"environment_count": len(environment_rows), "package_count": len(package_rows), "query_count": len(query_rows)}
