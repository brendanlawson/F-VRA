"""One JARVIS graph pipeline for project and package fragments."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from typing import Any

from f_vra.evaluation.contracts import UnknownReason


DRIVER = Path(__file__).with_name("jarvis_driver.py")


class BackendFailure(RuntimeError):
    def __init__(self, reason: UnknownReason, detail: str):
        super().__init__(detail)
        self.reason = reason


class JarvisAdapter:
    def __init__(
        self, jarvis_root: Path, *, fragment_timeout_s: int = 300, project_timeout_s: int = 300,
        entrypoint_ignore_dirs: tuple[str, ...] = (), entrypoint_types: tuple[str, ...] = ("main", "cli", "web"),
    ) -> None:
        self.jarvis_root = jarvis_root.resolve()
        self.fragment_timeout_s = fragment_timeout_s
        self.project_timeout_s = project_timeout_s
        self.entrypoint_ignore_dirs = entrypoint_ignore_dirs
        self.entrypoint_types = set(entrypoint_types)

    def _invoke(self, image: str, source: str, package_base: str, roots: tuple[str, ...], *, timeout: int, inventory_only: bool = False, modules: tuple[str, ...] = (), ignore_dirs: tuple[str, ...] = ()) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="f_vra-eval-") as temp:
            output = Path(temp) / "graph.json"
            inventory_output = Path(temp) / "inventory.json"
            docker_prefix = [
                "docker", "run", "--rm", "--network=none", "--cpus=8", "--memory=16g",
                "-v", f"{self.jarvis_root.as_posix()}:/jarvis:ro",
                "-v", f"{DRIVER.resolve().as_posix()}:/driver.py:ro",
                "-v", f"{Path(temp).resolve().as_posix()}:/output",
            ]
            common = [
                "/driver.py", "--jarvis-root", "/jarvis", "--source", source,
                "--package-base", package_base,
            ]
            started = time.perf_counter()

            def run(command: list[str], phase: str) -> None:
                remaining = max(1.0, timeout - (time.perf_counter() - started))
                try:
                    result = subprocess.run(
                        command, capture_output=True, text=True, encoding="utf-8",
                        errors="replace", timeout=remaining,
                    )
                except subprocess.TimeoutExpired as exc:
                    raise BackendFailure(UnknownReason.TIMEOUT, f"{phase} timed out after {timeout}s total") from exc
                if result.returncode:
                    raise BackendFailure(
                        UnknownReason.BACKEND,
                        (result.stderr or result.stdout or f"{phase} failed")[-3000:],
                    )

            inventory_command = [
                *docker_prefix, image, "sh", "-c", 'exec "$F_VRA_TARGET_PYTHON" "$@"', "sh",
                *common, "--inventory-only", "--output", "/output/inventory.json",
            ]
            for module in modules:
                inventory_command.extend(["--module", module])
            for directory in ignore_dirs:
                inventory_command.extend(["--ignore-dir", directory])
            run(inventory_command, "AST inventory")
            if not inventory_output.is_file():
                raise BackendFailure(UnknownReason.BACKEND, "AST inventory produced no output")
            inventory_payload = json.loads(inventory_output.read_text(encoding="utf-8"))
            if inventory_only:
                inventory_payload["wall_clock_ms"] = (time.perf_counter() - started) * 1000
                return inventory_payload

            command = [
                *docker_prefix, image, "/opt/jarvis-python/bin/python3.8", *common,
                "--inventory-input", "/output/inventory.json", "--output", "/output/graph.json",
            ]
            for root in roots:
                command.extend(["--root", root])
            for module in modules:
                command.extend(["--module", module])
            for directory in ignore_dirs:
                command.extend(["--ignore-dir", directory])
            run(command, "JARVIS")
            if not output.is_file():
                raise BackendFailure(UnknownReason.BACKEND, "JARVIS produced no graph output")
            payload = json.loads(output.read_text(encoding="utf-8"))
            payload["cpu_time_ms"] = float(payload.get("cpu_time_ms") or 0) + float(inventory_payload.get("cpu_time_ms") or 0)
            payload["peak_rss_mb"] = max(float(payload.get("peak_rss_mb") or 0), float(inventory_payload.get("peak_rss_mb") or 0))
            payload["wall_clock_ms"] = (time.perf_counter() - started) * 1000
            return payload

    def project_graph(self, env: dict[str, Any], project_root: Path) -> dict[str, Any]:
        from f_vra.analysis.project.entrypoints import scan_project

        entrypoints = scan_project(project_root, ignore_dirs=set(self.entrypoint_ignore_dirs))
        entrypoints = [node for node in entrypoints if node.entry_type.value in self.entrypoint_types]
        files = sorted({Path(node.file_path).resolve() for node in entrypoints if Path(node.file_path).is_file()})
        if not files:
            return {
                "adjacency": {}, "boundary_edges": {}, "api_aliases": {}, "functions": [],
                "functions_analyzed": 0, "unique_functions_analyzed": 0,
                "analyzed_functions": [], "call_edges_materialized": 0,
                "cpu_time_ms": 0.0, "wall_clock_ms": 0.0, "peak_rss_mb": 0.0,
                "parse_errors": [], "entrypoint_modules": [], "usage_index": [],
                "frontier_complete": False, "incomplete_reason": "NO_ELIGIBLE_ENTRYPOINT",
            }
        modules = tuple(f"/app/{path.relative_to(project_root).as_posix()}" for path in files)
        graph = self._invoke(
            str(env["docker_image_digest"]), "/app", "/app", (),
            timeout=self.project_timeout_s, modules=modules, ignore_dirs=self.entrypoint_ignore_dirs,
        )
        graph["entrypoint_modules"] = list(modules)
        active_callers = set(graph.get("analyzed_functions") or ()) | set(graph.get("adjacency") or {})
        graph["usage_index"] = sorted({
            target
            for caller, targets in (graph.get("boundary_edges") or {}).items()
            if caller in active_callers
            for target in targets
        })
        graph["frontier_complete"] = not bool(graph.get("parse_errors"))
        return graph

    def inventory(self, package: dict[str, Any], env: dict[str, Any]) -> list[str]:
        roots = package.get("import_root_paths") or {}
        functions = set()
        for _root, source in roots.items():
            if not source:
                continue
            base = str(PurePosixPath(source).parent)
            payload = self._invoke(str(env["docker_image_digest"]), source, base, (), timeout=self.fragment_timeout_s, inventory_only=True)
            functions.update(payload["functions"])
            functions.update(payload["api_aliases"])
        return sorted(functions)

    def fragment(self, package: dict[str, Any], root: str, env: dict[str, Any]) -> dict[str, Any]:
        source_roots = package.get("import_root_paths") or {}
        top = root.removeprefix("src.").split(".", 1)[0]
        source = source_roots.get(top)
        if not source:
            raise BackendFailure(UnknownReason.SOURCE, f"source unavailable for {root}")
        base = str(PurePosixPath(source).parent)
        graph = self._invoke(str(env["docker_image_digest"]), source, base, (root.removeprefix("src."),), timeout=self.fragment_timeout_s)
        requested = root.removeprefix("src.")
        if graph.get("requested_roots") and not graph.get("resolved_roots"):
            raise BackendFailure(UnknownReason.UNRESOLVED, f"JARVIS could not resolve demanded root {root}")
        adjacency: dict[str, list[str]] = {str(key): list(value) for key, value in graph["adjacency"].items()}
        for caller, targets in graph["boundary_edges"].items():
            adjacency.setdefault(caller, []).extend(targets)
        alias = graph["api_aliases"].get(root.removeprefix("src."), root.removeprefix("src."))
        queue = [(alias, [alias])]
        seen = {alias}
        inner: dict[str, list[str]] = {}
        outer: dict[str, list[str]] = {}
        while queue:
            current, path = queue.pop(0)
            for target in sorted(set(adjacency.get(current, []))):
                candidate = [*path, target]
                if target.split(".", 1)[0] == top:
                    inner.setdefault(target, candidate)
                    if target not in seen:
                        seen.add(target)
                        queue.append((target, candidate))
                else:
                    outer.setdefault(target, candidate)
        return {
            "root": root, "inner_paths": inner, "outer_paths": outer,
            "functions_analyzed": graph["functions_analyzed"],
            "unique_functions_analyzed": graph["unique_functions_analyzed"],
            "analyzed_functions": graph["analyzed_functions"],
            "call_edges_materialized": graph["call_edges_materialized"] + sum(len(v) for v in graph["boundary_edges"].values()),
            "wall_clock_ms": graph["wall_clock_ms"], "cpu_time_ms": graph["cpu_time_ms"],
            "peak_rss_mb": graph["peak_rss_mb"], "parse_errors": graph["parse_errors"],
        }
