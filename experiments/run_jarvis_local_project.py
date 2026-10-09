from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from f_vra.analysis.callgraph.jarvis_backend import (  # noqa: E402
    JarvisOptions,
    build_jarvis_project_graph,
)


def _resolve(path_value: str | Path) -> Path:
    path = Path(path_value)
    return path if path.is_absolute() else REPO_ROOT / path


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _project_from_manifest(manifest: dict[str, Any], project_id: str) -> dict[str, Any]:
    for project in manifest.get("projects", []):
        if project.get("id") == project_id:
            if not project.get("enabled", True):
                raise RuntimeError(f"project is disabled in local manifest: {project_id}")
            return project
    raise RuntimeError(f"project is not listed in local manifest: {project_id}")


def _default_jarvis_root() -> Path | None:
    env_value = os.getenv("F_VRA_JARVIS_ROOT")
    if env_value:
        return _resolve(env_value)
    bundled = REPO_ROOT / "vendor" / "pythonJaRvis" / "Jarvis"
    return bundled if (bundled / "tool" / "Jarvis" / "jarvis_cli.py").exists() else None


def _summarize_graph(project: dict[str, Any], graph: Any, usage_index: list[Any]) -> dict[str, Any]:
    external_edges = [edge for edge in graph.edges if getattr(edge.callee, "is_external", False)]
    return {
        "project": {
            "id": project["id"],
            "name": project.get("name", project["id"]),
            "repo_url": project.get("repo_url", ""),
            "commit": project.get("commit", ""),
            "path": project["path"],
        },
        "analysis": {
            "mode": graph.metadata.get("analysis_mode", "jarvis"),
            "jarvis_mode": graph.metadata.get("jarvis_mode", ""),
            "jarvis_scope": graph.metadata.get("jarvis_scope", ""),
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "external_edges": len(external_edges),
            "usage_index_count": len(usage_index),
            "entry_points": graph.metadata.get("entry_points", []),
            "entrypoint_fallback": graph.metadata.get("jarvis_scope_meta", {}).get("fallback", False),
        },
        "usage_index": [
            {
                "identity": node.identity_string,
                "target_module": node.target_module,
                "target_name": node.target_name,
            }
            for node in usage_index
        ],
    }


def run(args: argparse.Namespace) -> int:
    manifest_path = _resolve(args.local_projects)
    manifest = _load_json(manifest_path)
    project = _project_from_manifest(manifest, args.project_id)
    project_root = _resolve(project["path"])
    if not project_root.exists():
        raise RuntimeError(
            f"project path does not exist: {project_root}. "
            "Clone only the project listed in configs/local_projects.json first."
        )

    jarvis_root = _resolve(args.jarvis_root) if args.jarvis_root else _default_jarvis_root()
    if jarvis_root is None:
        raise RuntimeError("Jarvis root not found; set F_VRA_JARVIS_ROOT or pass --jarvis-root")

    graph, usage_index = build_jarvis_project_graph(
        project_root,
        JarvisOptions(
            jarvis_root=jarvis_root,
            runner=args.runner,
            scope=args.scope,
            mode=args.mode,
            timeout_s=args.timeout,
            pip_install=args.pip_install,
        ),
    )
    output = _resolve(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(_summarize_graph(project, graph, usage_index), indent=2),
        encoding="utf-8",
    )
    print(f"PASS jarvis {project['id']}")
    print(f"report: {output.relative_to(REPO_ROOT)}")
    print(f"nodes: {len(graph.nodes)}")
    print(f"edges: {len(graph.edges)}")
    print(f"usage_index: {len(usage_index)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Jarvis on one project from local_projects.json.")
    parser.add_argument("--project-id", default="alerta")
    parser.add_argument("--local-projects", type=Path, default=REPO_ROOT / "configs" / "local_projects.json")
    parser.add_argument("--jarvis-root", type=Path, default=None)
    parser.add_argument("--runner", choices=["docker", "local"], default="docker")
    parser.add_argument("--scope", choices=["entrypoints", "whole-project", "whole_project", "all"], default="entrypoints")
    parser.add_argument("--mode", choices=["EA", "DW", "AW"], default="EA")
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--pip-install", default="")
    parser.add_argument("--output", type=Path, default=REPO_ROOT / "results" / "metrics" / "jarvis_alerta_project_graph.json")
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
