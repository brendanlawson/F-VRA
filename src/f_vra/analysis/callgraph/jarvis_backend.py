from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from f_vra.core.models import CallEdge, CallGraph, ExternalNode, FunctionNode
from f_vra.core.paths import resolve_workspace_executable, resolve_workspace_path
from f_vra.analysis.project.entrypoints import scan_project


def _default_jarvis_python() -> str:
    """Prefer the repository-local Python 3.8 runtime required by JARVIS."""
    candidates = (
        Path(".tools/jarvis-py38/python.exe"),
        Path(".tools/jarvis-py38/bin/python"),
    )
    for candidate in candidates:
        if candidate.exists():
            return str(candidate.resolve())
    return sys.executable


@dataclass(frozen=True)
class JarvisOptions:
    jarvis_root: Path | None = None
    mode: str = "EA"
    runner: str = "docker"
    python_executable: str = field(default_factory=_default_jarvis_python)
    timeout_s: int = 240
    scope: str = "entrypoints"
    precision: bool = True
    pip_install: str = ""
    # The upstream CLI calls this option ``--entry_point``.  Keep the
    # selection explicit in the adapter instead of approximating demand mode
    # by filtering an exhaustive graph after JARVIS has finished.
    entry_point_names: tuple[str, ...] = ()


def build_jarvis_project_graph(project_root: Path, options: JarvisOptions | None = None) -> tuple[CallGraph, list[ExternalNode]]:
    """Build a F-VRA project graph by running the official Jarvis artifact externally."""
    options = options or JarvisOptions()
    root = Path(project_root).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Project root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Project root is not a directory: {root}")
    jarvis_root = (options.jarvis_root or _env_jarvis_root())
    if jarvis_root is None:
        raise RuntimeError("Jarvis root is required; pass --jarvis-root or set F_VRA_JARVIS_ROOT")
    jarvis_root = Path(jarvis_root).resolve()
    jarvis_cli = jarvis_root / "tool" / "Jarvis" / "jarvis_cli.py"
    if not jarvis_cli.exists():
        raise RuntimeError(f"Jarvis CLI not found: {jarvis_cli}")

    modules, scope_meta = _select_modules(root, options.scope)
    if not modules:
        graph = CallGraph(metadata={"analysis_mode": "jarvis", "jarvis_warning": "no Python files found"})
        return graph, []

    entry_point_names = list(options.entry_point_names or scope_meta.get("entrypoint_names", []))
    raw_graph, run_meta = _run_jarvis(
        root, jarvis_root, jarvis_cli, modules, options,
        entry_point_names=entry_point_names if options.scope == "entrypoints" else [],
    )
    graph, usage_index = _convert_adjacency_graph(
        root,
        raw_graph,
        resolver="jarvis",
        reason="Resolved by Jarvis static call graph backend.",
    )
    graph.metadata.update(
        {
            "analysis_mode": "jarvis",
            "project_mode": f"jarvis_{options.mode}_{options.scope}",
            "entry_points": [str(path) for path in modules],
            "jarvis_mode": options.mode,
            "jarvis_scope": options.scope,
            "jarvis_scope_meta": scope_meta,
            "jarvis_entry_point_names": entry_point_names,
            "jarvis": run_meta,
            "function_type_graphs": {},
            "unresolved_calls": [],
            "candidate_edges": [],
            "reanalyzed_contexts": [],
        }
    )
    return graph, usage_index


def build_jarvis_package_graph(package_root: Path, options: JarvisOptions | None = None) -> CallGraph:
    """Build an exhaustive package graph by running the official Jarvis artifact externally."""
    options = options or JarvisOptions(scope="whole-project")
    root = Path(package_root).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Package root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Package root is not a directory: {root}")
    jarvis_root = (options.jarvis_root or _env_jarvis_root())
    if jarvis_root is None:
        raise RuntimeError("Jarvis root is required; pass --jarvis-root or set F_VRA_JARVIS_ROOT")
    jarvis_root = Path(jarvis_root).resolve()
    jarvis_cli = jarvis_root / "tool" / "Jarvis" / "jarvis_cli.py"
    if not jarvis_cli.exists():
        raise RuntimeError(f"Jarvis CLI not found: {jarvis_cli}")

    modules, scope_meta = _select_modules(root, "whole-project")
    if not modules:
        return CallGraph(metadata={"analysis_mode": "jarvis", "jarvis_warning": "no Python files found"})

    raw_graph, run_meta = _run_jarvis(root, jarvis_root, jarvis_cli, modules, options, entry_point_names=[])
    graph, _usage_index = _convert_adjacency_graph(
        root,
        raw_graph,
        resolver="jarvis",
        reason="Resolved by Jarvis static call graph backend.",
    )
    graph.metadata.update(
        {
            "analysis_mode": "jarvis",
            "package_mode": f"jarvis_{options.mode}_whole-project",
            "entry_points": [str(path) for path in modules],
            "jarvis_mode": options.mode,
            "jarvis_scope": "whole-project",
            "jarvis_scope_meta": scope_meta,
            "jarvis": run_meta,
            "function_type_graphs": {},
            "unresolved_calls": [],
            "candidate_edges": [],
            "reanalyzed_contexts": [],
        }
    )
    return graph


def _env_jarvis_root() -> Path | None:
    value = os.getenv("F_VRA_JARVIS_ROOT")
    if value:
        root = resolve_workspace_path(value)
        return root if root.exists() else None
    # The engine is vendored in the repository; the environment variable is
    # still supported as an override for experiments using another checkout.
    bundled = Path(__file__).resolve().parents[4] / "vendor" / "pythonJaRvis" / "Jarvis"
    return bundled if bundled.exists() else None


def _select_modules(root: Path, scope: str) -> tuple[list[Path], dict[str, Any]]:
    all_files = sorted(path for path in root.rglob("*.py") if _is_source_file(path))
    if scope in {"whole-project", "whole_project", "all"}:
        return all_files, {"scope": "whole-project", "entrypoint_count": 0, "fallback": False}
    if scope != "entrypoints":
        raise ValueError(f"unknown Jarvis scope: {scope}")
    entrypoints = scan_project(root)
    files = sorted({Path(item.file_path).resolve() for item in entrypoints if item.file_path})
    selected = [path for path in files if path.exists() and _is_source_file(path)]
    if selected:
        return selected, {
            "scope": "entrypoints",
            "entrypoint_count": len(entrypoints),
            "entrypoint_names": sorted({item.qualified_name or item.function_name for item in entrypoints}),
            "entrypoint_files": [str(path) for path in selected],
            "fallback": False,
        }
    return all_files, {
        "scope": "entrypoints",
        "entrypoint_count": 0,
        "entrypoint_names": [],
        "entrypoint_files": [],
        "fallback": True,
        "warning": "no entry points found; fell back to all project Python files",
    }


def _run_jarvis(
    project_root: Path,
    jarvis_root: Path,
    jarvis_cli: Path,
    modules: list[Path],
    options: JarvisOptions,
    *,
    entry_point_names: list[str],
) -> tuple[dict[str, list[str]], dict[str, Any]]:
    tmp_root = Path(os.getenv("F_VRA_TMP_DIR", ".tmp")).resolve()
    tmp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="f_vra-jarvis-", dir=str(tmp_root)) as tmp:
        output = Path(tmp) / "callgraph.json"
        if options.runner == "docker":
            command = _docker_command(
                project_root, jarvis_root, jarvis_cli, modules, output, options,
                entry_point_names,
            )
            cwd = _common_mount([project_root, jarvis_root, output.parent])
            env = None
        elif options.runner == "local":
            command = [
                resolve_workspace_executable(options.python_executable),
                str(jarvis_cli),
                *[str(path) for path in modules],
                "--package",
                str(project_root),
            ]
            if options.precision:
                command.append("--precision")
            if options.mode.upper() in {"DW", "AW"}:
                command.append("--decy")
            if entry_point_names:
                command.extend(["--entry_point", *entry_point_names])
            command.extend(["-o", str(output)])
            cwd = jarvis_root
            env = os.environ.copy()
        else:
            raise RuntimeError(f"unknown Jarvis runner: {options.runner}")

        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd),
                env=env,
                text=True,
                capture_output=True,
                timeout=options.timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Jarvis timed out after {options.timeout_s}s") from exc
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or "no output").strip()
            raise RuntimeError(f"Jarvis failed with exit code {completed.returncode}: {detail}")
        if not output.exists():
            raise RuntimeError("Jarvis completed but did not write a callgraph JSON file")
        data = json.loads(output.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise RuntimeError("Jarvis output is not an adjacency object")
        return (
            {_normalize_adjacency_name(str(key)): [_normalize_adjacency_name(str(item)) for item in value] for key, value in data.items() if isinstance(value, list)},
            {
                "runner": options.runner,
                "mode": options.mode,
                "precision": options.precision,
                "entry_point_names": entry_point_names,
                "dependency_traversal": options.mode.upper() in {"DW", "AW"},
                "jarvis_root": str(jarvis_root),
                "timeout_s": options.timeout_s,
                "module_count": len(modules),
                "pip_install": options.pip_install,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            },
        )


def _docker_command(
    project_root: Path,
    jarvis_root: Path,
    jarvis_cli: Path,
    modules: list[Path],
    output: Path,
    options: JarvisOptions,
    entry_point_names: list[str],
) -> list[str]:
    mount_root = _common_mount([project_root, jarvis_root, output.parent])
    modules_file = output.parent / "jarvis-modules.txt"
    modules_file.write_text(
        "\n".join(_docker_path(path, mount_root) for path in modules),
        encoding="utf-8",
    )
    wrapper = output.parent / "jarvis-wrapper.py"
    wrapper.write_text(
        """
import argparse
import os
import runpy
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--jarvis-cli", required=True)
parser.add_argument("--modules-file", required=True)
parser.add_argument("--package", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--precision", action="store_true")
parser.add_argument("--decy", action="store_true")
parser.add_argument("--entry-point", nargs="*")
args = parser.parse_args()

modules = [
    line.strip()
    for line in open(args.modules_file, encoding="utf-8")
    if line.strip()
]
sys.argv = [
    args.jarvis_cli,
    *modules,
    "--package",
    args.package,
    "-o",
    args.output,
]
if args.precision:
    sys.argv.append("--precision")
if args.decy:
    sys.argv.append("--decy")
if args.entry_point:
    sys.argv.extend(["--entry_point", *args.entry_point])
os.chdir(os.path.dirname(args.jarvis_cli))
sys.path.insert(0, os.path.dirname(args.jarvis_cli))
runpy.run_path(args.jarvis_cli, run_name="__main__")
""".lstrip(),
        encoding="utf-8",
    )
    python_cmd = [
        "python",
        _docker_path(wrapper, mount_root),
        "--jarvis-cli",
        _docker_path(jarvis_cli, mount_root),
        "--modules-file",
        _docker_path(modules_file, mount_root),
        "--package",
        _docker_path(project_root, mount_root),
        "--output",
        _docker_path(output, mount_root),
    ]
    if options.precision:
        python_cmd.append("--precision")
    if options.mode.upper() in {"DW", "AW"}:
        python_cmd.append("--decy")
    if entry_point_names:
        python_cmd.extend(["--entry-point", *entry_point_names])
    if options.pip_install:
        shell = f"pip install -q {options.pip_install} && " + " ".join(_sh_quote(part) for part in python_cmd)
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{mount_root.as_posix()}:/workspace",
            "-w",
            _docker_path(jarvis_root, mount_root),
            "python:3.8-slim",
            "sh",
            "-c",
            shell,
        ]
    return [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{mount_root.as_posix()}:/workspace",
        "-w",
        _docker_path(jarvis_root, mount_root),
        "python:3.8-slim",
        *python_cmd,
    ]


def _common_mount(paths: list[Path]) -> Path:
    resolved = [str(path.resolve()) for path in paths]
    return Path(os.path.commonpath(resolved))


def _docker_path(path: Path, mount_root: Path) -> str:
    rel = path.resolve().relative_to(mount_root.resolve()).as_posix()
    return "/workspace" if not rel else f"/workspace/{rel}"


def _sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


@dataclass(frozen=True)
class _SymbolInfo:
    file_path: str
    line_number: int = 0
    signature: str = ""
    source_snippet: str = ""


@dataclass(frozen=True)
class _AugmentedExternalEdge:
    caller: str
    callee: str
    file_path: str
    line_number: int
    call_expr: str


def _normalize_adjacency_name(name: str) -> str:
    return name.replace("\\", ".").replace("/", ".")


def _reachable_adjacency(adjacency: dict[str, list[str]], roots: set[str]) -> dict[str, list[str]]:
    reachable: set[str] = set()
    stack = [root for root in roots if root in adjacency]
    while stack:
        node = stack.pop()
        if node in reachable:
            continue
        reachable.add(node)
        stack.extend(callee for callee in adjacency.get(node, []) if callee not in reachable)
    return {
        caller: [callee for callee in callees if callee in reachable or callee not in adjacency]
        for caller, callees in adjacency.items()
        if caller in reachable
    }


def _is_source_file(path: Path) -> bool:
    parts = set(path.parts)
    return not bool(parts & {"__pycache__", ".git", ".venv", "venv", "env", ".tox", "site-packages"})


def _convert_adjacency_graph(
    root: Path,
    adjacency: dict[str, list[str]],
    *,
    resolver: str,
    reason: str,
) -> tuple[CallGraph, list[ExternalNode]]:
    modules = _project_modules(root)
    symbols = _collect_symbol_info(root)
    graph = CallGraph()
    nodes: dict[str, FunctionNode] = {}
    usage: dict[str, ExternalNode] = {}
    usage_before_filter: set[str] = set()
    project_module_names = set(modules)

    def get_node(name: str) -> FunctionNode:
        existing = nodes.get(name)
        if existing is not None:
            return existing
        if _is_internal_name(name, project_module_names):
            node = _internal_node(name, modules, symbols)
        else:
            node = _external_node(name)
        nodes[name] = node
        graph.add_node(node)
        return node

    for caller_name, callees in adjacency.items():
        if not _is_internal_name(caller_name, project_module_names):
            continue
        caller = get_node(caller_name)
        for callee_name in callees:
            callee = get_node(callee_name)
            graph.edges.append(
                CallEdge(
                    caller=caller,
                    callee=callee,
                    edge_type="confirmed_static",
                    confidence=0.95,
                    resolver=resolver,
                    reason=reason,
                )
            )
            if isinstance(callee, ExternalNode):
                if callee.identity_string:
                    usage_before_filter.add(callee.identity_string)
                if _is_dependency_usage(callee):
                    usage.setdefault(callee.identity_string, callee)

    edge_keys = {
        (_node_name(edge.caller), _node_name(edge.callee))
        for edge in graph.edges
    }
    allowed_callers = {
        name
        for name, node in nodes.items()
        if not node.is_external and _is_internal_name(name, project_module_names)
    }
    augmented_edges = _augment_external_usage_edges(root, modules, allowed_callers)
    kept_augmented: list[dict[str, Any]] = []
    for item in augmented_edges:
        if (item.caller, item.callee) in edge_keys:
            continue
        caller = get_node(item.caller)
        callee = get_node(item.callee)
        if not isinstance(callee, ExternalNode):
            continue
        edge = CallEdge(
            caller=caller,
            callee=callee,
            edge_type="confirmed_static_augmented",
            confidence=0.9,
            resolver="jarvis_external_usage_ast",
            reason="Recovered statically resolvable external dependency call omitted by Jarvis output.",
            call_expr=item.call_expr,
            line_number=item.line_number,
        )
        graph.edges.append(edge)
        edge_keys.add((item.caller, item.callee))
        usage_before_filter.add(callee.identity_string)
        if _is_dependency_usage(callee):
            usage.setdefault(callee.identity_string, callee)
            kept_augmented.append(
                {
                    "caller": item.caller,
                    "callee": item.callee,
                    "file_path": item.file_path,
                    "line_number": item.line_number,
                    "call_expr": item.call_expr,
                }
            )

    graph.metadata.update(
        {
            "jarvis_external_usage_augmented_count": len(kept_augmented),
            "jarvis_external_usage_augmented_edges": kept_augmented,
            "jarvis_usage_index_before_filter": sorted(usage_before_filter),
            "jarvis_usage_index_after_filter": sorted(usage),
            "jarvis_usage_augmentation_warnings": [],
        }
    )
    return graph, [usage[key] for key in sorted(usage)]


def _node_name(node: FunctionNode) -> str:
    return node.qualified_name or node.function_name


def _augment_external_usage_edges(
    root: Path,
    modules: dict[str, str],
    allowed_callers: set[str],
) -> list[_AugmentedExternalEdge]:
    project_roots = {module.split(".", 1)[0] for module in modules}
    out: list[_AugmentedExternalEdge] = []
    for module, file_path in modules.items():
        path = Path(file_path)
        try:
            source = path.read_text(encoding="utf-8-sig")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        module_aliases = _external_import_aliases(tree.body, project_roots)
        out.extend(
            _augment_external_usage_in_body(
                tree.body,
                prefix=module,
                file_path=str(path),
                module_aliases=module_aliases,
                project_roots=project_roots,
                allowed_callers=allowed_callers,
            )
        )
    return out


def _augment_external_usage_in_body(
    body: Iterable[ast.stmt],
    *,
    prefix: str,
    file_path: str,
    module_aliases: dict[str, str],
    project_roots: set[str],
    allowed_callers: set[str],
) -> list[_AugmentedExternalEdge]:
    out: list[_AugmentedExternalEdge] = []
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            caller = f"{prefix}.{node.name}"
            if caller in allowed_callers:
                aliases = dict(module_aliases)
                aliases.update(_external_import_aliases(_non_nested_statements(node.body), project_roots))
                for call in _non_nested_calls(node.body):
                    target = _resolve_external_call_target(call, aliases, project_roots)
                    if target:
                        out.append(
                            _AugmentedExternalEdge(
                                caller=caller,
                                callee=target,
                                file_path=file_path,
                                line_number=getattr(call, "lineno", 0),
                                call_expr=_call_expr(call),
                            )
                        )
            out.extend(
                _augment_external_usage_in_body(
                    node.body,
                    prefix=caller,
                    file_path=file_path,
                    module_aliases=module_aliases,
                    project_roots=project_roots,
                    allowed_callers=allowed_callers,
                )
            )
        elif isinstance(node, ast.ClassDef):
            out.extend(
                _augment_external_usage_in_body(
                    node.body,
                    prefix=f"{prefix}.{node.name}",
                    file_path=file_path,
                    module_aliases=module_aliases,
                    project_roots=project_roots,
                    allowed_callers=allowed_callers,
                )
            )
    return out


def _non_nested_statements(body: Iterable[ast.stmt]) -> list[ast.stmt]:
    statements: list[ast.stmt] = []
    stack = list(body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.stmt):
            statements.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return statements


def _non_nested_calls(body: Iterable[ast.stmt]) -> list[ast.Call]:
    calls: list[ast.Call] = []
    stack = list(body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        if isinstance(node, ast.Call):
            calls.append(node)
        stack.extend(ast.iter_child_nodes(node))
    return calls


def _external_import_aliases(body: Iterable[ast.stmt], project_roots: set[str]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if not _is_external_dependency_name(name, project_roots):
                    continue
                aliases[alias.asname or name.split(".", 1)[0]] = name
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            module = node.module
            for alias in node.names:
                if alias.name == "*":
                    continue
                target = f"{module}.{alias.name}"
                if not _is_external_dependency_name(target, project_roots):
                    continue
                aliases[alias.asname or alias.name] = target
    return aliases


def _resolve_external_call_target(
    call: ast.Call,
    aliases: dict[str, str],
    project_roots: set[str],
) -> str:
    parts = _attribute_parts(call.func)
    if not parts:
        return ""
    base = parts[0]
    if base not in aliases:
        return ""
    target = ".".join([aliases[base], *parts[1:]])
    return target if _is_external_dependency_name(target, project_roots) else ""


def _attribute_parts(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        parent = _attribute_parts(node.value)
        return [*parent, node.attr] if parent else []
    return []


def _is_external_dependency_name(name: str, project_roots: set[str]) -> bool:
    root = name.split(".", 1)[0] if name else ""
    if not root or root in project_roots:
        return False
    if root in {"<builtin>", "builtins"} or root.startswith("<"):
        return False
    if root in getattr(sys, "stdlib_module_names", set()):
        return False
    if "." not in name:
        return True
    return _is_dependency_usage(_external_node(name))


def _call_expr(call: ast.Call) -> str:
    try:
        return ast.unparse(call)
    except Exception:
        parts = _attribute_parts(call.func)
        return ".".join(parts) + "(...)"


def _project_modules(root: Path) -> dict[str, str]:
    modules: dict[str, str] = {}
    for path in root.rglob("*.py"):
        if not _is_source_file(path):
            continue
        rel = path.relative_to(root).with_suffix("")
        parts = list(rel.parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        if not parts:
            continue
        module = ".".join(parts)
        modules[module] = str(path)
    return modules


def _collect_symbol_info(root: Path) -> dict[str, _SymbolInfo]:
    symbols: dict[str, _SymbolInfo] = {}
    for module, file_path in _project_modules(root).items():
        path = Path(file_path)
        try:
            source = path.read_text(encoding="utf-8-sig")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        lines = source.splitlines()
        symbols[module] = _SymbolInfo(file_path=str(path))
        _collect_defs(tree.body, module, str(path), lines, symbols)
    return symbols


def _collect_defs(
    body: Iterable[ast.stmt],
    prefix: str,
    file_path: str,
    lines: list[str],
    symbols: dict[str, _SymbolInfo],
) -> None:
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = f"{prefix}.{node.name}"
            symbols[name] = _SymbolInfo(
                file_path=file_path,
                line_number=node.lineno,
                signature=_signature(node),
                source_snippet=lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else "",
            )
            _collect_defs(node.body, name, file_path, lines, symbols)
        elif isinstance(node, ast.ClassDef):
            name = f"{prefix}.{node.name}"
            symbols[name] = _SymbolInfo(
                file_path=file_path,
                line_number=node.lineno,
                source_snippet=lines[node.lineno - 1].strip() if 0 < node.lineno <= len(lines) else "",
            )
            _collect_defs(node.body, name, file_path, lines, symbols)


def _signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = [arg.arg for arg in node.args.posonlyargs + node.args.args]
    if node.args.vararg:
        args.append("*" + node.args.vararg.arg)
    args.extend(arg.arg for arg in node.args.kwonlyargs)
    if node.args.kwarg:
        args.append("**" + node.args.kwarg.arg)
    return f"{node.name}({', '.join(args)})"


def _is_internal_name(name: str, modules: set[str]) -> bool:
    return any(name == module or name.startswith(module + ".") for module in modules)


def _internal_node(name: str, modules: dict[str, str], symbols: dict[str, _SymbolInfo]) -> FunctionNode:
    module = _longest_module_prefix(name, modules) or name.split(".", 1)[0]
    info = symbols.get(name) or symbols.get(module) or _SymbolInfo(file_path=modules.get(module, ""))
    return FunctionNode(
        file_path=info.file_path,
        function_name=name,
        qualified_name=name,
        line_number=info.line_number,
        module=module,
        scope=name.rsplit(".", 1)[0] if "." in name else "",
        signature=info.signature,
        source_snippet=info.source_snippet,
    )


def _longest_module_prefix(name: str, modules: dict[str, str]) -> str | None:
    matches = [module for module in modules if name == module or name.startswith(module + ".")]
    if not matches:
        return None
    return max(matches, key=len)


def _external_node(name: str) -> ExternalNode:
    target_module, target_name = _split_external_name(name)
    return ExternalNode(
        file_path="",
        function_name=name,
        qualified_name=name,
        target_module=target_module,
        target_name=target_name,
    )


def _is_dependency_usage(node: ExternalNode) -> bool:
    if not node.identity_string:
        return False
    if not node.target_module:
        return False
    if node.target_module.startswith("<"):
        return False
    if node.target_module in {"<builtin>", "builtins"}:
        return False
    root = node.target_module.split(".", 1)[0] if node.target_module else node.target_name.split(".", 1)[0]
    if root in getattr(sys, "stdlib_module_names", set()):
        return False
    return True


def _split_external_name(name: str) -> tuple[str, str]:
    if "." not in name:
        return "", name
    module, target = name.rsplit(".", 1)
    return module, target
