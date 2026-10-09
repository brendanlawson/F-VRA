"""Pinned subprocess entry point run inside an experiment image.

The file is mounted read-only. JARVIS source is also mounted read-only; no
third-party files are patched to collect analysis counters.
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import resource
import sys
import time
from collections import defaultdict


def _source_files(source: pathlib.Path, extra_excluded: set[str] | None = None) -> list[pathlib.Path]:
    if source.is_file():
        return [source]
    excluded = {".git", ".venv", "venv", "tests", "test", "build", "dist", "__pycache__"}
    excluded.update(extra_excluded or ())
    return sorted(path for path in source.rglob("*.py") if not excluded.intersection(path.relative_to(source).parts))


def _module(path: pathlib.Path, package_base: pathlib.Path) -> str:
    relative = path.relative_to(package_base).with_suffix("")
    parts = list(relative.parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _ast_inventory(source: pathlib.Path, package_base: pathlib.Path, internal_roots: set[str], extra_excluded: set[str] | None = None) -> dict:
    functions: set[str] = set()
    boundary: dict[str, set[str]] = defaultdict(set)
    aliases: dict[str, str] = {}
    parse_errors: list[str] = []
    for path in _source_files(source, extra_excluded):
        module = _module(path, package_base)
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except (SyntaxError, OSError, UnicodeError) as exc:
            parse_errors.append(f"{path}:{exc}")
            continue
        imports: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        imports[alias.asname] = alias.name
                    else:
                        top = alias.name.split(".", 1)[0]
                        imports[top] = top
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    package_parts = module.split(".") if path.name == "__init__.py" else module.split(".")[:-1]
                    prefix = package_parts[: max(0, len(package_parts) - node.level + 1)]
                    base = ".".join(part for part in [*prefix, node.module or ""] if part)
                else:
                    base = node.module or ""
                for alias in node.names:
                    if alias.name != "*":
                        imports[alias.asname or alias.name] = ".".join(part for part in (base, alias.name) if part)
        class Visitor(ast.NodeVisitor):
            def __init__(self) -> None:
                self.scope: list[str] = []

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                self.scope.append(node.name)
                self.generic_visit(node)
                self.scope.pop()

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                name = ".".join([module, *self.scope, node.name])
                functions.add(name)
                self.scope.append(node.name)
                self.generic_visit(node)
                self.scope.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Call(self, node: ast.Call) -> None:
                parts = []
                cursor = node.func
                while isinstance(cursor, ast.Attribute):
                    parts.insert(0, cursor.attr)
                    cursor = cursor.value
                if isinstance(cursor, ast.Name) and cursor.id in imports:
                    target = ".".join([imports[cursor.id], *parts])
                    if target.split(".", 1)[0] not in internal_roots:
                        caller = ".".join([module, *self.scope])
                        boundary[caller].add(target)
                self.generic_visit(node)

        Visitor().visit(tree)
        if path.name == "__init__.py":
            for node in tree.body:
                if isinstance(node, ast.ImportFrom):
                    for alias in node.names:
                        public = ".".join([module, alias.asname or alias.name])
                        target = imports.get(alias.asname or alias.name)
                        if target and target.split(".", 1)[0] in internal_roots:
                            aliases[public] = target
    return {
        "functions": sorted(functions),
        "boundary_edges": {key: sorted(values) for key, values in sorted(boundary.items())},
        "api_aliases": aliases,
        "parse_errors": parse_errors,
    }


def main() -> None:
    started_cpu = time.process_time()
    parser = argparse.ArgumentParser()
    parser.add_argument("--jarvis-root", type=pathlib.Path, required=True)
    parser.add_argument("--source", type=pathlib.Path, required=True)
    parser.add_argument("--package-base", type=pathlib.Path, required=True)
    parser.add_argument("--root", action="append", default=[])
    parser.add_argument("--module", action="append", default=[])
    parser.add_argument("--ignore-dir", action="append", default=[])
    parser.add_argument("--inventory-only", action="store_true")
    parser.add_argument("--inventory-input", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    all_files = _source_files(args.source, set(args.ignore_dir))
    files = [pathlib.Path(value) for value in args.module] if args.module else all_files
    # The AST boundary classifier must know every local import root even when
    # JARVIS demand starts from a smaller entrypoint file set.
    internal_roots = {(_module(path, args.package_base).split(".", 1)[0]) for path in all_files}
    inventory = (
        json.loads(args.inventory_input.read_text(encoding="utf-8"))
        if args.inventory_input
        else _ast_inventory(args.source, args.package_base, internal_roots, set(args.ignore_dir))
    )
    for key in (
        "adjacency", "functions_analyzed", "unique_functions_analyzed",
        "analyzed_functions", "call_edges_materialized", "cpu_time_ms", "peak_rss_mb",
    ):
        inventory.pop(key, None)
    if args.inventory_only:
        payload = {"adjacency": {}, "functions_analyzed": 0, "unique_functions_analyzed": 0, "analyzed_functions": [], "call_edges_materialized": 0, **inventory}
    else:
        sys.path.insert(0, str(args.jarvis_root / "tool" / "Jarvis"))
        from jarvis import CallGraphGenerator  # type: ignore
        from processing.extProcessor import ExtProcessor  # type: ignore
        from utils.constants import FUN_DEF  # type: ignore
        import formats  # type: ignore

        analyzed: list[str] = []
        original = ExtProcessor.pushStack

        def tracked(self, callDefi, *positional, **keywords):
            if callDefi is not None and callDefi.get_type() == FUN_DEF:
                analyzed.append(callDefi.get_ns())
            return original(self, callDefi, *positional, **keywords)

        ExtProcessor.pushStack = tracked
        roots = [inventory["api_aliases"].get(root, root) for root in args.root]
        generator = CallGraphGenerator([str(path) for path in files], str(args.package_base), decy=False, moduleEntry=roots, precision=True)
        generator.analyze()
        adjacency = formats.Simple(generator).generate()
        payload = {
            "adjacency": adjacency,
            "functions_analyzed": len(analyzed),
            "unique_functions_analyzed": len(set(analyzed)),
            "analyzed_functions": sorted(set(analyzed)),
            "requested_roots": args.root,
            "resolved_roots": [root for root in roots if root in inventory["functions"]],
            "call_edges_materialized": sum(len(values) for values in adjacency.values()),
            **inventory,
        }
    payload["cpu_time_ms"] = (time.process_time() - started_cpu) * 1000
    payload["peak_rss_mb"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    args.output.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


if __name__ == "__main__":
    main()
