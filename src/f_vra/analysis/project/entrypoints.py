"""
project_scanner.scanner
═══════════════════════
Static entry-point discovery for a target Python project.

This is the first stage of the Application-Centered Call Graph pipeline. It
walks a project tree, parses every `.py` file with the stdlib ``ast`` module
(it NEVER imports or executes user code) and reports the functions that can
act as *entry points* into the application:

    a) functions invoked inside an ``if __name__ == "__main__":`` guard
    b) CLI commands           -> @app.command(), @click.command(), ...
    c) web routes             -> @app.get(...), @router.post(...), @app.route(...)
    d) pytest test functions  -> def test_*(...)

Framework decorators are matched by the *method name* on the router object
(``command`` / ``get`` / ``route`` / ...) because a purely static scan cannot
know the real type of the ``app`` / ``router`` object that owns them.

Files that fail to parse (syntax errors, null bytes, ...) are logged and
skipped so a single broken module never aborts the scan.
"""
from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Union

from f_vra.core.models import EntryPointType, FunctionNode

logger = logging.getLogger(__name__)

PathLike = Union[str, "os.PathLike[str]"]

# ══════════════════════════════════════════════════════════════════
# CONFIGURATION
# ══════════════════════════════════════════════════════════════════

# Directory names never worth descending into. Hidden directories (name
# starts with ".") are pruned in addition to these, which also covers
# ".venv", ".git", ".tox", etc.
DEFAULT_IGNORE_DIRS: Set[str] = {
    "venv", "env", "virtualenv", "__pycache__", "node_modules",
    "site-packages", "build", "dist", "var", "project_local",
}

# Decorator "verbs" (the attribute after the router object) that mark a
# function as a CLI command or a web route.
CLI_DECORATOR_NAMES: Set[str] = {"command", "group", "callback"}
WEB_DECORATOR_NAMES: Set[str] = {
    "get", "post", "put", "delete", "patch", "options", "head",
    "route", "api_route", "websocket", "websocket_route",
}

# pytest's default `python_functions` convention.
TEST_PREFIX = "test_"


# ══════════════════════════════════════════════════════════════════
# AST HELPERS
# ══════════════════════════════════════════════════════════════════

def _is_main_guard(test: ast.expr) -> bool:
    """True for ``__name__ == "__main__"`` (either operand order)."""
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    left, right = test.left, test.comparators[0]
    return ((_is_name(left, "__name__") and _is_str(right, "__main__")) or
            (_is_name(right, "__name__") and _is_str(left, "__main__")))


def _is_name(node: ast.expr, ident: str) -> bool:
    return isinstance(node, ast.Name) and node.id == ident


def _is_str(node: ast.expr, value: str) -> bool:
    return isinstance(node, ast.Constant) and node.value == value


def _called_name(call: ast.Call) -> Optional[str]:
    """Bare-name target of a call, e.g. ``main`` for ``main()``.

    Attribute calls (``app.run()``, ``sys.exit()``) return ``None`` — only
    direct calls can refer to a function defined in the same module.
    """
    return call.func.id if isinstance(call.func, ast.Name) else None


def _decorator_name(dec: ast.expr) -> Optional[str]:
    """The verb of a decorator: ``command`` for ``@app.command()`` / ``@app.command``."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return None


# ══════════════════════════════════════════════════════════════════
# AST VISITOR
# ══════════════════════════════════════════════════════════════════

_FuncDef = Union[ast.FunctionDef, ast.AsyncFunctionDef]


class _EntryPointVisitor(ast.NodeVisitor):
    """
    Collects entry-point functions from a single parsed module.

    A scope stack of enclosing class names lets the visitor build a qualified
    name (``module.Class.method``) and tell module-level functions (the only
    valid ``__main__`` targets) from nested ones.
    """

    def __init__(self, file_path: str, module: str) -> None:
        self.file_path = file_path
        self.module = module
        self._classes: List[str] = []              # enclosing class names
        self._func_depth = 0                       # >0 => nested inside a function
        self._found: Dict[int, FunctionNode] = {}  # def-lineno -> node (de-dups)
        self._module_funcs: Dict[str, _FuncDef] = {}  # module-level def name -> node
        self._main_calls: Set[str] = set()         # names called in any __main__ guard

    # -- public ----------------------------------------------------

    def collect(self, tree: ast.Module) -> List[FunctionNode]:
        self.visit(tree)
        self._resolve_main_guard()
        return [self._found[line] for line in sorted(self._found)]

    # -- traversal -------------------------------------------------

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._classes.append(node.name)
        self.generic_visit(node)
        self._classes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._handle_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._handle_function(node)

    def visit_If(self, node: ast.If) -> None:
        if _is_main_guard(node.test):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    name = _called_name(sub)
                    if name:
                        self._main_calls.add(name)
        self.generic_visit(node)

    # -- detection -------------------------------------------------

    def _handle_function(self, node: _FuncDef) -> None:
        at_module_level = not self._classes and self._func_depth == 0
        if at_module_level:
            self._module_funcs.setdefault(node.name, node)

        etype = self._classify(node, at_module_level)
        if etype is not None:
            self._record(node.name, node.lineno, self._qualified(node.name), etype)

        self._func_depth += 1
        self.generic_visit(node)
        self._func_depth -= 1

    def _classify(self, node: _FuncDef, at_module_level: bool) -> Optional[EntryPointType]:
        # An explicit framework decorator is the strongest signal.
        for dec in node.decorator_list:
            verb = _decorator_name(dec)
            if verb in WEB_DECORATOR_NAMES:
                return EntryPointType.WEB
            if verb in CLI_DECORATOR_NAMES:
                return EntryPointType.CLI
        # pytest collects module-level `test_*` functions and `test_*` methods
        # of `Test*` classes — but not functions nested inside other functions.
        if node.name.startswith(TEST_PREFIX) and self._func_depth == 0:
            if at_module_level or self._classes[-1].startswith("Test"):
                return EntryPointType.TEST
        return None

    def _resolve_main_guard(self) -> None:
        """Emit a node for each `__main__`-guard call that resolves to a local def."""
        for name in self._main_calls:
            node = self._module_funcs.get(name)
            if node is not None:
                self._record(name, node.lineno, self._qualified(name),
                             EntryPointType.MAIN)

    # -- bookkeeping -----------------------------------------------

    def _record(self, name: str, lineno: int, qualified: str,
                etype: EntryPointType) -> None:
        # Keyed by def line so a function matched by several rules is reported
        # once; the first (strongest) classification wins.
        self._found.setdefault(lineno, FunctionNode(
            file_path=self.file_path,
            function_name=name,
            qualified_name=qualified,
            line_number=lineno,
            entry_type=etype,
        ))

    def _qualified(self, name: str) -> str:
        return ".".join(p for p in ([self.module] + self._classes + [name]) if p)


# ══════════════════════════════════════════════════════════════════
# PROJECT SCANNER
# ══════════════════════════════════════════════════════════════════

class EntryPointScanner:
    """
    Recursively scan a Python project for entry-point functions.

    Usage:
        scanner = EntryPointScanner("path/to/project")
        entry_points = scanner.scan()   # -> List[FunctionNode]
    """

    def __init__(self, target_project_path: PathLike, *,
                 ignore_dirs: Optional[Set[str]] = None) -> None:
        self.root = Path(target_project_path).resolve()
        self.ignore_dirs = set(DEFAULT_IGNORE_DIRS)
        if ignore_dirs:
            self.ignore_dirs |= set(ignore_dirs)
        self.entry_points: List[FunctionNode] = []

    def scan(self) -> List[FunctionNode]:
        if not self.root.exists():
            raise FileNotFoundError(f"Target project path does not exist: {self.root}")
        if not self.root.is_dir():
            raise NotADirectoryError(f"Target project path is not a directory: {self.root}")

        files = list(self._iter_py_files())
        logger.info("[ProjectScanner] Scanning %d .py file(s) under %s",
                    len(files), self.root)

        self.entry_points = []
        for path in files:
            self.entry_points.extend(self._scan_file(path))

        self.entry_points.sort(key=lambda fn: (fn.file_path, fn.line_number))
        logger.info("[ProjectScanner] Found %d entry point(s)", len(self.entry_points))
        return self.entry_points

    # -- file discovery --------------------------------------------

    def _iter_py_files(self) -> Iterator[Path]:
        # os.walk lets us prune ignored subtrees in place, so we never even
        # descend into a virtualenv full of third-party packages.
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if not self._is_ignored_dir(d)]
            for name in filenames:
                if name.endswith(".py"):
                    yield Path(dirpath) / name

    def _is_ignored_dir(self, name: str) -> bool:
        return name.startswith(".") or name in self.ignore_dirs

    # -- per-file parse --------------------------------------------

    def _scan_file(self, path: Path) -> List[FunctionNode]:
        try:
            source = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            logger.warning("[ProjectScanner] Cannot read %s: %s", path, exc)
            return []

        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            logger.warning("[ProjectScanner] Skipping %s (syntax error: %s)", path, exc)
            return []
        except (ValueError, RecursionError) as exc:
            # ValueError: source contains null bytes; RecursionError: pathological nesting.
            logger.warning("[ProjectScanner] Skipping %s (parse failure: %s)", path, exc)
            return []

        try:
            return _EntryPointVisitor(str(path), self._module_name(path)).collect(tree)
        except Exception as exc:  # last-resort guard: one file must never kill the scan
            logger.warning("[ProjectScanner] Skipping %s (visitor error: %s)", path, exc)
            return []

    def _module_name(self, path: Path) -> str:
        """Dotted module path relative to the project root (best effort)."""
        try:
            rel = path.resolve().relative_to(self.root)
        except ValueError:
            return path.stem
        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)


def scan_project(target_project_path: PathLike, *,
                 ignore_dirs: Optional[Set[str]] = None) -> List[FunctionNode]:
    """Convenience wrapper: scan a project and return its entry-point FunctionNodes."""
    return EntryPointScanner(target_project_path, ignore_dirs=ignore_dirs).scan()
