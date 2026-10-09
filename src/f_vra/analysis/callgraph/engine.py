"""
callgraph_builder.library_builder
══════════════════════════════════
Library-Centered Call Graph construction — the **G_L** (library call graph)
side of the VRA / F-VRA framework.

Where ``project_builder`` walks *outward from application entry points* (lazy,
reachability-driven), this module does the opposite: it **exhaustively** scans an
entire third-party library (TPL) and reconstructs the most precise call graph it
can for *every* function and method the library defines. That graph later lets us
ask "does a vulnerable library function lie on a path reachable from the API the
application actually calls?".

Two cooperating layers implement the engine — a *generate-then-prune* pipeline:

  * **Layer 1 — :class:`ASTCandidateGenerator` (broad net / high recall).**
    Pure-syntactic. For a call ``x.m()`` it knows nothing about the type of ``x``,
    so it conservatively emits a *tentative* edge to **every** in-scope class that
    defines a method named ``m``. This over-approximates: recall is ~100 %, but
    precision is poor (many spurious edges).

  * **Layer 2 — :class:`AndersenPointsToAnalyzer` (fine filter / flow-sensitive).**
    The "brain". It re-walks each function maintaining a flow-sensitive
    :class:`PointsToState` (``pt(x) = {TypeA, TypeB}``) and applies **strong
    updates** on unconditional assignments (``x = Dog()`` ⇒ ``pt(x) = {Dog}``,
    *overwriting* — not merging — any prior binding). At each call site it uses
    the points-to set of the receiver to **prune** the spurious Layer-1 edges:
    if ``pt(x) = {Dog}`` then the tentative edge to ``Cat.m`` is dropped.

  * **Orchestrator — :class:`LibraryAnalyzer`.** Builds a whole-library index,
    drives Layer 1 then Layer 2 over every definition, and assembles the final
    :class:`~f_vra.core.models.CallGraph`. The shared construction pipeline
    also hosts the future :meth:`CallGraphConstructionPipeline.resolve_dynamic_call`
    oracle hook (a no-op stub for now)
    that will eventually disambiguate genuinely dynamic dispatch (``getattr`` &
    friends) that neither static layer can resolve.

Hard rules for this engine (same robustness contract as ``project_builder``):
  * **Never execute library code.** Analysis is 100 % static ``ast`` parsing.
  * **Never crash on bad input.** Third-party code is read with ``utf-8-sig`` and
    every parse / per-definition analysis is wrapped so one unreadable or
    syntactically-broken module can never abort the whole build.
  * **Reuse the core models** (:class:`FunctionNode`, :class:`CallEdge`,
    :class:`CallGraph`) rather than inventing parallel ones.

Identity note
-------------
``FunctionNode`` identity is ``(normpath(file_path), function_name)``. A single
library file routinely defines many same-named methods (``Dog.run`` and
``Cat.run`` in one module), so for **methods** this engine sets
``function_name = "Class.method"`` (e.g. ``"Dog.run"``) to keep their identities
distinct, while ``qualified_name`` carries the full dotted path
(``pkg.mod.Dog.run``). Module-level functions keep their bare name. This is a
deliberate, documented divergence from ``project_builder`` (which deals in bare
names because it resolves one reachable target at a time).
"""
from __future__ import annotations

import ast
import logging
import os
import symtable as py_symtable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union

from f_vra.core.models import (
    CallEdge,
    CallGraph,
    CandidateEdge,
    EntryPointType,
    ExternalNode,
    FunctionNode,
    UnresolvedCall,
)
from f_vra.analysis.callgraph.type_graph import FunctionTypeGraph

logger = logging.getLogger(__name__)

PathLike = Union[str, "os.PathLike[str]"]
CANDIDATE_FANOUT_CAP = 20

# Subtrees that never hold the library's own first-party source. We still scan a
# library exhaustively, but we skip vendored deps / build artefacts / caches so
# the graph reflects *this* library rather than everything bundled beside it.
IGNORE_DIRS = {
    "venv", "env", "virtualenv", "__pycache__", "node_modules",
    "site-packages", "build", "dist", ".tox", ".eggs", "tests", "test",
}

_FuncDef = Union[ast.FunctionDef, ast.AsyncFunctionDef]

# A points-to set is the set of (fully-qualified) class names a variable may
# refer to at a given program point. The empty / absent state means "top":
# unknown — could be anything (so Layer 2 must not prune on it).
PointsToSet = Set[str]
PointsToState = Dict[str, PointsToSet]


# ══════════════════════════════════════════════════════════════════
# SAFE PARSING  (third-party code is hostile to assumptions)
# ══════════════════════════════════════════════════════════════════

def _safe_parse(path: Path, skipped_files: Optional[List[dict]] = None) -> Optional[ast.Module]:
    """Parse *path* with ``ast``; return ``None`` (and log) on any failure.

    Mirrors ``project_builder._safe_parse`` — uses ``utf-8-sig`` so BOM-prefixed
    sources read cleanly, and swallows every failure mode a random TPL file can
    throw (unreadable, wrong encoding, null bytes, syntax error, pathological
    nesting) so the exhaustive scan never aborts mid-library.
    """
    try:
        source = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("[LibGraph] Cannot read %s: %s", path, exc)
        if skipped_files is not None:
            skipped_files.append({"file_path": str(path), "reason": "read_error", "detail": str(exc)})
        return None

    try:
        return ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        logger.warning("[LibGraph] Skipping %s (syntax error: %s)", path, exc)
        if skipped_files is not None:
            skipped_files.append(
                {
                    "file_path": str(path),
                    "reason": "syntax_error",
                    "line_number": getattr(exc, "lineno", 0) or 0,
                    "detail": str(exc),
                }
            )
        return None
    except (ValueError, RecursionError) as exc:
        # ValueError: null bytes in source; RecursionError: pathological nesting.
        logger.warning("[LibGraph] Skipping %s (parse failure: %s)", path, exc)
        if skipped_files is not None:
            skipped_files.append({"file_path": str(path), "reason": "parse_failure", "detail": str(exc)})
        return None


def _safe_symtable(path: Path) -> Optional[py_symtable.SymbolTable]:
    """Build Python's lexical symbol table for *path*, returning ``None`` safely."""
    try:
        source = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        logger.warning("[LibGraph] Cannot read symbols from %s: %s", path, exc)
        return None

    try:
        return py_symtable.symtable(source, str(path), "exec")
    except (SyntaxError, ValueError, RecursionError) as exc:
        logger.warning("[LibGraph] Skipping symbols for %s: %s", path, exc)
        return None


# ══════════════════════════════════════════════════════════════════
# INDEX DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════

@dataclass
class ClassInfo:
    """A class discovered in the library and the methods it directly defines.

    ``methods`` maps a method's *simple* name (``run``) to the prebuilt
    :class:`FunctionNode` for it, so candidate generation and the worklist share
    one canonical node per method (identity stays consistent across call sites).

    ``base_classes`` holds the parent classes *as written* in the ``ClassDef``
    bases (e.g. ``"Base"`` or ``"animals.Base"``). They are stored raw because a
    base name can only be resolved to a concrete :class:`ClassInfo` once the
    *whole* library is indexed and the child's import scope is known — that
    resolution happens lazily in :meth:`LibraryIndex.iter_bases`.
    """
    name: str                                   # simple name, e.g. "Dog"
    qualified: str                              # dotted, e.g. "pkg.animals.Dog"
    file_path: Path
    methods: Dict[str, FunctionNode] = field(default_factory=dict)
    base_classes: List[str] = field(default_factory=list)   # parent names as written


@dataclass
class ModuleScope:
    """Everything visible *inside one source file* that we can resolve a call to.

    Built in a second pass once every class/function in the library is known, so
    imports can be resolved to first-party :class:`ClassInfo` / :class:`FunctionNode`
    objects. Third-party / stdlib imports simply fail to resolve and are ignored.
    """
    file_path: Path
    module_dotted: str
    # Classes visible by the name used in *this* file (local defs + imported).
    classes: Dict[str, ClassInfo] = field(default_factory=dict)
    # Classes physically defined in this file (used to iterate own methods).
    local_classes: Dict[str, ClassInfo] = field(default_factory=dict)
    # Module-level functions defined in this file.
    local_funcs: Dict[str, FunctionNode] = field(default_factory=dict)
    # Functions pulled in by ``from mod import func``.
    imported_funcs: Dict[str, FunctionNode] = field(default_factory=dict)
    # Module aliases for ``import a.b as m`` / ``import a`` -> dotted module path,
    # enabling ``m.func()`` and ``m.Class()`` resolution.
    module_aliases: Dict[str, str] = field(default_factory=dict)
    # ── Cross-TPL boundary tracking ────────────────────────────────────────
    # External (third-party / stdlib) module aliases that do NOT resolve to this
    # library's own source: bound name -> external dotted module. Drives
    # ``requests.get()`` / ``serving.run_simple()`` to ExternalNode edges.
    external_modules: Dict[str, str] = field(default_factory=dict)
    # External symbols imported via ``from mod import sym``: bound name ->
    # (external module, symbol). Drives a bare ``sym()`` to an ExternalNode edge.
    external_funcs: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    # Module-level literal type facts, especially callable registries such as
    # ``HANDLERS = {"x": handle}``, reused inside function bodies.
    global_types: Dict[str, PointsToSet] = field(default_factory=dict)


@dataclass
class Candidate:
    """One tentative call edge emitted by Layer 1, awaiting Layer-2 judgement.

    ``prunable`` marks edges that Layer 2 may filter using points-to (i.e. the
    ``x.m()`` method-dispatch edges). Direct function / constructor calls have a
    single statically-known target, so ``prunable=False`` keeps them verbatim.
    """
    callee: FunctionNode
    owner: Optional[str]            # qualified class owning the method (prunable edges)
    base_var: Optional[str]        # receiver variable name in ``x.m()`` (else None)
    call_node: ast.Call
    prunable: bool
    edge_type: str = "confirmed_static"
    confidence: float = 1.0
    resolver: str = "static"
    reason: str = ""


class LazyMethodCandidates:
    """Lazy broad-net candidates for an object-method call.

    The exhaustive dispatch set is intentionally conservative, but retaining a
    ``Candidate`` object for every visible class at every ``x.m()`` site can
    multiply into millions of short-lived objects in large packages.  Keep the
    indexed target pairs and materialize one candidate only while the call site
    is being resolved.  This preserves the same Layer-1 candidate semantics
    without retaining the cartesian product in ``ASTCandidateGenerator.sites``.
    """

    def __init__(self, index: "LibraryIndex", scope: ModuleScope,
                 method: str, call_node: ast.Call, base_var: str) -> None:
        self.index = index
        self.scope = scope
        self.method = method
        self.call_node = call_node
        self.base_var = base_var

    def __bool__(self) -> bool:
        return bool(self.index.method_dispatch_targets(self.scope, self.method))

    def __iter__(self) -> Iterator[Candidate]:
        for owner, callee in self.index.method_dispatch_targets(self.scope, self.method):
            yield Candidate(
                callee,
                owner=owner.qualified,
                base_var=self.base_var,
                call_node=self.call_node,
                prunable=True,
            )


@dataclass
class FunctionSummary:
    param_types: Dict[str, PointsToSet] = field(default_factory=dict)
    return_types: PointsToSet = field(default_factory=set)
    call_edges: List[dict] = field(default_factory=list)
    external_edges: List[dict] = field(default_factory=list)
    unresolved_calls: List[dict] = field(default_factory=list)
    evidence: List[dict] = field(default_factory=list)
    context_signature: str = "default"
    function_type_graph: Optional[FunctionTypeGraph] = None


EXTERNAL_CALL_RETURN_TYPES: Dict[str, PointsToSet] = {
    "sqlite3.connect": {"external:sqlite3.Connection"},
}

EXTERNAL_METHOD_RETURN_TYPES: Dict[Tuple[str, str], Optional[PointsToSet]] = {
    ("sqlite3.Connection", "execute"): {"external:sqlite3.Cursor"},
    ("sqlite3.Cursor", "fetchall"): {"external:builtins.list"},
    ("sqlite3.Connection", "close"): set(),
}


def _dotted_name(expr: ast.expr) -> Optional[str]:
    """Flatten a ``Name`` / ``Attribute`` chain to a dotted string, else ``None``.

    ``Base`` -> ``"Base"``; ``animals.Base`` -> ``"animals.Base"``. Complex base
    expressions (``Generic[T]``, ``mixin_factory()``) flatten to ``None`` and are
    simply not treated as resolvable parent classes.
    """
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        head = _dotted_name(expr.value)
        return f"{head}.{expr.attr}" if head else None
    return None


def _literal_string_arg(call: ast.Call, index: int) -> Optional[str]:
    if len(call.args) <= index:
        return None
    value = call.args[index]
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return None


def _make_external_node(module: str, name: str, line: int = 0) -> ExternalNode:
    """Build the boundary marker for a statically-known call into another library.

    External targets are *exact* (the symbol was explicitly imported), so the
    resulting :class:`ExternalNode` is always emitted as a non-prunable edge —
    Layer 2 (Andersen) never needs to second-guess it.
    """
    qualified = ".".join(p for p in (module, name) if p)
    return ExternalNode(
        file_path=f"<external:{module or '?'}>",
        function_name=qualified,
        qualified_name=qualified,
        line_number=line,
        entry_type=EntryPointType.UNKNOWN,
        target_module=module,
        target_name=name,
    )


def _type_external(dotted: str) -> str:
    return f"external:{dotted}"


def _type_factory(call_name: str) -> str:
    return f"factory:{call_name or '?'}"


def _type_container(kind: str, element_types: PointsToSet) -> str:
    return f"container:{kind}[{','.join(sorted(element_types))}]"


def _type_function(function_name: str) -> str:
    return f"function:{function_name or '?'}"


def _is_function_type(value: str) -> bool:
    return value.startswith("function:")


def _function_type_name(value: str) -> str:
    return value.split(":", 1)[1]


def _is_container_type(value: str) -> bool:
    return value.startswith("container:")


def _container_element_types(value: str) -> PointsToSet:
    if "[" not in value or not value.endswith("]"):
        return set()
    inner = value.rsplit("[", 1)[1][:-1]
    return {item for item in inner.split(",") if item}


def _is_external_type(value: str) -> bool:
    return value.startswith("external:")


def _external_type_name(value: str) -> str:
    return value.split(":", 1)[1]


def _context_signature(entry_types: Optional[Dict[str, PointsToSet]]) -> str:
    if not entry_types:
        return "default"
    parts: list[str] = []
    for name, values in sorted(entry_types.items()):
        if not values:
            continue
        parts.append(f"{name}={','.join(sorted(values))}")
    return "|".join(parts) if parts else "default"


def _merge_function_summary(existing: Optional[FunctionSummary], incoming: FunctionSummary) -> FunctionSummary:
    if existing is None:
        return incoming
    param_types = {name: set(values) for name, values in existing.param_types.items()}
    for name, values in incoming.param_types.items():
        param_types.setdefault(name, set()).update(values)
    return FunctionSummary(
        param_types=param_types,
        return_types=set(existing.return_types) | set(incoming.return_types),
        external_edges=list(existing.external_edges) + list(incoming.external_edges),
        unresolved_calls=list(existing.unresolved_calls) + list(incoming.unresolved_calls),
        evidence=list(existing.evidence) + list(incoming.evidence),
        context_signature=existing.context_signature,
        function_type_graph=incoming.function_type_graph or existing.function_type_graph,
    )


# ══════════════════════════════════════════════════════════════════
# LIBRARY INDEX  — exhaustive whole-library symbol table
# ══════════════════════════════════════════════════════════════════

class LibraryIndex:
    """Scan *every* ``.py`` file under the library root and build symbol tables.

    Produces:
      * one :class:`ClassInfo` per class (with its methods as canonical nodes),
      * one :class:`FunctionNode` per module-level function,
      * **longest-suffix** lookup tables (``class_suffix`` / ``func_suffix``) that
        map any dotted import path to the right symbol regardless of how the
        library is rooted (``requests.sessions.Session`` ↔ ``sessions.Session``),
      * a per-file :class:`ModuleScope` resolving the file's imports.

    Suffix collisions (two different symbols sharing a tail) are *dropped* rather
    than guessed, exactly like ``project_builder._ProjectIndex``.
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.asts: Dict[Path, ast.Module] = {}
        self.virtual_sources: Dict[Path, str] = {}
        self.symbol_tables: Dict[Path, py_symtable.SymbolTable] = {}
        self.classes: List[ClassInfo] = []
        self.functions: List[FunctionNode] = []
        self.public_api: List[FunctionNode] = []
        self.scopes: Dict[Path, ModuleScope] = {}
        self.class_defs: Dict[str, ast.ClassDef] = {}
        self.class_attribute_types: Dict[str, Dict[str, PointsToSet]] = {}
        self.function_defs: Dict[str, _FuncDef] = {}
        self.function_params: Dict[str, List[str]] = {}
        self.skipped_files: List[dict] = []
        self.unresolved_public_exports: List[dict] = []
        # All dotted suffixes of every first-party module — lets us tell a
        # library-internal import apart from a third-party / stdlib one
        # regardless of how the library is rooted (``requests.sessions`` ↔
        # ``sessions``). Anything that matches none of these is *external*.
        self.internal_module_suffixes: Set[str] = set()

        # suffix -> (qualified, value); ambiguous suffixes are removed entirely.
        self._class_suffix: Dict[str, Tuple[str, ClassInfo]] = {}
        self._func_suffix: Dict[str, Tuple[str, FunctionNode]] = {}
        self._class_ambig: Set[str] = set()
        self._func_ambig: Set[str] = set()
        # These indexes are immutable after ``build`` and avoid repeating the
        # same MRO walk for every syntactic call site in a module.
        self._mro_cache: Dict[str, Tuple[ClassInfo, ...]] = {}
        self._method_cache: Dict[Tuple[str, str], Optional[FunctionNode]] = {}
        self._dispatch_cache: Dict[
            Tuple[Path, str], Tuple[Tuple[ClassInfo, FunctionNode], ...]
        ] = {}

    # -- public build entry ---------------------------------------

    def build(self) -> "LibraryIndex":
        # Pass 1: collect every class / function and their AST.
        for path in self._iter_py_files():
            tree = _safe_parse(path, self.skipped_files)
            if tree is None:
                continue
            self.asts[path] = tree
            symbols = _safe_symtable(path)
            if symbols is not None:
                self.symbol_tables[path] = symbols
            self._register_module_suffixes(self.module_dotted(path))
            self._collect_definitions(path, tree)
            self._collect_embedded_python_sources(path, tree)
        # Pass 2: now that all symbols exist, resolve each file's imports.
        for path, tree in self.asts.items():
            self.scopes[path] = self._build_scope(path, tree)
        self._collect_class_attribute_types()
        logger.info("[LibGraph] Indexed %d class(es), %d function(s) across %d file(s)",
                    len(self.classes), len(self.functions), len(self.asts))
        return self

    def _collect_embedded_python_sources(self, host_path: Path, tree: ast.Module) -> None:
        """Index string-literal Python files embedded in generator scripts.

        Some real benchmark clients ship as a script that writes a small project
        from a ``{"path.py": "...source..."}`` mapping. We keep this static by
        parsing only literal strings whose keys look like Python file paths.
        """
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if not (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and key.value.endswith(".py")
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    continue
                source = value.value
                try:
                    embedded_tree = ast.parse(source, filename=key.value)
                except SyntaxError:
                    continue
                virtual_path = host_path.parent / "__embedded_sources__" / key.value
                if virtual_path in self.asts:
                    continue
                self.virtual_sources[virtual_path] = source
                self.asts[virtual_path] = embedded_tree
                self._register_module_suffixes(self.module_dotted(virtual_path))
                self._collect_definitions(virtual_path, embedded_tree)

    # -- filesystem walk ------------------------------------------

    def _iter_py_files(self) -> Iterator[Path]:
        # A distribution can expose a single top-level module such as
        # ``mypy_extensions.py`` rather than a package directory.  In that
        # case the captured runtime source is the file itself; never widen the
        # analysis root to its parent site-packages directory.
        if self.root.is_file():
            if self.root.suffix == ".py":
                yield self.root
            return
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames
                           if not d.startswith(".") and d not in IGNORE_DIRS]
            for name in filenames:
                if name.endswith(".py"):
                    yield Path(dirpath) / name

    def module_dotted(self, path: Path) -> str:
        """Dotted module name of *path* relative to the root (``__init__`` dropped)."""
        if self.root.is_file():
            return self.root.parent.name if self.root.stem == "__init__" else self.root.stem
        try:
            rel = path.resolve().relative_to(self.root)
        except ValueError:
            return path.stem
        parts = list(rel.with_suffix("").parts)
        if parts and parts[-1] == "__init__":
            parts.pop()
        return ".".join(parts)

    def _register_module_suffixes(self, dotted: str) -> None:
        """Record every dotted suffix of an internal module for later lookup."""
        if not dotted:
            return
        parts = dotted.split(".")
        for i in range(len(parts)):
            self.internal_module_suffixes.add(".".join(parts[i:]))

    def is_internal_module(self, dotted: str) -> bool:
        """``True`` iff *dotted* names a module belonging to *this* library.

        Uses longest-suffix matching so an absolute self-import
        (``requests.sessions``) still matches an internally-rooted module
        (``sessions``). A miss means the import crosses the TPL boundary and must
        be recorded as external rather than dropped.
        """
        if not dotted:
            return False
        parts = [p for p in dotted.split(".") if p]
        for i in range(len(parts)):
            if ".".join(parts[i:]) in self.internal_module_suffixes:
                return True
        return False

    # -- pass 1: definition collection ----------------------------

    def _collect_definitions(self, path: Path, tree: ast.Module) -> None:
        mod = self.module_dotted(path)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = self._make_func_node(path, node.name, node.name,
                                          self._join(mod, node.name), node.lineno,
                                          module=mod, scope="", def_node=node)
                self.functions.append(fn)
                self._index_func(fn)
                if not node.name.startswith("_"):
                    self.public_api.append(fn)
            elif isinstance(node, ast.ClassDef):
                self._collect_class(path, mod, node)

    def _collect_class(self, path: Path, mod: str, cls: ast.ClassDef) -> None:
        qualified = self._join(mod, cls.name)
        bases = [name for name in (_dotted_name(b) for b in cls.bases) if name]
        info = ClassInfo(name=cls.name, qualified=qualified, file_path=path,
                         base_classes=bases)
        self.class_defs[qualified] = cls
        for sub in cls.body:
            if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # function_name carries the class to keep node identity unique
                # within a file; qualified_name carries the full dotted path.
                node = self._make_func_node(
                    path,
                    function_name=f"{cls.name}.{sub.name}",
                    method_name=sub.name,
                    qualified=self._join(qualified, sub.name),
                    line=sub.lineno,
                    module=mod,
                    scope=cls.name,
                    def_node=sub,
                )
                info.methods.setdefault(sub.name, node)
                self.functions.append(node)
                if not sub.name.startswith("_") or sub.name == "__init__":
                    self.public_api.append(node)
        self.classes.append(info)
        self._index_class(info)

    def _collect_class_attribute_types(self) -> None:
        """Summarize constructor-written attributes for reuse by other methods.

        This is a lightweight function-level type graph reuse step: facts like
        ``self.client = Client()`` in ``__init__`` are seeded into later method
        analyses so ``self.client.request()`` can be resolved without executing
        or inlining the constructor.
        """
        for info in self.classes:
            cls = self.class_defs.get(info.qualified)
            scope = self.scopes.get(info.file_path)
            if cls is None or scope is None:
                continue
            init = next(
                (
                    node
                    for node in cls.body
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == "__init__"
                ),
                None,
            )
            if init is None:
                continue
            methods = {
                sub.name: sub
                for sub in cls.body
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            attrs: Dict[str, PointsToSet] = {}
            for stmt in ast.walk(init):
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and stmt is not init:
                    continue
                if isinstance(stmt, ast.Assign):
                    types = self._constructor_types(stmt.value, scope)
                    if not types:
                        continue
                    for target in stmt.targets:
                        name = self._self_attribute_name(target)
                        if name is not None:
                            attrs[name] = set(types)
                elif isinstance(stmt, ast.AnnAssign):
                    types = self._constructor_types(stmt.value, scope) if stmt.value is not None else None
                    name = self._self_attribute_name(stmt.target)
                    if name is not None and types:
                        attrs[name] = set(types)
                elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                    self._collect_self_method_container_writes(attrs, stmt.value, methods, scope)
            if attrs:
                self.class_attribute_types[info.qualified] = attrs

    def _collect_self_method_container_writes(
        self,
        attrs: Dict[str, PointsToSet],
        call: ast.Call,
        methods: Dict[str, _FuncDef],
        scope: ModuleScope,
    ) -> None:
        if not isinstance(call.func, ast.Attribute):
            return
        try:
            receiver = ast.unparse(call.func.value)
        except Exception:
            return
        if receiver != "self":
            return
        method = methods.get(call.func.attr)
        if method is None:
            return
        param_types = self._call_argument_types(method, call, scope)
        if not param_types:
            return
        for stmt in ast.walk(method):
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and stmt is not method:
                continue
            if not isinstance(stmt, ast.Assign):
                continue
            value_types = self._value_param_types(stmt.value, param_types)
            if not value_types:
                continue
            for target in stmt.targets:
                container = self._self_container_name(target)
                if container is None:
                    continue
                attrs.setdefault(f"{container}[]", set()).update(value_types)

    @staticmethod
    def _method_param_names(args: ast.arguments) -> list[str]:
        params = [arg.arg for arg in args.posonlyargs + args.args]
        if params and params[0] in {"self", "cls"}:
            params = params[1:]
        params.extend(arg.arg for arg in args.kwonlyargs)
        return params

    def _call_argument_types(
        self,
        method: _FuncDef,
        call: ast.Call,
        scope: ModuleScope,
    ) -> Dict[str, PointsToSet]:
        names = self._method_param_names(method.args)
        out: Dict[str, PointsToSet] = {}
        for name, arg in zip(names, call.args):
            types = self._constructor_types(arg, scope)
            if types:
                out[name] = set(types)
        for keyword in call.keywords:
            if not keyword.arg or keyword.arg not in names:
                continue
            types = self._constructor_types(keyword.value, scope)
            if types:
                out[keyword.arg] = set(types)
        return out

    @staticmethod
    def _value_param_types(value: ast.expr, param_types: Dict[str, PointsToSet]) -> Optional[PointsToSet]:
        if isinstance(value, ast.Name):
            types = param_types.get(value.id)
            return set(types) if types else None
        return None

    @staticmethod
    def _self_container_name(target: ast.AST) -> Optional[str]:
        if not isinstance(target, ast.Subscript):
            return None
        if not isinstance(target.value, ast.Attribute):
            return None
        try:
            base = ast.unparse(target.value.value)
        except Exception:
            return None
        if base != "self":
            return None
        return f"self.{target.value.attr}"

    @staticmethod
    def _self_attribute_name(target: ast.AST) -> Optional[str]:
        if not isinstance(target, ast.Attribute):
            return None
        try:
            base = ast.unparse(target.value)
        except Exception:
            return None
        if base != "self":
            return None
        return f"self.{target.attr}"

    def _constructor_types(self, value: Optional[ast.expr], scope: ModuleScope) -> Optional[PointsToSet]:
        if not isinstance(value, ast.Call):
            return None
        ci: Optional[ClassInfo] = None
        if isinstance(value.func, ast.Name):
            ci = scope.classes.get(value.func.id)
        elif isinstance(value.func, ast.Attribute) and isinstance(value.func.value, ast.Name):
            dotted = scope.module_aliases.get(value.func.value.id)
            if dotted is not None:
                ci = self.resolve_class_dotted(f"{dotted}.{value.func.attr}")
        return {ci.qualified} if ci is not None else None

    def _make_func_node(
        self,
        path: Path,
        function_name: str,
        method_name: str,
        qualified: str,
        line: int,
        *,
        module: str,
        scope: str,
        def_node: _FuncDef,
    ) -> FunctionNode:
        node = FunctionNode(
            file_path=str(path),
            function_name=function_name,
            qualified_name=qualified,
            line_number=line,
            module=module,
            scope=scope,
            signature=self._signature(def_node.args),
            arity=self._callable_arity(def_node.args, method_name, bool(scope)),
            source_snippet=self._source_snippet(path, def_node, self.virtual_sources.get(path)),
            entry_type=EntryPointType.UNKNOWN,
        )
        self.function_defs[qualified] = def_node
        self.function_defs[function_name] = def_node
        self.function_params[qualified] = self._callable_params(def_node.args, method_name, bool(scope))
        return node

    @staticmethod
    def _signature(args: ast.arguments) -> str:
        try:
            return f"({ast.unparse(args)})"
        except Exception:
            return "()"

    @staticmethod
    def _callable_arity(args: ast.arguments, method_name: str, is_method: bool) -> int:
        count = len(args.posonlyargs) + len(args.args) + len(args.kwonlyargs)
        if is_method and method_name != "__new__" and count > 0:
            first = (args.posonlyargs + args.args)[0].arg if (args.posonlyargs + args.args) else ""
            if first in {"self", "cls"}:
                count -= 1
        return max(count, 0)

    @staticmethod
    def _callable_params(args: ast.arguments, method_name: str, is_method: bool) -> List[str]:
        params = [arg.arg for arg in (args.posonlyargs + args.args)]
        if is_method and method_name != "__new__" and params and params[0] in {"self", "cls"}:
            params = params[1:]
        params.extend(arg.arg for arg in args.kwonlyargs)
        return params

    @staticmethod
    def _source_snippet(path: Path, node: _FuncDef, source: str | None = None) -> str:
        if source is not None:
            lines = source.splitlines()
        else:
            try:
                lines = path.read_text(encoding="utf-8-sig").splitlines()
            except (OSError, UnicodeDecodeError):
                return ""
        start = max(getattr(node, "lineno", 1) - 1, 0)
        end = getattr(node, "end_lineno", None) or getattr(node, "lineno", 1)
        return "\n".join(lines[start:end])[:4000]

    @staticmethod
    def _join(*parts: str) -> str:
        return ".".join(p for p in parts if p)

    # -- suffix index maintenance ---------------------------------

    def _index_class(self, info: ClassInfo) -> None:
        self._index_suffixes(self._class_suffix, self._class_ambig,
                             info.qualified, info)

    def _index_func(self, fn: FunctionNode) -> None:
        self._index_suffixes(self._func_suffix, self._func_ambig,
                             fn.qualified_name, fn)

    @staticmethod
    def _index_suffixes(table: Dict[str, Tuple[str, object]], ambig: Set[str],
                        qualified: str, value: object) -> None:
        parts = qualified.split(".")
        for i in range(len(parts)):
            suffix = ".".join(parts[i:])
            if not suffix or suffix in ambig:
                continue
            existing = table.get(suffix)
            if existing is not None and existing[0] != qualified:
                # Same tail, different symbol -> ambiguous, drop it.
                table.pop(suffix, None)
                ambig.add(suffix)
            else:
                table[suffix] = (qualified, value)

    # -- dotted -> symbol resolution ------------------------------

    def resolve_class_dotted(self, dotted: str) -> Optional[ClassInfo]:
        return self._resolve_suffix(self._class_suffix, dotted)  # type: ignore[return-value]

    def resolve_func_dotted(self, dotted: str) -> Optional[FunctionNode]:
        return self._resolve_suffix(self._func_suffix, dotted)  # type: ignore[return-value]

    @staticmethod
    def _resolve_suffix(table: Dict[str, Tuple[str, object]],
                        dotted: str) -> Optional[object]:
        parts = [p for p in dotted.split(".") if p]
        for i in range(len(parts)):                 # longest suffix first
            hit = table.get(".".join(parts[i:]))
            if hit is not None:
                return hit[1]
        return None

    # -- inheritance / MRO resolution -----------------------------

    def _resolve_base_name(self, scope: Optional["ModuleScope"],
                           name: str) -> Optional[ClassInfo]:
        """Resolve a raw base-class name to its :class:`ClassInfo`.

        Resolution is performed in the *child's* own file scope so that imported
        parents (``from .base import Base``; ``import animals``) bind correctly,
        with a final fall-back to the global longest-suffix class index.
        """
        if scope is not None:
            hit = scope.classes.get(name)            # local def or imported parent
            if hit is not None:
                return hit
            if "." in name:                          # ``alias.Base`` / ``pkg.Base``
                head, _, tail = name.partition(".")
                dotted = scope.module_aliases.get(head)
                if dotted is not None:
                    ci = self.resolve_class_dotted(f"{dotted}.{tail}")
                    if ci is not None:
                        return ci
        return self.resolve_class_dotted(name)

    def iter_bases(self, info: ClassInfo) -> Iterator[ClassInfo]:
        """Yield the *direct* first-party base classes of *info* (external or
        unresolvable parents are silently skipped)."""
        scope = self.scopes.get(info.file_path)
        for raw in info.base_classes:
            base = self._resolve_base_name(scope, raw)
            if base is not None:
                yield base

    def mro_classes(self, info: ClassInfo) -> List[ClassInfo]:
        """A linearised, cycle-safe method-resolution order starting at *info*.

        A breadth-first walk over ``base_classes`` — close enough to CPython's C3
        for static dispatch and robust against the malformed / cyclic hierarchies
        that turn up in real third-party code.
        """
        cached = self._mro_cache.get(info.qualified)
        if cached is not None:
            return list(cached)
        order: List[ClassInfo] = []
        seen: Set[str] = set()
        queue: List[ClassInfo] = [info]
        while queue:
            cur = queue.pop(0)
            if cur.qualified in seen:
                continue
            seen.add(cur.qualified)
            order.append(cur)
            queue.extend(self.iter_bases(cur))
        self._mro_cache[info.qualified] = tuple(order)
        return order

    def resolve_method_mro(self, info: ClassInfo,
                           method: str) -> Optional[FunctionNode]:
        """First definition of *method* found walking *info*'s MRO (own then
        inherited), or ``None`` if no ancestor defines it."""
        key = (info.qualified, method)
        if key in self._method_cache:
            return self._method_cache[key]
        for cls in self.mro_classes(info):
            node = cls.methods.get(method)
            if node is not None:
                self._method_cache[key] = node
                return node
        self._method_cache[key] = None
        return None

    def method_dispatch_targets(
        self, scope: ModuleScope, method: str
    ) -> Tuple[Tuple[ClassInfo, FunctionNode], ...]:
        """Return the broad-net targets for ``x.method()`` in *scope*.

        The returned immutable tuples contain only canonical owner/callee
        references.  Call-specific ``Candidate`` objects are created lazily by
        :class:`LazyMethodCandidates`, so a large package does not retain one
        object per owner per call site.
        """
        key = (scope.file_path, method)
        cached = self._dispatch_cache.get(key)
        if cached is not None:
            return cached
        out: List[Tuple[ClassInfo, FunctionNode]] = []
        seen: Set[str] = set()
        for ci in scope.classes.values():
            if ci.qualified in seen:
                continue
            callee = self.resolve_method_mro(ci, method)
            if callee is not None:
                seen.add(ci.qualified)
                out.append((ci, callee))
        result = tuple(out)
        self._dispatch_cache[key] = result
        return result

    # -- public API aliases --------------------------------------

    def public_api_aliases(self) -> Dict[str, str]:
        """Return public root-package re-exports as alias -> canonical target.

        Package users often call a symbol exposed from ``__init__.py`` while the
        implementation lives deeper in the tree, e.g. ``pkg.public`` re-exporting
        ``pkg.impl.public``. Reports store aliases relative to the package root,
        including subpackage prefixes when present, so callers can choose the
        import root later with ``--package-report ROOT=PATH``.
        """
        aliases: Dict[str, str] = {}
        for scope in self.scopes.values():
            if scope.file_path.name != "__init__.py":
                continue
            for name, fn in scope.imported_funcs.items():
                if name.startswith("_"):
                    continue
                alias = self._join(scope.module_dotted, name)
                target = fn.qualified_name or fn.function_name
                if target and target != alias:
                    aliases.setdefault(alias, target)
            for name, info in scope.classes.items():
                if name.startswith("_"):
                    continue
                alias = self._join(scope.module_dotted, name)
                init = info.methods.get("__init__")
                target = init.qualified_name if init is not None else info.qualified
                if target and target != alias:
                    aliases.setdefault(alias, target)
        return dict(sorted(aliases.items()))

    def public_export_warnings(self) -> List[dict]:
        return list(self.unresolved_public_exports)

    def _module_path(self, dotted: str) -> Optional[Path]:
        for path in self.asts:
            if self.module_dotted(path) == dotted:
                return path
        return None

    def _module_all(self, dotted: str) -> Optional[List[str]]:
        path = self._module_path(dotted)
        tree = self.asts.get(path) if path is not None else None
        if tree is None:
            return None
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
                continue
            value = node.value
            names = self._literal_str_sequence(value) if value is not None else None
            if names is None:
                self.unresolved_public_exports.append(
                    {
                        "module": dotted,
                        "file_path": str(path),
                        "reason": "dynamic __all__ is not statically resolvable",
                    }
                )
            return names
        return None

    @staticmethod
    def _literal_str_sequence(node: ast.AST) -> Optional[List[str]]:
        if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return None
        out: List[str] = []
        for elt in node.elts:
            if not isinstance(elt, ast.Constant) or not isinstance(elt.value, str):
                return None
            out.append(elt.value)
        return out

    def _module_export_names(self, dotted: str) -> List[str]:
        explicit = self._module_all(dotted)
        if explicit is not None:
            return [name for name in explicit if name and not name.startswith("_")]

        names: Set[str] = set()
        for fn in self.functions:
            if fn.module == dotted and "." not in fn.function_name and not fn.function_name.startswith("_"):
                names.add(fn.function_name)
        for cls in self.classes:
            if self.module_dotted(cls.file_path) == dotted and not cls.name.startswith("_"):
                names.add(cls.name)
        return sorted(names)

    def _record_dynamic_exports(self, scope: ModuleScope, tree: ast.Module) -> None:
        if scope.file_path.name != "__init__.py":
            return
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "__getattr__":
                self.unresolved_public_exports.append(
                    {
                        "module": scope.module_dotted,
                        "file_path": str(scope.file_path),
                        "line_number": node.lineno,
                        "reason": "module __getattr__ may expose dynamic public symbols",
                    }
                )
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript):
                        text = self._call_expr_from_node(target)
                        if text.startswith("globals()[") or text.startswith("locals()["):
                            self.unresolved_public_exports.append(
                                {
                                    "module": scope.module_dotted,
                                    "file_path": str(scope.file_path),
                                    "line_number": node.lineno,
                                    "reason": "dynamic globals()/locals() export assignment",
                                }
                            )

    @staticmethod
    def _call_expr_from_node(node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return ""

    # -- pass 2: per-file scope -----------------------------------

    def _build_scope(self, path: Path, tree: ast.Module) -> ModuleScope:
        mod = self.module_dotted(path)
        scope = ModuleScope(file_path=path, module_dotted=mod)

        # Local definitions first (they shadow imports of the same name).
        for info in self.classes:
            if info.file_path == path:
                scope.classes[info.name] = info
                scope.local_classes[info.name] = info
        for fn in self.functions:
            # module-level funcs have qualified == mod + "." + name and a bare
            # function_name (methods carry "Class.method", so "." in the name
            # filters them out here).
            if str(Path(fn.file_path)) == str(path) and "." not in fn.function_name:
                scope.local_funcs[fn.function_name] = fn

        # Resolve imports into the scope.
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._scope_import(scope, node)
            elif isinstance(node, ast.ImportFrom):
                self._scope_import_from(scope, node)
        self._scope_alias_assignments(scope, tree)
        self._record_dynamic_exports(scope, tree)
        return scope

    def _scope_import(self, scope: ModuleScope, node: ast.Import) -> None:
        for alias in node.names:
            full = alias.name                        # dotted module being imported
            if alias.asname:                         # import a.b.c as m
                bind, target = alias.asname, full
            else:                                    # import a / import a.b.c
                bind = target = full.split(".")[0]
            # Internal modules feed the in-library resolver; external ones become
            # boundary aliases instead of being dropped.
            sink = (scope.module_aliases if self.is_internal_module(full)
                    else scope.external_modules)
            sink.setdefault(bind, target)
            sink.setdefault(full, full)

    def _scope_import_from(self, scope: ModuleScope, node: ast.ImportFrom) -> None:
        # Relative levels are ignored when matching, but a relative import
        # (``from .mod import X``) is by definition internal to the package.
        base = node.module or ""
        internal = bool(node.level) or self.is_internal_module(base)
        for alias in node.names:
            if alias.name == "*":
                if internal:
                    for export in self._module_export_names(base):
                        self._scope_import_symbol(scope, base, export)
                else:
                    self.unresolved_public_exports.append(
                        {
                            "module": scope.module_dotted,
                            "file_path": str(scope.file_path),
                            "line_number": node.lineno,
                            "reason": f"external wildcard import from {base or '?'} is not expanded",
                        }
                    )
                continue
            bind = alias.asname or alias.name
            dotted = self._join(base, alias.name)
            if internal:
                self._scope_import_symbol(scope, base, alias.name, bind=bind)
            else:
                # Cross-TPL: ``from werkzeug import serving`` records both a bare
                # callable (``serving()``) and a submodule (``serving.run_simple()``).
                scope.external_funcs.setdefault(bind, (base, alias.name))
                scope.external_modules.setdefault(bind, dotted)

    def _scope_import_symbol(
        self,
        scope: ModuleScope,
        base: str,
        name: str,
        *,
        bind: Optional[str] = None,
    ) -> None:
        bind = bind or name
        dotted = self._join(base, name)
        ci = self.resolve_class_dotted(dotted)
        if ci is not None:
            scope.classes.setdefault(bind, ci)
        else:
            fn = self.resolve_func_dotted(dotted)
            if fn is not None:
                scope.imported_funcs.setdefault(bind, fn)
        scope.module_aliases.setdefault(bind, dotted)

    def _scope_alias_assignments(self, scope: ModuleScope, tree: ast.Module) -> None:
        for node in tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if value is None:
                continue
            target_symbol = self._resolve_alias_value(scope, value)
            if target_symbol is not None:
                kind, resolved = target_symbol
                for target in targets:
                    if not isinstance(target, ast.Name):
                        continue
                    if kind == "func":
                        scope.imported_funcs.setdefault(target.id, resolved)  # type: ignore[arg-type]
                    elif kind == "class":
                        scope.classes.setdefault(target.id, resolved)  # type: ignore[arg-type]
            value_types = self._literal_scope_value_types(scope, value)
            if not value_types:
                continue
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                scope.global_types[target.id] = set(value_types)
                element_types: PointsToSet = set()
                for typ in value_types:
                    if _is_container_type(typ):
                        element_types.update(_container_element_types(typ))
                if element_types:
                    scope.global_types[f"{target.id}[]"] = element_types

    def _resolve_alias_value(
        self,
        scope: ModuleScope,
        value: ast.expr,
    ) -> Optional[Tuple[str, object]]:
        if isinstance(value, ast.Name):
            if value.id in scope.imported_funcs:
                return ("func", scope.imported_funcs[value.id])
            if value.id in scope.classes:
                return ("class", scope.classes[value.id])
            return None
        if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name):
            dotted = scope.module_aliases.get(value.value.id)
            if dotted is None:
                return None
            target = self._join(dotted, value.attr)
            fn = self.resolve_func_dotted(target)
            if fn is not None:
                return ("func", fn)
            ci = self.resolve_class_dotted(target)
            if ci is not None:
                return ("class", ci)
        return None

    def _literal_scope_value_types(self, scope: ModuleScope, value: ast.expr) -> Optional[PointsToSet]:
        if isinstance(value, ast.Name):
            fn = scope.local_funcs.get(value.id) or scope.imported_funcs.get(value.id)
            if fn is not None:
                return {_type_function(fn.qualified_name or fn.function_name)}
            ci = scope.classes.get(value.id)
            if ci is not None:
                return {ci.qualified}
            return None
        if isinstance(value, ast.Attribute):
            target_symbol = self._resolve_alias_value(scope, value)
            if target_symbol is None:
                return None
            kind, resolved = target_symbol
            if kind == "func" and isinstance(resolved, FunctionNode):
                fn = resolved
                return {_type_function(fn.qualified_name or fn.function_name)}
            if kind == "class" and isinstance(resolved, ClassInfo):
                ci = resolved
                return {ci.qualified}
            return None
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            element_types: PointsToSet = set()
            for elt in value.elts:
                types = self._literal_scope_value_types(scope, elt)
                if types:
                    element_types.update(types)
            return {_type_container("builtins.list", element_types)} if element_types else None
        if isinstance(value, ast.Dict):
            value_types: PointsToSet = set()
            for item in value.values:
                if item is None:
                    continue
                types = self._literal_scope_value_types(scope, item)
                if types:
                    value_types.update(types)
            return {_type_container("builtins.dict", value_types)} if value_types else None
        return None


# ══════════════════════════════════════════════════════════════════
# LAYER 1 — AST CANDIDATE GENERATOR  (broad net / high recall)
# ══════════════════════════════════════════════════════════════════

class ASTCandidateGenerator(ast.NodeVisitor):
    """Pure-syntactic generation of *tentative* call edges for one function.

    Walks the body of a single definition (never descending into nested
    ``def`` / ``class`` scopes — those are analysed on their own) and, for each
    call expression, emits one or more :class:`Candidate` edges:

      * ``f()``        → the local / imported function ``f`` (exact, not prunable).
      * ``Cls()``      → ``Cls.__init__`` constructor edge (exact, not prunable).
      * ``mod.f()``    → function ``f`` inside module alias ``mod`` (exact).
      * ``super().m()`` → method ``m`` resolved through the *enclosing* class's
                         parents via the MRO (inheritance-aware, not prunable).
      * ``x.m()``      → **every** in-scope class whose MRO resolves a method ``m``
                         (own *or* inherited — the broad net, prunable,
                         base_var=``x``).

    Candidates are keyed by ``id(call_node)`` so Layer 2 can re-discover the very
    same call sites during its flow-sensitive pass and prune them.
    """

    def __init__(self, index: LibraryIndex, scope: ModuleScope,
                 enclosing: Optional[ClassInfo] = None) -> None:
        self.index = index
        self.scope = scope
        self.enclosing = enclosing          # class owning this def (for super())
        self.sites: Dict[int, Iterable[Candidate]] = {}
        self.unresolved: Dict[int, ast.Call] = {}

    def generate(self, func_def: _FuncDef) -> Dict[int, Iterable[Candidate]]:
        for stmt in func_def.body:
            self.visit(stmt)
        return self.sites

    # Scope barriers: nested definitions are separate units of analysis.
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:            # noqa: N802
        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        return None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:                  # noqa: N802
        return None

    def visit_Call(self, node: ast.Call) -> None:                          # noqa: N802
        try:
            cands = self._candidates(node)
        except Exception as exc:        # one odd call must not abort generation
            logger.debug("[LibGraph] candidate-gen error in %s: %s",
                         self.scope.file_path, exc)
            cands = []
        if cands:
            self.sites[id(node)] = cands
        else:
            self.unresolved[id(node)] = node
        self.generic_visit(node)        # recurse into nested calls in the args

    # -- candidate construction -----------------------------------

    def _candidates(self, node: ast.Call) -> Iterable[Candidate]:
        func = node.func
        literal_getattr = self._literal_getattr_target(func)
        if literal_getattr is not None:
            base, method = literal_getattr
            return self._candidates_attr(base, method, node)
        if isinstance(func, ast.Name):
            return self._candidates_name(func.id, node)
        if isinstance(func, ast.Attribute):
            # ``super().m()`` / ``super(Child, self).m()`` — the receiver is a
            # ``super()`` proxy, not a plain Name, so it needs the MRO walk.
            if self._is_super_call(func.value):
                return self._candidates_super(func.attr, node)
            if isinstance(func.value, (ast.Name, ast.Attribute)):
                try:
                    base = ast.unparse(func.value)
                except Exception:
                    base = ""
                return self._candidates_attr(base, func.attr, node)
        return []                        # subscripts / dynamic expressions -> LLM territory

    @staticmethod
    def _literal_getattr_target(func: ast.expr) -> Optional[Tuple[str, str]]:
        if not isinstance(func, ast.Call):
            return None
        if not isinstance(func.func, ast.Name) or func.func.id != "getattr":
            return None
        method = _literal_string_arg(func, 1)
        if not method:
            return None
        try:
            base = ast.unparse(func.args[0])
        except Exception:
            return None
        return (base, method) if base else None

    @staticmethod
    def _is_super_call(expr: ast.expr) -> bool:
        return (isinstance(expr, ast.Call)
                and isinstance(expr.func, ast.Name)
                and expr.func.id == "super")

    def _candidates_super(self, method: str, node: ast.Call) -> List[Candidate]:
        """``super().m()`` → method ``m`` in the enclosing class's ancestors.

        Statically we cannot know the runtime MRO (a subclass instance could
        re-route ``super`` through a sibling), so we tentatively bind to the first
        ``m`` reachable from *each* direct parent. There is no receiver variable to
        key points-to on, so these edges are non-prunable — Layer 2 ignores them.
        """
        if self.enclosing is None:
            return []
        out: List[Candidate] = []
        seen: Set[str] = set()
        for base in self.index.iter_bases(self.enclosing):
            meth = self.index.resolve_method_mro(base, method)
            if meth is not None and meth.qualified_name not in seen:
                seen.add(meth.qualified_name)
                out.append(Candidate(meth, owner=None, base_var=None,
                                     call_node=node, prunable=False))
        return out

    def _candidates_name(self, name: str, node: ast.Call) -> List[Candidate]:
        # Constructor call ``Cls()``.
        ci = self.scope.classes.get(name)
        if ci is not None:
            init = ci.methods.get("__init__")
            if init is not None:
                return [Candidate(init, owner=None, base_var=None,
                                  call_node=node, prunable=False)]
            return []
        # Plain function ``f()`` — local def or ``from mod import f``.
        fn = self.scope.local_funcs.get(name) or self.scope.imported_funcs.get(name)
        if fn is not None:
            return [Candidate(fn, owner=None, base_var=None,
                              call_node=node, prunable=False)]
        # External function ``f()`` pulled in via ``from <tpl> import f`` — an
        # exact cross-TPL boundary edge, not something to drop.
        ext = self.scope.external_funcs.get(name)
        if ext is not None:
            module, symbol = ext
            return [Candidate(_make_external_node(module, symbol, node.lineno),
                              owner=None, base_var=None,
                              call_node=node, prunable=False)]
        return []

    def _candidates_attr(self, base: str, method: str,
                         node: ast.Call) -> Iterable[Candidate]:
        # 1. Module-qualified call ``mod.func()`` / ``mod.Class()``.
        dotted = self._resolve_module_alias(self.scope.module_aliases, base)
        if dotted is not None:
            target = self._join(dotted, method)
            fn = self.index.resolve_func_dotted(target)
            if fn is not None:
                return [Candidate(fn, owner=None, base_var=None,
                                  call_node=node, prunable=False)]
            ci = self.index.resolve_class_dotted(target)
            if ci is not None and "__init__" in ci.methods:
                return [Candidate(ci.methods["__init__"], owner=None, base_var=None,
                                  call_node=node, prunable=False)]
            # `base` is a module alias but didn't resolve a member — do NOT also
            # treat it as an object receiver (that would invent bogus edges).
            return []

        # 2. External module-qualified call ``tpl.func()`` — exact boundary edge
        #    to an ExternalNode. Static target is the imported symbol, so this is
        #    non-prunable and Layer 2 leaves it untouched.
        ext = self._resolve_module_alias(self.scope.external_modules, base)
        if ext is not None:
            return [Candidate(_make_external_node(ext, method, node.lineno),
                              owner=None, base_var=None,
                              call_node=node, prunable=False)]

        # 3. Object method dispatch ``x.m()`` — the BROAD NET. Every in-scope
        #    class whose MRO resolves a method `m` (defined on the class itself OR
        #    inherited from a parent) is a tentative target. Crucially, ``owner``
        #    is the *receiver* class while ``callee`` is the method's actual
        #    defining node: so when Layer 2 proves ``pt(x) = {Child}`` and ``Child``
        #    only inherits `m` from ``Base``, the edge ``owner=Child`` survives and
        #    correctly points at ``Base.m`` rather than being wrongly pruned away.
        return LazyMethodCandidates(self.index, self.scope, method, node, base)

    @staticmethod
    def _resolve_module_alias(aliases: Dict[str, str], base: str) -> Optional[str]:
        """Resolve ``alias`` or ``alias.submodule`` using the longest known prefix."""
        if base in aliases:
            return aliases[base]
        parts = [part for part in base.split(".") if part]
        for i in range(len(parts) - 1, 0, -1):
            prefix = ".".join(parts[:i])
            target = aliases.get(prefix)
            if target is not None:
                suffix = ".".join(parts[i:])
                return ".".join(part for part in (target, suffix) if part)
        return None

    @staticmethod
    def _join(*parts: str) -> str:
        return ".".join(p for p in parts if p)


# ══════════════════════════════════════════════════════════════════
# LAYER 2 — ANDERSEN POINTS-TO ANALYZER  (fine filter / flow-sensitive)
# ══════════════════════════════════════════════════════════════════

class AndersenPointsToAnalyzer:
    """Flow-sensitive points-to analysis that records the receiver type at each
    call site — the precision "brain" that prunes Layer 1's over-approximation.

    The analyzer threads a :class:`PointsToState` (``var -> {qualified class}``)
    through the statements of a function **in source order**. Key semantics:

      * **Strong update** on an *unconditional* assignment: ``x = Dog()`` sets
        ``pt(x) = {Dog}``, completely *overwriting* the previous value of ``pt(x)``
        (this is what makes the analysis flow-sensitive rather than a flat union).
      * **Weak update** inside a conditional branch (``if`` / loop / ``try``):
        the new type is *merged* with the existing one, because the assignment
        may or may not have executed on the path reaching a later use.
      * **Top (unknown)** is represented by the *absence* of a key. An assignment
        whose right-hand side we cannot type (a non-constructor call, a parameter,
        an attribute read) drives the variable to top, so we never prune on a
        guess.
      * **Branch join**: after an ``if`` / loop / ``try`` the per-path states are
        joined — a variable keeps a concrete type only if it is the same/known on
        every path, otherwise it falls to top (sound over-approximation).

    For a method, ``self`` / ``cls`` are seeded to the enclosing class, which both
    types ``self.m()`` precisely and lets ``x = self`` propagate.

    The result, :attr:`call_pt`, maps ``id(call_node) -> Optional[PointsToSet]``:
    a concrete set when the receiver's type is known at that point, or ``None``
    (top) when it is not — the orchestrator keeps all candidates in the top case.
    """

    def __init__(
        self,
        index: LibraryIndex,
        scope: ModuleScope,
        enclosing: Optional[ClassInfo],
        entry_types: Optional[Dict[str, PointsToSet]] = None,
        function_summaries: Optional[Dict[str, FunctionSummary]] = None,
        context_summaries: Optional[Dict[Tuple[str, str], FunctionSummary]] = None,
        in_progress: Optional[Set[Tuple[str, str]]] = None,
        function_name: str = "",
        context_signature: str = "default",
        entry_type_provider: Optional[Callable[[str], Dict[str, PointsToSet]]] = None,
    ) -> None:
        self.index = index
        self.scope = scope
        self.enclosing = enclosing
        self.entry_types = entry_types or {}
        self.function_summaries = function_summaries if function_summaries is not None else {}
        self.context_summaries = context_summaries if context_summaries is not None else {}
        self.in_progress = in_progress if in_progress is not None else set()
        self.function_name = function_name or scope.module_dotted
        self.context_signature = context_signature
        self.entry_type_provider = entry_type_provider
        self.call_pt: Dict[int, Optional[PointsToSet]] = {}
        self.call_func_types: Dict[int, Optional[PointsToSet]] = {}
        self.call_arg_types: Dict[int, List[Optional[PointsToSet]]] = {}
        self.return_types: PointsToSet = set()
        self.assignment_type_facts: List[dict] = []
        self.return_type_facts: List[dict] = []
        self.external_model_facts: List[dict] = []
        self.function_type_graph = FunctionTypeGraph(self.function_name, context=self.context_signature)

    def compute(self, func_def: _FuncDef) -> Dict[int, Optional[PointsToSet]]:
        state: PointsToState = {}
        if self.enclosing is not None:
            state["self"] = {self.enclosing.qualified}
            state["cls"] = {self.enclosing.qualified}
            for attr, types in self.index.class_attribute_types.get(self.enclosing.qualified, {}).items():
                state[attr] = set(types)
                self.function_type_graph.record_attribute_flow(
                    attr,
                    types,
                    reason="constructor attribute summary",
                )
        self.function_type_graph.entry_types = {
            key: set(value)
            for key, value in self.entry_types.items()
        }
        self._seed_parameter_types(func_def, state)
        try:
            self._walk_stmts(func_def.body, state, conditional=False)
        except Exception as exc:        # never let analysis abort the build
            logger.debug("[LibGraph] points-to error in %s: %s",
                         self.scope.file_path, exc)
        return self.call_pt

    def _seed_parameter_types(self, func_def: _FuncDef, state: PointsToState) -> None:
        for arg in func_def.args.posonlyargs + func_def.args.args + func_def.args.kwonlyargs:
            propagated = self.entry_types.get(arg.arg)
            if propagated:
                state[arg.arg] = set(propagated)
                self.function_type_graph.record_parameter_flow(
                    arg.arg,
                    propagated,
                    caller="context",
                )
                continue
            annotated = self._annotation_types(arg.annotation)
            if annotated:
                state[arg.arg] = annotated
                self.function_type_graph.record_parameter_flow(
                    arg.arg,
                    annotated,
                    caller="annotation",
                )

    # -- statement walker -----------------------------------------

    def _walk_stmts(self, stmts: List[ast.stmt], state: PointsToState,
                    conditional: bool) -> PointsToState:
        for stmt in stmts:
            state = self._walk_stmt(stmt, state, conditional)
        return state

    def _walk_stmt(self, stmt: ast.stmt, state: PointsToState,
                   conditional: bool) -> PointsToState:
        # Scope barriers — never descend into nested definitions.
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return state

        if isinstance(stmt, ast.Assign):
            return self._walk_assign(stmt, state, conditional)
        if isinstance(stmt, ast.AnnAssign):
            annotated = self._annotation_types(stmt.annotation)
            if stmt.value is not None:
                self._walk_expr(stmt.value, state)
                if isinstance(stmt.target, ast.Name):
                    self._update(state, stmt.target.id,
                                 self._eval_types(stmt.value, state) or annotated, conditional)
                elif isinstance(stmt.target, ast.Attribute):
                    self._update_attribute(stmt.target, self._eval_types(stmt.value, state) or annotated, state, conditional)
            elif annotated and isinstance(stmt.target, ast.Name):
                self._update(state, stmt.target.id, annotated, conditional)
            return state
        if isinstance(stmt, ast.AugAssign):
            self._walk_expr(stmt.value, state)
            self._assign_top(stmt.target, state)     # x += ... -> conservatively top
            return state
        if isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self._walk_expr(stmt.value, state)
                types = self._eval_types(stmt.value, state)
                if types:
                    self.return_types.update(types)
                    self.function_type_graph.record_return_flow(types, reason="return expression")
                    self.return_type_facts.append(
                        {
                            "line_number": getattr(stmt, "lineno", 0),
                            "return_expr": self._call_expr(stmt.value),
                            "types": sorted(types),
                        }
                    )
            return state
        if isinstance(stmt, ast.If):
            self._walk_expr(stmt.test, state)
            st = self._walk_stmts(stmt.body, self._copy(state), True)
            sf = self._walk_stmts(stmt.orelse, self._copy(state), True)
            return self._join(st, sf)
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self._walk_expr(stmt.iter, state)
            if not self._assign_iter_target(stmt.target, stmt.iter, state, conditional):
                self._assign_top(stmt.target, state)     # loop variable: unknown type
            body = self._walk_stmts(stmt.body, self._copy(state), True)
            orelse = self._walk_stmts(stmt.orelse, self._copy(state), True)
            # Loop may run zero times -> also fold in the pre-loop state.
            return self._join(self._join(body, orelse), state)
        if isinstance(stmt, ast.While):
            self._walk_expr(stmt.test, state)
            body = self._walk_stmts(stmt.body, self._copy(state), True)
            orelse = self._walk_stmts(stmt.orelse, self._copy(state), True)
            return self._join(self._join(body, orelse), state)
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            return self._walk_with(stmt, state, conditional)
        if isinstance(stmt, ast.Try):
            return self._walk_try(stmt, state, conditional)

        # Default: record any calls in the statement's expressions, recurse into
        # nested statement lists conditionally. Tracked state is left unchanged.
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.expr):
                self._walk_expr(child, state)
            elif isinstance(child, ast.stmt):
                state = self._walk_stmt(child, state, conditional)
        return state

    def _walk_assign(self, node: ast.Assign, state: PointsToState,
                     conditional: bool) -> PointsToState:
        # RHS is evaluated (and its calls recorded) under the *pre*-assignment
        # state, which is correct for ``x = x.m()``.
        self._walk_expr(node.value, state)
        for target in node.targets:
            self._bind_assignment_target(target, node.value, state, conditional, node)
        return state

    def _bind_assignment_target(
        self,
        target: ast.expr,
        value: ast.expr,
        state: PointsToState,
        conditional: bool,
        stmt: ast.AST,
    ) -> None:
        if isinstance(target, ast.Name):
            types = self._eval_types(value, state)
            self._update(state, target.id, types, conditional)
            if isinstance(value, ast.Call):
                self._apply_constructor_attribute_side_effects(target.id, value, state, conditional)
            element_types = self._container_element_types_from_value(value, state)
            if element_types:
                self._update(state, f"{target.id}[]", element_types, conditional)
            self._record_assignment_fact(target.id, value, types, stmt)
            return
        if isinstance(target, ast.Attribute):
            types = self._eval_types(value, state)
            self._update_attribute(target, types, state, conditional)
            try:
                target_name = ast.unparse(target)
            except Exception:
                target_name = ""
            if target_name:
                self._record_assignment_fact(target_name, value, types, stmt)
            return
        if isinstance(target, (ast.Tuple, ast.List)):
            if self._bind_sequence_assignment(target, value, state, conditional, stmt):
                return
        self._assign_top(target, state)

    def _bind_sequence_assignment(
        self,
        target: ast.Tuple | ast.List,
        value: ast.expr,
        state: PointsToState,
        conditional: bool,
        stmt: ast.AST,
    ) -> bool:
        if not isinstance(value, (ast.Tuple, ast.List)):
            return False
        values = list(value.elts)
        targets = list(target.elts)
        starred_index = next((idx for idx, item in enumerate(targets) if isinstance(item, ast.Starred)), None)
        if starred_index is None:
            if len(targets) != len(values):
                return False
            for child_target, child_value in zip(targets, values):
                self._bind_assignment_target(child_target, child_value, state, conditional, stmt)
            return True

        before = targets[:starred_index]
        after = targets[starred_index + 1:]
        if len(values) < len(before) + len(after):
            return False
        for child_target, child_value in zip(before, values[:len(before)]):
            self._bind_assignment_target(child_target, child_value, state, conditional, stmt)
        if after:
            tail_values = values[-len(after):]
            for child_target, child_value in zip(after, tail_values):
                self._bind_assignment_target(child_target, child_value, state, conditional, stmt)
        else:
            tail_values = []
        middle_values = values[len(before): len(values) - len(tail_values)]
        starred = targets[starred_index]
        if isinstance(starred, ast.Starred):
            element_types: PointsToSet = set()
            for child_value in middle_values:
                types = self._eval_types(child_value, state)
                if types:
                    element_types.update(types)
            if isinstance(starred.value, ast.Name):
                if element_types:
                    self._update(state, starred.value.id, {_type_container("builtins.list", element_types)}, conditional)
                    self._update(state, f"{starred.value.id}[]", element_types, conditional)
                else:
                    self._assign_top(starred.value, state)
            else:
                self._assign_top(starred.value, state)
        return True

    def _container_element_types_from_value(self, value: ast.expr, state: PointsToState) -> Optional[PointsToSet]:
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            out: PointsToSet = set()
            for elt in value.elts:
                types = self._eval_types(elt, state)
                if types:
                    out.update(types)
            return out or None
        if isinstance(value, ast.Dict):
            out: PointsToSet = set()
            for item in value.values:
                if item is None:
                    continue
                types = self._eval_types(item, state)
                if types:
                    out.update(types)
            return out or None
        types = self._eval_types(value, state)
        if not types:
            return None
        out: PointsToSet = set()
        for typ in types:
            if _is_container_type(typ):
                out.update(_container_element_types(typ))
        return out or None

    def _walk_with(self, stmt: Union[ast.With, ast.AsyncWith],
                   state: PointsToState, conditional: bool) -> PointsToState:
        for item in stmt.items:
            self._walk_expr(item.context_expr, state)
            if isinstance(item.optional_vars, ast.Name):
                self._update(state, item.optional_vars.id,
                             self._context_manager_enter_types(item.context_expr, state),
                             conditional)
            elif item.optional_vars is not None:
                self._assign_top(item.optional_vars, state)
        # The with-body executes in the current (un)conditional context.
        return self._walk_stmts(stmt.body, state, conditional)

    def _context_manager_enter_types(
        self,
        context_expr: ast.expr,
        state: PointsToState,
    ) -> Optional[PointsToSet]:
        context_types = self._eval_types(context_expr, state)
        if not context_types:
            return None

        enter_returns: PointsToSet = set()
        saw_enter = False
        for typ in context_types:
            if _is_external_type(typ) or typ.startswith("factory:"):
                continue
            ci = self.index.resolve_class_dotted(typ)
            if ci is None:
                continue
            enter = self.index.resolve_method_mro(ci, "__enter__")
            if enter is None:
                continue
            saw_enter = True
            inferred = self._infer_function_return_types(enter)
            if inferred:
                enter_returns.update(inferred)
            else:
                enter_returns.add(typ)

        if enter_returns:
            return enter_returns
        if saw_enter:
            return set(context_types)
        return context_types

    def _walk_try(self, stmt: ast.Try, state: PointsToState,
                  conditional: bool) -> PointsToState:
        states = [self._walk_stmts(stmt.body, self._copy(state), True)]
        for handler in stmt.handlers:
            states.append(self._walk_stmts(handler.body, self._copy(state), True))
        if stmt.orelse:
            states.append(self._walk_stmts(stmt.orelse, self._copy(states[0]), True))
        joined = states[0]
        for other in states[1:]:
            joined = self._join(joined, other)
        # ``finally`` always runs -> apply it in the incoming (un)conditional ctx.
        return self._walk_stmts(stmt.finalbody, joined, conditional)

    # -- expression walker (records receiver points-to at call sites) --

    def _walk_expr(self, expr: ast.AST, state: PointsToState) -> None:
        if isinstance(expr, ast.Call):
            func = expr.func
            self.call_arg_types[id(expr)] = [self._eval_types(arg, state) for arg in expr.args]
            literal_getattr = ASTCandidateGenerator._literal_getattr_target(func)
            if literal_getattr is not None:
                base, _method = literal_getattr
                current = state.get(base)
                self.call_pt[id(expr)] = set(current) if current is not None else None
            elif isinstance(func, ast.Attribute):
                try:
                    base = ast.unparse(func.value)
                except Exception:
                    base = ""
                current = self._eval_types(func.value, state) if isinstance(func.value, ast.Call) else state.get(base)
                func_types = self._eval_types(func, state)
                if func_types is not None:
                    self.call_func_types[id(expr)] = set(func_types)
                # Concrete set if known, else None (= top: receiver type unknown).
                self.call_pt[id(expr)] = set(current) if current is not None else None
                self._apply_method_attribute_side_effects(expr, state)
            elif isinstance(func, ast.Name):
                current = state.get(func.id)
                self.call_func_types[id(expr)] = set(current) if current is not None else None
            else:
                current = self._eval_types(func, state)
                self.call_func_types[id(expr)] = set(current) if current is not None else None
        for child in ast.iter_child_nodes(expr):
            self._walk_expr(child, state)

    # -- type evaluation of a right-hand side ---------------------

    def _eval_types(self, value: ast.expr, state: PointsToState) -> Optional[PointsToSet]:
        """The set of classes an assigned RHS may produce, or ``None`` for top."""
        if isinstance(value, ast.Call):
            dynamic_import = self._literal_dynamic_import_target(value)
            if dynamic_import is not None:
                types = {_type_external(dynamic_import)}
                self._record_call_result(value, types, "literal dynamic import")
                return types
            callable_returns = self._resolve_callable_value_return_types(value, state)
            if callable_returns is not None:
                self._record_call_result(value, callable_returns, "callable value return")
                return callable_returns or None
            modeled = self._resolve_external_call_return_types(value, state)
            if modeled is not None:
                self._record_call_result(value, modeled, "external model return")
                return modeled or None
            modeled = self._resolve_internal_method_return_types(value, state)
            if modeled is not None:
                self._record_call_result(value, modeled, "internal method return")
                return modeled or None
            ci = self._resolve_class_expr(value.func)
            if ci is not None:                       # constructor -> instance type
                types = {ci.qualified}
                self._record_call_result(value, types, "constructor result")
                return types
            external = self._resolve_external_expr(value.func)
            if external is not None:
                modeled_direct = EXTERNAL_CALL_RETURN_TYPES.get(external)
                if modeled_direct is not None:
                    self._record_external_model(value, external, "call", modeled_direct)
                    self._record_call_result(value, modeled_direct, "external model return")
                    return set(modeled_direct) or None
                if self._looks_like_constructor(external):
                    types = {_type_external(external)}
                    self._record_call_result(value, types, "external constructor result")
                    return types
                types = {_type_factory(external)}
                self._record_call_result(value, types, "external factory result")
                return types
            fn = self._resolve_function_expr(value.func)
            if fn is not None:
                types = self._infer_function_return_types(fn)
                self._record_call_result(value, types, "internal function return")
                return types
            call_name = _dotted_name(value.func) if isinstance(value.func, (ast.Name, ast.Attribute)) else ""
            types = {_type_factory(call_name or "")}  # function return type unknown, but receiver methods are potential
            self._record_call_result(value, types, "unknown function result")
            return types
        if isinstance(value, ast.Name):              # x = y -> copy pt(y)
            current = state.get(value.id)
            if current is not None:
                return set(current)
            current = self.scope.global_types.get(value.id)
            if current is not None:
                return set(current)
            fn = self._resolve_function_expr(value)
            if fn is not None:
                return {_type_function(fn.qualified_name or fn.function_name)}
            return None
        if isinstance(value, ast.Attribute):
            try:
                current = state.get(ast.unparse(value))
            except Exception:
                current = None
            if current is not None:
                return set(current)
            attr_types = self._resolve_attribute_value_types(value, state)
            if attr_types:
                return attr_types
            fn = self._resolve_function_expr(value)
            if fn is not None:
                return {_type_function(fn.qualified_name or fn.function_name)}
            return None
        if isinstance(value, ast.Subscript):
            try:
                base = ast.unparse(value.value)
            except Exception:
                base = ""
            element_types = state.get(f"{base}[]")
            if element_types is None:
                element_types = self.scope.global_types.get(f"{base}[]")
            if element_types:
                return set(element_types)
            container_types = self._eval_types(value.value, state)
            if container_types:
                out: PointsToSet = set()
                for typ in container_types:
                    if _is_container_type(typ):
                        out.update(_container_element_types(typ))
                if out:
                    return out
            return None
        if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            element_types: PointsToSet = set()
            for elt in value.elts:
                types = self._eval_types(elt, state)
                if types:
                    element_types.update(types)
            return {_type_container("builtins.list", element_types)} if element_types else None
        if isinstance(value, ast.Dict):
            value_types: PointsToSet = set()
            for item in value.values:
                if item is None:
                    continue
                types = self._eval_types(item, state)
                if types:
                    value_types.update(types)
            return {_type_container("builtins.dict", value_types)} if value_types else None
        return None                                  # literals/attrs/etc. -> top

    def _apply_constructor_attribute_side_effects(
        self,
        target_name: str,
        call: ast.Call,
        state: PointsToState,
        conditional: bool,
    ) -> None:
        ci = self._resolve_class_expr(call.func)
        if ci is None:
            return
        init = ci.methods.get("__init__")
        if init is None:
            return
        self._apply_callable_attribute_side_effects(target_name, init, call, state, conditional)

    def _apply_method_attribute_side_effects(self, call: ast.Call, state: PointsToState) -> None:
        if not isinstance(call.func, ast.Attribute):
            return
        try:
            receiver_name = ast.unparse(call.func.value)
        except Exception:
            return
        receiver_types = self._eval_types(call.func.value, state)
        if not receiver_types:
            return
        for typ in receiver_types:
            if _is_external_type(typ) or typ.startswith("factory:"):
                continue
            ci = self.index.resolve_class_dotted(typ)
            if ci is None:
                continue
            method = self.index.resolve_method_mro(ci, call.func.attr)
            if method is None:
                continue
            self._apply_callable_attribute_side_effects(receiver_name, method, call, state, conditional=False)

    def _apply_callable_attribute_side_effects(
        self,
        receiver_name: str,
        method: FunctionNode,
        call: ast.Call,
        state: PointsToState,
        conditional: bool,
    ) -> None:
        method_name = method.qualified_name or method.function_name
        func_def = self.index.function_defs.get(method_name)
        if func_def is None:
            return
        params = self.index.function_params.get(method_name, [])
        method_state = self._copy(state)
        for param, arg in zip(params, call.args):
            types = self._eval_types(arg, state)
            if types:
                method_state[param] = set(types)
        for keyword in call.keywords:
            if keyword.arg not in params:
                continue
            types = self._eval_types(keyword.value, state)
            if types:
                method_state[keyword.arg] = set(types)
        for stmt in ast.walk(func_def):
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and stmt is not func_def:
                continue
            targets: list[ast.expr]
            value: ast.expr | None
            if isinstance(stmt, ast.Assign):
                targets = list(stmt.targets)
                value = stmt.value
            elif isinstance(stmt, ast.AnnAssign):
                targets = [stmt.target]
                value = stmt.value
            else:
                continue
            if value is None:
                continue
            types = self._eval_types(value, method_state)
            if not types:
                continue
            for target in targets:
                if not isinstance(target, ast.Attribute):
                    continue
                if not isinstance(target.value, ast.Name) or target.value.id not in {"self", "cls"}:
                    continue
                self._update(state, f"{receiver_name}.{target.attr}", types, conditional)

    def _resolve_callable_value_return_types(self, value: ast.Call, state: PointsToState) -> Optional[PointsToSet]:
        callable_types = self._eval_types(value.func, state)
        if not callable_types:
            return None
        out: PointsToSet = set()
        matched = False
        for typ in callable_types:
            if not _is_function_type(typ):
                continue
            matched = True
            fn_name = _function_type_name(typ)
            fn = self.index.resolve_func_dotted(fn_name)
            if fn is None:
                continue
            returns = self._infer_function_return_types(fn)
            if returns:
                out.update(returns)
        if not matched:
            return None
        return out

    def _resolve_attribute_value_types(self, value: ast.Attribute, state: PointsToState) -> Optional[PointsToSet]:
        receiver_types = self._eval_types(value.value, state)
        if not receiver_types:
            return None
        out: PointsToSet = set()
        for typ in receiver_types:
            if _is_external_type(typ) or typ.startswith("factory:"):
                continue
            ci = self.index.resolve_class_dotted(typ)
            if ci is None:
                continue
            for key in (f"self.{value.attr}", value.attr):
                types = self.index.class_attribute_types.get(ci.qualified, {}).get(key)
                if types:
                    out.update(types)
        return out or None

    def _assign_iter_target(
        self,
        target: ast.expr,
        iter_expr: ast.expr,
        state: PointsToState,
        conditional: bool,
    ) -> bool:
        if not isinstance(iter_expr, ast.Call) or not isinstance(iter_expr.func, ast.Attribute):
            return False
        method = iter_expr.func.attr
        if method not in {"items", "values"}:
            return False
        try:
            base = ast.unparse(iter_expr.func.value)
        except Exception:
            return False
        value_types = state.get(f"{base}[]")
        if not value_types:
            return False
        if method == "values":
            if isinstance(target, ast.Name):
                self._update(state, target.id, value_types, conditional)
                return True
            return False
        if method == "items" and isinstance(target, (ast.Tuple, ast.List)) and len(target.elts) >= 2:
            self._assign_top(target.elts[0], state)
            value_target = target.elts[1]
            if isinstance(value_target, ast.Name):
                self._update(state, value_target.id, value_types, conditional)
            else:
                self._assign_top(value_target, state)
            for extra in target.elts[2:]:
                self._assign_top(extra, state)
            return True
        return False

    def _resolve_external_call_return_types(self, value: ast.Call, state: PointsToState) -> Optional[PointsToSet]:
        if not isinstance(value.func, ast.Attribute):
            return None
        receiver_types = self._eval_types(value.func.value, state)
        if not receiver_types:
            return None
        out: PointsToSet = set()
        matched = False
        for typ in receiver_types:
            if not _is_external_type(typ):
                continue
            external_type = _external_type_name(typ)
            key = (external_type, value.func.attr)
            if key not in EXTERNAL_METHOD_RETURN_TYPES:
                continue
            matched = True
            returns = EXTERNAL_METHOD_RETURN_TYPES[key]
            self._record_external_model(value, f"{external_type}.{value.func.attr}", "method", returns or set())
            if returns:
                out.update(returns)
        if not matched:
            return None
        return out

    def _literal_dynamic_import_target(self, value: ast.Call) -> Optional[str]:
        target = _literal_string_arg(value, 0)
        if not target:
            return None
        func_name = _dotted_name(value.func)
        external = self._resolve_external_expr(value.func)
        if func_name == "__import__" or external == "__import__":
            has_fromlist = any(keyword.arg == "fromlist" for keyword in value.keywords)
            return target if has_fromlist else target.split(".", 1)[0]
        if func_name in {"importlib.import_module", "import_module"} or external == "importlib.import_module":
            return target
        return None

    def _resolve_internal_method_return_types(self, value: ast.Call, state: PointsToState) -> Optional[PointsToSet]:
        if not isinstance(value.func, ast.Attribute):
            return None
        try:
            base = ast.unparse(value.func.value)
        except Exception:
            return None
        receiver_types = self._eval_types(value.func.value, state) if isinstance(value.func.value, ast.Call) else state.get(base)
        if not receiver_types:
            return None
        out: PointsToSet = set()
        matched = False
        for typ in receiver_types:
            if _is_external_type(typ) or typ.startswith("factory:"):
                continue
            ci = self.index.resolve_class_dotted(typ)
            if ci is None:
                continue
            method = self.index.resolve_method_mro(ci, value.func.attr)
            if method is None:
                continue
            matched = True
            returns = self._infer_function_return_types(method)
            if returns:
                out.update(returns)
        if not matched:
            return None
        return out

    def _record_external_model(self, node: ast.Call, target: str, kind: str, returns: PointsToSet) -> None:
        self.external_model_facts.append(
            {
                "target": target,
                "kind": kind,
                "line_number": getattr(node, "lineno", 0),
                "call_expr": self._call_expr(node),
                "return_types": sorted(returns),
                "reason": "deterministic external type model",
            }
        )

    def _record_assignment_fact(
        self,
        target: str,
        value: ast.AST,
        types: Optional[PointsToSet],
        node: ast.AST,
    ) -> None:
        if not types:
            return
        value_expr = self._call_expr(value)
        self.assignment_type_facts.append(
            {
                "target": target,
                "value_expr": value_expr,
                "line_number": getattr(node, "lineno", 0),
                "types": sorted(types),
            }
        )
        self.function_type_graph.record_assignment_flow(
            target,
            types,
            value_expr=value_expr,
            location=str(getattr(node, "lineno", 0)),
            reason="assignment",
        )

    def _record_call_result(
        self,
        node: ast.Call,
        types: Optional[PointsToSet],
        reason: str,
    ) -> None:
        if not types:
            return
        self.function_type_graph.record_call_result(
            self._call_expr(node),
            types,
            location=str(getattr(node, "lineno", 0)),
            reason=reason,
        )

    @staticmethod
    def _call_expr(node: ast.AST) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return "<expr>"

    def _resolve_class_expr(self, func: ast.expr) -> Optional[ClassInfo]:
        """Resolve a constructor expression (``Cls`` or ``mod.Cls``) to a class."""
        if isinstance(func, ast.Name):
            return self.scope.classes.get(func.id)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            dotted = self.scope.module_aliases.get(func.value.id)
            if dotted is not None:
                return self.index.resolve_class_dotted(f"{dotted}.{func.attr}")
        return None

    def _resolve_function_expr(self, func: ast.expr) -> Optional[FunctionNode]:
        if isinstance(func, ast.Name):
            return self.scope.local_funcs.get(func.id) or self.scope.imported_funcs.get(func.id)
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            dotted = self.scope.module_aliases.get(func.value.id)
            if dotted is not None:
                return self.index.resolve_func_dotted(f"{dotted}.{func.attr}")
        return None

    def _resolve_external_expr(self, func: ast.expr) -> Optional[str]:
        if isinstance(func, ast.Name):
            ext = self.scope.external_funcs.get(func.id)
            if ext is not None:
                return ".".join(part for part in ext if part)
            module = self.scope.external_modules.get(func.id)
            return module
        if isinstance(func, ast.Attribute):
            try:
                base = ast.unparse(func.value)
            except Exception:
                base = ""
            dotted = ASTCandidateGenerator._resolve_module_alias(self.scope.external_modules, base)
            if dotted is not None:
                return ".".join(part for part in (dotted, func.attr) if part)
        return None

    @staticmethod
    def _looks_like_constructor(dotted: str) -> bool:
        leaf = dotted.rsplit(".", 1)[-1]
        return bool(leaf) and leaf[:1].isupper()

    def _infer_function_return_types(self, fn: FunctionNode) -> Optional[PointsToSet]:
        fn_name = fn.qualified_name or fn.function_name
        entry_types = self.function_entry_types_for(fn_name)
        context_signature = _context_signature(entry_types)
        context_key = (fn_name, context_signature)
        if context_key in self.context_summaries:
            cached = self.context_summaries[context_key].return_types
            return set(cached) if cached else None
        if context_signature == "default" and fn_name in self.function_summaries:
            cached = self.function_summaries[fn_name].return_types
            return set(cached) if cached else None
        if context_key in self.in_progress:
            return None
        func_def = self.index.function_defs.get(fn_name)
        if func_def is None:
            return None
        annotated = self._annotation_types(func_def.returns)
        if annotated:
            graph = FunctionTypeGraph(fn_name, context=context_signature)
            graph.entry_types = {key: set(value) for key, value in entry_types.items()}
            graph.record_return_flow(annotated, reason="return annotation")
            summary = FunctionSummary(
                param_types={key: set(value) for key, value in entry_types.items()},
                return_types=set(annotated),
                context_signature=context_signature,
                function_type_graph=graph,
            )
            self.context_summaries[context_key] = summary
            self.function_summaries[fn_name] = _merge_function_summary(self.function_summaries.get(fn_name), summary)
            return annotated
        path = Path(fn.file_path)
        scope = self.index.scopes.get(path)
        if scope is None:
            return None
        enclosing = self._enclosing_for(fn)
        self.in_progress.add(context_key)
        analyzer = AndersenPointsToAnalyzer(
            self.index,
            scope,
            enclosing,
            entry_types,
            function_summaries=self.function_summaries,
            context_summaries=self.context_summaries,
            in_progress=self.in_progress,
            function_name=fn_name,
            context_signature=context_signature,
            entry_type_provider=self.entry_type_provider,
        )
        analyzer.compute(func_def)
        self.in_progress.discard(context_key)
        summary = FunctionSummary(
            param_types={key: set(value) for key, value in analyzer.entry_types.items()},
            return_types=set(analyzer.return_types),
            evidence=list(analyzer.return_type_facts),
            context_signature=context_signature,
            function_type_graph=analyzer.function_type_graph,
        )
        self.context_summaries[context_key] = summary
        self.function_summaries[fn_name] = _merge_function_summary(self.function_summaries.get(fn_name), summary)
        return set(summary.return_types) if summary.return_types else None

    def function_entry_types_for(self, fn_name: str) -> Dict[str, PointsToSet]:
        if self.entry_type_provider is None:
            return {}
        return {
            key: set(value)
            for key, value in self.entry_type_provider(fn_name).items()
        }

    def _enclosing_for(self, fn: FunctionNode) -> Optional[ClassInfo]:
        fn_name = fn.qualified_name or fn.function_name
        for info in self.index.classes:
            for method in info.methods.values():
                if (method.qualified_name or method.function_name) == fn_name:
                    return info
        return None

    def _annotation_types(self, annotation: ast.expr | None) -> Optional[PointsToSet]:
        if annotation is None:
            return None
        dotted = _dotted_name(annotation)
        if dotted is None:
            return None
        resolved = self.scope.classes.get(dotted) or self.index.resolve_class_dotted(dotted)
        if resolved is not None:
            return {resolved.qualified}
        return None

    def _update_attribute(
        self,
        target: ast.Attribute,
        types: Optional[PointsToSet],
        state: PointsToState,
        conditional: bool,
    ) -> None:
        try:
            name = ast.unparse(target)
        except Exception:
            return
        self._update(state, name, types, conditional)
        if types:
            if self.enclosing is not None and name.startswith(("self.", "cls.")):
                self.index.class_attribute_types.setdefault(self.enclosing.qualified, {}).setdefault(name, set()).update(types)
            self.function_type_graph.record_attribute_flow(
                name,
                types,
                location=str(getattr(target, "lineno", 0)),
                reason="attribute assignment",
            )

    # -- state algebra --------------------------------------------

    @staticmethod
    def _copy(state: PointsToState) -> PointsToState:
        return {name: set(types) for name, types in state.items()}

    @staticmethod
    def _join(a: PointsToState, b: PointsToState) -> PointsToState:
        """Sound join: a variable survives with a concrete type only if both
        paths give it a *known* type (then union); otherwise it falls to top."""
        joined: PointsToState = {}
        for name in a.keys() & b.keys():
            joined[name] = a[name] | b[name]
        return joined

    def _update(self, state: PointsToState, name: str,
                types: Optional[PointsToSet], conditional: bool) -> None:
        if types is None:                            # RHS unknown -> drive to top
            state.pop(name, None)
            return
        if conditional:                              # weak update: merge with prior
            if name in state:
                state[name] = state[name] | types
            else:
                # Previously top (or undefined on the other path) ∪ known = top.
                state.pop(name, None)
        else:                                        # strong update: overwrite
            state[name] = set(types)

    def _assign_top(self, target: ast.expr, state: PointsToState) -> None:
        """Drive every Name bound by *target* to top (unknown)."""
        if isinstance(target, ast.Name):
            state.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign_top(elt, state)
        # Attribute / Subscript targets bind no tracked local -> nothing to do.


# ══════════════════════════════════════════════════════════════════
# ORCHESTRATOR — drives Layer 1 + Layer 2 over the whole library
# ══════════════════════════════════════════════════════════════════

class CallGraphConstructionPipeline:
    """Shared per-function call graph construction pipeline.

    Both package and project modes use this object for the common core:

        AST + symbol/scope table -> import-aware candidates -> points-to facts
        -> call target resolution -> internal/external callees

    The mode-specific layers decide only which functions to feed into this
    pipeline: package analysis feeds every definition exhaustively, while project
    analysis feeds reachable definitions from a worklist.
    """

    def __init__(self, index: LibraryIndex, *, retain_analysis_details: bool = True) -> None:
        self.index = index
        self.retain_analysis_details = retain_analysis_details
        self.unresolved_calls: List[UnresolvedCall] = []
        self.candidate_edges: List[CandidateEdge] = []
        self.llm_kept_edges: List[CandidateEdge] = []
        self.llm_pruned_edges: List[CandidateEdge] = []
        self.function_entry_types: Dict[str, Dict[str, PointsToSet]] = {}
        self.function_summaries: Dict[str, FunctionSummary] = {}
        self.function_context_summaries: Dict[Tuple[str, str], FunctionSummary] = {}
        self.function_type_graphs: Dict[Tuple[str, str], FunctionTypeGraph] = {}
        self._return_in_progress: Set[Tuple[str, str]] = set()
        self.last_changed_entry_functions: Set[str] = set()
        self.parameter_type_facts: List[dict] = []
        self.assignment_type_facts: List[dict] = []
        self.return_type_facts: List[dict] = []
        self.external_model_facts: List[dict] = []
        self.edge_evidence: Dict[Tuple[str, str], dict] = {}
        self._resolved_unresolved: Set[Tuple[str, int, str]] = set()
        self._functions_by_name = {
            (fn.qualified_name or fn.function_name): fn
            for fn in self.index.functions
        }
        self._functions_by_simple_arity: Dict[Tuple[str, int], List[FunctionNode]] = {}
        for fn in self.index.functions:
            self._functions_by_simple_arity.setdefault((self._simple_name(fn), fn.arity), []).append(fn)
        self._classes_by_name_arity: Dict[Tuple[str, int], List[Tuple[ClassInfo, Optional[FunctionNode]]]] = {}
        for ci in self.index.classes:
            init = ci.methods.get("__init__")
            self._classes_by_name_arity.setdefault((ci.name, init.arity if init is not None else 0), []).append((ci, init))

    def analyze_definition(
        self,
        caller: FunctionNode,
        func_def: _FuncDef,
        scope: ModuleScope,
        enclosing: Optional[ClassInfo],
    ) -> List[FunctionNode]:
        caller_name = caller.qualified_name or caller.function_name
        context_signature = self.context_signature_for(caller_name)
        self.last_changed_entry_functions = set()
        generator = ASTCandidateGenerator(self.index, scope, enclosing)
        sites = generator.generate(func_def)
        self._record_unresolved(caller, generator.unresolved)

        analyzer = AndersenPointsToAnalyzer(
            self.index,
            scope,
            enclosing,
            self.entry_types_for(caller_name),
            function_summaries=self.function_summaries,
            context_summaries=self.function_context_summaries,
            in_progress=self._return_in_progress,
            function_name=caller_name,
            context_signature=context_signature,
            entry_type_provider=self.entry_types_for,
        )
        pt = analyzer.compute(func_def)
        if self.retain_analysis_details:
            self.assignment_type_facts.extend(
                {**fact, "function": caller_name}
                for fact in analyzer.assignment_type_facts
            )
            self.return_type_facts.extend(
                {**fact, "function": caller_name}
                for fact in analyzer.return_type_facts
            )
            self.external_model_facts.extend(
                {**fact, "function": caller_name}
                for fact in analyzer.external_model_facts
            )
        summary = FunctionSummary(
            param_types={key: set(value) for key, value in analyzer.entry_types.items()},
            return_types=set(analyzer.return_types),
            evidence=list(analyzer.return_type_facts) if self.retain_analysis_details else [],
            context_signature=context_signature,
            function_type_graph=analyzer.function_type_graph if self.retain_analysis_details else None,
        )
        self.function_context_summaries[(caller_name, context_signature)] = summary
        self.function_summaries[caller_name] = _merge_function_summary(self.function_summaries.get(caller_name), summary)
        if self.retain_analysis_details:
            self.function_type_graphs[(caller_name, context_signature)] = analyzer.function_type_graph
        else:
            self._drop_type_graphs()
        callees: List[FunctionNode] = []
        for site_id, cands in sites.items():
            resolved = self.resolve_call_site(cands, pt.get(site_id))
            for callee in resolved:
                self._record_edge_evidence(caller, callee, self._evidence_for(callee, cands))
            self.last_changed_entry_functions.update(
                self._record_parameter_flows(caller, resolved, analyzer.call_arg_types.get(site_id, []))
            )
            callees.extend(resolved)
        for site_id, node in generator.unresolved.items():
            unresolved = self._unresolved_call(caller, node)
            pattern = self._function_value_candidates(unresolved, analyzer.call_func_types.get(site_id))
            if not pattern:
                pattern.extend(self._pattern_candidates(unresolved, node, pt.get(site_id)))
            for callee, evidence in pattern:
                self._record_edge_evidence(caller, callee, evidence)
                if evidence.get("resolver") == "external_type_model":
                    if self.retain_analysis_details:
                        self.external_model_facts.append(
                            {
                                "function": caller_name,
                                "target": getattr(callee, "identity_string", "") or (callee.qualified_name or callee.function_name),
                                "kind": "method",
                                "line_number": evidence.get("line_number", 0),
                                "call_expr": evidence.get("call_expr", ""),
                                "return_types": list(evidence.get("return_types", [])),
                                "reason": "deterministic external type model",
                            }
                        )
                callees.append(callee)
            self.last_changed_entry_functions.update(
                self._record_parameter_flows(caller, [callee for callee, _evidence in pattern], analyzer.call_arg_types.get(site_id, []))
            )
            if pattern:
                self._resolved_unresolved.add(self._unresolved_key(unresolved))
            else:
                analyzer.function_type_graph.record_dynamic_flow(
                    unresolved.call_expr,
                    location=str(unresolved.line_number),
                    reason="unresolved dynamic call retained for conservative review",
                )
        return callees

    def _drop_type_graphs(self) -> None:
        """Release per-function diagnostic graphs in compact package mode."""
        for summary in self.function_summaries.values():
            summary.function_type_graph = None
            summary.evidence.clear()
        for summary in self.function_context_summaries.values():
            summary.function_type_graph = None
            summary.evidence.clear()

    def entry_types_for(self, fn_name: str) -> Dict[str, PointsToSet]:
        return {
            key: set(value)
            for key, value in self.function_entry_types.get(fn_name, {}).items()
        }

    def context_signature_for(self, fn_name: str) -> str:
        return _context_signature(self.function_entry_types.get(fn_name))

    def _record_edge_evidence(self, caller: FunctionNode, callee: FunctionNode, evidence: dict) -> None:
        if not self.retain_analysis_details and not callee.is_external:
            # Package summaries only expose evidence for outer/external edges.
            # Retaining a dict keyed by every internal caller/callee pair can
            # duplicate a very large exhaustive graph (notably pip/Pygments).
            return
        caller_name = caller.qualified_name or caller.function_name
        callee_name = callee.qualified_name or callee.function_name
        allowed = {"edge_type", "confidence", "resolver", "reason", "call_expr", "line_number"}
        self.edge_evidence[(caller_name, callee_name)] = {
            key: value for key, value in evidence.items() if key in allowed
        }

    def _evidence_for(self, callee: FunctionNode, candidates: List[Candidate]) -> dict:
        for candidate in candidates:
            if candidate.callee == callee:
                return self._candidate_evidence(candidate)
        return {
            "edge_type": "confirmed_static",
            "confidence": 1.0,
            "resolver": "static",
            "reason": "statically resolved call target",
            "call_expr": "",
            "line_number": 0,
        }

    @staticmethod
    def _candidate_evidence(candidate: Candidate) -> dict:
        try:
            call_expr = ast.unparse(candidate.call_node)
        except Exception:
            call_expr = ""
        return {
            "edge_type": candidate.edge_type,
            "confidence": candidate.confidence,
            "resolver": candidate.resolver,
            "reason": candidate.reason,
            "call_expr": call_expr,
            "line_number": getattr(candidate.call_node, "lineno", 0),
        }

    def _pattern_candidates(
        self,
        unresolved: UnresolvedCall,
        node: ast.Call,
        receiver_pt: Optional[PointsToSet],
    ) -> List[Tuple[FunctionNode, dict]]:
        if not unresolved.call_name or not isinstance(node.func, ast.Attribute):
            return []
        method = unresolved.call_name
        out: List[Tuple[FunctionNode, dict]] = []
        if receiver_pt:
            for typ in sorted(receiver_pt):
                if _is_external_type(typ):
                    target = _external_type_name(typ)
                    model_key = (target, method)
                    resolver = "external_type_model" if model_key in EXTERNAL_METHOD_RETURN_TYPES else "external_constructor_receiver"
                    reason = (
                        f"method resolved using deterministic external type model for {target}"
                        if resolver == "external_type_model"
                        else f"receiver propagated from external constructor {target}"
                    )
                    confidence = 0.95 if resolver == "external_type_model" else 0.8
                    returns = EXTERNAL_METHOD_RETURN_TYPES.get(model_key) or set()
                    out.append(
                        (
                            _make_external_node(target, method, unresolved.line_number),
                            {
                                **self._pattern_evidence(
                                unresolved,
                                "confirmed_type",
                                resolver,
                                reason,
                                confidence,
                                ),
                                "return_types": sorted(returns),
                            },
                        )
                    )
                elif typ.startswith("factory:"):
                    out.append(
                        (
                            _make_external_node("", method, unresolved.line_number),
                            self._pattern_evidence(
                                unresolved,
                                "potential_pattern",
                                "factory_unknown_receiver",
                                f"receiver comes from unknown factory {typ.split(':', 1)[1]}",
                                0.45,
                            ),
                        )
                    )
                else:
                    ci = self.index.resolve_class_dotted(typ)
                    if ci is None:
                        continue
                    callee = self.index.resolve_method_mro(ci, method)
                    if callee is None:
                        continue
                    out.append(
                        (
                            callee,
                            self._pattern_evidence(
                                unresolved,
                                "confirmed_type",
                                "points_to_receiver",
                                f"receiver points to internal class {typ}",
                                0.95,
                            ),
                        )
                    )
        if out:
            return out
        if "(" in unresolved.receiver or "." in unresolved.receiver:
            return [
                (
                    _make_external_node("", method, unresolved.line_number),
                    self._pattern_evidence(
                        unresolved,
                        "potential_pattern",
                        "fluent_chain",
                        "method call appears in a fluent or chained expression",
                        0.4,
                    ),
                )
            ]
        if unresolved.receiver:
            return [
                (
                    _make_external_node("", method, unresolved.line_number),
                    self._pattern_evidence(
                        unresolved,
                        "potential_pattern",
                        "unknown_receiver_method",
                        "method call on an unknown receiver is retained as a conservative boundary candidate",
                        0.25,
                    ),
                )
            ]
        return []

    def _function_value_candidates(
        self,
        unresolved: UnresolvedCall,
        func_types: Optional[PointsToSet],
    ) -> List[Tuple[FunctionNode, dict]]:
        if not func_types:
            return []
        out: List[Tuple[FunctionNode, dict]] = []
        for value in sorted(func_types):
            if not _is_function_type(value):
                continue
            fn_name = _function_type_name(value)
            callee = self._functions_by_name.get(fn_name)
            if callee is None:
                continue
            out.append(
                (
                    callee,
                    self._pattern_evidence(
                        unresolved,
                        "confirmed_type",
                        "function_value",
                        f"call target propagated as callable value {fn_name}",
                        0.9,
                    ),
                )
            )
        return out

    @staticmethod
    def _pattern_evidence(
        unresolved: UnresolvedCall,
        edge_type: str,
        resolver: str,
        reason: str,
        confidence: float,
    ) -> dict:
        return {
            "edge_type": edge_type,
            "confidence": confidence,
            "resolver": resolver,
            "reason": reason,
            "call_expr": unresolved.call_expr,
            "line_number": unresolved.line_number,
        }

    def _record_parameter_flows(
        self,
        caller: FunctionNode,
        callees: List[FunctionNode],
        arg_types: List[Optional[PointsToSet]],
    ) -> Set[str]:
        changed: Set[str] = set()
        if not arg_types:
            return changed
        caller_name = caller.qualified_name or caller.function_name
        for callee in callees:
            if callee.is_external:
                continue
            callee_name = callee.qualified_name or callee.function_name
            params = self.index.function_params.get(callee_name, [])
            if not params:
                continue
            entry = self.function_entry_types.setdefault(callee_name, {})
            for param, types in zip(params, arg_types):
                if not types:
                    continue
                before = set(entry.get(param, set()))
                entry.setdefault(param, set()).update(types)
                if entry[param] != before:
                    changed.add(callee_name)
                    if self.retain_analysis_details:
                        self.parameter_type_facts.append(
                            {
                                "caller": caller_name,
                                "callee": callee_name,
                                "parameter": param,
                                "types": sorted(types),
                                "reason": "argument propagated from callsite",
                            }
                        )
        return changed

    def _record_unresolved(self, caller: FunctionNode, calls: Dict[int, ast.Call]) -> None:
        for node in calls.values():
            unresolved = self._unresolved_call(caller, node)
            self.unresolved_calls.append(unresolved)
            self.candidate_edges.extend(self._coarse_candidates(unresolved))

    @staticmethod
    def _unresolved_key(unresolved: UnresolvedCall) -> Tuple[str, int, str]:
        return (unresolved.caller, unresolved.line_number, unresolved.call_expr)

    def _unresolved_call(self, caller: FunctionNode, node: ast.Call) -> UnresolvedCall:
        call_name, receiver = self._call_name_and_receiver(node)
        return UnresolvedCall(
            caller=caller.qualified_name or caller.function_name,
            file_path=str(caller.file_path),
            line_number=getattr(node, "lineno", 0),
            call_expr=self._call_expr(node),
            call_name=call_name,
            receiver=receiver,
            arity=len(node.args) + len(node.keywords),
        )

    def _coarse_candidates(self, unresolved: UnresolvedCall) -> List[CandidateEdge]:
        if not unresolved.call_name:
            return []
        out: List[CandidateEdge] = []
        caller = self._functions_by_name.get(unresolved.caller)

        for fn in self._functions_by_simple_arity.get((unresolved.call_name, unresolved.arity), []):
            out.append(
                self._candidate_edge(
                    unresolved,
                    fn.qualified_name or fn.function_name,
                    "coarse_name_arity",
                    "matched unresolved call by simple function/method name and arity",
                    caller=caller,
                    callee=fn,
                    confidence=0.35,
                )
            )

        for ci, init in self._classes_by_name_arity.get((unresolved.call_name, unresolved.arity), []):
            out.append(
                self._candidate_edge(
                    unresolved,
                    ci.qualified,
                    "coarse_class_name_arity",
                    "matched unresolved constructor call by class name and arity",
                    caller=caller,
                    callee=init,
                    confidence=0.35,
                )
            )

        out = self._dedupe_candidates(out)
        if len(out) > CANDIDATE_FANOUT_CAP:
            return [
                CandidateEdge(
                    caller=unresolved.caller,
                    callee="",
                    file_path=unresolved.file_path,
                    line_number=unresolved.line_number,
                    call_expr=unresolved.call_expr,
                    confidence=0.0,
                    resolver="coarse_name_arity",
                    status="too_many_candidates",
                    reason=(
                        f"candidate fanout {len(out)} exceeds cap "
                        f"{CANDIDATE_FANOUT_CAP}; refine statically or with a narrower query"
                    ),
                    arity=unresolved.arity,
                    receiver=unresolved.receiver,
                    caller_signature=caller.signature if caller is not None else "",
                    caller_source=caller.source_snippet if caller is not None else "",
                )
            ]
        return out

    @staticmethod
    def _dedupe_candidates(candidates: List[CandidateEdge]) -> List[CandidateEdge]:
        seen: Set[Tuple[str, str, int, str]] = set()
        out: List[CandidateEdge] = []
        for candidate in candidates:
            key = (candidate.caller, candidate.callee, candidate.line_number, candidate.call_expr)
            if key in seen:
                continue
            seen.add(key)
            out.append(candidate)
        return out

    def _candidate_edge(
        self,
        unresolved: UnresolvedCall,
        callee_name: str,
        resolver: str,
        reason: str,
        *,
        caller: Optional[FunctionNode],
        callee: Optional[FunctionNode],
        confidence: float,
    ) -> CandidateEdge:
        return CandidateEdge(
            caller=unresolved.caller,
            callee=callee_name,
            file_path=unresolved.file_path,
            line_number=unresolved.line_number,
            call_expr=unresolved.call_expr,
            confidence=confidence,
            resolver=resolver,
            reason=reason,
            arity=unresolved.arity,
            receiver=unresolved.receiver,
            caller_signature=caller.signature if caller is not None else "",
            callee_signature=callee.signature if callee is not None else "",
            caller_source=caller.source_snippet if caller is not None else "",
            callee_source=callee.source_snippet if callee is not None else "",
        )

    @staticmethod
    def _simple_name(node: FunctionNode) -> str:
        name = node.qualified_name or node.function_name
        return name.rsplit(".", 1)[-1]

    @staticmethod
    def _call_expr(node: ast.Call) -> str:
        try:
            return ast.unparse(node)
        except Exception:
            return "<call>"

    @staticmethod
    def _call_name_and_receiver(node: ast.Call) -> Tuple[str, str]:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id, ""
        if isinstance(func, ast.Attribute):
            receiver = ""
            if isinstance(func.value, ast.Name):
                receiver = func.value.id
            else:
                try:
                    receiver = ast.unparse(func.value)
                except Exception:
                    receiver = ""
            return func.attr, receiver
        return "", ""

    def resolve_call_site(
        self,
        cands: Iterable[Candidate],
        receiver_pt: Optional[PointsToSet],
    ) -> List[FunctionNode]:
        """Resolve one call site's candidate set using Layer-2 points-to facts."""
        if isinstance(cands, LazyMethodCandidates):
            # Avoid materializing the broad dispatch set.  With a known
            # receiver, only matching owners need to become Candidate objects;
            # with an unknown receiver, stream all conservative targets into
            # the result exactly as the eager implementation did.
            if receiver_pt is None:
                resolved = self.resolve_dynamic_call(cands.call_node)
                if resolved is not None:
                    return [resolved]
                return [candidate.callee for candidate in cands]
            matched = [
                callee
                for owner, callee in self.index.method_dispatch_targets(cands.scope, cands.method)
                if owner.qualified in receiver_pt
            ]
            if matched:
                return matched
            resolved = self.resolve_dynamic_call(cands.call_node)
            return [resolved] if resolved is not None else []

        cands = list(cands)
        keep: List[FunctionNode] = [c.callee for c in cands if not c.prunable]
        prunable = [c for c in cands if c.prunable]
        if not prunable:
            return keep

        call_node = prunable[0].call_node
        if receiver_pt is None:
            resolved = self.resolve_dynamic_call(call_node)
            if resolved is not None:
                keep.append(resolved)
            else:
                keep.extend(c.callee for c in prunable)
            return keep

        matched = [c.callee for c in prunable if c.owner in receiver_pt]
        if matched:
            keep.extend(matched)
        else:
            resolved = self.resolve_dynamic_call(call_node)
            if resolved is not None:
                keep.append(resolved)
        return keep

    def resolve_dynamic_call(self, call_node: ast.Call) -> Optional[FunctionNode]:
        """Future hook for InferCG-style semantic pruning or LLM disambiguation."""
        return None

    def report(self) -> dict:
        unresolved = [
            item
            for item in self.unresolved_calls
            if self._unresolved_key(item) not in self._resolved_unresolved
        ]
        external_model_facts = self._dedupe_dicts(self.external_model_facts)
        return {
            "unresolved_calls": [vars(item) for item in unresolved],
            "candidate_edges": [vars(item) for item in self.candidate_edges],
            "llm_kept_edges": [vars(item) for item in self.llm_kept_edges],
            "llm_pruned_edges": [vars(item) for item in self.llm_pruned_edges],
            "parameter_type_facts": list(self.parameter_type_facts),
            "assignment_type_facts": list(self.assignment_type_facts),
            "return_type_facts": list(self.return_type_facts),
            "external_model_facts": external_model_facts,
            "function_summaries": {
                name: {
                    "param_types": {key: sorted(value) for key, value in summary.param_types.items()},
                    "return_types": sorted(summary.return_types),
                }
                for name, summary in sorted(self.function_summaries.items())
            },
            "function_context_summaries": {
                f"{name}@{context}": {
                    "function": name,
                    "context": context,
                    "param_types": {key: sorted(value) for key, value in summary.param_types.items()},
                    "return_types": sorted(summary.return_types),
                }
                for (name, context), summary in sorted(self.function_context_summaries.items())
            },
            "function_type_graphs": {
                f"{name}@{context}": graph.to_dict()
                for (name, context), graph in sorted(
                    {
                        **self.function_type_graphs,
                        **{
                            key: summary.function_type_graph
                            for key, summary in self.function_context_summaries.items()
                            if summary.function_type_graph is not None
                        },
                    }.items()
                )
                if graph is not None
            },
            "unresolved_public_exports": self.index.public_export_warnings(),
        }

    @staticmethod
    def _dedupe_dicts(items: List[dict]) -> List[dict]:
        seen: Set[Tuple[Tuple[str, str], ...]] = set()
        out: List[dict] = []
        for item in items:
            key = tuple(sorted((str(k), str(v)) for k, v in item.items()))
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
        return out


class LibraryAnalyzer:
    """Coordinate exhaustive indexing, candidate generation and points-to pruning
    into a single library call graph (G_L)."""

    def __init__(self, *, retain_analysis_details: bool = True) -> None:
        self.index: Optional[LibraryIndex] = None
        self.pipeline: Optional[CallGraphConstructionPipeline] = None
        self.retain_analysis_details = retain_analysis_details
        self._seen_edges: Set[Tuple[FunctionNode, FunctionNode]] = set()

    # -- public API -----------------------------------------------

    def build_library_graph(self, library_root: Path) -> CallGraph:
        """Build the exhaustive library call graph rooted at *library_root*.

        Every function and method defined under the root becomes a node; every
        statically-resolvable (and points-to-confirmed) call becomes an edge.
        Unreadable / unparsable modules are skipped, never fatal.
        """
        root = Path(library_root)
        if not root.exists():
            raise FileNotFoundError(f"Library root does not exist: {root}")
        if not root.is_dir() and not (root.is_file() and root.suffix == ".py"):
            raise NotADirectoryError(f"Library root is not a Python directory or file: {root}")

        self.index = LibraryIndex(root).build()
        self.pipeline = CallGraphConstructionPipeline(
            self.index,
            retain_analysis_details=self.retain_analysis_details,
        )
        graph = CallGraph()

        # Seed the graph with the full API surface + internal functions so even
        # never-called definitions are represented as nodes.
        for fn in self.index.functions:
            graph.add_node(fn)

        module_nodes: Dict[Path, FunctionNode] = {}
        for path, scope in self.index.scopes.items():
            module_node = self._module_node(path, scope)
            module_nodes[path] = module_node
            graph.add_node(module_node)

        # Jarvis-style adjacency output models a module body as an executable function. A small
        # fixpoint lets top-level calls seed parameter/return facts before later
        # function analyses consume them, and then revisits module bodies after
        # callable/return summaries have improved.
        for _iteration in range(3):
            changed_before = {
                name: {param: set(types) for param, types in params.items()}
                for name, params in self.pipeline.function_entry_types.items()
            }
            for path, scope in self.index.scopes.items():
                tree = self.index.asts.get(path)
                if tree is None:
                    continue
                self._analyze_and_add_edges(graph, module_nodes[path], self._module_body_def(tree, scope), scope, None)
                for func_def, caller, enclosing in self._iter_defs(tree, scope):
                    self._analyze_and_add_edges(graph, caller, func_def, scope, enclosing)
            changed_after = {
                name: {param: set(types) for param, types in params.items()}
                for name, params in self.pipeline.function_entry_types.items()
            }
            if changed_after == changed_before:
                break

        logger.info("[LibGraph] Built G_L: %d node(s), %d edge(s)",
                    len(graph.nodes), len(graph.edges))
        if self.pipeline is not None:
            graph.metadata.update(self.pipeline.report())
        graph.metadata["analysis_mode"] = "library_exhaustive"
        graph.metadata["skipped_files"] = list(self.index.skipped_files)
        return graph

    def _analyze_and_add_edges(
        self,
        graph: CallGraph,
        caller: FunctionNode,
        func_def: _FuncDef,
        scope: ModuleScope,
        enclosing: Optional[ClassInfo],
    ) -> None:
        try:
            assert self.pipeline is not None
            callees = self.pipeline.analyze_definition(caller, func_def, scope, enclosing)
        except Exception as exc:    # one bad definition never kills build
            logger.warning("[LibGraph] Failed to analyze %s in %s: %s",
                           caller.function_name, scope.file_path, exc)
            return
        for callee in callees:
            graph.add_node(callee)
            key = (caller, callee)
            if key in self._seen_edges:
                continue
            self._seen_edges.add(key)
            evidence = self.pipeline.edge_evidence.get(
                (caller.qualified_name or caller.function_name, callee.qualified_name or callee.function_name),
                {},
            )
            graph.edges.append(CallEdge(caller=caller, callee=callee, **evidence))

    @staticmethod
    def _module_body_def(tree: ast.Module, scope: ModuleScope) -> ast.FunctionDef:
        args = ast.arguments(
            posonlyargs=[],
            args=[],
            vararg=None,
            kwonlyargs=[],
            kw_defaults=[],
            kwarg=None,
            defaults=[],
        )
        body = list(tree.body) or [ast.Pass()]
        node = ast.FunctionDef(
            name=scope.module_dotted or scope.file_path.stem,
            args=args,
            body=body,
            decorator_list=[],
            returns=None,
            type_comment=None,
        )
        node.lineno = 1
        node.col_offset = 0
        node.end_lineno = getattr(tree, "end_lineno", None) or 1
        node.end_col_offset = 0
        return node

    @staticmethod
    def _module_node(path: Path, scope: ModuleScope) -> FunctionNode:
        module_name = scope.module_dotted or path.stem
        return FunctionNode(
            file_path=str(path),
            function_name=module_name,
            qualified_name=module_name,
            line_number=1,
            module=module_name,
            scope="<module>",
            signature="()",
            arity=0,
            entry_type=EntryPointType.MAIN,
        )

    # -- definition iteration -------------------------------------

    def _iter_defs(self, tree: ast.Module, scope: ModuleScope
                   ) -> Iterator[Tuple[_FuncDef, FunctionNode, Optional[ClassInfo]]]:
        """Yield ``(def_node, canonical_caller_node, enclosing_class)`` for every
        top-level function and direct method in *tree*. The caller node is fetched
        from the index so its identity matches the callee nodes produced elsewhere.
        """
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn = scope.local_funcs.get(node.name)
                if fn is not None:
                    yield node, fn, None
            elif isinstance(node, ast.ClassDef):
                ci = scope.local_classes.get(node.name)
                if ci is None:
                    continue
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        mnode = ci.methods.get(sub.name)
                        if mnode is not None:
                            yield sub, mnode, ci

    # -- per-definition analysis (Layer 1 -> Layer 2) -------------

    def _analyze_definition(self, func_def: _FuncDef, scope: ModuleScope,
                            enclosing: Optional[ClassInfo]) -> List[FunctionNode]:
        assert self.pipeline is not None
        # Compatibility wrapper for older callers; reports use a synthetic caller.
        caller = FunctionNode(
            file_path=str(scope.file_path),
            function_name=getattr(func_def, "name", "<unknown>"),
            qualified_name=getattr(func_def, "name", "<unknown>"),
            line_number=getattr(func_def, "lineno", 0),
        )
        return self.pipeline.analyze_definition(caller, func_def, scope, enclosing)



# ══════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def build_library_graph(library_root: Path) -> CallGraph:
    """Exhaustively build the library call graph (G_L) under *library_root*.

    Convenience wrapper around :class:`LibraryAnalyzer` — the canonical entry
    point referenced by the rest of the F-VRA pipeline.

    Parameters
    ----------
    library_root:
        Root directory of the third-party library to analyse.

    Returns
    -------
    CallGraph
        ``nodes`` = every function / method defined in the library; ``edges`` =
        the directed, points-to-refined call relationships between them.
    """
    return LibraryAnalyzer().build_library_graph(Path(library_root))
