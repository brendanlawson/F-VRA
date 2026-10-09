"""
callgraph_builder.project_builder
═════════════════════════════════
Project-Centered Call Graph construction — the **application** side of the
VRA / F-VRA framework, and the producer of the **Usage Index (UI)**.

Where :mod:`callgraph_builder.library_builder` (Phase 1) walks a third-party
library *exhaustively* — every function and method becomes a node whether or not
anything ever calls it — this module (Phase 3) does the opposite. An application
contains a great deal of dead code (unused helpers, disabled feature branches,
vendored snippets), and analysing it wastes time *and* manufactures spurious
cross-TPL edges that never actually fire at runtime. So we build the project's
call graph **lazily**, driven by *reachability*:

    Entry points → worklist → (analyse → discover callees → enqueue) → fixpoint

Only code transitively reachable from a real entry point is ever analysed. The
by-product of that walk is the prize: every time a reachable function crosses the
boundary into another library (``requests.get()``, ``flask.Flask()``), we emit a
precise :class:`~f_vra.core.models.ExternalNode`. The deduplicated set of those
boundary calls **is** the Usage Index ($UI$) — the exact list of third-party
symbols this application actually triggers, which downstream phases intersect
against the per-library summaries to answer "is the app reachable to this CVE?".

The 3-step engine
-----------------
**Step 1 — Global Project Indexing (exhaustive scan).** Reachability is lazy, but
*symbol resolution* cannot be: to know that a call inside file *A* lands on a
class defined in file *B* we must already have indexed *B*. So we first scan
**every** ``.py`` file and build a :class:`ProjectIndex`. This subclasses Phase
1's :class:`~callgraph_builder.library_builder.LibraryIndex` and therefore inherits
its battle-tested machinery *verbatim*: longest-suffix module resolution
(``pkg.mod.Cls`` ↔ ``mod.Cls``), MRO / ``base_classes`` linearisation for
``super()`` and inherited-method dispatch, and internal-vs-external import
classification. On top of that it builds one extra table — a **definition
registry** mapping each canonical :class:`FunctionNode` back to its AST node — so
the worklist can re-open a function for analysis the moment it is popped.

**Step 2 — Entry Point Discovery (:class:`EntryPointDetector`).** Scans the index
for the two strongest static signals of "the outside world calls in here":

    a) ``if __name__ == "__main__":`` guards (each bare call inside resolves to a
       module-level function → :attr:`EntryPointType.MAIN`).
    b) web-framework route decorators whose dotted name starts with one of
       ``@app.`` / ``@router.`` / ``@bp.`` (→ :attr:`EntryPointType.WEB`).

    **Critical fallback:** if *exactly zero* entry points are found (a library-like
    project, or one using a framework we don't pattern-match), we degrade
    gracefully by treating **all module-level public functions** as entry points,
    rather than returning an empty graph.

**Step 3 — Worklist-Driven Analyzer (:class:`WorklistProjectAnalyzer`).** Seeds a
worklist with the discovered entry points and runs to a fixpoint. Each popped
function is analysed with the **exact same 2-layer pipeline as Phase 1** — there
is deliberately *no* second implementation of it here; we import and drive the
real classes:

    * **Layer 1** — :class:`~callgraph_builder.library_builder.ASTCandidateGenerator`
      (broad net / high recall): pure-syntactic tentative edges for every call.
    * **Layer 2** — :class:`~callgraph_builder.library_builder.AndersenPointsToAnalyzer`
      (flow-sensitive points-to with strong updates): prunes Layer 1's
      over-approximation down to the receiver types that can actually reach a site.

Then the orchestration applies the same Layer-2 *refinement* rule as
:class:`~callgraph_builder.library_builder.LibraryAnalyzer` and acts on each
surviving callee:

    * **Internal** target (resolved to a project file) → record the edge and, if
      the function has never been analysed, push it onto the worklist.
    * **External** target (an :class:`ExternalNode`) → record the exact,
      *non-prunable* boundary edge and add it to the Usage Index, **but never
      enqueue it** — we do not own that code and do not walk into it.

Output
------
:func:`build_project_graph` returns ``Tuple[CallGraph, List[ExternalNode]]``:
the reachable internal call graph, and the Usage Index (deduplicated boundary
calls). :func:`build_application_centered_graph` is the lower-level entry point
for callers that supply their own roots and only need the :class:`CallGraph`.

Robustness contract (identical to Phase 1)
------------------------------------------
  * **Never execute project code** — 100 % static ``ast`` parsing.
  * **Never crash on bad input** — sources are read ``utf-8-sig`` and every parse
    / per-function analysis is wrapped so one broken module can't abort the build.
  * **Reuse, don't reinvent** — Layer 1, Layer 2, the index, MRO/``super()``
    handling and :class:`PointsToState` semantics are imported from
    ``library_builder``; only the entry-point discovery and the
    reachability-driven worklist are new here.
"""
from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from f_vra.core.models import (
    CallEdge,
    CallGraph,
    EntryPointType,
    ExternalNode,
    FunctionNode,
)

# ── Reuse Phase 1 verbatim — do NOT reimplement the index or either layer. ──────
# These are the precise, perfected building blocks from ``library_builder``:
#   * LibraryIndex                  — exhaustive symbol table + MRO + suffix lookup
#   * ModuleScope / ClassInfo       — per-file resolution context
from f_vra.analysis.callgraph.engine import (
    CallGraphConstructionPipeline,
    ClassInfo,
    LibraryIndex,
    ModuleScope,
    _FuncDef,
    _dotted_name,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════
# STEP 1 — GLOBAL PROJECT INDEX (exhaustive scan, lazy analysis)
# ══════════════════════════════════════════════════════════════════

@dataclass
class _DefContext:
    """Everything the worklist needs to (re-)analyse one function on demand.

    Captured once during indexing so that, when a :class:`FunctionNode` is popped
    off the worklist, we can immediately re-open its body without re-walking the
    whole tree: the AST def node to analyse, the :class:`ModuleScope` that resolves
    its names, and (for methods) the :class:`ClassInfo` that owns it so ``self`` /
    ``cls`` / ``super()`` resolve through the right MRO.
    """
    def_node: _FuncDef
    scope: ModuleScope
    enclosing: Optional[ClassInfo]


class ProjectIndex(LibraryIndex):
    """Exhaustive whole-project symbol table + a function→AST definition registry.

    Inherits *all* of :class:`~callgraph_builder.library_builder.LibraryIndex`'s
    behaviour unchanged — the filesystem walk, ``utf-8-sig`` safe parsing,
    longest-suffix class/function resolution, internal-vs-external import
    classification, and the MRO machinery (:meth:`iter_bases`,
    :meth:`mro_classes`, :meth:`resolve_method_mro`) that powers ``super()`` and
    inherited-method dispatch. We add exactly one thing the worklist needs that an
    exhaustive builder does not: a :attr:`def_registry` mapping every canonical
    :class:`FunctionNode` to its :class:`_DefContext`, so a popped node can be
    re-opened for analysis in O(1).

    The registry is keyed by :class:`FunctionNode` identity ``(normpath, name)``
    — methods carry ``"Class.method"`` names (set by the base index), so a fresh
    node built by the entry-point detector with the same file+name still hits the
    canonical context here.
    """

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        # FunctionNode -> how to analyse it. Populated after the base two passes.
        self.def_registry: Dict[FunctionNode, _DefContext] = {}

    def build(self) -> "ProjectIndex":
        super().build()                 # pass 1 (collect) + pass 2 (scopes)
        self._build_def_registry()      # pass 3: function -> AST def context
        logger.info("[ProjGraph] Project index ready: %d definition(s) registered",
                    len(self.def_registry))
        return self

    def _build_def_registry(self) -> None:
        """Map each canonical module-level function and direct method to its AST.

        Mirrors :meth:`LibraryAnalyzer._iter_defs` so the *same* canonical nodes
        the index already minted (``scope.local_funcs`` / ``ClassInfo.methods``)
        become the registry keys — guaranteeing the worklist, the candidate
        generator and the edges all share one node identity per function.
        """
        for path, tree in self.asts.items():
            scope = self.scopes.get(path)
            if scope is None:
                continue
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn = scope.local_funcs.get(node.name)
                    if fn is not None:
                        self.def_registry[fn] = _DefContext(node, scope, None)
                elif isinstance(node, ast.ClassDef):
                    ci = scope.local_classes.get(node.name)
                    if ci is None:
                        continue
                    for sub in node.body:
                        if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            mnode = ci.methods.get(sub.name)
                            if mnode is not None:
                                self.def_registry[mnode] = _DefContext(sub, scope, ci)


# ══════════════════════════════════════════════════════════════════
# STEP 2 — ENTRY POINT DISCOVERY
# ══════════════════════════════════════════════════════════════════

# A web route decorator's *head* — the object the decorator hangs off. Flask's
# ``@app.route`` / ``@bp.route``, FastAPI/Starlette's ``@app.get`` /
# ``@router.post`` all attach the verb to one of these well-known names. We match
# on the head rather than the verb so any HTTP method (or a custom one) counts,
# exactly as the task specifies ("node names starting with @app./@router./@bp.").
WEB_DECORATOR_HEADS: Set[str] = {"app", "router", "bp", "blueprint", "api"}


def _is_main_guard(test: ast.expr) -> bool:
    """``True`` for an ``if __name__ == "__main__":`` test (either operand order).

    Mirrors ``project_scanner.scanner._is_main_guard`` so entry-point detection is
    consistent with the standalone scanner.
    """
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    left, right = test.left, test.comparators[0]
    return (_eq_name_str(left, right) or _eq_name_str(right, left))


def _eq_name_str(name_side: ast.expr, str_side: ast.expr) -> bool:
    return (isinstance(name_side, ast.Name) and name_side.id == "__name__"
            and isinstance(str_side, ast.Constant) and str_side.value == "__main__")


def _decorator_dotted(dec: ast.expr) -> Optional[str]:
    """Dotted name of a decorator, unwrapping a decorator-factory call.

    ``@app.route("/")`` → ``"app.route"``; ``@router.get`` → ``"router.get"``;
    ``@staticmethod`` → ``"staticmethod"``. Returns ``None`` for shapes we can't
    flatten (subscripted / dynamically-built decorators).
    """
    target = dec.func if isinstance(dec, ast.Call) else dec
    return _dotted_name(target)


def _is_web_route_decorator(dec: ast.expr) -> bool:
    """Whether *dec* looks like a web route binding (``@app.`` / ``@router.`` …)."""
    dotted = _decorator_dotted(dec)
    if dotted == "cherrypy.expose":
        return True
    if not dotted or "." not in dotted:
        return False
    return dotted.split(".", 1)[0] in WEB_DECORATOR_HEADS


class EntryPointDetector:
    """Discover application entry points from an already-built :class:`ProjectIndex`.

    Two positive signals, then a safety net:

      a) **``__main__`` guards** — every bare ``name()`` called inside an
         ``if __name__ == "__main__":`` block that resolves to a module-level
         function in the same file (``EntryPointType.MAIN``).
      b) **Web route decorators** — any function or method decorated with
         ``@app.* / @router.* / @bp.*`` (``EntryPointType.WEB``).

      **Fallback** — if (a) and (b) together yield *nothing*, return **all
      module-level public functions** (name not starting with ``_``) so a
      library-style or unrecognised-framework project still produces a usable,
      non-empty reachable graph instead of an empty one.

    Returned nodes are the index's *canonical* :class:`FunctionNode` objects (so
    their identity matches everything the worklist will discover later), with
    their :attr:`entry_type` stamped to reflect *why* they were chosen.
    """

    def __init__(self, index: ProjectIndex) -> None:
        self.index = index
        self.used_fallback = False

    def detect(self) -> List[FunctionNode]:
        found: Dict[FunctionNode, EntryPointType] = {}

        for path, tree in self.index.asts.items():
            scope = self.index.scopes.get(path)
            if scope is None:
                continue
            try:
                self._scan_main_guards(tree, scope, found)
                self._scan_decorated_defs(tree, scope, found)
                self._scan_template_global_exports(tree, scope, found)
            except Exception as exc:    # one odd module never aborts discovery
                logger.debug("[ProjGraph] entry-point scan error in %s: %s", path, exc)

        if found:
            entries = self._stamp(found)
            logger.info("[ProjGraph] Discovered %d entry point(s) "
                        "(%d main, %d web)", len(entries),
                        sum(t is EntryPointType.MAIN for t in found.values()),
                        sum(t is EntryPointType.WEB for t in found.values()))
            return entries

        # ── CRITICAL FALLBACK ──────────────────────────────────────────────
        # No explicit entry signal anywhere → treat every module-level public
        # function as a possible entry, so the worklist still has something to
        # walk from. Better an over-approximate reachable set than an empty one.
        fallback = self._fallback_public_functions()
        self.used_fallback = True
        logger.warning("[ProjGraph] No explicit entry points found; falling back "
                       "to %d module-level public function(s)", len(fallback))
        return fallback

    # -- signal (a): __main__ guards ------------------------------

    def _scan_main_guards(self, tree: ast.Module, scope: ModuleScope,
                          found: Dict[FunctionNode, EntryPointType]) -> None:
        for node in ast.walk(tree):
            if not (isinstance(node, ast.If) and _is_main_guard(node.test)):
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
                    fn = scope.local_funcs.get(sub.func.id)
                    if fn is not None:
                        found.setdefault(fn, EntryPointType.MAIN)

    # -- signal (b): web route decorators -------------------------

    def _scan_decorated_defs(self, tree: ast.Module, scope: ModuleScope,
                             found: Dict[FunctionNode, EntryPointType]) -> None:
        # Module-level functions decorated as routes.
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if self._has_web_decorator(node):
                    fn = scope.local_funcs.get(node.name)
                    if fn is not None:
                        found.setdefault(fn, EntryPointType.WEB)
            elif isinstance(node, ast.ClassDef):
                # Class-based views: decorated methods are routes too.
                ci = scope.local_classes.get(node.name)
                if ci is None:
                    continue
                for sub in node.body:
                    if (isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and self._has_web_decorator(sub)):
                        meth = ci.methods.get(sub.name)
                        if meth is not None:
                            found.setdefault(meth, EntryPointType.WEB)

    @staticmethod
    def _has_web_decorator(node: _FuncDef) -> bool:
        return any(_is_web_route_decorator(dec) for dec in node.decorator_list)

    # -- signal (c): template/global exports ----------------------

    def _scan_template_global_exports(
        self,
        tree: ast.Module,
        scope: ModuleScope,
        found: Dict[FunctionNode, EntryPointType],
    ) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                self._scan_template_global_assignment(node, scope, found)
            elif isinstance(node, ast.Call):
                self._scan_template_global_update(node, scope, found)

    def _scan_template_global_assignment(
        self,
        node: ast.Assign,
        scope: ModuleScope,
        found: Dict[FunctionNode, EntryPointType],
    ) -> None:
        if not any(self._is_template_global_subscript(target) for target in node.targets):
            return
        if isinstance(node.value, ast.Name):
            self._record_local_function(scope, node.value.id, found)

    def _scan_template_global_update(
        self,
        node: ast.Call,
        scope: ModuleScope,
        found: Dict[FunctionNode, EntryPointType],
    ) -> None:
        if not self._is_template_globals_update(node.func):
            return
        if not node.args:
            return
        first = node.args[0]
        if self._is_globals_call(first):
            self._record_public_module_functions(scope, found)
        elif isinstance(first, ast.Dict):
            for value in first.values:
                if isinstance(value, ast.Name):
                    self._record_local_function(scope, value.id, found)

    @staticmethod
    def _is_template_global_subscript(target: ast.AST) -> bool:
        return (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Attribute)
            and target.value.attr == "globals"
        )

    @staticmethod
    def _is_template_globals_update(func: ast.expr) -> bool:
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "update"
            and isinstance(func.value, ast.Attribute)
            and func.value.attr == "globals"
        )

    @staticmethod
    def _is_globals_call(expr: ast.expr) -> bool:
        return (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == "globals"
        )

    @staticmethod
    def _record_local_function(
        scope: ModuleScope,
        name: str,
        found: Dict[FunctionNode, EntryPointType],
    ) -> None:
        fn = scope.local_funcs.get(name)
        if fn is not None:
            found.setdefault(fn, EntryPointType.WEB)

    def _record_public_module_functions(
        self,
        scope: ModuleScope,
        found: Dict[FunctionNode, EntryPointType],
    ) -> None:
        for name, fn in scope.local_funcs.items():
            if name.startswith("_"):
                continue
            found.setdefault(fn, EntryPointType.WEB)

    # -- fallback: all module-level public functions --------------

    def _fallback_public_functions(self) -> List[FunctionNode]:
        out: List[FunctionNode] = []
        seen: Set[FunctionNode] = set()
        for scope in self.index.scopes.values():
            for name, fn in scope.local_funcs.items():
                if name.startswith("_"):
                    continue
                if fn not in seen:
                    seen.add(fn)
                    fn.entry_type = EntryPointType.UNKNOWN
                    out.append(fn)
        return out

    def detect_public_surface(self) -> List[FunctionNode]:
        """Return public functions/methods as diagnostic roots for library-like projects."""
        out = self._fallback_public_functions()
        seen: Set[FunctionNode] = set(out)
        for scope in self.index.scopes.values():
            for info in scope.local_classes.values():
                if info.name.startswith("_"):
                    continue
                for name, method in info.methods.items():
                    if name.startswith("_") and name != "__init__":
                        continue
                    if method not in seen:
                        seen.add(method)
                        method.entry_type = EntryPointType.UNKNOWN
                        out.append(method)
        return out

    @staticmethod
    def _stamp(found: Dict[FunctionNode, EntryPointType]) -> List[FunctionNode]:
        """Stamp the discovered reason onto each canonical node and return them."""
        entries: List[FunctionNode] = []
        for fn, etype in found.items():
            fn.entry_type = etype
            entries.append(fn)
        return entries


# ══════════════════════════════════════════════════════════════════
# STEP 3 — WORKLIST-DRIVEN ANALYZER (reachability-driven, lazy)
# ══════════════════════════════════════════════════════════════════

class WorklistProjectAnalyzer:
    """Reachability-driven call-graph construction + Usage Index extraction.

    Seeds a worklist with the entry points and runs a classic fixpoint: pop a
    function, analyse it with the imported Phase-1 2-layer pipeline, record the
    resolved edges, enqueue every *internal* callee never seen before, and emit an
    :class:`ExternalNode` for every *external* callee (without enqueueing it).
    When the worklist drains, the reachable internal graph and the deduplicated
    Usage Index are complete.
    """

    def __init__(self, index: ProjectIndex) -> None:
        self.index = index
        self.pipeline = CallGraphConstructionPipeline(index)
        self.graph = CallGraph()
        self.worklist: List[FunctionNode] = []
        self._seen_edges: Set[Tuple[FunctionNode, FunctionNode]] = set()
        self._queued_contexts: Set[Tuple[str, str]] = set()
        self._analyzed_contexts: Set[Tuple[str, str]] = set()
        self.reanalyzed_contexts: List[dict] = []
        # Usage Index ($UI$): deduplicated boundary calls, keyed by ExternalNode
        # identity (target_module, target_name) so the same symbol called from
        # many sites collapses to one entry.
        self._external: Dict[ExternalNode, ExternalNode] = {}

    # -- public driver --------------------------------------------

    def run(self, entry_points: List[FunctionNode]) -> Tuple[CallGraph, List[ExternalNode]]:
        # Seed the worklist; entry points become the graph's roots.
        for ep in entry_points:
            self.graph.add_node(ep)
            self._enqueue(ep)

        # Fixpoint: internal nodes may be re-analysed when their propagated
        # argument/receiver types create a new context signature.
        while self.worklist:
            caller = self.worklist.pop()
            context = self._context_for(caller)
            key = (self._node_name(caller), context)
            self._queued_contexts.discard(key)
            if key in self._analyzed_contexts:
                continue
            if any(name == key[0] for name, _ctx in self._analyzed_contexts):
                self.reanalyzed_contexts.append({"function": key[0], "context": context})
            self._analyzed_contexts.add(key)
            try:
                callees = self._analyze(caller)
            except Exception as exc:    # a single bad function never kills the build
                logger.warning("[ProjGraph] Failed to analyze %s (%s): %s",
                               caller.function_name, caller.file_path, exc)
                continue
            changed = set(self.pipeline.last_changed_entry_functions)
            for callee in callees:
                self._record(caller, callee, force_enqueue=self._node_name(callee) in changed)

        ui = list(self._external.values())
        self.graph.metadata.update(self.pipeline.report())
        self.graph.metadata["skipped_files"] = list(self.index.skipped_files)
        self.graph.metadata["analysis_mode"] = "application_centered_worklist"
        self.graph.metadata["entry_contexts"] = [
            {
                "function": self._node_name(ep),
                "context": self.pipeline.context_signature_for(self._node_name(ep)),
            }
            for ep in entry_points
        ]
        self.graph.metadata["reanalyzed_contexts"] = list(self.reanalyzed_contexts)
        logger.info("[ProjGraph] Reachable graph: %d node(s), %d edge(s); "
                    "Usage Index: %d external symbol(s)",
                    len(self.graph.nodes), len(self.graph.edges), len(ui))
        return self.graph, ui

    # -- edge / node bookkeeping ----------------------------------

    def _enqueue(self, node: FunctionNode) -> None:
        key = (self._node_name(node), self._context_for(node))
        if key in self._analyzed_contexts or key in self._queued_contexts:
            return
        self._queued_contexts.add(key)
        self.worklist.append(node)

    def _context_for(self, node: FunctionNode) -> str:
        return self.pipeline.context_signature_for(self._node_name(node))

    @staticmethod
    def _node_name(node: FunctionNode) -> str:
        return node.qualified_name or node.function_name

    def _record(self, caller: FunctionNode, callee: FunctionNode, *, force_enqueue: bool = False) -> None:
        """Record one resolved edge and route the callee by internal/external."""
        edge_key = (caller, callee)
        if edge_key not in self._seen_edges:
            self._seen_edges.add(edge_key)
            evidence = self.pipeline.edge_evidence.get(
                (caller.qualified_name or caller.function_name, callee.qualified_name or callee.function_name),
                {},
            )
            self.graph.edges.append(CallEdge(caller=caller, callee=callee, **evidence))

        if callee.is_external:
            # Cross-TPL boundary: contribute to the Usage Index, keep the node in
            # the graph so the boundary edge is well-formed, but NEVER walk into
            # it — we do not own that library's source.
            assert isinstance(callee, ExternalNode)
            self._external.setdefault(callee, callee)
            self.graph.add_node(callee)
        else:
            # Internal project function: enqueue it when first seen or when
            # propagated parameter facts created a new context signature.
            added = self.graph.add_node(callee)
            if added or force_enqueue:
                self._enqueue(callee)

    # -- per-function analysis through the shared construction pipeline -------

    def _analyze(self, caller: FunctionNode) -> List[FunctionNode]:
        """Run the exact Phase-1 2-layer pipeline over one reachable function.

        Identical staging to :meth:`LibraryAnalyzer._analyze_definition`: the
        shared pipeline emits broad candidates, computes flow-sensitive receiver
        types, and resolves the final callees.

        """
        ctx = self.index.def_registry.get(caller)
        if ctx is None:
            # Caller has no body we can open (e.g. an external node accidentally
            # enqueued, or a node minted outside the index). Nothing to analyse.
            return []

        return self.pipeline.analyze_definition(caller, ctx.def_node, ctx.scope, ctx.enclosing)



# ══════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINTS
# ══════════════════════════════════════════════════════════════════

def build_project_graph(project_root: Path, *, project_mode: str = "application") -> Tuple[CallGraph, List[ExternalNode]]:
    """Build the reachable project call graph and its Usage Index ($UI$).

    Runs the full 3-step engine: exhaustive indexing → entry-point discovery →
    reachability-driven worklist analysis.

    Parameters
    ----------
    project_root:
        Root directory of the target application to analyse.

    Returns
    -------
    Tuple[CallGraph, List[ExternalNode]]
        * **CallGraph** — the reachable internal call graph: ``nodes`` = every
          project function transitively reachable from an entry point (plus the
          external boundary nodes that those calls land on), ``edges`` = the
          points-to-refined call relationships between them.
        * **List[ExternalNode]** — the **Usage Index**: the deduplicated set of
          exact cross-TPL boundary calls the application actually triggers.

    Raises
    ------
    FileNotFoundError / NotADirectoryError
        If *project_root* does not exist or is not a directory. Unreadable or
        unparsable individual modules are skipped, never fatal.
    """
    root = Path(project_root)
    if not root.exists():
        raise FileNotFoundError(f"Project root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Project root is not a directory: {root}")

    # Step 1 — exhaustive index (symbol resolution must be complete & eager).
    index = ProjectIndex(root).build()
    detector = EntryPointDetector(index)
    if project_mode == "application":
        # Step 2 — discover where the outside world calls in (with safe fallback).
        entry_points = detector.detect()
    elif project_mode == "public_surface":
        entry_points = detector.detect_public_surface()
    else:
        raise ValueError(f"unknown project_mode: {project_mode}")
    # Step 3 — lazily walk only what those entry points can reach.
    graph, usage_index = WorklistProjectAnalyzer(index).run(entry_points)
    graph.metadata["entrypoint_fallback_used"] = detector.used_fallback
    graph.metadata["project_mode"] = project_mode
    graph.metadata["entry_points"] = sorted(
        ep.qualified_name or ep.function_name for ep in entry_points
    )
    return graph, usage_index


def build_application_centered_graph(
    entry_points: List[FunctionNode], project_root: Path
) -> CallGraph:
    """Build the reachable graph from caller-supplied entry points.

    This runs the same reachability-driven worklist over the same 2-layer
    pipeline as :func:`build_project_graph`, but skips internal entry-point
    discovery and returns only the :class:`CallGraph`. Callers that also want
    the Usage Index should prefer :func:`build_project_graph`.

    Parameters
    ----------
    entry_points:
        Seed functions to start the worklist from — typically the output of
        ``project_scanner.scan_project``. An empty list yields an empty graph.
    project_root:
        Root directory of the target project; only functions defined under it are
        resolved and walked.
    """
    root = Path(project_root)
    if not root.exists():
        raise FileNotFoundError(f"Project root does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Project root is not a directory: {root}")

    index = ProjectIndex(root).build()
    # Re-key the caller-supplied entry points onto the index's canonical nodes
    # where possible, so identity matches everything the worklist discovers; any
    # node not in the registry is still usable as a seed (it simply analyses to
    # no callees if it has no resolvable body).
    seeds: List[FunctionNode] = []
    seen: Set[FunctionNode] = set()
    registry = index.def_registry
    for ep in entry_points:
        canonical = next((fn for fn in registry if fn == ep), ep)
        if canonical not in seen:
            seen.add(canonical)
            seeds.append(canonical)

    graph, _ui = WorklistProjectAnalyzer(index).run(seeds)
    return graph
