"""
pcsg_indexer.indexer
════════════════════
Phase 2 of the F-VRA framework — **Transitive Closure Indexing**.

``library_builder`` (Phase 1) hands us a precise but verbose
:class:`~f_vra.core.models.CallGraph`: every first-party
:class:`~f_vra.core.models.FunctionNode`, every cross-TPL-boundary
:class:`~f_vra.core.models.ExternalNode`, and the points-to-refined call
edges between them. Answering "is X reachable from public API Y?" by walking
that graph on every query is wasteful. This module instead pre-computes the
**transitive closure** (``G_L^+``) once and compresses it into a
:class:`~f_vra.core.models.LibrarySummary`, so later phases answer reachability
with an O(1) set lookup.

Why ``scipy.sparse``
--------------------
A real library call graph is large (tens of thousands of nodes) but *sparse* —
each function calls only a handful of others, so the adjacency matrix has a tiny
fraction of its ``N×N`` cells filled. Storing it as a dense matrix would cost
``N²`` bytes (gigabytes for a big library); a **CSR (Compressed Sparse Row)**
matrix stores only the non-zeros, keeping the footprint to a few MBs and giving
:mod:`scipy.sparse.csgraph` a cache-friendly layout for fast traversal. CSR is
mandatory here for exactly that enterprise-scalability reason.

Why per-API BFS rather than a full ``N×N`` closure
--------------------------------------------------
The mathematically tidy object is the full ``N×N`` boolean reachability matrix,
obtainable by repeated boolean squaring of the adjacency matrix
(``R = A | A² | A³ | …`` until it stabilises). But that closure is frequently
*dense* even when the graph is sparse (one widely-reachable utility makes a whole
column dense), which would blow the memory budget the CSR layout exists to
protect. Since the summary only ever needs the closure rows for the **public
APIs** — not for every internal node — we instead run a directed
breadth-first traversal (:func:`scipy.sparse.csgraph.breadth_first_order`) from
each API over the CSR adjacency. Each traversal materialises exactly one
closure row (the reach-set of that API) and nothing more, so peak memory stays
proportional to the largest single reach-set, not to ``N²``. The collected rows
are assembled into a sparse ``(num_api × N)`` closure matrix — the relevant
slice of ``G_L^+`` — which is what the summaries are read off of.
"""
from __future__ import annotations

import ast
import logging
from collections import deque
from typing import Any, Deque, Dict, List, Mapping, Optional, Sequence

import numpy as np
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import breadth_first_order

from f_vra.core.models import (
    CallGraph,
    ExternalNode,
    FunctionNode,
    LibrarySummary,
)

logger = logging.getLogger(__name__)


_NOISE_CALL_NAMES = {
    "__class__",
    "__enter__",
    "__exit__",
    "__getitem__",
    "__init__",
    "__iter__",
    "__len__",
    "__next__",
    "__setitem__",
    "add",
    "all",
    "any",
    "append",
    "bool",
    "bytes",
    "clear",
    "close",
    "copy",
    "count",
    "dict",
    "discard",
    "encode",
    "endswith",
    "enumerate",
    "extend",
    "filter",
    "float",
    "format",
    "get",
    "hasattr",
    "index",
    "insert",
    "int",
    "isinstance",
    "issubclass",
    "items",
    "iter",
    "join",
    "keys",
    "len",
    "list",
    "locals",
    "lower",
    "lstrip",
    "map",
    "max",
    "min",
    "next",
    "object",
    "open",
    "pop",
    "print",
    "range",
    "read",
    "remove",
    "replace",
    "reversed",
    "rstrip",
    "set",
    "setdefault",
    "sort",
    "split",
    "startswith",
    "str",
    "strip",
    "sum",
    "super",
    "tuple",
    "type",
    "update",
    "upper",
    "values",
    "write",
    "zip",
}

_NOISE_EXCEPTION_NAMES = {
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "EOFError",
    "Exception",
    "ImportError",
    "IndexError",
    "KeyError",
    "LookupError",
    "NameError",
    "NotImplementedError",
    "OSError",
    "RuntimeError",
    "StopIteration",
    "SyntaxError",
    "SystemExit",
    "TypeError",
    "ValueError",
    "Warning",
}


def _warning_leaf(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "(" in text:
        text = text.split("(", 1)[0]
    return text.rsplit(".", 1)[-1]


def _is_noise_leaf(value: Any) -> bool:
    leaf = _warning_leaf(value)
    if not leaf:
        return False
    return (
        leaf in _NOISE_CALL_NAMES
        or leaf in _NOISE_EXCEPTION_NAMES
        or leaf.endswith("Error")
        or leaf.endswith("Exception")
        or leaf.endswith("Warning")
    )


def is_verdict_noise_symbol(value: Any) -> bool:
    """Return True for builtin/container/exception-like symbols.

    Reachability verdict code uses this public wrapper to keep summary warning
    filtering and unresolved-frontier filtering aligned.
    """
    return _is_noise_leaf(value)


def _literal_arg(call_expr: str, index: int) -> str | None:
    try:
        expr = ast.parse(call_expr, mode="eval").body
    except SyntaxError:
        return None
    if not isinstance(expr, ast.Call) or len(expr.args) <= index:
        return None
    value = expr.args[index]
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return None


def _call_func_name(call_expr: str) -> str:
    try:
        expr = ast.parse(call_expr, mode="eval").body
    except SyntaxError:
        return str(call_expr or "").split("(", 1)[0]
    if not isinstance(expr, ast.Call):
        return ""
    try:
        return ast.unparse(expr.func)
    except Exception:
        return ""


def _is_literal_reflection_guard(item: Mapping[str, Any]) -> bool:
    call_name = str(item.get("call_name") or _warning_leaf(item.get("call_expr")) or "")
    call_expr = str(item.get("call_expr") or "")
    if call_name not in {"getattr", "hasattr", "setattr", "delattr"}:
        return False
    return _literal_arg(call_expr, 1) is not None


def _is_dynamic_import_warning(item: Mapping[str, Any]) -> bool:
    call_name = str(item.get("call_name") or _call_func_name(str(item.get("call_expr") or "")))
    return call_name in {"__import__", "importlib.import_module", "import_module"}


def _is_literal_dynamic_import(item: Mapping[str, Any]) -> bool:
    if not _is_dynamic_import_warning(item):
        return False
    return _literal_arg(str(item.get("call_expr") or ""), 0) is not None


def _is_verdict_affecting_warning_item(item: Mapping[str, Any]) -> bool:
    status = str(item.get("status") or "")
    resolver = str(item.get("resolver") or "")
    call_expr = str(item.get("call_expr") or "")
    call_name = str(item.get("call_name") or _call_func_name(call_expr) or item.get("target") or item.get("callee") or "")
    receiver = str(item.get("receiver") or "")

    if _is_literal_reflection_guard(item) or _is_literal_dynamic_import(item):
        return False
    if _is_dynamic_import_warning(item):
        return True
    if call_name in {"eval", "exec", "compile"}:
        return True
    if call_name in {"getattr", "setattr", "delattr"}:
        return True
    if status == "too_many_candidates":
        return not (_is_noise_leaf(call_name) or receiver == "super()")
    if resolver in {"factory_unknown_receiver", "fluent_chain", "unknown_receiver_method"}:
        return not _is_noise_leaf(call_name)
    if _is_noise_leaf(call_name) or _is_noise_leaf(item.get("callee")):
        return False
    return bool(call_name or item.get("callee") or item.get("target"))


def filter_verdict_affecting_warnings(warnings: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only summary warnings that should influence reachability verdicts.

    Diagnostics still retain raw counts. This filter removes builtin/container,
    exception-constructor, literal-reflection guard, and literal dynamic import
    noise so summaries only elevate ``potentially_reachable`` for unresolved
    dynamic behavior that can plausibly hide a vulnerable path.
    """
    filtered: dict[str, Any] = {}
    for key, value in warnings.items():
        if key == "skipped_files":
            continue
        if key == "unresolved_public_exports":
            if value:
                filtered[key] = value
            continue
        if key in {"candidate_edges", "unresolved_calls", "llm_kept_edges"} and isinstance(value, list):
            kept = [
                item
                for item in value
                if isinstance(item, Mapping) and _is_verdict_affecting_warning_item(item)
            ]
            if kept:
                filtered[key] = kept
            continue
        if value:
            filtered[key] = value
    return filtered


def _node_sort_key(node: FunctionNode) -> tuple:
    """Deterministic ordering key for assigning integer indices to nodes.

    ``CallGraph.nodes`` is a ``set`` (no stable iteration order across runs).
    We materialise a reproducible index map so the adjacency matrix — and any
    artefact derived from it — is byte-for-byte stable for the same graph, which
    matters for caching and for debuggable ``.npz`` dumps. Internal nodes sort
    before external ones; ties break on the dotted names so the order is
    human-readable.
    """
    return (node.is_external, node.qualified_name, node.file_path,
            node.function_name)


def _external_target(node: ExternalNode) -> str:
    """Render an :class:`ExternalNode` as its dotted ``module.name`` target.

    This is the canonical S_o identity for a cross-TPL edge: the symbol the
    library actually reaches into (``"werkzeug.serving"`` + ``"run_simple"`` →
    ``"werkzeug.serving.run_simple"``). Either component may be empty, so we drop
    blanks rather than emit a stray leading/trailing dot.
    """
    return ".".join(part for part in (node.target_module, node.target_name)
                    if part)


def _render_node(node: FunctionNode) -> str:
    if isinstance(node, ExternalNode):
        return _external_target(node)
    return node.qualified_name or node.function_name


def _api_key(api: FunctionNode) -> str:
    """The summary dictionary key for a public API — its ``qualified_name``,
    falling back to ``function_name`` for the rare node that carries no dotted
    path (keeps the key non-empty and stable)."""
    return api.qualified_name or api.function_name


def _matches_qualified_suffix(value: str, suffix: str) -> bool:
    return value == suffix or value.endswith(f".{suffix}") or suffix.endswith(f".{value}")


def _summary_key(summary: LibrarySummary, target: str) -> str | None:
    keys = set(summary.inner_summary) | set(summary.outer_summary)
    if target in keys:
        return target
    matches = [
        key
        for key in keys
        if _matches_qualified_suffix(key, target)
    ]
    if len(matches) == 1:
        return matches[0]
    if matches:
        return max(matches, key=lambda item: len(item.split(".")))
    return None


def _add_alias_candidate(
    summary: LibrarySummary,
    alias: str,
    canonical: str,
    *,
    source: str,
    confidence: str,
) -> None:
    if not alias or not canonical:
        return
    candidates = summary.alias_table.setdefault(alias, [])
    if any(item.get("canonical") == canonical and item.get("source") == source for item in candidates):
        return
    candidates.append(
        {
            "alias": alias,
            "canonical": canonical,
            "source": source,
            "confidence": confidence,
        }
    )


def _alias_keys(alias: str, import_root: str | None) -> list[str]:
    alias = alias.strip(".")
    if not alias:
        return []
    keys = [alias]
    if import_root:
        root = import_root.strip(".").replace("-", "_")
        parts = alias.split(".")
        if root in parts:
            rooted = ".".join(parts[parts.index(root):])
            if rooted and rooted not in keys:
                keys.append(rooted)
        elif root and not alias.startswith(f"{root}.") and not _matches_qualified_suffix(alias, root):
            keys.append(f"{root}.{alias}")
    return keys


def _expand_summary_alias(
    summary: LibrarySummary,
    alias: str,
    canonical: str,
    *,
    source: str,
    confidence: str = "high",
) -> None:
    summary.api_aliases.setdefault(alias, canonical)
    summary.export_table.setdefault(
        alias,
        {
            "alias": alias,
            "canonical": canonical,
            "export_kind": source,
            "confidence": confidence,
        },
    )
    _add_alias_candidate(summary, alias, canonical, source=source, confidence=confidence)
    summary.inner_summary.setdefault(alias, set()).add(canonical)
    summary.inner_summary[alias].update(summary.inner_summary.get(canonical, set()))
    summary.outer_summary.setdefault(alias, set()).update(summary.outer_summary.get(canonical, set()))
    summary.inner_paths.setdefault(alias, {}).update(summary.inner_paths.get(canonical, {}))
    summary.outer_paths.setdefault(alias, {}).update(summary.outer_paths.get(canonical, {}))
    summary.inner_paths[alias].setdefault(canonical, [alias, canonical])


def apply_public_api_aliases(
    summary: LibrarySummary,
    aliases: Mapping[str, Any],
    *,
    import_root: str | None = None,
) -> None:
    for raw_alias, raw_target in aliases.items():
        alias = str(raw_alias).strip()
        target = str(raw_target).strip()
        if not alias or not target:
            continue
        canonical = _summary_key(summary, target)
        if canonical is None:
            _add_alias_candidate(
                summary,
                alias,
                target,
                source="unresolved public API alias",
                confidence="low",
            )
            continue
        for key in _alias_keys(alias, import_root):
            _expand_summary_alias(
                summary,
                key,
                canonical,
                source="__init__.py re-export",
                confidence="high",
            )


def _add_suffix_alias_candidates(summary: LibrarySummary) -> None:
    keys = sorted(set(summary.inner_summary) | set(summary.outer_summary))
    candidates_by_alias: dict[str, set[str]] = {}
    for key in keys:
        parts = [part for part in key.split(".") if part]
        for index in range(1, len(parts)):
            alias = ".".join(parts[index:])
            if alias and alias != key:
                candidates_by_alias.setdefault(alias, set()).add(key)
    for alias, candidates in candidates_by_alias.items():
        confidence = "medium" if len(candidates) == 1 else "low"
        for canonical in sorted(candidates):
            _add_alias_candidate(
                summary,
                alias,
                canonical,
                source="component suffix",
                confidence=confidence,
            )


class PCSGIndexer:
    """Compress a library :class:`CallGraph` into a :class:`LibrarySummary`.

    Workflow (see module docstring for the *why*):

      1. **Index** every node to a contiguous integer (``_build_index``).
      2. **Construct** the boolean CSR adjacency matrix from the call edges
         (``_build_adjacency``).
      3. **Close** the graph by running a directed BFS from each public API over
         the CSR adjacency, assembling the public-API rows of ``G_L^+`` into a
         sparse closure matrix (``_build_closure``).
      4. **Extract** the inner (S_i) / outer (S_o) summaries from the closure,
         strictly partitioning first-party reach from cross-TPL reach
         (``_extract_summary``).

    Parameters
    ----------
    graph:
        The library call graph produced by Phase 1.
    public_apis:
        The public API surface to summarise. Nodes not present in *graph*
        are reported and skipped rather than treated as fatal.
    """

    def __init__(
        self,
        graph: CallGraph,
        public_apis: Sequence[FunctionNode],
        *,
        public_api_aliases: Mapping[str, Any] | None = None,
        import_root: str | None = None,
    ) -> None:
        self.graph = graph
        self.public_apis = list(public_apis)
        self.public_api_aliases = dict(public_api_aliases or {})
        self.import_root = import_root

        # Populated by build().
        self._nodes: List[FunctionNode] = []            # index -> node
        self._index: Dict[FunctionNode, int] = {}       # node  -> index
        self._adjacency: Optional[csr_matrix] = None    # N×N boolean, caller->callee

    # ── public entry point ───────────────────────────────────────────────

    def build(self) -> LibrarySummary:
        """Run the full index → matrix → closure → summary pipeline."""
        self._build_index()
        if not self._nodes:
            logger.info("[PCSG] Empty graph — nothing to index.")
            return LibrarySummary()

        self._adjacency = self._build_adjacency()

        api_indices = self._resolve_summary_indices()
        if not api_indices:
            logger.info("[PCSG] No internal callable nodes resolved against the graph.")
            summary = LibrarySummary()
            self._populate_diagnostics(summary, missing_public_apis=len(self.public_apis))
            return summary

        closure = self._build_closure(api_indices)
        summary = self._extract_summary(api_indices, closure)
        self._populate_metadata(summary)
        apply_public_api_aliases(summary, self.public_api_aliases, import_root=self.import_root)
        _add_suffix_alias_candidates(summary)
        self._populate_outer_edge_details(summary)
        self._populate_diagnostics(summary, missing_public_apis=self._missing_public_api_count())

        logger.info(
            "[PCSG] Indexed %d node(s), %d edge(s) -> %d API summary(ies) "
            "(S_i + S_o)",
            len(self._nodes), int(self._adjacency.nnz), len(summary.inner_summary),
        )
        return summary

    # ── step 1: integer indexing ─────────────────────────────────────────

    def _build_index(self) -> None:
        """Map every node to a contiguous integer index (and back).

        The two-way map (``_nodes`` list + ``_index`` dict) is the bridge
        between graph objects and matrix coordinates. Lookups go through
        :class:`FunctionNode` identity (``__hash__``/``__eq__``), so an edge that
        references a distinct-but-equal node instance still resolves to the same
        column — and an :class:`ExternalNode`'s 3-tuple identity can never
        collide with a :class:`FunctionNode`'s 2-tuple identity.
        """
        self._nodes = sorted(self.graph.nodes, key=_node_sort_key)
        self._index = {node: i for i, node in enumerate(self._nodes)}

    # ── step 2: CSR adjacency construction ────────────────────────────────

    def _build_adjacency(self) -> csr_matrix:
        """Build the boolean ``N×N`` adjacency matrix in CSR form.

        ``A[i, j] = True`` iff node ``i`` (caller) calls node ``j`` (callee).
        We accumulate coordinate triplets and let SciPy assemble the CSR matrix
        directly, summing duplicate ``(i, j)`` entries (parallel edges) into a
        single non-zero — ``dtype=bool`` keeps every cell a clean 0/1. Edges
        whose endpoints are somehow absent from the index are skipped defensively
        so a malformed graph degrades gracefully instead of raising.
        """
        n = len(self._nodes)
        rows: List[int] = []
        cols: List[int] = []
        skipped = 0
        for edge in self.graph.edges:
            i = self._index.get(edge.caller)
            j = self._index.get(edge.callee)
            if i is None or j is None:
                skipped += 1
                continue
            rows.append(i)
            cols.append(j)

        if skipped:
            logger.warning("[PCSG] Skipped %d edge(s) with unindexed endpoints.",
                           skipped)

        data = np.ones(len(rows), dtype=bool)
        matrix = csr_matrix(
            (data, (np.asarray(rows, dtype=np.int64),
                    np.asarray(cols, dtype=np.int64))),
            shape=(n, n),
            dtype=bool,
        )
        # Coalesce any duplicate coordinates into single boolean non-zeros.
        matrix.sum_duplicates()
        return matrix

    # ── step 3: transitive closure (G_L^+) over the public-API rows ───────

    def _resolve_summary_indices(self) -> Dict[int, FunctionNode]:
        """Map each internal callable/module node to its matrix index.

        Python package reachability cannot rely on a stable public API contract,
        so the summary is keyed by every first-party graph node. Public APIs are
        still tracked separately as export metadata.
        """
        resolved: Dict[int, FunctionNode] = {}
        for node in self._nodes:
            if isinstance(node, ExternalNode):
                continue
            key = _api_key(node)
            if not key:
                continue
            idx = self._index.get(node)
            if idx is not None:
                resolved.setdefault(idx, node)
        missing = self._missing_public_api_count()
        if missing:
            logger.warning("[PCSG] %d public API(s) not found in graph; skipped.",
                           missing)
        return resolved

    def _missing_public_api_count(self) -> int:
        return sum(1 for api in self.public_apis if self._index.get(api) is None)

    def _build_closure(self, api_indices: Dict[int, FunctionNode]) -> csr_matrix:
        """Assemble the public-API rows of the transitive closure ``G_L^+``.

        For each API index we run a directed BFS over the CSR adjacency; the set
        of visited nodes is exactly that API's reachability row (including the
        API itself — :meth:`_extract_summary` filters it out). Rows are returned
        as a sparse ``(num_api × N)`` CSR matrix, the only slice of the full
        ``N×N`` closure the summaries need — so memory tracks the reach-sets, not
        ``N²``.
        """
        assert self._adjacency is not None
        n = len(self._nodes)
        ordered = sorted(api_indices)                 # stable row order

        rows: List[int] = []
        cols: List[int] = []
        for row, src in enumerate(ordered):
            reachable = breadth_first_order(
                self._adjacency,
                i_start=src,
                directed=True,
                return_predecessors=False,
            )
            rows.extend([row] * len(reachable))
            cols.extend(int(c) for c in reachable)

        data = np.ones(len(rows), dtype=bool)
        return csr_matrix(
            (data, (np.asarray(rows, dtype=np.int64),
                    np.asarray(cols, dtype=np.int64))),
            shape=(len(ordered), n),
            dtype=bool,
        )

    # ── step 4: S_i / S_o summary extraction ──────────────────────────────

    def _shortest_paths_from(self, src: int) -> dict[int, list[int]]:
        """Return one deterministic witness path from *src* to each reachable node."""
        assert self._adjacency is not None
        queue: Deque[int] = deque([src])
        paths: dict[int, list[int]] = {src: [src]}

        while queue:
            node = queue.popleft()
            start, end = self._adjacency.indptr[node], self._adjacency.indptr[node + 1]
            for nxt in sorted(int(item) for item in self._adjacency.indices[start:end]):
                if nxt in paths:
                    continue
                paths[nxt] = [*paths[node], nxt]
                queue.append(nxt)
        return paths

    def _extract_summary(self, api_indices: Dict[int, FunctionNode],
                         closure: csr_matrix) -> LibrarySummary:
        """Read the inner (S_i) and outer (S_o) reach-sets off the closure rows.

        Row ``r`` of *closure* corresponds to the ``r``-th API in sorted-index
        order. For every node that row marks reachable we partition strictly:
        a first-party :class:`FunctionNode` (other than the API itself) feeds
        S_i with its ``qualified_name``; an :class:`ExternalNode` feeds S_o with
        its dotted ``module.name`` target. The two summaries never share an
        entry — first-party reach and cross-TPL reach stay disjoint by
        construction.
        """
        summary = LibrarySummary()
        ordered = sorted(api_indices)
        indptr, col_idx = closure.indptr, closure.indices

        for row, src in enumerate(ordered):
            api = api_indices[src]
            key = _api_key(api)
            inner = summary.inner_summary.setdefault(key, set())
            outer = summary.outer_summary.setdefault(key, set())
            inner_paths = summary.inner_paths.setdefault(key, {})
            outer_paths = summary.outer_paths.setdefault(key, {})
            paths_by_index = self._shortest_paths_from(src)

            # CSR row slice: the reachable column indices for this API.
            for j in col_idx[indptr[row]:indptr[row + 1]]:
                col = int(j)
                if col == src:
                    continue                          # exclude the API itself
                node = self._nodes[col]
                path = [_render_node(self._nodes[idx]) for idx in paths_by_index.get(col, [src, col])]
                if isinstance(node, ExternalNode):
                    target = _external_target(node)
                    outer.add(target)
                    outer_paths.setdefault(target, path)
                else:
                    target = node.qualified_name
                    inner.add(target)
                    inner_paths.setdefault(target, path)

        return summary

    def _populate_metadata(self, summary: LibrarySummary) -> None:
        public_keys = {_api_key(api) for api in self.public_apis if _api_key(api)}
        for node in self._nodes:
            if isinstance(node, ExternalNode):
                continue
            key = _api_key(node)
            if not key:
                continue
            kind = "method" if node.scope else "function"
            if node.scope == "<module>" or node.function_name == node.module:
                kind = "module"
            elif node.function_name.endswith(".__init__"):
                kind = "constructor"
            summary.symbol_table[key] = {
                "canonical": key,
                "kind": kind,
                "module": node.module,
                "scope": node.scope,
                "file_path": node.file_path,
                "line_number": node.line_number,
                "signature": node.signature,
                "arity": node.arity,
                "entry_type": node.entry_type.value,
                "public": key in public_keys,
            }
            if key in public_keys:
                summary.export_table.setdefault(
                    key,
                    {
                        "alias": key,
                        "canonical": key,
                        "export_kind": "public_api",
                        "confidence": "high",
                    },
                )

    def _external_edge_evidence(self) -> dict[tuple[str, str], dict[str, Any]]:
        evidence: dict[tuple[str, str], dict[str, Any]] = {}
        for edge in self.graph.external_edges:
            caller = _render_node(edge.caller)
            target = _render_node(edge.callee)
            evidence.setdefault(
                (caller, target),
                {
                    "edge_type": edge.edge_type,
                    "confidence": edge.confidence,
                    "resolver": edge.resolver,
                    "reason": edge.reason,
                    "call_expr": edge.call_expr,
                    "line_number": edge.line_number,
                },
            )
        return evidence

    def _populate_outer_edge_details(self, summary: LibrarySummary) -> None:
        evidence = self._external_edge_evidence()
        for key, targets in sorted(summary.outer_summary.items()):
            details = summary.outer_edge_details.setdefault(key, [])
            for target in sorted(targets):
                path = summary.outer_paths.get(key, {}).get(target, [])
                caller = path[-2] if len(path) > 1 else key
                item = {
                    "target": target,
                    "status": "resolved_external_call",
                    "path": path,
                    "source": "callgraph",
                }
                item.update(evidence.get((caller, target), {}))
                details.append(item)

        unresolved_calls = self.graph.metadata.get("unresolved_calls") or []
        candidate_edges = self.graph.metadata.get("candidate_edges") or []
        for key, inner in sorted(summary.inner_summary.items()):
            reachable_callers = {key, *inner}
            details = summary.outer_edge_details.setdefault(key, [])
            for item in unresolved_calls:
                caller = str(item.get("caller", ""))
                if caller not in reachable_callers:
                    continue
                details.append(
                    {
                        "target": str(item.get("call_name") or item.get("call_expr") or ""),
                        "status": "unresolved_external_call",
                        "caller": caller,
                        "file_path": item.get("file_path", ""),
                        "line_number": item.get("line_number", 0),
                        "call_expr": item.get("call_expr", ""),
                        "call_name": item.get("call_name", ""),
                        "receiver": item.get("receiver", ""),
                        "reason": item.get("reason", "static resolver found no target"),
                        "source": "unresolved_calls",
                    }
                )
            for item in candidate_edges:
                caller = str(item.get("caller", ""))
                if caller not in reachable_callers:
                    continue
                status = str(item.get("status") or "candidate")
                callee = str(item.get("callee") or item.get("call_name") or item.get("call_expr") or "")
                if status == "candidate" and callee and "." in callee:
                    continue
                details.append(
                    {
                        "target": callee,
                        "status": "partially_resolved_external_call",
                        "caller": caller,
                        "file_path": item.get("file_path", ""),
                        "line_number": item.get("line_number", 0),
                        "call_expr": item.get("call_expr", ""),
                        "resolver": item.get("resolver", ""),
                        "confidence": item.get("confidence", 0.0),
                        "reason": item.get("reason", status),
                        "source": "candidate_edges",
                    }
                )

    def _populate_diagnostics(self, summary: LibrarySummary, *, missing_public_apis: int) -> None:
        unresolved_calls = self.graph.metadata.get("unresolved_calls") or []
        candidate_edges = self.graph.metadata.get("candidate_edges") or []
        unresolved_exports = self.graph.metadata.get("unresolved_public_exports") or []
        resolved_outer = sum(len(values) for values in summary.outer_summary.values())
        partial_outer = sum(
            1
            for details in summary.outer_edge_details.values()
            for item in details
            if item.get("status") != "resolved_external_call"
        )
        summary.diagnostics.update(
            {
                "summary_key_count": len(set(summary.inner_summary) | set(summary.outer_summary)),
                "symbol_count": len(summary.symbol_table),
                "export_count": len(summary.export_table),
                "alias_count": sum(len(values) for values in summary.alias_table.values()),
                "outer_edge_count": resolved_outer,
                "resolved_outer_edge_count": resolved_outer,
                "partial_outer_edge_count": partial_outer,
                "unresolved_call_count": len(unresolved_calls),
                "candidate_edge_count": len(candidate_edges),
                "unresolved_public_export_count": len(unresolved_exports),
                "missing_public_api_count": missing_public_apis,
                "confidence": "low" if unresolved_calls or unresolved_exports else "high",
            }
        )
        warnings = {
            key: self.graph.metadata.get(key, [])
            for key in ("candidate_edges", "unresolved_public_exports", "unresolved_calls", "skipped_files")
            if self.graph.metadata.get(key)
        }
        filtered_warnings = filter_verdict_affecting_warnings(warnings)
        summary.diagnostics["verdict_affecting_warning_count"] = sum(
            len(value) if isinstance(value, list) else 1
            for value in filtered_warnings.values()
        )
        if filtered_warnings:
            summary.analysis_warnings.update(filtered_warnings)


# ══════════════════════════════════════════════════════════════════════════
# PUBLIC ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

def build_library_summary(
    graph: CallGraph,
    public_apis: Sequence[FunctionNode],
    *,
    public_api_aliases: Mapping[str, Any] | None = None,
    import_root: str | None = None,
) -> LibrarySummary:
    """Compress *graph* into a :class:`LibrarySummary` over *public_apis*.

    Convenience wrapper around :class:`PCSGIndexer` — the canonical Phase-2 entry
    point referenced by the rest of the F-VRA pipeline.
    """
    return PCSGIndexer(
        graph,
        public_apis,
        public_api_aliases=public_api_aliases,
        import_root=import_root,
    ).build()
