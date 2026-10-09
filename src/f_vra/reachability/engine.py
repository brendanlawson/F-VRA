"""
Phase 4 — the Compositional Query Engine.

This module composes the per-library Phase 2 summaries (``S_i`` / ``S_o``) into a
single transitive, cross-TPL reachability answer. Given:

  * the **Usage Index** (``ui``) — the set of external symbols the *project
    itself* calls, each an :class:`~f_vra.core.models.ExternalNode`;
  * a map of **library summaries** keyed by root library name; and
  * a set of **vulnerabilities** (qualified sink / vulnerable-function names),

it performs a path-aware breadth-first search over the supply chain and reports
every concrete path that lands on a known vulnerability.

Design notes that the four critical requirements pin down:

1. **The Direct-Sink blind spot.** A hop may *be* the vulnerability itself —
   e.g. the project (or a TPL) calls ``os.system`` directly. The standard
   library has no :class:`LibrarySummary`, so a summary lookup would silently
   drop it. Every hop is therefore tested against ``vulnerabilities`` *before*
   any summary is consulted.
2. **Sinks live in both summaries.** A vulnerability can be a first-party
   function reached intra-library (S_i) *or* a cross-library symbol the API
   reaches (S_o). Both are intersected against ``vulnerabilities``.
3. **Path-aware BFS.** The queue stores ``(current_target, path_so_far)`` so the
   exact supply-chain trace can be reconstructed for the report.
4. **Routing + longest-suffix matching.** The root module of a dotted target
   selects its :class:`LibrarySummary`; the precise API key inside that summary
   is then resolved by longest dotted-suffix match, tolerating partial
   qualification differences between how a symbol is *referenced* and how it is
   *keyed*.

Exact vulnerability tests use set membership. Qualification mismatches fall
back to a component-aligned suffix scan.
"""
from collections import deque
from typing import Deque, Dict, List, Optional, Set, Tuple

from f_vra.core.models import (
    ExternalNode,
    LibrarySummary,
    QueryReport,
    ReachabilityPath,
)

# A BFS work item: current target, path so far, and summaries traversed so far.
_QueueItem = Tuple[str, List[str], List[str]]


class ReachabilityQueryEngine:
    """
    Answers "does the project reach a vulnerable function?" by walking the
    composed S_i / S_o summaries across TPL boundaries.

    Parameters
    ----------
    ui:
        The Phase 3 Usage Index — every external call the project makes. Each
        node's :pyattr:`~f_vra.core.models.ExternalNode.identity_string`
        (``target_module.target_name``) seeds the search and matches how S_o
        renders reachable targets, so hops chain together by plain strings.
    summaries:
        Maps a **root library name** (e.g. ``"fastapi"``) to its precomputed
        :class:`LibrarySummary`. Lookups are routed by the root module of the
        dotted target currently under inspection.
    vulnerabilities:
        Qualified names of known-vulnerable functions / sinks. Membership and
        intersection against this set is what flags a path as dangerous.
    max_depth:
        Maximum number of cross-package hops in a transitive path.
    max_paths:
        Maximum number of distinct witness paths returned.
    """

    def __init__(
        self,
        ui: List[ExternalNode],
        summaries: Dict[str, LibrarySummary],
        vulnerabilities: Set[str],
        *,
        max_depth: int = 25,
        max_paths: int = 100,
    ) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        if max_paths < 1:
            raise ValueError("max_paths must be at least 1")
        self.ui = ui
        self.summaries = summaries
        self.vulnerabilities = vulnerabilities
        self.max_depth = max_depth
        self.max_paths = max_paths

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def check_reachability(self) -> QueryReport:
        """
        Run the path-aware BFS from every Usage-Index entry point and collect
        all concrete paths that reach a known vulnerability.

        Returns a :class:`QueryReport` whose ``is_vulnerable`` flag is ``True``
        iff at least one such path exists.
        """
        paths: List[ReachabilityPath] = []
        path_keys: Set[Tuple[str, ...]] = set()
        unresolved: Set[str] = set()
        unresolved_frontier: Set[str] = set()
        queue: Deque[_QueueItem] = deque()

        # Seed the frontier with the project's own external calls. Each UI node
        # is a *project API* — the head of any chain it begins.
        seeded: Set[str] = set()
        for ui_node in self.ui:
            start = ui_node.identity_string
            if not start or start in seeded:
                continue
            seeded.add(start)
            queue.append((start, [start], []))

        while queue and len(paths) < self.max_paths:
            current_target, current_path, used_summaries = queue.popleft()

            # ---- Step 1: Direct vulnerability check (the blind-spot guard). --
            # The hop may itself be a sink with no LibrarySummary (stdlib, C
            # extensions, ...). Test it *before* any routing so such sinks are
            # never lost. Suffix matching tolerates qualification differences.
            direct_vuln = self._match_vulnerability(current_target)
            if direct_vuln is not None:
                bridged_path, bridged_summaries = self._alias_bridge_path(
                    current_target,
                    current_path,
                    used_summaries,
                )
                self._append_path(paths, path_keys, bridged_path, direct_vuln, bridged_summaries)
                # The target is terminal-as-a-sink; nothing further to expand
                # for *this* node along the vulnerability dimension.
                continue

            # ---- Step 2: Library routing. -----------------------------------
            root = self._root_module(current_target)
            summary = self.summaries.get(root)
            if summary is None:
                unresolved.add(current_target)
                if used_summaries:
                    unresolved_frontier.add(current_target)
                # No summary for this library — cannot expand further. (Any
                # vulnerability it directly *is* was already caught in Step 1.)
                continue

            # ---- Step 3: Resolve the API key. -------------------------------
            api_keys = self._resolve_api_keys(current_target, summary)
            if not api_keys:
                unresolved.add(current_target)
                if used_summaries:
                    unresolved_frontier.add(current_target)
                continue
            next_used_summaries = self._append_summary_root(used_summaries, root)

            for api_key in api_keys:
                inner_reach: Set[str] = summary.inner_summary.get(api_key, set())
                outer_reach: Set[str] = summary.outer_summary.get(api_key, set())

                for target in sorted(inner_reach):
                    vuln = self._match_vulnerability(target)
                    if vuln is not None:
                        composed = self._extend_with_summary_path(
                            current_path,
                            summary,
                            api_key,
                            target,
                            inner=True,
                        )
                        self._append_path(paths, path_keys, composed, vuln, next_used_summaries)
                        if len(paths) >= self.max_paths:
                            break
                if len(paths) >= self.max_paths:
                    break

                # S_o targets are the transitive package-boundary frontier. Cycle
                # prevention is path-local so converging callers retain witnesses.
                for next_hop in sorted(outer_reach):
                    composed = self._extend_with_summary_path(
                        current_path,
                        summary,
                        api_key,
                        next_hop,
                        inner=False,
                    )
                    vuln = self._match_vulnerability(next_hop)
                    if vuln is not None:
                        self._append_path(paths, path_keys, composed, vuln, next_used_summaries)
                        if len(paths) >= self.max_paths:
                            break
                        continue
                    if len(current_path) >= self.max_depth:
                        unresolved.add(next_hop)
                        unresolved_frontier.add(next_hop)
                        continue
                    if next_hop in current_path:
                        continue
                    queue.append((next_hop, composed, next_used_summaries))
                if len(paths) >= self.max_paths:
                    break

        return QueryReport(
            is_vulnerable=bool(paths),
            paths=paths,
            unresolved_targets=sorted(unresolved),
            unresolved_frontier=sorted(unresolved_frontier),
            used_summaries=sorted({root for path in paths for root in path.used_summaries}),
        )

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _root_module(dotted: str) -> str:
        """Root package of a dotted name: ``"werkzeug.serving.run_simple" -> "werkzeug"``."""
        return dotted.split(".", 1)[0]

    @staticmethod
    def _suffix_overlap(a: str, b: str) -> int:
        """
        Number of trailing **dotted components** ``a`` and ``b`` share.

        Comparison is component-aligned (not character-wise) so that
        ``"json.loads"`` and ``"x.loads"`` overlap by exactly one component
        (``loads``), while ``"json.loads"`` and ``"y.dumps"`` overlap by zero.
        """
        ap = a.split(".")
        bp = b.split(".")
        n = 0
        for x, y in zip(reversed(ap), reversed(bp)):
            if x != y:
                break
            n += 1
        return n

    def _match_vulnerability(self, target: str) -> Optional[str]:
        """
        Return the vulnerability ``target`` corresponds to, or ``None``.

        Fast path is an O(1) exact set membership test. Only when that misses do
        we fall back to a longest-suffix scan, so qualification mismatches
        (e.g. ``"a.b.os.system"`` vs. a recorded ``"os.system"``) still resolve.
        The fallback requires a *full* suffix containment on a component
        boundary, never a mere partial-component overlap.
        """
        if target in self.vulnerabilities:
            return target

        best: Optional[str] = None
        best_score = 0
        for vuln in self.vulnerabilities:
            # Require one string to be a component-aligned suffix of the other.
            if not (target == vuln
                    or target.endswith("." + vuln)
                    or vuln.endswith("." + target)):
                continue
            score = self._suffix_overlap(target, vuln)
            if score > best_score:
                best, best_score = vuln, score
        return best

    def _resolve_api_key(self, target: str, summary: LibrarySummary) -> Optional[str]:
        keys = self._resolve_api_keys(target, summary)
        return keys[0] if keys else None

    def _resolve_api_keys(self, target: str, summary: LibrarySummary) -> List[str]:
        keys = set(summary.inner_summary) | set(summary.outer_summary)
        scored: dict[str, tuple[int, int]] = {}

        def add(candidate: str, rank: int, score: int = 0) -> None:
            if candidate not in keys:
                return
            current = scored.get(candidate)
            value = (rank, score)
            if current is None or value > current:
                scored[candidate] = value

        add(target, 100, len(target.split(".")))
        canonical = summary.api_aliases.get(target)
        if canonical:
            add(canonical, 95, len(canonical.split(".")))

        parts = [part for part in target.split(".") if part]
        alias_probes = [target, *(".".join(parts[index:]) for index in range(1, len(parts)))]
        confidence_rank = {"high": 90, "medium": 75, "low": 60}
        for probe in alias_probes:
            for item in summary.alias_table.get(probe, []):
                canonical = str(item.get("canonical") or "")
                confidence = str(item.get("confidence") or "low")
                add(canonical, confidence_rank.get(confidence, 60), len(canonical.split(".")))

        for key in keys:
            if not (target == key
                    or target.endswith("." + key)
                    or key.endswith("." + target)):
                continue
            add(key, 70, self._suffix_overlap(target, key))

        if not scored and parts:
            tail = parts[-1]
            for key in keys:
                if key.rsplit(".", 1)[-1] == tail:
                    add(key, 40, 1)

        return [
            key
            for key, _score in sorted(
                scored.items(),
                key=lambda item: (item[1][0], item[1][1], item[0]),
                reverse=True,
            )
        ]

    def _alias_bridge_path(
        self,
        target: str,
        current_path: List[str],
        used_summaries: List[str],
    ) -> Tuple[List[str], List[str]]:
        root = self._root_module(target)
        summary = self.summaries.get(root)
        if summary is None:
            return current_path, used_summaries
        api_key = self._resolve_api_key(target, summary)
        if api_key is None:
            return current_path, used_summaries
        canonical = summary.api_aliases.get(api_key) or summary.api_aliases.get(target)
        if not canonical or canonical == target or canonical in current_path:
            return current_path, used_summaries
        bridged = self._extend_with_summary_path(
            current_path,
            summary,
            api_key,
            canonical,
            inner=True,
        )
        return bridged, self._append_summary_root(used_summaries, root)

    @staticmethod
    def _merge_paths(prefix: List[str], suffix: List[str]) -> List[str]:
        if not suffix:
            return list(prefix)
        merged = list(prefix)
        for node in suffix:
            if merged and merged[-1] == node:
                continue
            if node in merged:
                continue
            merged.append(node)
        return merged

    def _extend_with_summary_path(
        self,
        current_path: List[str],
        summary: LibrarySummary,
        api_key: str,
        target: str,
        *,
        inner: bool,
    ) -> List[str]:
        paths = summary.inner_paths if inner else summary.outer_paths
        summary_path = paths.get(api_key, {}).get(target)
        if summary_path:
            return self._merge_paths(current_path, summary_path)
        if target in current_path:
            return list(current_path)
        return [*current_path, target]

    @staticmethod
    def _append_summary_root(used_summaries: List[str], root: str) -> List[str]:
        if root in used_summaries:
            return list(used_summaries)
        return [*used_summaries, root]

    @staticmethod
    def _make_path(current_path: List[str], vuln: str, used_summaries: List[str]) -> ReachabilityPath:
        """
        Build a :class:`ReachabilityPath` from the BFS chain and matched sink.

        ``tpl_chain`` is the full ordered trace ending at ``vuln``; when the
        vulnerability *is* the current hop (a direct sink) it is already the
        tail, so we avoid duplicating it.
        """
        chain = list(current_path)
        if chain and chain[-1] != vuln:
            tail = chain[-1]
            if vuln.endswith("." + tail):
                chain[-1] = vuln
            elif tail.endswith("." + vuln):
                pass
            elif vuln not in chain:
                chain.append(vuln)
        elif not chain:
            chain.append(vuln)
        return ReachabilityPath(
            project_api=chain[0],
            tpl_chain=chain,
            vulnerable_target=vuln,
            used_summaries=list(used_summaries),
        )

    def _append_path(
        self,
        paths: List[ReachabilityPath],
        path_keys: Set[Tuple[str, ...]],
        current_path: List[str],
        vuln: str,
        used_summaries: List[str],
    ) -> None:
        path = self._make_path(current_path, vuln, used_summaries)
        key = tuple(path.tpl_chain)
        if key in path_keys or len(paths) >= self.max_paths:
            return
        path_keys.add(key)
        paths.append(path)

