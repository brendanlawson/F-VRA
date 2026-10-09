from __future__ import annotations

from collections import defaultdict, deque
from pathlib import Path

from f_vra.localization.models import FunctionInfo
from f_vra.localization.sources import PatchAnalysis

MAX_AMBIGUOUS_FANOUT = 25
COMMON_CALL_NAMES = {
    "__init__",
    "super",
    "len",
    "str",
    "int",
    "float",
    "bool",
    "list",
    "dict",
    "set",
    "tuple",
    "print",
    "isinstance",
    "getattr",
    "setattr",
    "hasattr",
    "range",
    "enumerate",
    "zip",
}


def _matches_file(function: FunctionInfo, patch_file: str) -> bool:
    return function.file_path == patch_file or function.file_path.endswith("/" + patch_file)


def _path_matches(left: str, right: str) -> bool:
    left_norm = str(Path(left)).replace("\\", "/")
    right_norm = str(Path(right)).replace("\\", "/")
    return (
        left_norm == right_norm
        or left_norm.endswith("/" + right_norm)
        or right_norm.endswith("/" + left_norm)
    )


def _contains_changed_line(function: FunctionInfo, lines: set[int]) -> bool:
    return any(function.start_line <= line <= function.end_line for line in lines)


def _class_scope(function: FunctionInfo) -> str | None:
    parts = function.qualname.split(".")
    if len(parts) < 2:
        return None
    return ".".join(parts[:-1])


def _simple_class(function: FunctionInfo) -> str | None:
    scope = _class_scope(function)
    return scope.split(".")[-1] if scope else None


def _data_symbols(function: FunctionInfo) -> set[str]:
    ignored = COMMON_CALL_NAMES | {"self", "cls", "True", "False", "None"}
    return (
        function.referenced_names
        | function.assigned_names
        | function.parameter_names
    ) - ignored


def _symbol_hits(function: FunctionInfo, symbols: set[str]) -> set[str]:
    if not symbols:
        return set()
    candidates = _data_symbols(function) | {
        function.function_name,
        function.qualname,
        function.qualname.split(".")[-1],
    }
    if scope := _class_scope(function):
        candidates.add(scope)
        candidates.add(scope.split(".")[-1])
    return candidates & symbols


def _matches_graph_node(function: FunctionInfo, node: object) -> bool:
    node_file = str(getattr(node, "file_path", ""))
    if not _path_matches(function.file_path, node_file):
        return False

    node_function = str(getattr(node, "function_name", ""))
    node_qualified = str(getattr(node, "qualified_name", ""))
    names = {function.function_name, function.qualname}
    return (
        node_function in names
        or node_qualified in names
        or node_qualified.endswith("." + function.qualname)
        or node_qualified.endswith("." + function.function_name)
    )


def _jarvis_type_engine_edges(
    functions: list[FunctionInfo],
    repository_root: str | Path | None,
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[tuple[str, str], str]]:
    if repository_root is None:
        return {}, {}, {}

    try:
        from f_vra.analysis.callgraph import build_library_graph
    except Exception:
        return {}, {}, {}

    try:
        graph = build_library_graph(Path(repository_root))
    except Exception:
        return {}, {}, {}

    by_file: dict[str, list[FunctionInfo]] = defaultdict(list)
    for function in functions:
        by_file[function.file_path].append(function)

    node_to_identity: dict[object, str] = {}
    for node in graph.internal_nodes:
        node_file = str(getattr(node, "file_path", ""))
        candidates = [
            function
            for file_path, file_functions in by_file.items()
            if _path_matches(file_path, node_file)
            for function in file_functions
        ]
        for function in candidates:
            if _matches_graph_node(function, node):
                node_to_identity[node] = function.identity
                break

    callers: dict[str, set[str]] = defaultdict(set)
    callees: dict[str, set[str]] = defaultdict(set)
    edge_evidence: dict[tuple[str, str], str] = {}
    for edge in graph.internal_edges:
        caller_id = node_to_identity.get(edge.caller)
        callee_id = node_to_identity.get(edge.callee)
        if not caller_id or not callee_id or caller_id == callee_id:
            continue
        callers[callee_id].add(caller_id)
        callees[caller_id].add(callee_id)
        resolver = getattr(edge, "resolver", "") or "type_engine"
        call_expr = getattr(edge, "call_expr", "") or getattr(edge, "reason", "")
        edge_evidence[(caller_id, callee_id)] = (
            f"Jarvis type-engine edge ({resolver})"
            + (f": {call_expr}" if call_expr else "")
        )

    return dict(callers), dict(callees), edge_evidence


def track_patch_candidates(
    functions: list[FunctionInfo],
    patch: PatchAnalysis,
    *,
    max_depth: int = 2,
    repository_root: str | Path | None = None,
    use_type_engine: bool = True,
) -> dict[str, set[str]]:
    evidence: dict[str, set[str]] = defaultdict(set)
    by_id = {function.identity: function for function in functions}
    by_simple: dict[str, list[FunctionInfo]] = defaultdict(list)
    by_qualname: dict[str, FunctionInfo] = {}
    by_class_method: dict[tuple[str, str], list[FunctionInfo]] = defaultdict(list)
    by_file_symbol: dict[tuple[str, str], list[FunctionInfo]] = defaultdict(list)
    for function in functions:
        by_simple[function.function_name].append(function)
        by_qualname[function.qualname] = function
        if class_name := _simple_class(function):
            by_class_method[(class_name, function.function_name)].append(function)
        by_file_symbol[(function.file_path, function.function_name)].append(function)

    seeds: set[str] = set()
    for change in patch.files:
        for function in functions:
            if not _matches_file(function, change.file_path):
                continue
            if _contains_changed_line(function, change.old_lines | change.new_lines):
                seeds.add(function.identity)
                evidence[function.identity].add("function overlaps changed patch lines")

        for symbol in patch.hunk_symbols:
            for function in by_file_symbol.get((change.file_path, symbol), []):
                seeds.add(function.identity)
                evidence[function.identity].add(f"patch hunk scope names function/class: {symbol}")

    name_seeds = (patch.called_names | patch.hunk_symbols) - COMMON_CALL_NAMES
    for name in name_seeds:
        matches = by_simple.get(name, [])
        if len(matches) > MAX_AMBIGUOUS_FANOUT:
            continue
        for function in matches:
            seeds.add(function.identity)
            evidence[function.identity].add(f"function name appears in changed invocation: {name}")

    changed_symbols = (
        patch.changed_globals
        | patch.changed_imports
        | patch.hunk_symbols
        | (patch.called_names - COMMON_CALL_NAMES)
    ) - COMMON_CALL_NAMES
    for function in functions:
        symbol_hit = _symbol_hits(function, changed_symbols)
        if symbol_hit:
            seeds.add(function.identity)
            evidence[function.identity].add(
                "references symbol changed by patch: " + ", ".join(sorted(symbol_hit))
            )

    callers: dict[str, set[str]] = defaultdict(set)
    callees: dict[str, set[str]] = defaultdict(set)
    edge_evidence: dict[tuple[str, str], str] = {}

    def resolve_call(caller: FunctionInfo, raw_name: str) -> set[str]:
        if raw_name in by_qualname:
            return {by_qualname[raw_name].identity}
        simple = raw_name.split(".")[-1]
        if "." in raw_name:
            receiver, method = raw_name.rsplit(".", 1)
            if receiver in {"self", "cls"} and (class_name := _simple_class(caller)):
                return {
                    item.identity
                    for item in by_class_method.get((class_name, method), [])
                }
            if receiver in caller.local_types:
                class_name = caller.local_types[receiver]
                return {
                    item.identity
                    for item in by_class_method.get((class_name, method), [])
                }
            if receiver[:1].isupper():
                return {
                    item.identity
                    for item in by_class_method.get((receiver.split(".")[-1], method), [])
                }
        matches = by_simple.get(simple, [])
        if simple in COMMON_CALL_NAMES or len(matches) > MAX_AMBIGUOUS_FANOUT:
            return set()
        return {item.identity for item in matches}

    for caller in functions:
        for called in caller.calls:
            for callee_id in resolve_call(caller, called):
                if callee_id == caller.identity:
                    continue
                callers[callee_id].add(caller.identity)
                callees[caller.identity].add(callee_id)

    if use_type_engine:
        engine_callers, engine_callees, engine_evidence = _jarvis_type_engine_edges(
            functions,
            repository_root,
        )
        for callee_id, caller_ids in engine_callers.items():
            callers[callee_id].update(caller_ids)
        for caller_id, callee_ids in engine_callees.items():
            callees[caller_id].update(callee_ids)
        edge_evidence.update(engine_evidence)

    data_peers: dict[str, set[str]] = defaultdict(set)
    by_changed_symbol: dict[str, set[str]] = defaultdict(set)
    for function in functions:
        for symbol in _data_symbols(function) & changed_symbols:
            by_changed_symbol[symbol].add(function.identity)
    for symbol, identities in by_changed_symbol.items():
        if len(identities) > MAX_AMBIGUOUS_FANOUT:
            continue
        for identity in identities:
            data_peers[identity].update(identities - {identity})

    queue = deque((seed, 0) for seed in seeds)
    visited = set(seeds)
    while queue:
        current, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for neighbour in callers[current]:
            edge_reason = edge_evidence.get((neighbour, current))
            evidence[neighbour].add(f"calls patch-related function {by_id[current].qualname}")
            if edge_reason:
                evidence[neighbour].add(edge_reason)
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append((neighbour, depth + 1))
        for neighbour in callees[current]:
            edge_reason = edge_evidence.get((current, neighbour))
            evidence[neighbour].add(f"called by patch-related function {by_id[current].qualname}")
            if edge_reason:
                evidence[neighbour].add(edge_reason)
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append((neighbour, depth + 1))
        for neighbour in data_peers[current]:
            if by_id[neighbour].file_path != by_id[current].file_path and _simple_class(
                by_id[neighbour]
            ) != _simple_class(by_id[current]):
                continue
            evidence[neighbour].add(
                f"shares patch-changed data symbol with {by_id[current].qualname}"
            )
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append((neighbour, depth + 1))

    return dict(evidence)
