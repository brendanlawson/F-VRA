from __future__ import annotations

from dataclasses import dataclass, field

from f_vra.localization.retrieval.bm25 import rank_bm25
from f_vra.localization.retrieval.embedding import embedding_scores
from f_vra.localization.models import FunctionInfo


@dataclass
class CandidateSelection:
    candidates: list[FunctionInfo]
    relevance_scores: dict[str, float]
    evidence: dict[str, set[str]]
    lexical_scores: dict[str, float] = field(default_factory=dict)
    embedding_scores: dict[str, float] = field(default_factory=dict)
    embedding_model: str | None = None
    embedding_status: str = "disabled"


def _as_rankable(function: FunctionInfo) -> dict:
    return {
        "name": function.function_name,
        "qualname": function.qualname,
        "file": function.file_path,
        "start_line": function.start_line,
        "end_line": function.end_line,
        "body": function.source,
        "docstring": function.docstring,
        "_identity": function.identity,
    }


def lexical_scores(description: str, functions: list[FunctionInfo]) -> dict[str, float]:
    ranked = rank_bm25(
        description,
        [_as_rankable(function) for function in functions],
        top_k=len(functions),
    )
    return {item["_identity"]: float(item["bm25_score"]) for item in ranked}


def _rank_positions(
    scores: dict[str, float],
    *,
    include_non_positive: bool,
) -> dict[str, int]:
    eligible = [
        identity
        for identity, score in scores.items()
        if include_non_positive or score > 0
    ]
    ordered = sorted(eligible, key=lambda identity: scores[identity], reverse=True)
    return {identity: rank for rank, identity in enumerate(ordered, 1)}


def reciprocal_rank_fusion(
    lexical: dict[str, float],
    dense: dict[str, float],
    *,
    lexical_weight: float = 0.45,
    dense_weight: float = 0.55,
    rank_constant: int = 60,
) -> dict[str, float]:
    lexical_ranks = _rank_positions(lexical, include_non_positive=False)
    dense_ranks = _rank_positions(dense, include_non_positive=True)
    identities = lexical.keys() | dense.keys()
    fused = {
        identity: (
            lexical_weight / (rank_constant + lexical_ranks[identity])
            if identity in lexical_ranks
            else 0.0
        )
        + (
            dense_weight / (rank_constant + dense_ranks[identity])
            if identity in dense_ranks
            else 0.0
        )
        for identity in identities
    }
    maximum = max(fused.values(), default=0.0)
    return {
        identity: score / maximum if maximum else 0.0
        for identity, score in fused.items()
    }


def _retrieve(
    description: str,
    functions: list[FunctionInfo],
    *,
    use_embeddings: bool,
) -> tuple[dict[str, float], dict[str, float], dict[str, float], str | None, str]:
    lexical = lexical_scores(description, functions)
    dense: dict[str, float] = {}
    model = None
    status = "disabled"
    if use_embeddings:
        try:
            dense, model = embedding_scores(description, functions)
            status = "used"
        except RuntimeError as exc:
            status = f"fallback: {exc}"

    fused = reciprocal_rank_fusion(lexical, dense) if dense else lexical
    return fused, lexical, dense, model, status


def select_patch_absent(
    description: str,
    functions: list[FunctionInfo],
    *,
    pool_size: int = 100,
    use_embeddings: bool = True,
) -> CandidateSelection:
    fused, lexical, dense, model, status = _retrieve(
        description,
        functions,
        use_embeddings=use_embeddings,
    )
    by_id = {function.identity: function for function in functions}
    ordered = sorted(fused, key=lambda identity: fused[identity], reverse=True)[:pool_size]
    relevance = {identity: fused[identity] for identity in ordered}

    evidence: dict[str, set[str]] = {}
    for identity in ordered:
        items = {"selected by lexical retrieval from expanded CVE description"}
        if dense:
            items.add("selected by semantic embedding retrieval from CVE description")
        evidence[identity] = items
    return CandidateSelection(
        candidates=[by_id[identity] for identity in ordered],
        relevance_scores=relevance,
        evidence=evidence,
        lexical_scores=lexical,
        embedding_scores=dense,
        embedding_model=model,
        embedding_status=status,
    )


def select_patch_present(
    description: str,
    functions: list[FunctionInfo],
    tracker_evidence: dict[str, set[str]],
    *,
    pool_size: int = 100,
    use_embeddings: bool = True,
) -> CandidateSelection:
    by_id = {function.identity: function for function in functions}
    fused, lexical, dense, model, status = _retrieve(
        description,
        functions,
        use_embeddings=use_embeddings,
    )
    selected_ids = list(tracker_evidence)
    target_size = min(pool_size, max(20, len(selected_ids)))
    for identity in sorted(fused, key=lambda item: fused[item], reverse=True):
        if identity not in selected_ids:
            selected_ids.append(identity)
        if len(selected_ids) >= target_size:
            break

    evidence = {identity: set(items) for identity, items in tracker_evidence.items()}
    for identity in selected_ids:
        evidence.setdefault(identity, set()).add("retrieval-relevant to expanded CVE description")
        if dense:
            evidence[identity].add("semantic embedding similarity considered")
    return CandidateSelection(
        candidates=[by_id[identity] for identity in selected_ids],
        relevance_scores={identity: fused.get(identity, 0.0) for identity in selected_ids},
        evidence=evidence,
        lexical_scores=lexical,
        embedding_scores=dense,
        embedding_model=model,
        embedding_status=status,
    )
