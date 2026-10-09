from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from f_vra.core.config import settings
from f_vra.localization.models import FunctionInfo
from f_vra.localization.ranking.ranking import _source_excerpt


@dataclass(frozen=True)
class PairwiseRankingConfig:
    swiss_rounds: int = 8
    finalists: int = 20
    use_pairwise: bool = False
    model: str | None = None


def _base_order(
    candidates: list[FunctionInfo],
    relevance: dict[str, float],
    evidence: dict[str, set[str]],
) -> list[FunctionInfo]:
    def key(function: FunctionInfo) -> tuple[float, float]:
        evidence_bonus = min(0.5, 0.1 * len(evidence.get(function.identity, set())))
        return evidence_bonus + relevance.get(function.identity, 0.0), relevance.get(
            function.identity, 0.0
        )

    return sorted(candidates, key=key, reverse=True)


def _pair_prompt(description: str, left: FunctionInfo, right: FunctionInfo) -> str:
    return (
        "Given the CVE description, choose which Python function is more likely "
        "to be the vulnerable function. Reply with only A, B, or TIE.\n\n"
        f"CVE description:\n{description}\n\n"
        f"A name: {left.qualname}\n"
        f"A file: {left.file_path}:{left.start_line}-{left.end_line}\n"
        f"A source:\n{_source_excerpt(left.source, 2200)}\n\n"
        f"B name: {right.qualname}\n"
        f"B file: {right.file_path}:{right.start_line}-{right.end_line}\n"
        f"B source:\n{_source_excerpt(right.source, 2200)}"
    )


def _parse_choice(raw: str) -> float:
    text = raw.strip().upper()
    if re.search(r"\bTIE\b|\bDRAW\b", text):
        return 0.5
    if re.search(r"\bA\b", text):
        return 1.0
    if re.search(r"\bB\b", text):
        return 0.0
    return 0.5


def _compare_pair(
    description: str,
    left: FunctionInfo,
    right: FunctionInfo,
    *,
    model: str | None,
    cache: dict[str, float],
) -> float:
    key_parts = sorted([left.identity, right.identity])
    cache_key = hashlib.sha256(
        "\0".join([description, *key_parts]).encode("utf-8", errors="ignore")
    ).hexdigest()
    if cache_key in cache:
        score = cache[cache_key]
        return score if key_parts[0] == left.identity else 1.0 - score

    from f_vra.localization.providers.llm_client import chat

    first = left if key_parts[0] == left.identity else right
    second = right if first is left else left
    raw = chat(
        messages=[
            {
                "role": "system",
                "content": (
                    "You compare vulnerable-function candidates for SCA. "
                    "Prefer the function containing exploitable vulnerable logic, "
                    "not merely callers or patched helpers."
                ),
            },
            {"role": "user", "content": _pair_prompt(description, first, second)},
        ],
        model=model,
    )
    score = _parse_choice(raw)
    cache[cache_key] = score
    return score if first is left else 1.0 - score


def _fallback_compare(
    left: FunctionInfo,
    right: FunctionInfo,
    relevance: dict[str, float],
    evidence: dict[str, set[str]],
) -> float:
    ordered = _base_order([left, right], relevance, evidence)
    if ordered[0].identity == ordered[1].identity:
        return 0.5
    return 1.0 if ordered[0].identity == left.identity else 0.0


def pairwise_rank_scores(
    description: str,
    candidates: list[FunctionInfo],
    relevance: dict[str, float],
    evidence: dict[str, set[str]],
    *,
    config: PairwiseRankingConfig,
) -> tuple[dict[str, float], dict[str, str | bool | int | None]]:
    """Rank candidates with Swiss-system then finalist pairwise voting."""
    if not candidates:
        return {}, {"used": False, "status": "empty", "source": "pairwise_ranking"}

    ordered = _base_order(candidates[:100], relevance, evidence)
    from f_vra.localization.providers.llm_client import chat_available

    use_llm = bool(config.use_pairwise and chat_available())
    model = config.model or settings.llm_model
    status = "used" if use_llm else "fallback: pairwise LLM disabled or no LLM provider API key is set"
    cache: dict[str, float] = {}

    def compare(left: FunctionInfo, right: FunctionInfo) -> float:
        if use_llm:
            return _compare_pair(description, left, right, model=model, cache=cache)
        return _fallback_compare(left, right, relevance, evidence)

    scores = {function.identity: 0.0 for function in ordered}
    rounds = max(0, config.swiss_rounds)
    for _ in range(rounds):
        swiss_order = sorted(
            ordered,
            key=lambda function: (
                scores[function.identity],
                relevance.get(function.identity, 0.0),
            ),
            reverse=True,
        )
        for i in range(0, len(swiss_order) - 1, 2):
            left = swiss_order[i]
            right = swiss_order[i + 1]
            result = compare(left, right)
            scores[left.identity] += result
            scores[right.identity] += 1.0 - result

    finalists = sorted(
        ordered,
        key=lambda function: (
            scores[function.identity],
            relevance.get(function.identity, 0.0),
        ),
        reverse=True,
    )[: max(1, min(config.finalists, len(ordered)))]

    final_scores = {function.identity: 0.0 for function in finalists}
    for i, left in enumerate(finalists):
        for right in finalists[i + 1 :]:
            result = compare(left, right)
            final_scores[left.identity] += result
            final_scores[right.identity] += 1.0 - result

    max_score = max(final_scores.values(), default=0.0)
    normalised = {
        identity: (score / max_score if max_score else 0.0)
        for identity, score in final_scores.items()
    }
    return normalised, {
        "used": use_llm,
        "status": status,
        "source": "pairwise_ranking",
        "model": model if use_llm else None,
        "swiss_rounds": rounds,
        "finalists": len(finalists),
        "comparisons_cached": len(cache),
    }
