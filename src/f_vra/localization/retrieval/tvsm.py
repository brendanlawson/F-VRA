"""A deterministic, dependency-light tVSM-style report-to-function ranker.

This implements the core log-TF / inverse-function-frequency idea used by
VFDetector. It deliberately does not claim an exact reproduction of the
paper's WordNet expansion and language-specific preprocessing.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from f_vra.localization.models import FunctionInfo

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_STOP = {
    "a", "an", "and", "are", "as", "at", "be", "been", "being", "by",
    "for", "from", "in", "into", "is", "it", "of", "on", "or", "that",
    "the", "this", "to", "was", "were", "with", "when", "which", "while",
    "can", "could", "may", "might", "should", "would", "will", "use", "used",
    "function", "method", "vulnerability", "vulnerable", "cve",
}


def _tokens(text: str) -> list[str]:
    result: list[str] = []
    for token in _TOKEN.findall(text or ""):
        parts = re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", token)
        parts.extend(token.split("_"))
        for part in parts:
            value = part.lower()
            if len(value) > 1 and value not in _STOP and value not in {"self", "cls"}:
                result.append(value)
    return result


def rank_tvsm(description: str, functions: list[FunctionInfo]) -> list[tuple[FunctionInfo, float]]:
    """Rank every function by log-TF × inverse-function-frequency similarity."""
    if not functions:
        return []
    query = Counter(_tokens(description))
    docs = [
        Counter(_tokens(" ".join((func.qualname, func.docstring, func.source))))
        for func in functions
    ]
    document_frequency: Counter[str] = Counter()
    for document in docs:
        document_frequency.update(document.keys())
    count = len(functions)
    query_weights = {
        term: math.log1p(freq) * math.log((count + 1) / (document_frequency[term] + 1))
        for term, freq in query.items()
    }
    query_norm = math.sqrt(sum(weight * weight for weight in query_weights.values()))
    scores: list[tuple[FunctionInfo, float]] = []
    for function, document in zip(functions, docs):
        weights = {
            term: math.log1p(freq) * math.log((count + 1) / (document_frequency[term] + 1))
            for term, freq in document.items()
        }
        denominator = query_norm * math.sqrt(sum(weight * weight for weight in weights.values()))
        similarity = (
            sum(query_weights.get(term, 0.0) * weight for term, weight in weights.items()) / denominator
            if denominator else 0.0
        )
        # VFDetector's tVSM favors larger functions slightly; keep that effect
        # bounded so it cannot swamp report/code lexical agreement.
        length_bonus = 1.0 + min(0.10, math.log1p(sum(document.values())) / 100.0)
        scores.append((function, similarity * length_bonus))
    return sorted(scores, key=lambda item: (-item[1], item[0].identity))
