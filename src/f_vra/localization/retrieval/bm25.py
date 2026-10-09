from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _tokenize(text: str) -> list[str]:
    raw = _TOKEN.findall(text or "")
    out: list[str] = []
    for token in raw:
        lowered = token.lower()
        out.append(lowered)
        for sub in re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", token):
            value = sub.lower()
            if value and value != lowered:
                out.append(value)
        for sub in token.split("_"):
            if sub:
                out.append(sub.lower())
    return out


def _score(query: list[str], doc: Counter[str], doc_len: int, avgdl: float, idf: dict[str, float]) -> float:
    k1 = 1.5
    b = 0.75
    total = 0.0
    for term in query:
        freq = doc.get(term, 0)
        if not freq:
            continue
        denom = freq + k1 * (1 - b + b * doc_len / max(avgdl, 1.0))
        total += idf.get(term, 0.0) * (freq * (k1 + 1)) / denom
    return total


def rank_bm25(description: str, funcs: list[dict], top_k: int) -> list[dict]:
    if not funcs:
        return []

    tokenized = [
        _tokenize(func["body"] + " " + func["qualname"] + " " + func.get("docstring", ""))
        for func in funcs
    ]
    counters = [Counter(doc) for doc in tokenized]
    lengths = [len(doc) for doc in tokenized]
    avgdl = sum(lengths) / len(lengths)

    df: Counter[str] = Counter()
    for doc in counters:
        df.update(doc.keys())
    n_docs = len(counters)
    idf = {
        term: math.log(1 + (n_docs - count + 0.5) / (count + 0.5))
        for term, count in df.items()
    }

    query = _tokenize(description)
    scored = [
        {**func, "bm25_score": float(_score(query, counters[i], lengths[i], avgdl, idf))}
        for i, func in enumerate(funcs)
    ]
    scored.sort(key=lambda item: item["bm25_score"], reverse=True)
    return scored[:top_k]
