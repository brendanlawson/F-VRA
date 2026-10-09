from __future__ import annotations

import re

from tqdm import tqdm

from f_vra.core.config import settings
from f_vra.localization.providers.llm_client import chat
from f_vra.localization.ranking.prompts import BATCH_SYSTEM, batch_user_prompt

_LINE = re.compile(r"^\s*(\d+)\s*,\s*(\d+(?:\.\d+)?)\s*$")


def _score_batch(description: str, funcs: list[dict]) -> dict[int, float]:
    raw = chat(
        messages=[
            {"role": "system", "content": BATCH_SYSTEM},
            {"role": "user", "content": batch_user_prompt(description, funcs)},
        ]
    )
    scores: dict[int, float] = {}
    for line in raw.splitlines():
        match = _LINE.match(line)
        if match:
            scores[int(match.group(1))] = float(match.group(2))
    return scores


def rerank_with_llm(description: str, funcs: list[dict], top_k: int | None = None) -> list[dict]:
    if not funcs:
        return []

    scored: list[dict] = []
    for start in tqdm(range(0, len(funcs), settings.llm_batch_size), desc="LLM compare"):
        batch = funcs[start : start + settings.llm_batch_size]
        batch_scores = _score_batch(description, batch)
        for i, func in enumerate(batch):
            scored.append({**func, "llm_score": batch_scores.get(i, 0.0)})

    scored.sort(key=lambda item: (item["llm_score"], item.get("bm25_score", 0.0)), reverse=True)
    return scored[: top_k or settings.llm_top_k]
