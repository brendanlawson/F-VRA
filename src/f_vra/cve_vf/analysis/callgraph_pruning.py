from __future__ import annotations

import json
from typing import Any


def apply_llm_pruning(
    report: dict[str, Any],
    *,
    model: str,
    threshold: float,
    limit: int,
) -> None:
    """Use the server-side LLM client to validate coarse callgraph edges."""
    candidates = report.get("candidate_edges", [])
    if limit > 0:
        candidates = candidates[:limit]
    if not candidates:
        return

    from f_vra.localization.providers.llm_client import chat

    kept: list[dict[str, Any]] = []
    pruned: list[dict[str, Any]] = []
    for candidate in candidates:
        if candidate.get("status") == "too_many_candidates" or not candidate.get("callee"):
            pruned.append(
                {
                    **candidate,
                    "confidence": 0.0,
                    "resolver": "llm_pruner",
                    "status": "llm_pruned",
                    "reason": candidate.get("reason", "candidate cannot be evaluated"),
                }
            )
            continue
        messages = [
            {
                "role": "system",
                "content": (
                    "You validate Python call graph candidate edges. "
                    "Return strict JSON only with keys decision, confidence, reason. "
                    "decision must be keep or prune; confidence is 0.0 to 1.0. "
                    "Keep only when the caller directly invokes the candidate callee at this call site."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "question": "Can the caller directly call the candidate callee at this call site?",
                        "call_expr": candidate.get("call_expr", ""),
                        "arity": candidate.get("arity", 0),
                        "receiver": candidate.get("receiver", ""),
                        "caller": {
                            "name": candidate.get("caller", ""),
                            "signature": candidate.get("caller_signature", ""),
                            "source": candidate.get("caller_source", ""),
                        },
                        "callee": {
                            "name": candidate.get("callee", ""),
                            "signature": candidate.get("callee_signature", ""),
                            "source": candidate.get("callee_source", ""),
                        },
                        "candidate_metadata": candidate,
                    },
                    ensure_ascii=False,
                ),
            },
        ]
        raw = chat(messages=messages, model=model, temperature=0.0)
        try:
            verdict = json.loads(raw)
        except json.JSONDecodeError:
            verdict = {"decision": "prune", "confidence": 0.0, "reason": f"invalid JSON: {raw[:120]}"}
        confidence = float(verdict.get("confidence", 0.0) or 0.0)
        enriched = {
            **candidate,
            "callee_type": "internal",
            "edge_type": "llm_candidate",
            "confidence": confidence,
            "resolver": "llm_pruner",
            "status": "llm_kept" if verdict.get("decision") == "keep" and confidence >= threshold else "llm_pruned",
            "reason": str(verdict.get("reason", "")),
        }
        if enriched["status"] == "llm_kept":
            kept.append(enriched)
        else:
            pruned.append(enriched)

    report["llm_kept_edges"] = kept
    report["llm_pruned_edges"] = pruned
    report["final_edges_detail"] = list(report.get("edges_detail", [])) + kept
    report["llm_pruning"] = {
        "provider": "local",
        "model": model,
        "threshold": threshold,
        "limit": limit,
        "candidate_count": len(candidates),
        "kept": len(kept),
        "pruned": len(pruned),
    }

