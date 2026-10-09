from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from f_vra.core.config import settings


@dataclass
class DescriptionEnrichment:
    text: str
    status: str
    model: str | None = None
    entities: dict[str, str] = field(default_factory=dict)


def _extract_json(raw: str) -> dict[str, str]:
    text = raw.strip()
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if match:
        text = match.group(0)
    payload = json.loads(text)
    if not isinstance(payload, dict):
        return {}
    return {
        str(key): str(value).strip()
        for key, value in payload.items()
        if value is not None and str(value).strip() and str(value).strip().lower() != "none"
    }


def enrich_description_with_llm_entities(
    description: str,
    *,
    model: str | None = None,
) -> DescriptionEnrichment:
    from f_vra.localization.providers.llm_client import chat_available

    if not chat_available():
        return DescriptionEnrichment(
            text=description,
            status="disabled: no LLM provider API key is set",
            model=model,
        )

    from f_vra.localization.providers.llm_client import chat

    active_model = model or settings.llm_model
    try:
        raw = chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Extract concise vulnerability-search entities from CVE text. "
                        "Return only JSON with keys attack_vector, root_cause, "
                        "component, vulnerability_type, and affected_behavior."
                    ),
                },
                {"role": "user", "content": description},
            ],
            model=active_model,
        )
        entities = _extract_json(raw)
    except (RuntimeError, json.JSONDecodeError) as exc:
        return DescriptionEnrichment(
            text=description,
            status=f"fallback: {exc}",
            model=active_model,
        )

    additions = "\n".join(f"{key}: {value}" for key, value in sorted(entities.items()))
    enriched = f"{description}\n{additions}".strip() if additions else description
    return DescriptionEnrichment(
        text=enriched,
        status="used" if entities else "used: no entities",
        model=active_model,
        entities=entities,
    )
