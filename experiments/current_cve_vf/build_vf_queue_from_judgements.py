"""Build the VF annotation queue from LLM evidence judgements."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from f_vra.cve_vf.current_scope import read_jsonl, write_json, write_jsonl  # noqa: E402

JUDGEMENTS_FILE = ROOT / "data" / "interim" / "annotations" / "evidence_judgements.jsonl"
SCOPE_FILE = ROOT / "data" / "interim" / "current_cve_vf" / "current_cve_scope.jsonl"
CAND_FILE = ROOT / "data" / "interim" / "current_cve_vf" / "current_candidate_functions.jsonl"
QUEUE_FILE = ROOT / "data" / "interim" / "annotations" / "current_cve_vf" / "judged_vf_queue.jsonl"
AUDIT_FILE = ROOT / "data" / "interim" / "current_cve_vf" / "audits" / "judged_vf_queue_audit.json"
STRONG_EVIDENCE = {"patch_verified", "poc_verified", "advisory_explicit"}


def candidate_count(record: dict[str, Any] | None) -> int:
    if not record:
        return 0
    cands = record.get("candidates") or {}
    if isinstance(cands, dict):
        return len(cands.get("patch_modified") or cands.get("patch_extended") or [])
    if isinstance(cands, list):
        return len(cands)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--judgements-file", type=Path, default=JUDGEMENTS_FILE)
    parser.add_argument("--scope-file", type=Path, default=SCOPE_FILE)
    parser.add_argument("--cand-file", type=Path, default=CAND_FILE)
    parser.add_argument("--queue-file", type=Path, default=QUEUE_FILE)
    parser.add_argument("--audit-file", type=Path, default=AUDIT_FILE)
    parser.add_argument("--allow-low-confidence", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    judgements = read_jsonl(args.judgements_file)
    scope_by_gid = {str(row.get("group_id") or ""): row for row in read_jsonl(args.scope_file)}
    cand_by_gid = {str(row.get("group_id") or ""): row for row in read_jsonl(args.cand_file)}

    queue: list[dict[str, Any]] = []
    reject_reasons: Counter[str] = Counter()
    for judgement in judgements:
        gid = str(judgement.get("group_id") or "")
        scope = scope_by_gid.get(gid)
        cand = cand_by_gid.get(gid)
        level = str(judgement.get("evidence_level") or "unknown")
        confidence = str(judgement.get("confidence") or "low")
        ccount = candidate_count(cand)
        reason = ""
        if judgement.get("error"):
            reason = "judge_error"
        elif not judgement.get("should_vf_annotate"):
            reason = "judge_rejected"
        elif level not in STRONG_EVIDENCE:
            reason = f"weak_evidence:{level}"
        elif confidence == "low" and not args.allow_low_confidence:
            reason = "low_confidence"
        elif ccount <= 0:
            reason = "no_candidate_functions"
        elif scope is None:
            reason = "missing_scope_row"
        elif cand is None:
            reason = "missing_candidate_record"

        if reason:
            reject_reasons[reason] += 1
            continue

        record = dict(scope)
        record["pre_evidence_level"] = record.pop("evidence_level", "")
        record["judged_evidence_level"] = level
        record["evidence_level"] = level
        record["judge_confidence"] = confidence
        record["judge_reasoning"] = judgement.get("reasoning") or ""
        record["material_status"] = judgement.get("material_status") or ""
        record["material_gaps"] = judgement.get("material_gaps") or []
        record["candidate_count"] = ccount
        record["annotation_bucket"] = "judged_vf_ready"
        queue.append(record)

    audit = {
        "judgement_count": len(judgements),
        "queue_count": len(queue),
        "reject_reasons": dict(sorted(reject_reasons.items())),
        "judged_evidence_counts": dict(sorted(Counter(str(row.get("evidence_level")) for row in judgements).items())),
        "queue_evidence_counts": dict(sorted(Counter(str(row.get("evidence_level")) for row in queue).items())),
        "queue_confidence_counts": dict(sorted(Counter(str(row.get("judge_confidence")) for row in queue).items())),
        "passes_no_duplicate_group_id": len(queue) == len({row["group_id"] for row in queue}),
    }
    write_jsonl(args.queue_file, queue)
    write_json(args.audit_file, audit)
    print(json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if audit["passes_no_duplicate_group_id"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

