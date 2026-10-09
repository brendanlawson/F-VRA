"""LLM evidence judge for the current CVE-level scope.

This stage decides the real evidence level from material, instead of trusting
the pre-existing evidence_level imported from earlier pipeline artifacts.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
import traceback
from collections import Counter
from pathlib import Path
from typing import Any

import requests

BASE_DIR = Path(__file__).resolve().parents[2]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from annotate_vf import (  # noqa: E402
    DEFAULT_MODEL,
    MAX_DIFF_CHARS,
    OPENROUTER_API_KEY,
    OPENROUTER_HTTP_REFERER,
    OPENROUTER_URL,
    OPENROUTER_X_TITLE,
    build_diff_excerpt,
    load_diff_excerpt,
    load_jsonl,
    load_modified_source,
)

SCOPE_FILE = BASE_DIR / "data" / "interim" / "current_cve_vf" / "current_cve_scope.jsonl"
CAND_FILE = BASE_DIR / "data" / "interim" / "current_cve_vf" / "current_candidate_functions.jsonl"
OUT_DIR = BASE_DIR / "data" / "interim" / "annotations"
RESULT_FILE = OUT_DIR / "evidence_judgements.jsonl"
CKPT_FILE = OUT_DIR / ".checkpoint_evidence_judgements.json"
AUDIT_FILE = BASE_DIR / "data" / "interim" / "current_cve_vf" / "audits" / "evidence_judge_run_audit.json"

MAX_DESCRIPTION_CHARS = int(os.environ.get("EVIDENCE_JUDGE_MAX_DESCRIPTION_CHARS", "6000"))
MAX_REFERENCES = int(os.environ.get("EVIDENCE_JUDGE_MAX_REFERENCES", "100"))
MAX_COMMITS = int(os.environ.get("EVIDENCE_JUDGE_MAX_COMMITS", "30"))
MAX_CANDIDATES = int(os.environ.get("EVIDENCE_JUDGE_MAX_CANDIDATES", "10"))
MAX_SOURCE_LINES = int(os.environ.get("EVIDENCE_JUDGE_MAX_SOURCE_LINES", "220"))
MAX_RETRIES = int(os.environ.get("OPENROUTER_MAX_RETRIES", "3"))
RETRY_DELAY = int(os.environ.get("OPENROUTER_RETRY_DELAY", "10"))
RETRY_JITTER = 0.2

VALID_EVIDENCE = {
    "patch_verified",
    "poc_verified",
    "advisory_explicit",
    "weak_or_uncertain",
    "unknown",
    "ambiguous",
}
VALID_CONFIDENCE = {"high", "medium", "low"}
STRONG_EVIDENCE = {"patch_verified", "poc_verified", "advisory_explicit"}

SYSTEM_PROMPT = """\
You are a security evidence judge for a Python CVE-to-vulnerable-function
benchmark. Your job is NOT to label vulnerable functions. Your job is to read
the supplied material and decide whether the CVE has enough evidence for a
later vulnerable-function annotation pass.

Evidence labels:
- patch_verified: patch/diff plus source context demonstrates security-relevant
  changed logic for this CVE/package. Use this only when the diff materially
  fixes the described vulnerability, not for docs/tests/refactors alone.
- poc_verified: PoC, exploit path, or regression/security test demonstrates
  the vulnerable behavior and maps to this package/source path.
- advisory_explicit: advisory explicitly names a vulnerable function, API,
  module, component, or code path, and source/candidate material makes the
  mapping plausible, even if patch evidence is incomplete.
- weak_or_uncertain: some useful material exists, but the mapping from CVE to
  vulnerable logic/function is not strong enough.
- ambiguous: multiple plausible packages/components/functions or conflicting
  evidence prevent a reliable judgement.
- unknown: material is too sparse to judge.

Return ONLY one JSON object with this schema:
{
  "evidence_level": "patch_verified|poc_verified|advisory_explicit|weak_or_uncertain|ambiguous|unknown",
  "confidence": "high|medium|low",
  "material_status": "patch_material|poc_material|advisory_material|candidate_material|insufficient_material",
  "should_vf_annotate": true,
  "reasoning": "<short explanation grounded in the supplied material>",
  "material_gaps": ["<missing or weak material>"]
}
"""


def load_checkpoint(path: Path) -> set[str]:
    if path.exists():
        return set(json.loads(path.read_text(encoding="utf-8-sig")))
    return set()


def save_checkpoint(done: set[str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(sorted(done), ensure_ascii=False), encoding="utf-8")


def candidate_count(cand_rec: dict[str, Any] | None) -> int:
    if not cand_rec:
        return 0
    cands = cand_rec.get("candidates") or {}
    if isinstance(cands, dict):
        return len(cands.get("patch_modified") or cands.get("patch_extended") or [])
    if isinstance(cands, list):
        return len(cands)
    return 0


def get_candidates(cand_rec: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not cand_rec:
        return []
    cands = cand_rec.get("candidates") or {}
    if isinstance(cands, dict):
        return list(cands.get("patch_modified") or cands.get("patch_extended") or [])
    if isinstance(cands, list):
        return list(cands)
    return []


def material_status(row: dict[str, Any], cand_rec: dict[str, Any] | None, diff_text: str) -> str:
    if row.get("has_poc_reference"):
        return "poc_material"
    if diff_text or row.get("diff_paths") or row.get("fix_commits"):
        return "patch_material"
    if candidate_count(cand_rec) > 0:
        return "candidate_material"
    if row.get("description") or row.get("references"):
        return "advisory_material"
    return "insufficient_material"


def _truncate_text(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars] + "\n\n...[truncated]...", True


def build_prompt(
    row: dict[str, Any],
    cand_rec: dict[str, Any] | None,
    diff_text: str,
    diff_truncated: bool,
    source_lk: dict[str, str],
) -> tuple[str, int]:
    gid = str(row.get("group_id") or "")
    desc, desc_truncated = _truncate_text(str(row.get("description") or ""), MAX_DESCRIPTION_CHARS)
    refs = row.get("references") or []
    aliases = row.get("aliases") or {}
    fix_commits = row.get("fix_commits") or []
    cands = get_candidates(cand_rec)[:MAX_CANDIDATES]

    lines: list[str] = [
        f"Group ID: {gid}",
        f"CVE ID: {row.get('cve_id')}",
        f"Package: {row.get('package')}",
        f"Pre evidence level (untrusted): {row.get('evidence_level') or 'unknown'}",
        f"Repo URL: {row.get('repo_url') or '[missing]'}",
        f"Vulnerable ref: {row.get('vulnerable_ref') or '[missing]'}",
        f"Fixed ref: {row.get('fixed_ref') or '[missing]'}",
        f"Affected versions: {row.get('affected_versions') or '[missing]'}",
        f"Fixed versions: {row.get('fixed_versions') or '[missing]'}",
        f"Has PoC reference: {bool(row.get('has_poc_reference'))}",
        f"Has PR reference: {bool(row.get('has_pr_reference'))}",
        f"Has test reference: {bool(row.get('has_test_reference'))}",
        f"Description mentions function/component: {bool(row.get('description_mentions_function'))}",
        f"Candidate count: {candidate_count(cand_rec)}",
        "",
        "Advisory description"
        + (" [truncated]" if desc_truncated else "")
        + ":",
        desc or "[missing]",
        "",
        "Aliases:",
        json.dumps(aliases, ensure_ascii=False, sort_keys=True) if aliases else "[none]",
        "",
        "References:",
    ]
    if refs:
        for idx, ref in enumerate(refs, start=1):
            if idx > MAX_REFERENCES:
                lines.append(f"... [{len(refs) - MAX_REFERENCES} references omitted for length]")
                break
            if isinstance(ref, dict):
                lines.append(f"- [{ref.get('category') or ref.get('type') or ''}] {ref.get('url') or ''}")
            else:
                lines.append(f"- {ref}")
    else:
        lines.append("[none]")

    lines.extend(["", "Fix commits:"])
    if fix_commits:
        for idx, commit in enumerate(fix_commits, start=1):
            if idx > MAX_COMMITS:
                lines.append(f"... [{len(fix_commits) - MAX_COMMITS} commits omitted for length]")
                break
            if isinstance(commit, dict):
                lines.append(
                    "- "
                    + json.dumps(
                        {
                            "sha": commit.get("sha"),
                            "url": commit.get("url"),
                            "diff_path": commit.get("diff_path"),
                            "has_source_changes": commit.get("has_source_changes"),
                            "source": commit.get("source"),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                )
            else:
                lines.append(f"- {commit}")
    else:
        lines.append("[none]")

    if diff_text:
        lines.extend(
            [
                "",
                "PATCH DIFF"
                + (" [truncated per file; omitted hunks are explicitly marked]" if diff_truncated else "")
                + ":",
                "```diff",
                diff_text,
                "```",
            ]
        )
    else:
        lines.append("\nPATCH DIFF: [missing]")

    lines.extend(["", f"CANDIDATE/SOURCE MATERIAL ({len(cands)} shown):"])
    if cands:
        for idx, cand in enumerate(cands, start=1):
            qname = cand.get("qualified_name") or cand.get("name") or f"candidate_{idx}"
            source = (
                source_lk.get(qname)
                or cand.get("source")
                or cand.get("source_code")
                or cand.get("code")
                or ""
            )
            source_lines = source.splitlines()
            if len(source_lines) > MAX_SOURCE_LINES:
                source_lines = source_lines[:MAX_SOURCE_LINES] + [
                    f"... [{len(source_lines) - MAX_SOURCE_LINES} source lines truncated]"
                ]
            lines.extend(
                [
                    f"[{idx}] {qname}",
                    f"File: {cand.get('file_path') or '[missing]'}",
                    "```python",
                    "\n".join(source_lines) if source_lines else "[SOURCE_MISSING]",
                    "```",
                ]
            )
    else:
        lines.append("[no candidate functions available]")

    lines.append(
        "\nDecide the evidence_level from the material above. "
        "Do not trust the pre evidence level. Return only JSON."
    )
    return "\n".join(lines), len(cands)


def _sleep_retry() -> None:
    wait = max(1.0, RETRY_DELAY + random.uniform(-RETRY_DELAY * RETRY_JITTER, RETRY_DELAY * RETRY_JITTER))
    time.sleep(wait)


def parse_json_object(content: str) -> dict[str, Any]:
    text = content.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:].strip()
    start = text.find("{")
    if start < 0:
        raise json.JSONDecodeError("No JSON object found", text, 0)

    depth = 0
    in_string = False
    escaped = False
    for idx in range(start, len(text)):
        char = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:idx + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
                    return json.loads(repaired)
    candidate = text[start:]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
        return json.loads(repaired)


def call_openrouter(prompt: str, model: str, num_candidates: int) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": OPENROUTER_HTTP_REFERER,
        "X-Title": OPENROUTER_X_TITLE,
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        "max_tokens": min(4096, max(1500, 250 + num_candidates * 120)),
        "reasoning": {"enabled": False},
    }
    last_error = ""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(OPENROUTER_URL, headers=headers, json=payload, timeout=90)
            if resp.status_code in {402, 429}:
                body = resp.text[:500]
                if resp.status_code == 402:
                    raise RuntimeError(f"OpenRouter payment/quota error: {body}")
                print(f"    rate limited attempt {attempt}/{MAX_RETRIES}: {body[:160]}")
                if attempt < MAX_RETRIES:
                    _sleep_retry()
                    continue
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"] or ""
            return parse_json_object(content)
        except (requests.RequestException, json.JSONDecodeError, KeyError, IndexError, RuntimeError) as exc:
            last_error = str(exc)
            print(f"    attempt {attempt} failed: {last_error[:220]}")
            if attempt < MAX_RETRIES:
                _sleep_retry()
    raise RuntimeError(f"No valid evidence judgement after {MAX_RETRIES} retries: {last_error}")


def normalize_judgement(raw: dict[str, Any], row: dict[str, Any], model: str, mat_status: str) -> dict[str, Any]:
    level = str(raw.get("evidence_level") or "unknown")
    if level not in VALID_EVIDENCE:
        level = "unknown"
    confidence = str(raw.get("confidence") or "low")
    if confidence not in VALID_CONFIDENCE:
        confidence = "low"
    gaps = raw.get("material_gaps") or []
    if not isinstance(gaps, list):
        gaps = [str(gaps)]
    should = bool(raw.get("should_vf_annotate"))
    if level not in STRONG_EVIDENCE:
        should = False
    return {
        "group_id": row.get("group_id"),
        "cve_id": row.get("cve_id"),
        "package": row.get("package"),
        "package_normalized": row.get("package_normalized"),
        "pre_evidence_level": row.get("evidence_level") or "unknown",
        "material_status": str(raw.get("material_status") or mat_status),
        "evidence_level": level,
        "confidence": confidence,
        "reasoning": str(raw.get("reasoning") or ""),
        "material_gaps": [str(item) for item in gaps],
        "should_vf_annotate": should,
        "model": model,
        "judged_at": int(time.time()),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope-file", default=str(SCOPE_FILE))
    parser.add_argument("--cand-file", default=str(CAND_FILE))
    parser.add_argument("--out-file", default=str(RESULT_FILE))
    parser.add_argument("--ckpt-file", default=str(CKPT_FILE))
    parser.add_argument("--audit-file", default=str(AUDIT_FILE))
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.dry_run and not OPENROUTER_API_KEY:
        print("Missing OPENROUTER_API_KEY")
        return 2

    scope_rows = load_jsonl(Path(args.scope_file))
    cand_rows = load_jsonl(Path(args.cand_file))
    cand_by_gid = {str(row.get("group_id") or ""): row for row in cand_rows}
    if args.limit:
        scope_rows = scope_rows[: args.limit]

    out_file = Path(args.out_file)
    ckpt_file = Path(args.ckpt_file)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    done = load_checkpoint(ckpt_file) if args.resume else set()
    mode = "a" if args.resume and out_file.exists() else "w"
    stats = Counter()

    print(f"Model       : {args.model}")
    print(f"Scope rows  : {len(scope_rows)}")
    print(f"Candidates  : {len(cand_rows)}")
    print(f"Output      : {out_file}")
    print(f"Dry-run     : {args.dry_run}")
    print(f"Resume done : {len(done)}")

    with out_file.open(mode, encoding="utf-8") as handle:
        for idx, row in enumerate(scope_rows, start=1):
            gid = str(row.get("group_id") or "")
            if gid in done:
                stats["skip"] += 1
                continue
            cand_rec = cand_by_gid.get(gid)
            source_lk = load_modified_source(gid)
            diff_text, diff_truncated = load_diff_excerpt(gid, (cand_rec or {}).get("diff_sha_used") or row.get("fixed_ref"))
            mat_status = material_status(row, cand_rec, diff_text)
            prompt, num_candidates = build_prompt(row, cand_rec, diff_text, diff_truncated, source_lk)
            if args.dry_run:
                print(f"\n{'=' * 80}\n[{idx}] {gid}\n{'-' * 80}")
                print(prompt[:5000])
                if len(prompt) > 5000:
                    print(f"... [prompt truncated for display: {len(prompt)} chars]")
                if idx >= 3:
                    break
                continue
            print(f"[{idx}/{len(scope_rows)}] {gid} ", end="", flush=True)
            started = time.time()
            try:
                raw = call_openrouter(prompt, args.model, num_candidates)
                judged = normalize_judgement(raw, row, args.model, mat_status)
                judged["prompt_chars"] = len(prompt)
                judged["candidate_count"] = candidate_count(cand_rec)
                judged["has_diff"] = bool(diff_text)
                handle.write(json.dumps(judged, ensure_ascii=False) + "\n")
                handle.flush()
                done.add(gid)
                save_checkpoint(done, ckpt_file)
                stats["ok"] += 1
                print(
                    f"✓ {judged['evidence_level']} | {judged['confidence']} | "
                    f"annotate={judged['should_vf_annotate']} [{time.time() - started:.1f}s]"
                )
            except Exception as exc:
                traceback.print_exc()
                err = {
                    "group_id": gid,
                    "cve_id": row.get("cve_id"),
                    "package": row.get("package"),
                    "pre_evidence_level": row.get("evidence_level") or "unknown",
                    "material_status": mat_status,
                    "evidence_level": "unknown",
                    "confidence": "low",
                    "reasoning": "",
                    "material_gaps": [str(exc)],
                    "should_vf_annotate": False,
                    "model": args.model,
                    "judged_at": int(time.time()),
                    "error": str(exc),
                }
                handle.write(json.dumps(err, ensure_ascii=False) + "\n")
                handle.flush()
                stats["error"] += 1

    all_rows = []
    if out_file.exists():
        all_rows = [json.loads(line) for line in out_file.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
    audit = {
        "requested_count": len(scope_rows),
        "output_count": len(all_rows),
        "run_ok": stats["ok"],
        "run_skip": stats["skip"],
        "run_error": stats["error"],
        "error_count": sum(1 for row in all_rows if row.get("error")),
        "evidence_level_counts": dict(sorted(Counter(str(row.get("evidence_level")) for row in all_rows).items())),
        "confidence_counts": dict(sorted(Counter(str(row.get("confidence")) for row in all_rows).items())),
        "should_vf_annotate_count": sum(1 for row in all_rows if row.get("should_vf_annotate")),
        "model": args.model,
        "out_file": str(out_file),
    }
    audit_path = Path(args.audit_file)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    audit_path.write_text(json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
