"""
Phase 6 – build_annotation_queue.py
=====================================
Xây dựng annotation queue từ các groups đã qua Phase 4-5.

Inclusion tiers (theo §6 DATASET_PROTOCOL):
  TIER A — patch_verified + commit_verified + diff có Python files
  TIER B — advisory_explicit với strong signal (PR/PoC/function mention)
  EXCLUDE — weak_or_uncertain, unverifiable, no signal

Input:
  raw/advisory_groups_web_scope.jsonl
  raw/evidence_index.jsonl
  raw/verified_snapshots.jsonl
  raw/snapshot_failures.jsonl
  raw/backport_map.jsonl

Output:
  raw/annotation_queue.jsonl
  raw/annotation_exclusion_log.jsonl

Chạy: python scripts/build_annotation_queue.py
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

# ─── CONFIG ──────────────────────────────────────────────────────────────────
WEB_SCOPE_FILE        = r"C:\Users\Admin\Downloads\fvra-vf-benchmark-phase1\fvra-vf-benchmark\raw\advisory_groups_web_scope.jsonl"
EVIDENCE_INDEX_FILE   = r"C:\Users\Admin\Downloads\fvra-vf-benchmark-phase1\fvra-vf-benchmark\raw\evidence_index.jsonl"
VERIFIED_SNAPS_FILE   = r"C:\Users\Admin\Downloads\fvra-vf-benchmark-phase1\fvra-vf-benchmark\raw\verified_snapshots.jsonl"
SNAP_FAILURES_FILE    = r"C:\Users\Admin\Downloads\fvra-vf-benchmark-phase1\fvra-vf-benchmark\raw\snapshot_failures.jsonl"
BACKPORT_MAP_FILE     = r"C:\Users\Admin\Downloads\fvra-vf-benchmark-phase1\fvra-vf-benchmark\raw\backport_map.jsonl"
ANNOTATION_QUEUE_FILE = r"C:\Users\Admin\Downloads\fvra-vf-benchmark-phase1\fvra-vf-benchmark\raw\annotation_queue.jsonl"
EXCLUSION_LOG_FILE    = r"C:\Users\Admin\Downloads\fvra-vf-benchmark-phase1\fvra-vf-benchmark\raw\annotation_exclusion_log.jsonl"
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger(__name__)


def _now():
    return datetime.now(timezone.utc).isoformat()


def load_jsonl(path):
    result = []
    p = Path(path)
    if not p.exists():
        log.warning(f"File not found: {path}")
        return result
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    result.append(json.loads(line))
                except Exception:
                    pass
    return result


def classify_tier(ev, snap):
    """Trả về (tier, exclusion_reason). tier = 'A' | 'B' | 'EXCLUDE'"""
    el              = ev.get("evidence_level", "weak_or_uncertain")
    commit_verified = snap.get("commit_verified", False) if snap else False
    diff_py         = snap.get("diff_files_py", 0) if snap else 0
    diff_total      = snap.get("diff_total_files", 0) if snap else 0

    if el == "patch_verified":
        if not commit_verified:
            return "EXCLUDE", "patch_verified_commit_unverifiable"
        if diff_py >= 1 or diff_total >= 1:
            return "A", ""
        if diff_total == 0:
            return "EXCLUDE", "patch_verified_empty_diff"
        # diff có files nhưng 0 .py (có thể .pyx/.c) → Tier B cho manual review
        return "B", ""

    if el == "advisory_explicit":
        has_signal = (ev.get("has_pr_reference")
                      or ev.get("has_poc_reference")
                      or ev.get("description_mentions_function"))
        if has_signal:
            return "B", ""
        return "EXCLUDE", "advisory_explicit_no_strong_signal"

    return "EXCLUDE", f"evidence_level:{el}"


def build_queue():
    groups   = load_jsonl(WEB_SCOPE_FILE)
    ev_recs  = load_jsonl(EVIDENCE_INDEX_FILE)
    verified = load_jsonl(VERIFIED_SNAPS_FILE)
    failures = load_jsonl(SNAP_FAILURES_FILE)
    bps      = load_jsonl(BACKPORT_MAP_FILE)

    log.info(f"Groups={len(groups)} EvidenceIdx={len(ev_recs)} "
             f"Verified={len(verified)} Failures={len(failures)} Backports={len(bps)}")

    ev_lookup   = {r["group_id"]: r for r in ev_recs}
    snap_lookup = {r["group_id"]: r for r in verified}
    fail_ids    = {r["group_id"] for r in failures}
    bp_counts   = {}
    for bp in bps:
        g = bp.get("group_id", "")
        bp_counts[g] = bp_counts.get(g, 0) + 1

    stats = {"total": len(groups), "tier_A": 0, "tier_B": 0,
             "excluded": 0, "exclusion_reasons": {}}

    Path(ANNOTATION_QUEUE_FILE).parent.mkdir(parents=True, exist_ok=True)
    counter = 0

    with open(ANNOTATION_QUEUE_FILE, "w", encoding="utf-8") as qf, \
         open(EXCLUSION_LOG_FILE,    "w", encoding="utf-8") as ef:

        for group in groups:
            gid  = group["group_id"]
            ev   = ev_lookup.get(gid, {})
            snap = snap_lookup.get(gid)

            if not ev:
                reason = "no_evidence_record"
                ef.write(json.dumps({
                    "group_id": gid, "advisory_id": group.get("advisory_id"),
                    "package": group.get("package", {}).get("name"),
                    "exclusion_reason": reason, "excluded_at": _now(),
                }, ensure_ascii=False) + "\n")
                stats["excluded"] += 1
                stats["exclusion_reasons"][reason] = \
                    stats["exclusion_reasons"].get(reason, 0) + 1
                continue

            tier, excl_reason = classify_tier(ev, snap)

            if tier == "EXCLUDE":
                ef.write(json.dumps({
                    "group_id": gid,
                    "advisory_id": group.get("advisory_id"),
                    "package": group.get("package", {}).get("name"),
                    "evidence_level": ev.get("evidence_level"),
                    "exclusion_reason": excl_reason,
                    "snapshot_failed": gid in fail_ids,
                    "excluded_at": _now(),
                }, ensure_ascii=False) + "\n")
                stats["excluded"] += 1
                stats["exclusion_reasons"][excl_reason] = \
                    stats["exclusion_reasons"].get(excl_reason, 0) + 1
                continue

            counter += 1
            queue_id = f"AQ-{counter:05d}"

            record = {
                "queue_id":          queue_id,
                "tier":              tier,
                "group_id":          gid,
                "advisory_id":       group.get("advisory_id"),
                "package":           group.get("package", {}).get("name"),
                "repo_url":          (snap.get("repo_url") if snap
                                      else ev.get("repo_url")),
                # Advisory content
                "description":       group.get("description", ""),
                "published_at":      group.get("published_at"),
                "affected_versions": group.get("affected_versions"),
                "fixed_versions":    group.get("fixed_versions"),
                "references":        group.get("references", []),
                "aliases":           group.get("aliases", {}),
                # Source resolution
                "vulnerable_ref":    snap.get("vulnerable_ref") if snap else None,
                "fixed_ref":         (snap.get("fixed_ref") if snap
                                      else ev.get("fixed_ref")),
                "fix_commits":       (snap.get("fix_commits") if snap else
                                      [fc["sha"] for fc in ev.get("fix_commits", [])
                                       if fc.get("sha")]),
                "tree_sha":          snap.get("tree_sha") if snap else None,
                # Evidence signals
                "evidence_level":    ev.get("evidence_level"),
                "diff_files_py":     snap.get("diff_files_py", 0) if snap else 0,
                "diff_total_files":  snap.get("diff_total_files", 0) if snap else 0,
                "diff_py_files_list": (snap.get("diff_py_files_list", [])
                                       if snap else []),
                "has_pr_reference":  ev.get("has_pr_reference", False),
                "has_poc_reference": ev.get("has_poc_reference", False),
                "description_mentions_function": ev.get(
                    "description_mentions_function", False),
                # Annotation metadata
                "needs_source_inspection": (tier == "B"),
                "backports_count":   bp_counts.get(gid, 0),
                "annotation_status": "pending",
                "queued_at":         _now(),
            }

            qf.write(json.dumps(record, ensure_ascii=False) + "\n")
            stats[f"tier_{tier}"] += 1

    total_q = stats["tier_A"] + stats["tier_B"]
    top_reasons = sorted(stats["exclusion_reasons"].items(),
                         key=lambda x: -x[1])[:6]

    summary = {
        "run_at": _now(),
        "total_groups": stats["total"],
        "total_queued": total_q,
        "tier_A": stats["tier_A"],
        "tier_B": stats["tier_B"],
        "excluded": stats["excluded"],
        "top_exclusion_reasons": dict(top_reasons),
    }

    log.info("=" * 60)
    log.info(f"Queue: {total_q} items — Tier A: {stats['tier_A']}, Tier B: {stats['tier_B']}")
    log.info(f"Excluded: {stats['excluded']} | Top reasons: {dict(top_reasons)}")
    print("\n📊 Summary:\n" + json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    build_queue()
