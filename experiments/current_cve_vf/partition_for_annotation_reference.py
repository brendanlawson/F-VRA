"""
partition_for_annotation.py
================================================================================
Tách các active groups từ annotation_queue_v4.jsonl thành các bucket rõ ràng:

  BUCKET A — tier1_ready.jsonl       : Tier 1 (pm ≤ 5), có candidate record
                                        → annotate ngay bằng annotate_vf.py
  BUCKET B — tier2_needs_rank.jsonl  : Tier 2 (6 ≤ pm ≤ 100)
                                        → rank trước rồi annotate
  BUCKET C — tier3_manual.jsonl      : Tier 3 (pm > 100)
                                        → review tay, không annotate tự động
  BUCKET D — needs_verify.jsonl      : GHSA+CVE unconfirmed alias
                                        → OSV check tay, sau đó phân về A/B/C
  BUCKET E — no_corpus.jsonl         : Không có candidate record
                                        → bỏ qua hoặc Phase 4 retry

Mỗi record trong output giữ nguyên toàn bộ field từ annotation_queue_v4
+ thêm patch_modified_count và candidate_count từ candidate_functions_v2.

Output: data/annotation_buckets/
"""

import json
from pathlib import Path

BASE_DIR    = Path(r"D:\fvra-vf-benchmark-phase1\fvra-vf-benchmark")
AQ_FILE     = BASE_DIR / "data" / "annotation_queue_v4.jsonl"
CAND_FILE   = BASE_DIR / "data" / "candidate_functions_v2.jsonl"
OUT_DIR     = BASE_DIR / "data" / "annotation_buckets"
OUT_DIR.mkdir(parents=True, exist_ok=True)

TIER1_MAX = 5
TIER3_MIN = 100


def load_jsonl(path) -> list[dict]:
    out = []
    p = Path(path)
    if not p.exists():
        print(f"⚠ Không tìm thấy: {p}")
        return out
    with open(p, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s:
                try:
                    out.append(json.loads(s))
                except json.JSONDecodeError:
                    pass
    return out


def write_jsonl(records: list[dict], path: Path) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def main():
    aq      = load_jsonl(AQ_FILE)
    cand    = load_jsonl(CAND_FILE)

    # Index candidates by group_id
    cand_by_gid: dict[str, dict] = {r["group_id"]: r for r in cand}

    active = [r for r in aq if not r.get("excluded")]
    print(f"Active records: {len(active)}")

    buckets = {"A": [], "B": [], "C": [], "D": [], "E": []}

    for rec in active:
        gid          = rec["group_id"]
        cand_rec     = cand_by_gid.get(gid)
        needs_verify = rec.get("needs_manual_verify", False)

        # Merge useful fields from candidate record
        enriched = dict(rec)
        if cand_rec:
            enriched["patch_modified_count"]   = cand_rec["patch_modified_count"]
            enriched["patch_extended_count"]   = cand_rec["patch_extended_count"]
            enriched["full_corpus_count"]      = cand_rec["full_corpus_count"]
            enriched["candidate_count"]        = len(
                (cand_rec.get("candidates") or {}).get("patch_modified", [])
            )
        else:
            enriched["patch_modified_count"] = None
            enriched["patch_extended_count"] = None
            enriched["full_corpus_count"]    = None
            enriched["candidate_count"]      = 0

        pm = enriched["patch_modified_count"]

        # Phân bucket
        if cand_rec is None:
            bucket = "E"  # no_corpus
        elif needs_verify:
            bucket = "D"  # cần xác nhận alias trước
        elif pm is None or pm > TIER3_MIN:
            bucket = "C"  # Tier 3 anomaly
        elif pm > TIER1_MAX:
            bucket = "B"  # Tier 2 cần rank
        else:
            bucket = "A"  # Tier 1 ready

        enriched["annotation_bucket"] = bucket
        buckets[bucket].append(enriched)

    # Write buckets
    bucket_meta = {
        "A": ("tier1_ready.jsonl",      "Tier 1 — annotate ngay"),
        "B": ("tier2_needs_rank.jsonl", "Tier 2 — rank trước"),
        "C": ("tier3_manual.jsonl",     "Tier 3 — review tay"),
        "D": ("needs_verify.jsonl",     "GHSA+CVE — xác nhận alias"),
        "E": ("no_corpus.jsonl",        "No corpus — skip"),
    }

    print(f"\n{'─'*55}")
    print(f"{'Bucket':<6} {'File':<32} {'Count':>6}  Mô tả")
    print(f"{'─'*55}")
    for bk, (fname, desc) in bucket_meta.items():
        records = buckets[bk]
        out_path = OUT_DIR / fname
        write_jsonl(records, out_path)
        print(f"  {bk}    {fname:<32} {len(records):>5}   {desc}")

    print(f"{'─'*55}")
    print(f"       {'TOTAL':<32} {sum(len(v) for v in buckets.values()):>5}")
    print(f"\n📁 Output: {OUT_DIR}")

    # Bucket A stats
    a = buckets["A"]
    if a:
        print(f"\nBucket A (Tier 1) — chi tiết:")
        pm_vals = [r["patch_modified_count"] for r in a if r["patch_modified_count"] is not None]
        print(f"  pm=0 : {sum(1 for v in pm_vals if v == 0)}")
        print(f"  pm=1 : {sum(1 for v in pm_vals if v == 1)}")
        print(f"  pm=2 : {sum(1 for v in pm_vals if v == 2)}")
        print(f"  pm=3 : {sum(1 for v in pm_vals if v == 3)}")
        print(f"  pm=4 : {sum(1 for v in pm_vals if v == 4)}")
        print(f"  pm=5 : {sum(1 for v in pm_vals if v == 5)}")
        avg_cand = sum(r["candidate_count"] for r in a) / len(a) if a else 0
        print(f"  avg candidate_count: {avg_cand:.1f}")
        print(f"\n  → Input cho annotate_vf.py: {OUT_DIR / 'tier1_ready.jsonl'}")


if __name__ == "__main__":
    main()
