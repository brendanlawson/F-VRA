"""Build the current CVE-level scope and annotation inputs.

This script intentionally reads ``docs/output_file`` as a reference only. All
current-run outputs are written under ``data/interim/current_cve_vf`` and
``data/interim/annotations/current_cve_vf``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from f_vra.cve_vf.current_scope import (  # noqa: E402
    build_current_candidates,
    evidence_tier_audit,
    load_candidate_group_ids,
    load_candidate_records,
    partition_annotation_buckets,
    read_jsonl,
    read_valid_alert_rows,
    scope_audit,
    select_canonical_scope,
    write_json,
    write_jsonl,
)

DEFAULT_EVIDENCE = ROOT / "data" / "interim" / "evidence" / "all_alert_evidence_index.jsonl"
DEFAULT_VALID_ALERTS = (
    ROOT / "data" / "interim" / "version_reconciliation" / "valid_alerts_for_annotation.csv"
)
PHASE7E_CANDIDATES = ROOT / "docs" / "output_file" / "Phase 7e" / "candidate_functions_v2.jsonl"
PHASE7B_CANDIDATES = ROOT / "docs" / "output_file" / "Phase 7b" / "candidate_functions.jsonl"
PHASE7B_EXTENDED = ROOT / "docs" / "output_file" / "Phase 7b" / "patch_extended_candidates"
DEFAULT_OUT = ROOT / "data" / "interim" / "current_cve_vf"
DEFAULT_ANNOTATION_OUT = ROOT / "data" / "interim" / "annotations" / "current_cve_vf"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-file", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--valid-alerts-file", type=Path, default=DEFAULT_VALID_ALERTS)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--annotation-out-dir", type=Path, default=DEFAULT_ANNOTATION_OUT)
    parser.add_argument("--strict", action="store_true", default=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    out_dir: Path = args.out_dir
    annotation_out_dir: Path = args.annotation_out_dir
    bucket_dir = annotation_out_dir / "annotation_buckets"
    audit_dir = out_dir / "audits"

    evidence_rows = read_jsonl(args.evidence_file)
    valid_rows = read_valid_alert_rows(args.valid_alerts_file)
    candidate_paths = [PHASE7E_CANDIDATES, PHASE7B_CANDIDATES]
    candidate_group_ids = load_candidate_group_ids(candidate_paths, PHASE7B_EXTENDED)

    scope_rows, package_audit = select_canonical_scope(evidence_rows, valid_rows, candidate_group_ids)
    one_cve_audit = scope_audit(scope_rows, evidence_rows)
    tier_audit = evidence_tier_audit(scope_rows)

    source_records = load_candidate_records(
        [
            (PHASE7E_CANDIDATES, "phase7e_candidate_functions_v2"),
            (PHASE7B_CANDIDATES, "phase7b_candidate_functions"),
        ]
    )
    candidate_records, candidate_coverage, candidate_summary = build_current_candidates(
        scope_rows,
        source_records,
        PHASE7B_EXTENDED,
        ROOT,
    )
    buckets = partition_annotation_buckets(scope_rows, candidate_records)

    write_jsonl(out_dir / "current_cve_scope.jsonl", scope_rows)
    write_jsonl(out_dir / "current_candidate_functions.jsonl", candidate_records)
    write_jsonl(out_dir / "candidate_coverage_audit.jsonl", candidate_coverage)
    write_json(audit_dir / "scope_audit.json", one_cve_audit)
    write_json(audit_dir / "package_resolution_audit.json", package_audit)
    write_json(audit_dir / "evidence_tier_audit.json", tier_audit)
    write_json(audit_dir / "candidate_coverage_summary.json", candidate_summary)

    queue_rows = []
    for name, rows in buckets.items():
        write_jsonl(bucket_dir / f"{name}.jsonl", rows)
        queue_rows.extend(rows)
    write_jsonl(annotation_out_dir / "current_annotation_queue.jsonl", queue_rows)
    write_json(
        audit_dir / "annotation_bucket_summary.json",
        {
            "bucket_counts": {name: len(rows) for name, rows in sorted(buckets.items())},
            "candidate_summary": candidate_summary,
            "scope_audit": one_cve_audit,
            "evidence_tier_audit": tier_audit,
        },
    )

    print(json.dumps(one_cve_audit, ensure_ascii=False, indent=2, sort_keys=True))
    print(json.dumps({"bucket_counts": {k: len(v) for k, v in buckets.items()}}, indent=2))
    print(json.dumps(candidate_summary, ensure_ascii=False, indent=2, sort_keys=True))

    if args.strict and not one_cve_audit["passes_one_cve_one_package"]:
        print("ERROR: scope still has duplicate CVEs or mismatched row count", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

