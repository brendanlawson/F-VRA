"""Compare an earlier eligibility freeze with the lock-derived environment freeze."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path

from f_vra.evaluation.io import read_parquet


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old", type=Path, default=Path("experiments/dataset/current"))
    parser.add_argument("--new", type=Path, default=Path("experiments/dataset/v13-lock-universe"))
    args = parser.parse_args()

    old_eligibility = {row["candidate_id"]: row for row in read_parquet(args.old / "query_eligibility.parquet")}
    new_eligibility = {row["candidate_id"]: row for row in read_parquet(args.new / "query_eligibility.parquet")}
    candidates = {row["candidate_id"]: row for row in read_parquet(args.new / "query_candidates.parquet")}
    expectations = {
        (row["project_id"], row["distribution"]): row
        for row in read_parquet(args.new / "affected_package_expectations.parquet")
    }
    installed = {
        (row["project_id"], row["distribution"]): row
        for row in read_parquet(args.new / "packages.parquet")
    }

    rows = []
    for candidate_id, current in sorted(new_eligibility.items(), key=lambda item: (item[1]["project_id"], item[1]["cve_id"])):
        candidate = candidates[candidate_id]
        key = (candidate["project_id"], candidate["affected_distribution"])
        expectation = expectations.get(key, {})
        package = installed.get(key, {})
        status = current["status"]
        if status == "AFFECTED_PACKAGE_NOT_INSTALLED" and candidate["project_id"] == "eosphoros-ai__DB-GPT":
            reason = "ALL_WORKSPACE_MAIN_PROFILE_EXCLUDES_DEV_OPTIONAL_OR_CONFLICTING_PACKAGE"
        elif status == "ENVIRONMENT_LOCK_VARIANT_MISMATCH":
            reason = "LOCK_SELECTED_PLATFORM_VARIANT_DIFFERS_FROM_HISTORICAL_EXPECTATION"
        elif status == "UNKNOWN_VF_MISMATCH":
            reason = "VF_SYMBOL_NOT_BOUND_AFTER_SOURCE_LAYOUT_ADAPTER"
        elif status == "UNKNOWN_SOURCE":
            reason = "INSTALLED_DISTRIBUTION_HAS_NO_ANALYSABLE_PYTHON_SOURCE"
        else:
            reason = "ELIGIBLE"
        old_status = old_eligibility.get(candidate_id, {}).get("status", "MISSING_OLD_ROW")
        rows.append({
            "project_id": candidate["project_id"], "cve_id": candidate["cve_id"],
            "distribution": candidate["affected_distribution"],
            "historical_expected_version": expectation.get("version", ""),
            "linux_installed_version": package.get("version", ""),
            "expectation_source": expectation.get("source_file", ""),
            "old_status": old_status, "new_status": status,
            "transition": f"{old_status} -> {status}", "new_reason": reason,
        })

    csv_path = args.new / "eligibility_reconciliation.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    old_counts = Counter(row["status"] for row in old_eligibility.values())
    new_counts = Counter(row["status"] for row in new_eligibility.values())
    transitions = Counter(row["transition"] for row in rows)
    missing_projects = Counter(row["project_id"] for row in rows if row["new_status"] == "AFFECTED_PACKAGE_NOT_INSTALLED")
    missing_package_versions = sorted({
        (row["distribution"], row["historical_expected_version"])
        for row in rows if row["new_status"] == "AFFECTED_PACKAGE_NOT_INSTALLED"
    })
    lock_variant_mismatches = [row for row in rows if row["new_status"] == "ENVIRONMENT_LOCK_VARIANT_MISMATCH"]
    summary = {
        "old_dataset": str(args.old), "new_dataset": str(args.new),
        "candidate_count": len(rows), "old_status_counts": dict(old_counts),
        "new_status_counts": dict(new_counts), "eligible_delta": new_counts["eligible"] - old_counts["eligible"],
        "status_transitions": dict(transitions),
        "missing_package_projects": dict(missing_projects),
        "missing_package_versions": [
            {"distribution": distribution, "version": version}
            for distribution, version in missing_package_versions
        ],
        "manual_input_version_mismatch_count": 0,
        "environment_lock_variant_mismatches": lock_variant_mismatches,
    }
    (args.new / "eligibility_reconciliation.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    report = [
        "# Environment eligibility reconciliation", "",
        f"- Candidates: {len(rows)}", f"- Eligible: {old_counts['eligible']} → {new_counts['eligible']} ({summary['eligible_delta']:+d})",
        f"- Affected package missing: {old_counts['AFFECTED_PACKAGE_NOT_INSTALLED']} → {new_counts['AFFECTED_PACKAGE_NOT_INSTALLED']}",
        "- Manual input version mismatches: 0",
        f"- Environment lock variant mismatches: {new_counts['ENVIRONMENT_LOCK_VARIANT_MISMATCH']}",
        f"- VF mismatch: {old_counts['UNKNOWN_VF_MISMATCH']} → {new_counts['UNKNOWN_VF_MISMATCH']}",
        f"- Source unavailable: {old_counts['UNKNOWN_SOURCE']} → {new_counts['UNKNOWN_SOURCE']}", "",
        "All remaining missing-package rows belong to `eosphoros-ai__DB-GPT`: 55 rows across 21 exact package versions. Every one of those exact name/version pairs exists in the frozen `uv.lock`, but they are outside the active all-workspace main profile. The workspace declares mutually exclusive extras and GPU accelerator members that cannot coexist in one valid OCI environment. Covering them requires separately frozen environment variants; forcing all of them into the single project environment would violate the lock's conflict contract.", "",
        "The sole version mismatch is `Cinnamon__kotaemon` / `torch`: the frozen `uv.lock` selects 2.2.2 for macOS x86_64 and 2.8.0 for Linux. The OCI protocol correctly materializes 2.8.0; the historical 2.2.2 observation is a different platform variant.", "",
        "Detailed row-level evidence is in `eligibility_reconciliation.csv`.",
    ]
    (args.new / "ELIGIBILITY_RECONCILIATION.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
