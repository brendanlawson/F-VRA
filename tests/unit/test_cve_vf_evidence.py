import csv
import json
from pathlib import Path

from f_vra.cve_vf.evidence import (
    accepted_benchmark_rows,
    attach_snapshot_evidence,
    build_alert_evidence_index,
    build_annotation_queue,
    build_evidence_index,
    load_advisory_groups,
    load_evidence_cache,
    materialize_diff_paths,
    reference_category,
    valid_alert_rows,
    write_jsonl,
)


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def accepted_row(project: str = "owner__repo") -> dict:
    return {
        "benchmark_id": f"{project}::CVE-2026-0001::django-allauth",
        "benchmark_status": "accepted",
        "project": project,
        "cve_id": "CVE-2026-0001",
        "package": "Django_AllAuth",
        "package_normalized": "django-allauth",
        "annotation_summary": "patched vulnerable view",
        "evidence_level": "patch_verified",
        "target_vfs": [{"qualified_name": "pkg.views.vulnerable", "label": "root_cause_vf"}],
    }


def valid_alert(project: str = "owner__repo", status: str = "consistent") -> dict[str, str]:
    return {
        "project": project,
        "cve_id": "CVE-2026-0001",
        "package": "django-allauth",
        "package_normalized": "django-allauth",
        "resolved_version": "1.1.0",
        "scanner_version": "1.0.0",
        "version_status": status,
        "scanner": "snyk",
        "severity": "high",
        "title": "title",
        "fixed_versions": "2.0.0",
        "annotation_decision": "valid_for_annotation",
    }


def test_reference_category_classifies_evidence_links() -> None:
    assert reference_category("https://github.com/o/r/commit/abcdef123456") == "commit"
    assert reference_category("https://github.com/o/r/pull/12") == "pull_request"
    assert reference_category("https://example.com/poc.py") == "poc"
    assert reference_category("https://example.com/exploit-db") == "exploit"
    assert reference_category("https://example.com/fix.patch") == "patch"
    assert reference_category("https://nvd.nist.gov/vuln/detail/CVE-2026-0001") == "advisory"


def test_enrichment_imports_cache_and_builds_project_queue(tmp_path: Path) -> None:
    benchmark = tmp_path / "benchmark.jsonl"
    valid_alerts = tmp_path / "valid.csv"
    cache = tmp_path / "evidence.jsonl"
    advisories = tmp_path / "advisories.jsonl"

    write_jsonl(benchmark, [accepted_row("owner__repo"), accepted_row("other__repo")])
    write_csv(valid_alerts, [valid_alert("owner__repo"), valid_alert("other__repo")])
    write_jsonl(
        cache,
        [
            {
                "advisory_id": "CVE-2026-0001",
                "package": "django-allauth",
                "evidence_level": "patch_verified",
                "fix_commits": [
                    {
                        "sha": "abcdef1",
                        "url": "https://github.com/o/r/commit/abcdef1",
                        "diff_path": "artifacts/patch.diff",
                    }
                ],
                "has_poc_reference": False,
                "has_pr_reference": False,
                "has_test_reference": False,
                "repo_url": "https://github.com/o/r",
                "vulnerable_ref": "parent",
                "fixed_ref": "fixed",
            }
        ],
    )
    write_jsonl(
        advisories,
        [
            {
                "advisory_id": "CVE-2026-0001",
                "package": {"name": "django-allauth"},
                "description": "advisory description",
                "references": [
                    {"url": "https://github.com/o/r/pull/12", "type": "pr"},
                    {"url": "https://example.com/poc", "type": "poc"},
                ],
            }
        ],
    )

    evidence_rows, _ = build_evidence_index(
        accepted_benchmark_rows(benchmark),
        valid_alert_rows(valid_alerts),
        load_evidence_cache(cache),
        load_advisory_groups([advisories]),
    )
    evidence_rows = attach_snapshot_evidence(
        evidence_rows,
        {},
        {
            ("CVE-2026-0001", "django-allauth"): {
                "tree_sha": "tree",
                "commit_verified": True,
                "diff_files_py": 1,
                "diff_total_files": 2,
                "diff_py_files_list": ["pkg/views.py"],
            }
        },
    )
    queue = build_annotation_queue(evidence_rows, valid_alert_rows(valid_alerts))

    assert len(evidence_rows) == 1
    assert evidence_rows[0]["projects"] == ["other__repo", "owner__repo"]
    assert evidence_rows[0]["evidence_provenance"] == ["imported_from_output_file", "imported_advisory_group"]
    assert evidence_rows[0]["has_poc_reference"] is True
    assert evidence_rows[0]["has_pr_reference"] is True
    assert evidence_rows[0]["patch_urls"] == ["https://github.com/o/r/commit/abcdef1"]
    assert len(queue) == 2
    assert {row["project"] for row in queue} == {"owner__repo", "other__repo"}
    assert queue[0]["resolved_version"] == "1.1.0"
    assert "target_vfs" not in queue[0]
    assert "has_existing_vf_seed" not in queue[0]["llm_prompt_context"]
    assert queue[0]["queue_id"].startswith("LLMQ-")
    assert queue[0]["llm_annotation_status"] == "pending"
    assert queue[0]["annotation_goal"] == "identify vulnerable function(s)"
    assert queue[0]["repo_url"] == "https://github.com/o/r"
    assert queue[0]["vulnerable_ref"] == "parent"
    assert queue[0]["fixed_ref"] == "fixed"
    assert queue[0]["tree_sha"] == "tree"
    assert queue[0]["diff_files_py"] == 1


def test_invalid_version_status_is_not_queued(tmp_path: Path) -> None:
    benchmark = tmp_path / "benchmark.jsonl"
    valid_alerts_path = tmp_path / "valid.csv"

    write_jsonl(benchmark, [accepted_row()])
    write_csv(
        valid_alerts_path,
        [
            valid_alert(status="consistent"),
            valid_alert(project="bad__repo", status="mismatch_not_applicable"),
        ],
    )

    evidence_rows, _ = build_evidence_index(accepted_benchmark_rows(benchmark), valid_alert_rows(valid_alerts_path), {}, {})
    queue = build_annotation_queue(evidence_rows, valid_alert_rows(valid_alerts_path))

    assert [row["project"] for row in queue] == ["owner__repo"]


def test_scanner_version_does_not_override_resolved_version(tmp_path: Path) -> None:
    benchmark = tmp_path / "benchmark.jsonl"
    valid_alerts_path = tmp_path / "valid.csv"
    row = valid_alert(status="mismatch_but_env_affected")
    row["resolved_version"] = "1.1.0"
    row["scanner_version"] = "1.0.0"

    write_jsonl(benchmark, [accepted_row()])
    write_csv(valid_alerts_path, [row])

    evidence_rows, _ = build_evidence_index(accepted_benchmark_rows(benchmark), valid_alert_rows(valid_alerts_path), {}, {})
    queue = build_annotation_queue(evidence_rows, valid_alert_rows(valid_alerts_path))

    assert queue[0]["resolved_version"] == "1.1.0"
    assert queue[0]["resolved_version"] != row["scanner_version"]


def test_all_alert_evidence_includes_pairs_without_accepted_vf(tmp_path: Path) -> None:
    benchmark = tmp_path / "benchmark.jsonl"
    valid_alerts_path = tmp_path / "valid.csv"
    write_jsonl(benchmark, [accepted_row()])
    extra = valid_alert(project="extra__repo")
    extra["cve_id"] = "CVE-2026-0002"
    extra["package"] = "urllib3"
    extra["package_normalized"] = "urllib3"
    write_csv(valid_alerts_path, [valid_alert(), extra])

    evidence_rows, _ = build_alert_evidence_index(
        valid_alert_rows(valid_alerts_path),
        {},
        {},
        accepted_benchmark_rows(benchmark),
    )
    queue = build_annotation_queue(evidence_rows, valid_alert_rows(valid_alerts_path))

    assert len(evidence_rows) == 2
    no_vf = next(row for row in evidence_rows if row["cve_id"] == "CVE-2026-0002")
    assert "accepted_record_count" not in no_vf
    assert no_vf["annotation_summary"] == ""
    assert {row["cve_id"] for row in queue} == {"CVE-2026-0001", "CVE-2026-0002"}


def test_materialize_diff_paths_rewrites_legacy_absolute_paths(tmp_path: Path) -> None:
    source_root = tmp_path / "docs" / "patch_diffs"
    artifact_root = tmp_path / "artifacts" / "patch_diffs"
    diff = source_root / "CVE-2026-0001__django-allauth" / "abcdef1.diff"
    diff.parent.mkdir(parents=True)
    diff.write_text("diff --git a/pkg.py b/pkg.py\n@@\n-old\n+new\n", encoding="utf-8")
    legacy = str(Path("C:/Users/Admin/Downloads/old/artifacts/patch_diffs") / "CVE-2026-0001__django-allauth" / "abcdef1.diff")

    rows, logs = materialize_diff_paths(
        [
            {
                "group_id": "CVE-2026-0001::django-allauth",
                "cve_id": "CVE-2026-0001",
                "package": "django-allauth",
                "fix_commits": [{"sha": "abcdef1", "diff_path": legacy}],
            }
        ],
        source_patch_root=source_root,
        artifact_patch_root=artifact_root,
        repo_root=tmp_path,
    )

    new_path = tmp_path / rows[0]["diff_paths"][0]
    assert new_path.exists()
    assert rows[0]["fix_commits"][0]["diff_path"] == rows[0]["diff_paths"][0]
    assert logs[0]["action"] == "diff_materialized"
