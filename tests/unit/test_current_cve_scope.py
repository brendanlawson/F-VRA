from f_vra.cve_vf.current_scope import (
    build_current_candidates,
    load_candidate_group_ids,
    partition_annotation_buckets,
    scope_audit,
    select_canonical_scope,
)


def evidence_row(
    cve_id: str,
    package: str,
    evidence_level: str = "weak_or_uncertain",
    *,
    has_diff: bool = False,
) -> dict:
    return {
        "cve_id": cve_id,
        "advisory_id": cve_id,
        "package": package,
        "package_normalized": package,
        "group_id": f"{cve_id}::{package}",
        "evidence_level": evidence_level,
        "diff_paths": ["artifacts/patch.diff"] if has_diff else [],
        "fix_commits": [{"sha": "abc"}] if has_diff else [],
        "repo_url": "https://github.com/example/repo" if has_diff else "",
        "vulnerable_ref": "parent" if has_diff else "",
    }


def valid_alert(cve_id: str, package: str, project: str = "owner__repo") -> dict[str, str]:
    return {
        "cve_id": cve_id,
        "package": package,
        "package_normalized": package,
        "project": project,
    }


def test_canonical_scope_keeps_one_row_per_single_package_cve() -> None:
    rows = [evidence_row("CVE-2026-0001", "django", "patch_verified", has_diff=True)]
    scope, package_audit = select_canonical_scope(rows, [valid_alert("CVE-2026-0001", "django")], set())

    assert len(scope) == 1
    assert scope[0]["group_id"] == "CVE-2026-0001::django"
    assert scope[0]["dropped_package_aliases"] == []
    assert package_audit == []
    assert scope_audit(scope, rows)["passes_one_cve_one_package"] is True


def test_canonical_scope_prefers_stronger_evidence_over_alert_count() -> None:
    rows = [
        evidence_row("CVE-2026-0002", "alias-pkg", "weak_or_uncertain"),
        evidence_row("CVE-2026-0002", "core-pkg", "patch_verified", has_diff=True),
    ]
    valid_rows = [
        valid_alert("CVE-2026-0002", "alias-pkg", "p1"),
        valid_alert("CVE-2026-0002", "alias-pkg", "p2"),
        valid_alert("CVE-2026-0002", "core-pkg", "p3"),
    ]
    scope, package_audit = select_canonical_scope(rows, valid_rows, {"CVE-2026-0002::core-pkg"})

    assert [row["cve_id"] for row in scope] == ["CVE-2026-0002"]
    assert scope[0]["package_normalized"] == "core-pkg"
    assert scope[0]["dropped_package_aliases"][0]["package_normalized"] == "alias-pkg"
    assert package_audit[0]["selected_group_id"] == "CVE-2026-0002::core-pkg"


def test_canonical_scope_tie_breaks_by_alerts_then_package_name() -> None:
    rows = [
        evidence_row("CVE-2026-0003", "z-package", "weak_or_uncertain"),
        evidence_row("CVE-2026-0003", "a-package", "weak_or_uncertain"),
    ]
    valid_rows = [
        valid_alert("CVE-2026-0003", "z-package", "p1"),
        valid_alert("CVE-2026-0003", "a-package", "p1"),
        valid_alert("CVE-2026-0003", "a-package", "p2"),
    ]
    scope, _package_audit = select_canonical_scope(rows, valid_rows, set())

    assert scope[0]["package_normalized"] == "a-package"


def test_partition_only_strong_evidence_with_candidates_is_ready() -> None:
    scope = [
        evidence_row("CVE-2026-0004", "django", "patch_verified", has_diff=True),
        evidence_row("CVE-2026-0005", "urllib3", "weak_or_uncertain", has_diff=True),
        evidence_row("CVE-2026-0006", "idna", "advisory_explicit"),
    ]
    candidates = [
        {
            "group_id": "CVE-2026-0004::django",
            "candidates": {"patch_modified": [{"qualified_name": "pkg.f"}]},
            "patch_modified_count": 1,
        }
    ]

    buckets = partition_annotation_buckets(scope, candidates)

    assert [row["group_id"] for row in buckets["tier1_ready"]] == ["CVE-2026-0004::django"]
    assert [row["group_id"] for row in buckets["weak_or_uncertain"]] == ["CVE-2026-0005::urllib3"]
    assert [row["group_id"] for row in buckets["no_candidate"]] == ["CVE-2026-0006::idna"]


def test_load_candidate_group_ids_reads_extended_dirs(tmp_path) -> None:
    extended = tmp_path / "patch_extended_candidates" / "CVE-2026-0007__django"
    extended.mkdir(parents=True)
    (extended / "extended.jsonl").write_text('{"qualified_name":"pkg.f"}\n', encoding="utf-8")

    assert load_candidate_group_ids([], tmp_path / "patch_extended_candidates") == {"CVE-2026-0007::django"}


def test_diff_fallback_creates_module_candidate_for_import_only_patch(tmp_path) -> None:
    diff = tmp_path / "artifacts" / "patch_diffs" / "CVE-2026-0008__banks" / "abc.diff"
    diff.parent.mkdir(parents=True)
    diff.write_text(
        "diff --git a/src/banks/env.py b/src/banks/env.py\n"
        "--- a/src/banks/env.py\n"
        "+++ b/src/banks/env.py\n"
        "@@ -1,2 +1,2 @@\n"
        "-from jinja2 import Environment\n"
        "+from jinja2.sandbox import SandboxedEnvironment as Environment\n",
        encoding="utf-8",
    )
    row = evidence_row("CVE-2026-0008", "banks", "patch_verified", has_diff=True)
    row["diff_paths"] = [str(diff.relative_to(tmp_path))]

    candidates, coverage, _summary = build_current_candidates([row], {}, tmp_path / "missing", tmp_path)

    assert coverage[0]["has_candidate"] is True
    assert candidates[0]["candidates"]["patch_modified"][0]["qualified_name"] == "src.banks.env.__module__"
