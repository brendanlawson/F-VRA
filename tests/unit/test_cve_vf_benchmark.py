from pathlib import Path

from f_vra.cve_vf.benchmark import (
    AnnotationRecord,
    ScanOccurrence,
    audit_reason,
    build_benchmark,
    load_annotations,
    normalize_package_name,
    target_vfs,
)


def make_annotation(
    *,
    group_id: str = "CVE-2026-0001::Django_AllAuth",
    confidence: str = "high",
    evidence_level: str = "patch_verified",
    mapping_type: str = "single_vf",
    vf_qualified_name: str | None = "pkg.module.vulnerable",
    vf_not_in_candidates: bool = False,
    per_candidate: list[dict] | None = None,
) -> AnnotationRecord:
    raw = {
        "group_id": group_id,
        "confidence": confidence,
        "evidence_level": evidence_level,
        "mapping_type": mapping_type,
        "vf_qualified_name": vf_qualified_name,
        "vf_not_in_candidates": vf_not_in_candidates,
        "summary": "summary",
        "per_candidate": per_candidate
        if per_candidate is not None
        else [
            {
                "qualified_name": "pkg.module.vulnerable",
                "label": "root_cause_vf",
                "reasoning": "patched vulnerable behavior",
            }
        ],
    }
    return AnnotationRecord(
        source_path="annotations.jsonl",
        source_tier="tier1",
        raw=raw,
        cve_id=group_id.split("::", 1)[0],
        package=group_id.split("::", 1)[1],
        package_normalized=normalize_package_name(group_id.split("::", 1)[1]),
    )


def make_occurrence(package: str = "django-allauth") -> ScanOccurrence:
    return ScanOccurrence(
        project="owner__repo",
        repo_full_name="owner/repo",
        cve_id="CVE-2026-0001",
        package=package,
        package_normalized=normalize_package_name(package),
        sources=["pip-audit", "osv-scanner"],
        affected_package_versions=[f"{package}==1.0.0"],
    )


def test_load_annotations_parses_group_id_and_targets(tmp_path: Path) -> None:
    path = tmp_path / "vf_annotations_tier1.jsonl"
    path.write_text(
        '{"group_id":"CVE-2026-0001::langchain_core",'
        '"confidence":"high","evidence_level":"patch_verified",'
        '"mapping_type":"multiple_independent_vfs",'
        '"vf_qualified_name":"pkg.a",'
        '"vf_not_in_candidates":false,'
        '"per_candidate":['
        '{"qualified_name":"pkg.a","label":"root_cause_vf","reasoning":"a"},'
        '{"qualified_name":"pkg.b","label":"vulnerable_usage_site","reasoning":"b"},'
        '{"qualified_name":"pkg.c","label":"discard","reasoning":"c"}]}\n',
        encoding="utf-8",
    )

    records = load_annotations([path])

    assert len(records) == 1
    assert records[0].cve_id == "CVE-2026-0001"
    assert records[0].package_normalized == "langchain-core"
    assert [target["qualified_name"] for target in target_vfs(records[0])] == ["pkg.a", "pkg.b"]
    assert target_vfs(records[0])[0]["is_primary"] is True


def test_build_benchmark_accepts_strict_cve_package_match() -> None:
    annotation = make_annotation()
    benchmark, audit, coverage, summary = build_benchmark([annotation], [make_occurrence()])

    assert len(benchmark) == 1
    assert benchmark[0]["benchmark_id"] == "owner__repo::CVE-2026-0001::django-allauth"
    assert benchmark[0]["target_vfs"]
    assert audit[0]["audit_reason"] == "accepted"
    assert coverage[0]["benchmark_status"] == "accepted"
    assert summary["accepted_records"] == 1


def test_build_benchmark_rejects_cve_only_package_mismatch() -> None:
    annotation = make_annotation(group_id="CVE-2026-0001::urllib3")
    benchmark, audit, coverage, _summary = build_benchmark([annotation], [make_occurrence("idna")])

    assert benchmark == []
    assert audit[0]["audit_reason"] == "reject_package_mismatch"
    assert audit[0]["scanned_packages_for_cve"] == ["idna"]
    assert coverage[0]["annotation_status"] == "unannotated"


def test_audit_gate_rejects_expected_cases() -> None:
    assert audit_reason(make_annotation(evidence_level="poc_verified")) == "accepted"
    assert audit_reason(make_annotation(evidence_level="weak_or_uncertain")) == "reject_weak_evidence"
    assert audit_reason(make_annotation(confidence="low")) == "reject_weak_evidence"
    assert audit_reason(make_annotation(vf_not_in_candidates=True)) == "reject_vf_missing"
    assert audit_reason(make_annotation(mapping_type="ambiguous")) == "reject_ambiguous"
    assert audit_reason(make_annotation(mapping_type="patch_variant_duplicate")) == "review_duplicate"
    assert (
        audit_reason(
            make_annotation(
                vf_qualified_name=None,
                per_candidate=[{"qualified_name": "pkg.x", "label": "discard", "reasoning": ""}],
            )
        )
        == "reject_no_vf"
    )
