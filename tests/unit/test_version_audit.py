from f_vra.version_audit import (
    ResolvedPackage,
    ScannerFinding,
    normalize_package,
    reconcile_findings,
    reconcile_status,
    versions_equal,
)


def finding(
    *,
    package: str = "Django_AllAuth",
    version: str = "1.0.0",
    fixed_versions: str = "2.0.0",
) -> ScannerFinding:
    return ScannerFinding(
        project="owner__repo",
        source="snyk",
        cve_id="CVE-2026-0001",
        package=package,
        package_normalized=normalize_package(package),
        scanner_version=version,
        fixed_versions=fixed_versions,
        severity="high",
        title="title",
        advisory_id="adv",
    )


def resolved(package: str = "django-allauth", version: str = "1.0.0") -> ResolvedPackage:
    return ResolvedPackage(
        project="owner__repo",
        package=package,
        package_normalized=normalize_package(package),
        version=version,
        source_type="requirements.txt",
        source_file="requirements.txt",
        provenance="lockfile_or_manifest",
        priority=40,
    )


def test_normalizes_package_names_and_versions() -> None:
    assert normalize_package("Django_AllAuth") == "django-allauth"
    assert normalize_package("langchain_core") == "langchain-core"
    assert versions_equal("3.10", "3.10.0")


def test_reconcile_consistent_version() -> None:
    status, decision, _reason = reconcile_status(finding(), resolved(), True)

    assert status == "consistent"
    assert decision == "valid_for_annotation"


def test_reconcile_scanner_version_missing_uses_env_version() -> None:
    status, decision, _reason = reconcile_status(finding(version=""), resolved(), True)

    assert status == "scanner_version_missing_but_env_affected"
    assert decision == "valid_for_annotation"


def test_reconcile_mismatch_fixed_version_is_not_applicable() -> None:
    status, decision, _reason = reconcile_status(
        finding(version="1.0.0", fixed_versions="2.0.0"),
        resolved(version="2.1.0"),
        True,
    )

    assert status == "mismatch_not_applicable"
    assert decision == "exclude_version_not_applicable"


def test_reconcile_mismatch_without_fixed_exclusion_stays_valid() -> None:
    status, decision, _reason = reconcile_status(
        finding(version="1.0.0", fixed_versions=""),
        resolved(version="1.1.0"),
        True,
    )

    assert status == "mismatch_but_env_affected"
    assert decision == "valid_for_annotation"


def test_reconcile_scanner_only_and_unresolved_project() -> None:
    status, decision, _reason = reconcile_status(finding(), None, True)
    assert status == "scanner_only_manifest"
    assert decision == "exclude_scanner_only_manifest"

    status, decision, _reason = reconcile_status(finding(), None, False)
    assert status == "unresolved_environment"
    assert decision == "exclude_unresolved_environment"


def test_reconcile_findings_does_not_override_env_version() -> None:
    rows = reconcile_findings(
        [finding(package="Django_AllAuth", version="1.0.0", fixed_versions="")],
        [resolved(package="django-allauth", version="1.1.0")],
        [{"project": "owner__repo", "environment_status": "resolved_from_lockfile_or_manifest"}],
    )

    assert rows[0]["scanner_version"] == "1.0.0"
    assert rows[0]["resolved_version"] == "1.1.0"
    assert rows[0]["version_status"] == "mismatch_but_env_affected"
