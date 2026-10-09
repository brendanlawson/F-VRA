from __future__ import annotations

import csv
import json
from pathlib import Path, PurePosixPath

import pytest
from openpyxl import Workbook

from f_vra.evaluation.artifacts import ArtifactStore
from f_vra.evaluation.contracts import Decision, PackageID
from f_vra.evaluation.io import read_parquet, write_json, write_parquet
from f_vra.evaluation.metrics import cluster_bootstrap, vf_input_quality
from f_vra.evaluation.oracle import adjudicate_oracle, import_oracle
from f_vra.evaluation.runner import ExperimentRunner
from f_vra.evaluation.environment_probe import _anchor, _hash_files, _root_paths
from f_vra.evaluation import environment as environment_module
from f_vra.evaluation.vf import _patch_candidates


def _package(**changes) -> PackageID:
    values = dict(
        distribution="example", version="1.0", source_hash="source-a", python_abi="cpython-311",
        platform_tag="linux-x86_64", wheel_hash="", backend_version="jarvis-a",
        ast_adapter_version="ast-v1", analysis_config_hash="config-a",
    )
    return PackageID(**(values | changes))


def test_artifact_identity_rejects_changed_context_and_corruption(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    fragment = {"root": "example.entry", "inner_paths": {}, "outer_paths": {}}
    original = _package()
    store.write("global", original.package_id, "example.entry", fragment)
    assert store.read("global", original.package_id, "example.entry")[1] == "HIT"
    for changed in (
        {"source_hash": "source-b"}, {"version": "2.0"}, {"platform_tag": "win-amd64"},
        {"python_abi": "cpython-312"}, {"backend_version": "jarvis-b"},
        {"analysis_config_hash": "config-b"}, {"distribution": "other"},
    ):
        assert store.read("global", _package(**changed).package_id, "example.entry")[1] == "MISS"
    path = store._path("global", store.compatibility_key(original.package_id, "example.entry"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["fragment"]["root"] = "tampered"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert store.read("global", original.package_id, "example.entry")[1] == "CONTENT_HASH_MISMATCH"


def test_oracle_import_resolves_semicolon_package_without_accepting_label(tmp_path: Path) -> None:
    candidate = {
        "project_id": "app", "cve_id": "CVE-1", "candidate_id": "candidate-a",
        "affected_distribution": "jaraco-context", "affected_versions_claimed": ["1.0"],
    }
    query = {"project_id": "app", "cve_id": "CVE-1", "query_id": "query-a", "affected_distribution": "jaraco-context"}
    write_parquet(tmp_path / "query_candidates.parquet", [candidate])
    write_parquet(tmp_path / "queries.parquet", [query])
    book = Workbook()
    sheet = book.active
    sheet.title = "manual_annotation"
    sheet.append(["project", "cve", "package", "version", "manual_label", "manual_reason", "Path(nếu reach)", "annotator"])
    sheet.append(["app", "CVE-1", "jaraco-context; jaraco.context", "1.0", "reachable", "inspected source", "app.main -> jaraco.context.sink", "Reviewer"])
    path = tmp_path / "manual.xlsx"
    book.save(path)
    result = import_oracle(path, tmp_path)
    labels = read_parquet(tmp_path / "oracle_labels.parquet")
    assert result["matched"] == 1
    assert labels[0]["decision"] == Decision.REACHABLE.value
    assert labels[0]["candidate_id"] == "candidate-a"
    assert labels[0]["query_id"] == "query-a"
    assert labels[0]["review_status"] == "pending_review"


def test_oracle_csv_import_uses_manual_label_and_ignores_auto_reachability(tmp_path: Path) -> None:
    candidate = {
        "project_id": "app", "cve_id": "CVE-1", "candidate_id": "candidate-a",
        "affected_distribution": "example", "affected_versions_claimed": ["1.0"],
    }
    query = {"project_id": "app", "cve_id": "CVE-1", "query_id": "query-a"}
    write_parquet(tmp_path / "query_candidates.parquet", [candidate])
    write_parquet(tmp_path / "queries.parquet", [query])
    path = tmp_path / "manual_annotation.csv"
    fields = [
        "project", "cve", "package", "version", "auto_reachability", "manual_label",
        "manual_reason", "Path(nếu reach)", "annotator",
    ]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow({
            "project": "app", "cve": "CVE-1", "package": "example", "version": "1.0",
            "auto_reachability": "reachable", "manual_label": "unreachable",
            "manual_reason": "manual source review found no path", "annotator": "Reviewer",
        })

    result = import_oracle(path, tmp_path)
    labels = read_parquet(tmp_path / "oracle_labels.parquet")

    assert result["matched"] == 1
    assert labels[0]["decision"] == Decision.UNREACHABLE.value
    assert labels[0]["reason"] == "manual source review found no path"


def test_oracle_acceptance_requires_eligibility_reviewer_and_decision_evidence(tmp_path: Path) -> None:
    write_parquet(tmp_path / "oracle_labels.parquet", [{
        "candidate_id": "c1", "query_id": "q1", "decision": "UNREACHABLE",
        "reason": "manual inspection", "witness": "", "annotator": "A",
        "source_workbook_hash": "hash", "review_status": "pending_review",
        "review_reason": "", "reviewer": "", "reviewed_at": "",
    }])
    write_parquet(tmp_path / "query_eligibility.parquet", [{"candidate_id": "c1", "query_eligible": True}])
    decisions = tmp_path / "reviews.jsonl"
    incomplete = {
        "candidate_id": "c1", "review_status": "accepted", "evidence": "source review",
        "reviewer": "Reviewer", "reviewed_at": "2026-09-20T00:00:00Z",
    }
    decisions.write_text(json.dumps(incomplete) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="complete reviewed frontier"):
        adjudicate_oracle(tmp_path, decisions)
    decisions.write_text(json.dumps(incomplete | {"frontier_complete": True}) + "\n", encoding="utf-8")
    result = adjudicate_oracle(tmp_path, decisions)
    assert result == {"updated": 1, "accepted": 1, "rejected": 0}


class FakeAdapter:
    fragment_timeout_s = 300

    def __init__(self) -> None:
        self.builds = 0

    def fragment(self, package, root, env):
        self.builds += 1
        return {
            "root": root, "inner_paths": {"example.sink": [root, "example.sink"]},
            "outer_paths": {}, "functions_analyzed": 2, "unique_functions_analyzed": 2,
            "call_edges_materialized": 1, "wall_clock_ms": 4, "cpu_time_ms": 3,
            "peak_rss_mb": 2, "parse_errors": [], "analyzed_functions": [root, "example.sink"],
        }

    def inventory(self, package, env):
        return ["example.entry"]


def _fixture_dataset(tmp_path: Path) -> Path:
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    write_json(dataset / "dataset.json", {"dataset_id": "fixture"})
    write_parquet(dataset / "projects.parquet", [{"snapshot_id": "p1"}, {"snapshot_id": "p2"}])
    write_parquet(dataset / "environments.parquet", [
        {"env_id": "e1", "docker_image_digest": "image"}, {"env_id": "e2", "docker_image_digest": "image"},
    ])
    write_parquet(dataset / "packages.parquet", [
        {"env_id": "e1", "package_id": "shared-package", "import_roots": ["example"], "source_status": "SOURCE_AVAILABLE"},
        {"env_id": "e2", "package_id": "shared-package", "import_roots": ["example"], "source_status": "SOURCE_AVAILABLE"},
    ])
    write_parquet(dataset / "queries.parquet", [
        {"query_id": "q1", "candidate_id": "c1", "project_id": "app1", "project_snapshot_id": "p1", "env_id": "e1", "cve_id": "CVE-1", "affected_package_id": "shared-package", "affected_distribution": "example", "vf_set": [{"qualified_name": "example.sink"}], "eligibility_reason": "eligible"},
        {"query_id": "q2", "candidate_id": "c2", "project_id": "app2", "project_snapshot_id": "p2", "env_id": "e2", "cve_id": "CVE-1", "affected_package_id": "shared-package", "affected_distribution": "example", "vf_set": [{"qualified_name": "example.sink"}], "eligibility_reason": "eligible"},
    ])
    return dataset


def test_policies_share_only_when_allowed_and_preserve_decisions(tmp_path: Path) -> None:
    dataset = _fixture_dataset(tmp_path)
    runner = ExperimentRunner(dataset, tmp_path)
    fake = FakeAdapter()
    runner.adapter = fake
    runner._project_graph = lambda env: ({"usage_index": ["example.entry"]}, True)
    results = {}
    for strategy in ("fresh", "project_local", "eager_shared", "progressive_shared"):
        before = fake.builds
        summary = runner.run(tmp_path / "runs", strategy=strategy, order="PROJECT_MAJOR")
        results[strategy] = summary
        expected = 1 if strategy in {"eager_shared", "progressive_shared"} else 2
        assert fake.builds - before == expected
        assert summary["verdict_counts"] == {"REACHABLE": 2}
    assert results["eager_shared"]["precomputation_ms"] > 0
    eager_events = read_parquet(tmp_path / "runs" / results["eager_shared"]["run_id"] / "artifact_events.parquet")
    assert any(event.get("precomputation") for event in eager_events)


def test_budget_and_missing_source_cannot_become_unreachable(tmp_path: Path) -> None:
    dataset = _fixture_dataset(tmp_path)
    runner = ExperimentRunner(dataset, tmp_path)
    runner.adapter = FakeAdapter()
    runner._project_graph = lambda env: ({"usage_index": ["example.entry"]}, True)
    budget = runner.run(tmp_path / "runs", strategy="fresh", order="PROJECT_MAJOR", root_budget=0, limit=1)
    assert budget["verdict_counts"] == {"UNKNOWN": 1}
    runner.by_env["e1"]["example"][0]["source_status"] = "NATIVE_ONLY"
    source = runner.run(tmp_path / "runs", strategy="fresh", order="PROJECT_MAJOR", limit=1)
    assert source["verdict_counts"] == {"UNKNOWN": 1}


def test_namespace_collision_expands_every_source_provider(tmp_path: Path) -> None:
    dataset = _fixture_dataset(tmp_path)
    packages = read_parquet(dataset / "packages.parquet")
    packages.append({
        "env_id": "e1", "package_id": "namespace-peer", "import_roots": ["example"],
        "source_status": "SOURCE_AVAILABLE",
    })
    write_parquet(dataset / "packages.parquet", packages)
    runner = ExperimentRunner(dataset, tmp_path)
    fake = FakeAdapter()
    runner.adapter = fake
    runner._project_graph = lambda env: ({"usage_index": ["example.entry"], "frontier_complete": True}, True)
    summary = runner.run(tmp_path / "runs", strategy="fresh", order="PROJECT_MAJOR", limit=1)
    assert summary["verdict_counts"] == {"REACHABLE": 1}
    assert fake.builds == 2


def test_probe_keeps_pep420_namespace_directory(tmp_path: Path) -> None:
    namespace = tmp_path / "shared_ns"
    namespace.mkdir()
    (namespace / "module.py").write_text("def value(): return 1\n", encoding="utf-8")

    class Distribution:
        def locate_file(self, value):
            return tmp_path / str(value)

    assert _root_paths(Distribution(), ["shared_ns"]) == {"shared_ns": str(namespace)}


def test_probe_source_hash_ignores_nondeterministic_native_binary_bytes(tmp_path: Path) -> None:
    files = [
        PurePosixPath("pkg/module.py"), PurePosixPath("pkg/_native.so"),
        PurePosixPath("example-1.0.dist-info/WHEEL"),
    ]
    for name, data in ((files[0], b"def value(): return 1\n"), (files[1], b"native-build-a"), (files[2], b"Tag: cp311-cp311-linux_x86_64\n")):
        path = tmp_path / name.as_posix()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    class Distribution:
        def __init__(self, distribution_files):
            self.files = distribution_files

        def locate_file(self, value):
            return tmp_path / value.as_posix()

        def read_text(self, name):
            return "Name: example\nVersion: 1.0\n" if name == "METADATA" else ""

    distribution = Distribution(files)
    first = _hash_files(distribution)
    (tmp_path / files[1].as_posix()).write_bytes(b"native-build-b-with-new-build-id")
    second = _hash_files(distribution)
    assert first[:3] == second[:3]
    (tmp_path / files[2].as_posix()).write_text(
        "Generator: setuptools (999.0)\nTag: cp311-cp311-linux_x86_64\n", encoding="utf-8",
    )
    assert _hash_files(distribution)[1] == first[1]
    (tmp_path / files[0].as_posix()).write_text("def value(): return 2\n", encoding="utf-8")
    assert _hash_files(distribution)[0] != first[0]


def test_anchor_resolves_repository_prefix_and_unique_class_method(tmp_path: Path) -> None:
    root = tmp_path / "langchain_core"
    root.mkdir()
    (root / "prompts.py").write_text(
        "class Template:\n    def render(self):\n        return 'ok'\n",
        encoding="utf-8",
    )
    package = {"import_root_paths": {"langchain_core": str(root)}}

    bound = _anchor(package, "libs.core.langchain_core.prompts.render")

    assert bound["status"] == "BOUND"
    assert bound["qualified_name"] == "langchain_core.prompts.Template.render"
    assert bound["requested_qualified_name"] == "libs.core.langchain_core.prompts.render"


def test_anchor_keeps_ambiguous_missing_class_as_vf_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "example"
    root.mkdir()
    (root / "module.py").write_text(
        "class One:\n    def run(self):\n        pass\n\nclass Two:\n    def run(self):\n        pass\n",
        encoding="utf-8",
    )
    package = {"import_root_paths": {"example": str(root)}}

    assert _anchor(package, "example.module.run")["status"] == "UNKNOWN_VF_MISMATCH"


def test_manifest_replay_does_not_install_local_project(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.5\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "local-app"\n', encoding="utf-8")
    monkeypatch.setattr(environment_module, "_pinned_base", lambda tag: f"{tag}@sha256:test")
    dockerfile, _, _ = environment_module._dockerfile(
        tmp_path, "3.11", prior_lock={
            "packages": [
                {"name": "requests", "version": "2.32.5"},
                {"name": "local-app", "version": "1.0"},
            ]
        },
    )
    assert "requests==2.32.5" in dockerfile
    assert "local-app==1.0" not in dockerfile
    assert " -e ." not in dockerfile


def test_uv_environment_installs_complete_original_lock_universe(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "example"\n', encoding="utf-8")
    (tmp_path / "uv.lock").write_text('version = 1\n', encoding="utf-8")
    monkeypatch.setattr(environment_module, "_pinned_base", lambda tag: f"{tag}@sha256:test")

    dockerfile, lock_type, _ = environment_module._dockerfile(tmp_path, "3.11")

    assert lock_type == "uv.lock"
    assert "uv sync --frozen --all-groups --all-extras --no-install-project" in dockerfile
    assert "--no-dev" not in dockerfile


def test_uv_environment_does_not_combine_declared_conflicting_extras(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "example"\n[tool.uv.workspace]\nmembers = ["packages/member"]\n',
        encoding="utf-8",
    )
    member = tmp_path / "packages" / "member"
    member.mkdir(parents=True)
    (member / "pyproject.toml").write_text(
        '[project]\nname = "member"\n[tool.uv]\nconflicts = [[{ extra = "cpu" }, { extra = "gpu" }]]\n',
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text('version = 1\n', encoding="utf-8")
    monkeypatch.setattr(environment_module, "_pinned_base", lambda tag: f"{tag}@sha256:test")

    dockerfile, _, _ = environment_module._dockerfile(tmp_path, "3.11")

    assert "uv sync --frozen --no-dev --all-packages --no-install-workspace" in dockerfile
    assert "--all-extras" not in dockerfile


def test_poetry_environment_materializes_original_lock_without_regeneration(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "sparckles__Robyn"
    project.mkdir()
    (project / "pyproject.toml").write_text(
        '[tool.poetry]\nname = "robyn-app"\nversion = "1.0"\n[tool.poetry.extras]\ntemplating = ["jinja2"]\n',
        encoding="utf-8",
    )
    (project / "poetry.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.28.2"\npython-versions = ">=3.8"\n'
        '[[package]]\nname = "colorama"\nversion = "0.4.6"\npython-versions = ">=3.8"\nmarkers = "sys_platform == \'win32\'"\n'
        '[[package]]\nname = "jinja2"\nversion = "3.1.4"\npython-versions = ">=3.8"\nmarkers = "extra == \'templating\'"\n'
        '[metadata]\nlock-version = "2.1"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(environment_module, "_pinned_base", lambda tag: f"{tag}@sha256:test")
    dockerfile, lock_type, _ = environment_module._dockerfile(project, "3.11")
    assert lock_type == "poetry.lock"
    assert "'requests==2.28.2'" in dockerfile
    assert "'jinja2==3.1.4'" in dockerfile
    assert "colorama" not in dockerfile
    assert "poetry lock" not in dockerfile
    assert "poetry install" not in dockerfile


def test_rq1_baselines_use_installed_package_and_project_usage(tmp_path: Path) -> None:
    dataset = _fixture_dataset(tmp_path)
    runner = ExperimentRunner(dataset, tmp_path)
    runner.adapter = FakeAdapter()
    runner._project_graph = lambda env: ({"usage_index": ["example.entry"], "frontier_complete": True}, True)
    exposed = runner.run(tmp_path / "runs", strategy="package_exposure", order="PROJECT_MAJOR")
    usage = runner.run(tmp_path / "runs", strategy="usage_filter", order="PROJECT_MAJOR")
    assert exposed["verdict_counts"] == {"REACHABLE": 2}
    assert usage["verdict_counts"] == {"REACHABLE": 2}
    runner._project_graph = lambda env: ({"usage_index": [], "frontier_complete": True}, True)
    unused = runner.run(tmp_path / "runs", strategy="usage_filter", order="PROJECT_MAJOR", run_label="unused")
    assert unused["verdict_counts"] == {"UNREACHABLE": 2}


def test_runner_excludes_queries_that_failed_eligibility_gate(tmp_path: Path) -> None:
    dataset = _fixture_dataset(tmp_path)
    rows = read_parquet(dataset / "queries.parquet")
    rows.append(rows[0] | {"query_id": "ineligible", "eligibility_reason": "UNKNOWN_VF_MISMATCH"})
    write_parquet(dataset / "queries.parquet", rows)
    runner = ExperimentRunner(dataset, tmp_path)
    assert {row["query_id"] for row in runner.queries} == {"q1", "q2"}
    assert {row["query_id"] for row in runner.all_queries} == {"q1", "q2", "ineligible"}


def test_run_registry_resumes_completed_config(tmp_path: Path) -> None:
    dataset = _fixture_dataset(tmp_path)
    runner = ExperimentRunner(dataset, tmp_path)
    fake = FakeAdapter()
    runner.adapter = fake
    runner._project_graph = lambda env: ({"usage_index": ["example.entry"], "frontier_complete": True}, True)
    first = runner.run(tmp_path / "runs", strategy="fresh", order="PROJECT_MAJOR")
    build_count = fake.builds
    second = runner.run(tmp_path / "runs", strategy="fresh", order="PROJECT_MAJOR")
    assert second["run_id"] == first["run_id"]
    assert second["resumed"] is True
    assert fake.builds == build_count
    registry = read_parquet(tmp_path / "run_registry.parquet")
    assert [row["status"] for row in registry] == ["COMPLETE"]


def test_cluster_bootstrap_is_deterministic_by_project() -> None:
    records = [
        {"project_id": "a", "value": 1.0}, {"project_id": "a", "value": 0.0},
        {"project_id": "b", "value": 1.0}, {"project_id": "c", "value": 0.0},
    ]
    assert cluster_bootstrap(records, "value", iterations=300, seed=23) == cluster_bootstrap(records, "value", iterations=300, seed=23)


def test_patch_vf_candidates_support_dict_and_list_shapes(tmp_path: Path) -> None:
    path = tmp_path / "patch.jsonl"
    path.write_text(
        '\n'.join([
            json.dumps({"cve_id": "CVE-1", "package": "Example", "candidates": {"patch_modified": [{"qualified_name": "example.sink"}]}}),
            json.dumps({"cve_id": "CVE-2", "package": "Other", "candidates": [{"qualified_name": "other.vf"}]}),
        ]) + '\n', encoding="utf-8",
    )
    parsed = _patch_candidates(path)
    assert parsed[("CVE-1", "example")] == ["example.sink"]
    assert parsed[("CVE-2", "other")] == ["other.vf"]


def test_vf_input_precision_and_recall_use_bound_function_identity() -> None:
    expected = {
        "q1": [{"package_id": "p", "qualified_name": "pkg.a", "function_hash": "ha"}],
        "q2": [{"package_id": "p", "qualified_name": "pkg.b", "function_hash": "hb"}],
    }
    observed = {
        "q1": [{"package_id": "p", "qualified_name": "pkg.a", "function_hash": "ha"}],
        "q2": [{"package_id": "p", "qualified_name": "pkg.c", "function_hash": "hc"}],
    }
    metrics = vf_input_quality(expected, observed)
    assert metrics["vf_precision"] == 0.5
    assert metrics["vf_recall"] == 0.5
