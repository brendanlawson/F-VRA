from __future__ import annotations

import json
import io
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from f_vra.evaluation import rq3
from f_vra.evaluation.rq3 import (
    RQ3CaseInput,
    RQ3LocalizationResult,
    audit_rq3_benchmark,
    bind_localized_names,
    build_rq3_vf_variants,
    downstream_consequence,
    error_propagation,
    exact_group_join,
    freeze_rq3_benchmark,
    localization_quality,
    localize_case,
    materialize_git_patch,
    materialize_release_patch,
    materialize_git_snapshot,
    pair_rq3_downstream_runs,
    parse_case,
    run_localization_batch,
)
from f_vra.localization.ranking.methods.description import DescriptionEnrichment
from f_vra.evaluation.io import read_parquet, write_json, write_parquet
from f_vra.cli.main import app

FIXTURE = Path(__file__).parents[1] / "fixtures" / "sample_app"


def _case(**changes) -> RQ3CaseInput:
    values = dict(
        case_id="case-1", cve_vf_group_id="CVE-1::sample", cve_id="CVE-1",
        package="sample", repo_url="https://example.invalid/sample", vulnerable_ref="deadbeef",
        description="request fetch URL without timeout", source_path=FIXTURE,
        cwe_ids=(), cwe_text="", patch_available=False, patch_text="", patch_sha="", snapshot_id="snap-a",
    )
    values.update(changes)
    return RQ3CaseInput(**values)


def _evaluation_case(case: RQ3CaseInput, gold: list[dict | str], *, eligible: bool = True):
    return rq3.RQ3EvaluationCase(case, tuple(gold), eligible)


def _write_cases(path: Path, count: int = 3) -> None:
    rows = []
    for index in range(count):
        rows.append({
            "case_id": f"case-{index}", "cve_vf_group_id": f"CVE-{index}::sample",
            "cve_id": f"CVE-{index}", "package": "sample", "repo_url": "local",
            "vulnerable_ref": "fixture", "description": "request fetch without timeout",
            "source_path": str(FIXTURE), "verified_vfs": ["Client.fetch"],
        })
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_tvsm_known_lexical_ranking_is_deterministic():
    from f_vra.localization.code.function_parser import parse_repository
    from f_vra.localization.retrieval.tvsm import rank_tvsm

    functions = parse_repository(FIXTURE)
    ranked = rank_tvsm("requests get url timeout fetch", functions)
    assert ranked[0][0].qualname == "Client.fetch"
    assert [item.identity for item, _ in ranked] == [item.identity for item, _ in rank_tvsm("requests get url timeout fetch", functions)]


def test_module_qualified_name_strips_nested_src_root(tmp_path: Path):
    from f_vra.localization.code.function_parser import extract_functions_from_file

    source = tmp_path / "sagemaker-serve" / "src" / "sagemaker" / "serve" / "builder.py"
    source.parent.mkdir(parents=True)
    source.write_text("class Builder:\n    def sign(self):\n        return True\n", encoding="utf-8")
    function = extract_functions_from_file(source, tmp_path)[0]
    assert rq3._module_qualified_name(function) == "sagemaker.serve.builder.Builder.sign"


def test_inventory_cache_reuses_immutable_snapshot_identity_without_rehashing(tmp_path: Path, monkeypatch):
    first = rq3.load_inventory(FIXTURE, tmp_path / "inventory", source_identity="snapshot-immutable")
    monkeypatch.setattr(rq3, "source_tree_hash", lambda root: (_ for _ in ()).throw(AssertionError("rehash")))
    second = rq3.load_inventory(FIXTURE, tmp_path / "inventory", source_identity="snapshot-immutable")
    assert first[1:] == second[1:]
    assert [item.identity for item in first[0]] == [item.identity for item in second[0]]


def test_embedding_cache_reuses_exact_function_vectors_and_resume_query(tmp_path: Path):
    from f_vra.localization.code.function_parser import parse_repository
    from f_vra.localization.retrieval.embedding import embedding_scores

    class StubBackend:
        model_name = "rq3-cache-test"

        def __init__(self):
            self.calls = []

        def embed(self, texts):
            self.calls.append(list(texts))
            return [[float(len(text) + 1), float(sum(map(ord, text)) % 97 + 1)] for text in texts]

    functions = parse_repository(FIXTURE)
    cache = tmp_path / "embeddings.sqlite"
    first_backend = StubBackend()
    first_scores, _ = embedding_scores("query one", functions, backend=first_backend, cache_path=cache)
    assert sum(map(len, first_backend.calls)) == len(functions) + 1

    second_backend = StubBackend()
    second_scores, _ = embedding_scores("query two", functions, backend=second_backend, cache_path=cache)
    assert sum(map(len, second_backend.calls)) == 1

    resumed_backend = StubBackend()
    resumed_scores, _ = embedding_scores("query two", functions, backend=resumed_backend, cache_path=cache)
    assert resumed_backend.calls == []
    assert second_scores == resumed_scores
    assert first_scores and cache.is_file()


def test_embedding_workers_are_bounded_ordered_and_usage_is_recorded(monkeypatch):
    import threading
    import time

    from f_vra.core.config import settings
    from f_vra.localization.code.function_parser import parse_repository
    from f_vra.localization.providers.llm_client import record_embedding_usage, track_provider_usage
    from f_vra.localization.retrieval.embedding import embedding_scores

    class InstrumentedBackend:
        model_name = "rq3-parallel-test"

        def __init__(self):
            self.lock = threading.Lock()
            self.active = 0
            self.peak = 0

        def embed(self, texts):
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
            try:
                record_embedding_usage({"usage": {"input_tokens": len(texts), "total_tokens": len(texts)}})
                time.sleep(0.02)
                return [[float(len(text) + 1), float(sum(map(ord, text)) % 97 + 1)] for text in texts]
            finally:
                with self.lock:
                    self.active -= 1

    monkeypatch.setattr(settings, "embedding_batch_size", 1)
    monkeypatch.setattr(settings, "embedding_max_workers", 2)
    functions = parse_repository(FIXTURE)[:3]
    parallel_backend = InstrumentedBackend()
    with track_provider_usage() as usage:
        parallel_scores, _ = embedding_scores("parallel query", functions, backend=parallel_backend)

    assert parallel_backend.peak == 2
    assert usage.to_dict()["embedding_calls"] == len(functions) + 1
    assert usage.to_dict()["embedding_input_tokens"] == len(functions) + 1

    monkeypatch.setattr(settings, "embedding_max_workers", 1)
    sequential_scores, _ = embedding_scores("parallel query", functions, backend=InstrumentedBackend())
    assert parallel_scores == sequential_scores


def test_parallel_embedding_failure_keeps_completed_cache_rows_for_retry(tmp_path: Path, monkeypatch):
    import sqlite3
    import threading
    import time

    from f_vra.core.config import settings
    from f_vra.localization.code.function_parser import parse_repository
    from f_vra.localization.retrieval.embedding import embedding_scores

    class FailingBackend:
        model_name = "rq3-parallel-failure-test"

        def __init__(self, *, fail):
            self.fail = fail
            self.calls = []
            self.lock = threading.Lock()

        def embed(self, texts):
            with self.lock:
                self.calls.append(list(texts))
            if self.fail and "failure query" in texts[0]:
                raise RuntimeError("simulated provider failure")
            time.sleep(0.02)
            return [[float(len(text) + 1), 1.0] for text in texts]

    monkeypatch.setattr(settings, "embedding_batch_size", 1)
    monkeypatch.setattr(settings, "embedding_max_workers", 2)
    functions = parse_repository(FIXTURE)[:2]
    cache = tmp_path / "parallel.sqlite"
    with pytest.raises(RuntimeError, match="simulated provider failure"):
        embedding_scores("failure query", functions, backend=FailingBackend(fail=True), cache_path=cache)

    with sqlite3.connect(cache) as connection:
        cached_count = connection.execute("SELECT COUNT(*) FROM embedding_vectors").fetchone()[0]
    assert cached_count == 1

    retry_backend = FailingBackend(fail=False)
    scores, _ = embedding_scores("failure query", functions, backend=retry_backend, cache_path=cache)
    assert sum(map(len, retry_backend.calls)) == len(functions)
    assert scores


def test_d_lex_uses_report_and_ignores_patch_and_cwe_evidence(monkeypatch):
    captured_reports = []

    def rank_tvsm(report, functions):
        captured_reports.append(report)
        return [(item, float(len(functions) - index)) for index, item in enumerate(functions)]

    monkeypatch.setattr("f_vra.localization.retrieval.tvsm.rank_tvsm", rank_tvsm)
    with_patch = _case(patch_available=True, patch_text="ignored patch", cwe_ids=("CWE-918",))
    without = _case()
    left = localize_case(with_patch, "D_LEX")
    right = localize_case(without, "D_LEX")
    assert captured_reports == [with_patch.description, without.description]
    assert [item["function_id"] for item in left.predictions] == [item["function_id"] for item in right.predictions]
    fetch = next(item for item in left.predictions if item["qualified_name"] == "Client.fetch")
    assert fetch["module_qualified_name"] == "pkg.lib.Client.fetch"
    assert "no patch/CWE/LLM/embedding" in left.method_label


def test_d_sem_extracts_attack_and_root_cause_and_uses_call_context(monkeypatch):
    captured = {}

    def extract(description):
        captured["extractor_input"] = description
        return DescriptionEnrichment(
            text=description, status="used", model="stub-extractor",
            entities={"attack_vector": "remote request", "root_cause": "missing timeout"},
        )

    monkeypatch.setattr(
        "f_vra.localization.ranking.methods.description.enrich_description_with_llm_entities",
        extract,
    )

    def scores(query, functions):
        captured["query"] = query
        captured["functions"] = functions
        return ({item.identity: (1.0 if item.qualname == "Client.fetch" else 0.0) for item in functions}, "stub-embed")

    monkeypatch.setattr(rq3, "_strict_semantic_scores", scores)
    case = _case()
    result = localize_case(case, "D_SEM")
    fetch = next(item for item in captured["functions"] if item.qualname == "Client.fetch")
    assert result.predictions[0]["qualified_name"] == "Client.fetch"
    assert captured["extractor_input"] == case.description
    assert captured["query"] == f"{case.description}\nremote request\nmissing timeout"
    assert result.metadata["retrieval_query"] == captured["query"]
    assert result.metadata["retrieval_query_components"] == {
        "description": case.description,
        "attack_vector": "remote request",
        "root_cause": "missing timeout",
    }
    assert "local callers: public_api" in fetch.source
    assert result.metadata["retrieval_model"] == "stub-embed"


def test_p_modified_returns_unordered_direct_patch_set_without_ranks():
    patch_text = (FIXTURE / "fix.patch").read_text(encoding="utf-8")
    result = localize_case(_case(patch_available=True, patch_text=patch_text), "P_MODIFIED")
    assert result.output_type == "set"
    assert "pkg/lib.py:Client.fetch" in result.candidate_ids
    assert result.predictions
    assert all(item["rank"] is None and item["score"] is None for item in result.predictions)


def test_p_modified_maps_insertion_only_hunk_to_containing_vulnerable_function():
    patch_text = """diff --git a/pkg/lib.py b/pkg/lib.py
--- a/pkg/lib.py
+++ b/pkg/lib.py
@@ -5,2 +5,3 @@
 def fetch(url):
+    timeout = 5
     return requests.get(url)
"""
    result = localize_case(_case(patch_available=True, patch_text=patch_text), "P_MODIFIED")
    assert "Client.fetch" in {item["qualified_name"] for item in result.predictions}
    assert result.output_type == "set"
    assert all(item["rank"] is None and item["score"] is None for item in result.predictions)
    assert result.metadata == {}


def test_p_modified_maps_python2_source_with_a_patch_hunk(tmp_path: Path):
    (tmp_path / "legacy.py").write_text(
        "class Legacy:\n    def vulnerable(self, value):\n        raise ValueError, value\n",
        encoding="utf-8",
    )
    patch = """diff --git a/legacy.py b/legacy.py
--- a/legacy.py
+++ b/legacy.py
@@ -1,3 +1,3 @@
 class Legacy:
     def vulnerable(self, value):
-        raise ValueError, value
+        raise ValueError(value)
"""
    result = localize_case(_case(source_path=tmp_path, patch_available=True, patch_text=patch), "P_MODIFIED")
    assert result.candidate_count == 1
    assert result.predictions[0]["qualified_name"] == "Legacy.vulnerable"


def test_p_dual_present_and_absent_have_separate_evidence_paths(monkeypatch):
    observed = {"embedding_queries": [], "pairwise_queries": []}

    def embedding(query, functions):
        observed["embedding_queries"].append(query)
        return ({item.identity: 1.0 if item.qualname == "Client.fetch" else 0.1 for item in functions}, "stub-embed")

    def pairwise(query, candidates, scores, evidence):
        observed["pairwise_queries"].append(query)
        ordered = sorted(candidates, key=lambda item: (item.qualname != "Client.fetch", item.identity))
        return ({item.identity: float(len(ordered) - index) for index, item in enumerate(ordered)}, {"used": True, "model": "stub-llm"})

    monkeypatch.setattr(rq3, "_strict_semantic_scores", embedding)
    monkeypatch.setattr(rq3, "_strict_pairwise", pairwise)
    patch_text = (FIXTURE / "fix.patch").read_text(encoding="utf-8")
    case_fields = {
        "description": "raw vulnerability report",
        "cwe_ids": ("CWE-20",),
        "cwe_text": "CWE explanatory text",
    }
    present = localize_case(_case(**case_fields, patch_available=True, patch_text=patch_text), "P_DUAL")
    absent = localize_case(_case(**case_fields, patch_available=False, patch_text=""), "P_DUAL")
    expected_query = "raw vulnerability report\nCWE: CWE explanatory text"
    assert observed["embedding_queries"] == [expected_query, expected_query]
    assert observed["pairwise_queries"] == [expected_query, expected_query]
    assert present.runtime_mode == "PATCH_PRESENT"
    assert present.metadata["tracker_adapter"].startswith("Python static")
    assert "pkg/lib.py:Client.fetch" in present.candidate_ids
    assert absent.runtime_mode == "PATCH_ABSENT"
    assert "tracker_adapter" not in absent.metadata
    assert "no CodeBERT checkpoint" in absent.metadata["candidate_model"]
    assert absent.predictions[0]["qualified_name"] == "Client.fetch"


def test_dual_fails_explicitly_instead_of_silent_pairwise_fallback(monkeypatch):
    monkeypatch.setattr(rq3, "_strict_semantic_scores", lambda query, functions: ({item.identity: 1.0 for item in functions}, "stub"))
    monkeypatch.setattr(rq3, "_strict_pairwise", lambda *args: (_ for _ in ()).throw(RuntimeError("provider offline")))
    with pytest.raises(RuntimeError, match="provider offline"):
        localize_case(_case(), "P_DUAL")


def test_missing_cwe_uses_description_only_and_multi_vf_recall():
    from f_vra.evaluation.rq3 import _expanded_query

    case = _case(description="unsafe fetch", cwe_ids=(), cwe_text="")
    assert _expanded_query(case) == "unsafe fetch"
    evaluation = _evaluation_case(case, ["Client.fetch", "public_api"])
    ranked = [{
        "case_id": "case-1", "config_id": "D_LEX", "status": "complete", "output_type": "ranked",
        "candidate_ids": ["a", "b", "c"],
        "candidate_details": [
            {"function_id": "a", "qualified_name": "Client.fetch", "file_path": "pkg/lib.py"},
            {"function_id": "b", "qualified_name": "public_api", "file_path": "pkg/lib.py"},
            {"function_id": "c", "qualified_name": "main", "file_path": "pkg/app.py"},
        ],
        "candidate_count": 3,
        "predictions": [
            {"function_id": "a", "qualified_name": "Client.fetch", "file_path": "pkg/lib.py", "rank": 1},
            {"function_id": "b", "qualified_name": "public_api", "file_path": "pkg/lib.py", "rank": 2},
            {"function_id": "c", "qualified_name": "main", "file_path": "pkg/app.py", "rank": 3},
        ],
    }]
    quality = localization_quality([evaluation], ranked)[0]
    assert quality["Recall@5"] == 1.0
    assert quality["Hit@1"] == 1.0
    assert quality["MRR"] == 1.0
    assert quality["CandidateRecall"] == 1.0
    two_configs = localization_quality([evaluation], ranked + [ranked[0] | {"config_id": "D_SEM"}])
    assert {row["config"] for row in two_configs} == {"D_LEX", "D_SEM"}
    dual_modes = localization_quality([evaluation], [
        ranked[0] | {"config_id": "P_DUAL", "runtime_mode": "PATCH_PRESENT"},
        ranked[0] | {"config_id": "P_DUAL", "runtime_mode": "PATCH_ABSENT"},
    ])
    assert {row["config"] for row in dual_modes} == {"P_DUAL/PATCH_PRESENT", "P_DUAL/PATCH_ABSENT"}


def test_metrics_match_short_and_module_qualified_function_names():
    evaluation = _evaluation_case(
        _case(),
        [{"qualified_name": "sample_app.pkg.Client.fetch", "file_path": "pkg/lib.py"}],
    )
    row = {
        "case_id": "case-1", "config_id": "D_LEX", "status": "complete", "output_type": "ranked",
        "candidate_count": 1,
        "candidate_details": [{"qualified_name": "Client.fetch", "module_qualified_name": "sample_app.pkg.Client.fetch", "file_path": "pkg/lib.py"}],
        "predictions": [{"qualified_name": "Client.fetch", "module_qualified_name": "sample_app.pkg.Client.fetch",
                         "file_path": "pkg/lib.py", "rank": 1}],
    }
    quality = localization_quality([evaluation], [row])[0]
    assert quality["Hit@1"] == 1.0
    assert quality["MRR"] == 1.0
    assert quality["CandidateRecall"] == 1.0


def test_set_output_has_set_recall_but_no_ranking_metrics():
    case = _evaluation_case(_case(patch_available=True, patch_text="patch diff"), ["Client.fetch", "public_api"])
    row = {
        "case_id": "case-1", "config_id": "P_MODIFIED", "status": "complete", "output_type": "set",
        "candidate_ids": ["pkg/lib.py:Client.fetch"], "candidate_count": 1,
        "candidate_details": [{"function_id": "pkg/lib.py:Client.fetch", "qualified_name": "Client.fetch", "file_path": "pkg/lib.py"}],
        "predictions": [{"function_id": "pkg/lib.py:Client.fetch", "qualified_name": "Client.fetch", "file_path": "pkg/lib.py", "rank": None, "score": None}],
    }
    quality = localization_quality([case], [row])[0]
    assert quality["SetRecall"] == 0.5
    assert quality["Hit@1"] is None and quality["MRR"] is None


def test_downstream_exact_join_does_not_fuzzy_match():
    cases = [{"group_id": "CVE-1::pkg"}]
    rows = [{"cve_vf_group_id": "CVE-1::pkg"}, {"cve_vf_group_id": "CVE-1::pkg-extra"}]
    joined, unmatched = exact_group_join(cases, rows)
    assert len(joined) == 1 and len(unmatched) == 1
    assert unmatched[0]["cve_vf_group_id"] == "CVE-1::pkg-extra"


def test_binding_failures_are_retained_in_audit():
    prediction = {"qualified_name": "Client.fetch", "file_path": "pkg/lib.py", "start_line": 5, "end_line": 7}
    anchors, audit = bind_localized_names("package-a", {"config_id": "D_LEX", "predictions": [prediction]}, {})
    assert anchors == []
    assert audit == [{"qualified_name": "Client.fetch", "source_qualified_name": "Client.fetch", "status": "UNKNOWN_VF_MISMATCH"}]


def test_downstream_three_valued_metrics_exclude_unknown_from_binary_rates():
    records = [
        {"oracle_decision": "REACHABLE", "decision": "REACHABLE"},
        {"oracle_decision": "REACHABLE", "decision": "UNREACHABLE"},
        {"oracle_decision": "UNREACHABLE", "decision": "REACHABLE"},
        {"oracle_decision": "UNREACHABLE", "decision": "UNKNOWN"},
    ]
    metrics = downstream_consequence(records)
    assert metrics["compared"] == 4 and metrics["decisive"] == 3
    assert metrics["coverage"] == 0.75
    assert metrics["downstream_precision"] == 0.5
    assert metrics["downstream_recall"] == 0.5
    assert metrics["flip_rate"] == 2 / 3
    assert error_propagation(records) == {"decision_invariant": 1, "FP_flip": 1, "FN_flip": 1, "UNKNOWN": 1}


def test_rq3_audit_accepts_existing_evidence_rules_and_unique_fix_parent(tmp_path: Path):
    benchmark = tmp_path / "benchmark.jsonl"
    downstream = tmp_path / "downstream.jsonl"
    rows = [
        {"group_id": "CVE-1::pkg", "ground_truth_evidence": "patch_verified", "mapping_type": "multiple_independent_vfs",
         "vulnerable_ref": "", "patches": [{"role": "canonical_fix", "parent_sha": "parent-a"}]},
        {"group_id": "CVE-2::pkg", "ground_truth_evidence": "patch_verified", "mapping_type": "patch_variant_duplicate",
         "vulnerable_ref": "ref", "patches": []},
    ]
    benchmark.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    downstream.write_text(json.dumps({"cve_vf_group_id": "CVE-1::pkg"}) + "\n", encoding="utf-8")
    audit = audit_rq3_benchmark(benchmark, downstream)
    assert audit["accepted_rows"] == 1
    assert audit["missing_ref_resolution"][0]["unique_canonical_parent"] == "parent-a"
    assert audit["downstream_rows_matched_exact_group"] == 1


def test_freeze_writes_exact_source_patch_cwe_text_and_gold_separately(tmp_path: Path, monkeypatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "RQ3 Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "rq3@example.invalid"], check=True)
    source = repo / "source.py"
    source.write_text("def vulnerable():\n    return 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "source.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "vulnerable"], check=True, capture_output=True)
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    benchmark = tmp_path / "benchmark.jsonl"
    output = tmp_path / "frozen.jsonl"
    cache_file = output.with_name("frozen.metadata_cache.json")
    cache_file.write_text(json.dumps({"CVE-1": {"cwe_ids": ["CWE-918"], "source": "NVD"}}), encoding="utf-8")
    monkeypatch.setattr(rq3, "_fetch_cwe_description", lambda cwe_id: {
        "text": "Server-side request forgery; untrusted URL validation", "status": "resolved", "source": "MITRE_CWE_REST/weakness",
    })
    patch_cache = tmp_path / "patches"
    patch_cache.mkdir()
    fix_sha = "fix-commit-id"
    repo_key = rq3._sha256(str(repo).encode("utf-8"))[:24]
    (patch_cache / f"{repo_key}_{fix_sha}_{commit}.patch").write_text(
        "diff --git a/source.py b/source.py\n--- a/source.py\n+++ b/source.py\n@@ -1,2 +1,2 @@\n def vulnerable():\n-    return 1\n+    return 2\n",
        encoding="utf-8",
    )
    row = {
        "group_id": "CVE-1::sample", "advisory_id": "CVE-1", "package_name": "sample",
        "description": "unsafe value", "repo_url": str(repo), "vulnerable_ref": commit,
        "patches": [{"role": "canonical_fix", "sha": fix_sha, "parent_sha": commit}],
        "root_cause_functions": [{"qualified_name": "vulnerable", "file_path": "source.py"}],
        "mapping_type": "multiple_independent_vfs", "ground_truth_evidence": "patch_verified",
    }
    benchmark.write_text(json.dumps(row) + "\n", encoding="utf-8")
    snapshot_map = tmp_path / "snapshots.json"
    snapshot_map.write_text(json.dumps({"CVE-1::sample": {
        "path": str(repo), "repo_url": str(repo), "commit_sha": commit,
    }}), encoding="utf-8")
    summary = freeze_rq3_benchmark(
        benchmark, output, snapshot_map=snapshot_map, patch_cache=patch_cache,
        resolve_cwe=True,
    )
    frozen = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert summary["full_batch_ready"] is True
    assert frozen["eligible"] is True and frozen["patch_available"] is True
    assert frozen["cwe_ids"] == ["CWE-918"]
    assert "Server-side request forgery" in frozen["cwe_text"]
    assert summary["cwe_text_resolution_complete"] is True
    assert not hasattr(parse_case(frozen).localizer_input, "verified_vfs")


def test_materialize_merge_patch_uses_verified_explicit_first_parent(tmp_path: Path):
    repo = tmp_path / "merge-repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "RQ3 Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "rq3@example.invalid"], check=True)
    (repo / "vulnerable.py").write_text("def vulnerable():\n    return 'old'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "vulnerable.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "vulnerable"], check=True, capture_output=True)
    vulnerable = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    subprocess.run(["git", "-C", str(repo), "switch", "-c", "fix-branch"], check=True, capture_output=True)
    (repo / "vulnerable.py").write_text("def vulnerable():\n    return 'fixed'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "vulnerable.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "fix"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "switch", "-",], check=True, capture_output=True)
    (repo / "unrelated.txt").write_text("mainline\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "unrelated.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "unrelated"], check=True, capture_output=True)
    first_parent = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", str(repo), "merge", "--no-ff", "fix-branch", "-m", "merge fix"],
        check=True, capture_output=True,
    )
    merge = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()

    patch_path = materialize_git_patch(str(repo), merge, tmp_path / "cache", first_parent)
    patch = patch_path.read_text(encoding="utf-8")
    assert "vulnerable.py" in patch
    assert "-    return 'old'" in patch and "+    return 'fixed'" in patch
    assert first_parent in patch_path.name
    with pytest.raises(rq3.PatchBaseMismatchError, match="not a direct parent"):
        materialize_git_patch(str(repo), merge, tmp_path / "cache", vulnerable)


def test_freeze_canonicalizes_abbreviated_source_fix_and_parent_refs(tmp_path: Path):
    repo = tmp_path / "abbreviated-ref-repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "RQ3 Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "rq3@example.invalid"], check=True)
    source = repo / "source.py"
    source.write_text("def vulnerable():\n    return 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "source.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "vulnerable"], check=True, capture_output=True)
    vulnerable = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    source.write_text("def vulnerable():\n    return 2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "source.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "fix"], check=True, capture_output=True)
    fix = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()

    benchmark = tmp_path / "benchmark.jsonl"
    output = tmp_path / "frozen.jsonl"
    output.with_name("frozen.metadata_cache.json").write_text(
        json.dumps({"CVE-REF": {"cwe_ids": [], "source": "NVD"}}), encoding="utf-8",
    )
    benchmark.write_text(json.dumps({
        "group_id": "CVE-REF::sample", "advisory_id": "CVE-REF", "package_name": "sample",
        "description": "unsafe return", "repo_url": str(repo), "vulnerable_ref": vulnerable[:9],
        "patches": [{"role": "canonical_fix", "sha": fix[:11], "parent_sha": f"{fix}^"}],
        "root_cause_functions": [{"qualified_name": "vulnerable", "file_path": "source.py"}],
        "mapping_type": "multiple_independent_vfs", "ground_truth_evidence": "patch_verified",
    }) + "\n", encoding="utf-8")

    summary = freeze_rq3_benchmark(
        benchmark, output, resolve_cwe=True, materialize_sources=True, materialize_patches=True,
        snapshot_cache=tmp_path / "cache", snapshot_root=tmp_path / "snapshots",
    )
    frozen = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert summary["full_batch_ready"] is True
    assert frozen["vulnerable_ref"] == vulnerable
    assert frozen["source_ref_original"] == vulnerable[:9]
    assert frozen["patch_sha"] == fix
    assert frozen["patch_sha_original"] == fix[:11]
    assert frozen["patch_base_sha"] == vulnerable
    assert frozen["patch_available"] is True


def test_freeze_reuses_only_exact_artifacts_across_benchmark_revisions(tmp_path: Path):
    repo = tmp_path / "cross-benchmark-reuse-repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "RQ3 Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "rq3@example.invalid"], check=True)
    source = repo / "source.py"
    source.write_text("def vulnerable():\n    return 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "source.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "vulnerable"], check=True, capture_output=True)
    vulnerable = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    source.write_text("def vulnerable():\n    return 2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "source.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "fix"], check=True, capture_output=True)
    fix = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()
    base_row = {
        "group_id": "CVE-REUSE::sample", "advisory_id": "CVE-REUSE", "package_name": "sample",
        "description": "old description", "repo_url": str(repo), "vulnerable_ref": vulnerable,
        "patches": [{"role": "canonical_fix", "sha": fix, "parent_sha": vulnerable}],
        "root_cause_functions": [{"qualified_name": "vulnerable_old", "file_path": "source.py"}],
        "mapping_type": "single_vf", "ground_truth_evidence": "patch_verified",
    }
    old_benchmark = tmp_path / "benchmark-v3.jsonl"
    old_benchmark.write_text(json.dumps(base_row) + "\n", encoding="utf-8")
    old_manifest = tmp_path / "prepared-v3.jsonl"
    freeze_rq3_benchmark(
        old_benchmark, old_manifest, resolve_cwe=False,
        materialize_sources=True, materialize_patches=True,
        snapshot_cache=tmp_path / "cache", snapshot_root=tmp_path / "snapshots",
    )

    revised_row = {
        **base_row, "description": "revised description",
        "root_cause_functions": [{"qualified_name": "vulnerable_new", "file_path": "source.py"}],
    }
    revised_benchmark = tmp_path / "benchmark-v4.jsonl"
    revised_benchmark.write_text(json.dumps(revised_row) + "\n", encoding="utf-8")
    revised_manifest = tmp_path / "prepared-v4.jsonl"
    summary = freeze_rq3_benchmark(
        revised_benchmark, revised_manifest, resolve_cwe=False,
        reuse_manifest_from=old_manifest,
        snapshot_cache=tmp_path / "cache", snapshot_root=tmp_path / "snapshots",
    )
    frozen = json.loads(revised_manifest.read_text(encoding="utf-8").splitlines()[0])
    assert summary["reuse_benchmark_matches"] is False
    assert summary["reused_source_cases"] == 1
    assert summary["reused_patch_cases"] == 1
    assert frozen["verified_vfs"][0]["qualified_name"] == "vulnerable_new"
    assert frozen["description"] == "revised description"

    wrong_base_row = {
        **revised_row,
        "patches": [{"role": "canonical_fix", "sha": fix, "parent_sha": "0" * 40}],
    }
    wrong_base_benchmark = tmp_path / "benchmark-wrong-base.jsonl"
    wrong_base_benchmark.write_text(json.dumps(wrong_base_row) + "\n", encoding="utf-8")
    wrong_base_manifest = tmp_path / "prepared-wrong-base.jsonl"
    wrong_base_summary = freeze_rq3_benchmark(
        wrong_base_benchmark, wrong_base_manifest, resolve_cwe=False,
        reuse_manifest_from=old_manifest,
        snapshot_cache=tmp_path / "cache", snapshot_root=tmp_path / "snapshots",
    )
    wrong_base_case = json.loads(wrong_base_manifest.read_text(encoding="utf-8").splitlines()[0])
    assert wrong_base_summary["reused_patch_cases"] == 0
    assert wrong_base_case["patch_available"] is False


def test_freeze_uses_adjudicated_patch_sha_with_verified_explicit_parent(tmp_path: Path):
    repo = tmp_path / "adjudicated-patch-repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "RQ3 Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "rq3@example.invalid"], check=True)
    source = repo / "source.py"
    source.write_text("def vulnerable():\n    return 'old'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "source.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "vulnerable"], check=True, capture_output=True)
    vulnerable = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()

    (repo / "README.md").write_text("unrelated branch change\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "unrelated"], check=True, capture_output=True)
    source.write_text("def vulnerable():\n    return 'fixed'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "source.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "canonical fix on another branch"], check=True, capture_output=True)
    canonical_fix = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()

    subprocess.run(["git", "-C", str(repo), "switch", "--detach", vulnerable], check=True, capture_output=True)
    source.write_text("def vulnerable():\n    return 'fixed'\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "source.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "backport fix"], check=True, capture_output=True)
    backport_fix = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True,
    ).stdout.strip()

    benchmark = tmp_path / "benchmark.jsonl"
    benchmark.write_text(json.dumps({
        "group_id": "CVE-OVERRIDE::sample", "advisory_id": "CVE-OVERRIDE", "package_name": "sample",
        "description": "unsafe value", "repo_url": str(repo), "vulnerable_ref": vulnerable,
        "patches": [{"role": "canonical_fix", "sha": canonical_fix, "parent_sha": vulnerable}],
        "root_cause_functions": [{"qualified_name": "vulnerable", "file_path": "source.py"}],
        "mapping_type": "single_vf", "ground_truth_evidence": "patch_verified",
    }) + "\n", encoding="utf-8")
    adjudication = tmp_path / "adjudication.json"
    adjudication.write_text(json.dumps({"cases": [{
        "group_id": "CVE-OVERRIDE::sample", "status": "APPROVED",
        "patch_sha": backport_fix, "patch_base_sha": vulnerable,
        "reason": "Use the branch-specific backport whose parent is the vulnerable revision.",
        "evidence": ["local git history"],
    }]}), encoding="utf-8")
    output = tmp_path / "frozen.jsonl"
    summary = freeze_rq3_benchmark(
        benchmark, output, resolve_cwe=False, materialize_sources=True, materialize_patches=True,
        adjudication=adjudication, snapshot_cache=tmp_path / "cache", snapshot_root=tmp_path / "snapshots",
    )
    frozen = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert summary["patches_unmaterialized"] == 0
    assert frozen["patch_sha"] == backport_fix
    assert frozen["patch_sha_original"] == canonical_fix
    assert frozen["patch_sha_adjudicated"] == backport_fix
    assert "-    return 'old'" in frozen["patch_text"]
    assert "+    return 'fixed'" in frozen["patch_text"]


def test_safe_archive_extracts_only_python_files(tmp_path: Path):
    archive_path = tmp_path / "source.tar"
    with rq3.tarfile.open(archive_path, "w") as archive:
        for name, payload in (("aux/anamon", b"data"), ("pkg/module.py", b"def safe(): pass\n")):
            info = rq3.tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        alias = rq3.tarfile.TarInfo("pkg/alias.py")
        alias.type = rq3.tarfile.SYMTYPE
        alias.linkname = "module.py"
        archive.addfile(alias)
    output = tmp_path / "out"
    output.mkdir()
    rq3._extract_archive_safely(archive_path, output)
    assert (output / "pkg" / "module.py").read_text(encoding="utf-8") == "def safe(): pass\n"
    assert (output / "pkg" / "alias.py").read_text(encoding="utf-8") == "def safe(): pass\n"
    assert not (output / "aux").exists()


def test_release_artifact_diff_is_python_only_and_reproducible(tmp_path: Path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    (before / "django_sendfile" / "backends").mkdir(parents=True)
    (after / "django_sendfile" / "backends").mkdir(parents=True)
    (before / "django_sendfile" / "backends" / "simple.py").write_text(
        "def sendfile(request, filename):\n    return open(filename)\n", encoding="utf-8",
    )
    (after / "django_sendfile" / "backends" / "simple.py").write_text(
        "def sendfile(request, filename):\n    return safe_open(filename)\n", encoding="utf-8",
    )
    patch = materialize_release_patch(before, after, "a" * 64, "b" * 64, tmp_path / "cache")
    text = patch.read_text(encoding="utf-8")
    assert "django_sendfile/backends/simple.py" in text
    assert "-    return open(filename)" in text
    assert "+    return safe_open(filename)" in text
    assert materialize_release_patch(before, after, "a" * 64, "b" * 64, tmp_path / "cache") == patch


def test_dual_does_not_relabel_adjudicated_patch_unavailable_as_absent(tmp_path: Path):
    cases = tmp_path / "cases.jsonl"
    cases.write_text(json.dumps({
        "case_id": "case-x", "cve_vf_group_id": "CVE-X::sample", "cve_id": "CVE-X",
        "package": "sample", "repo_url": "local", "vulnerable_ref": "ref",
        "description": "description", "source_path": str(FIXTURE), "eligible": True,
        "patch_available": False, "patch_status": "ADJUDICATED_PATCH_UNAVAILABLE",
        "verified_vfs": ["Client.fetch"],
    }) + "\n", encoding="utf-8")

    def unexpected_localizer(*args, **kwargs):
        raise AssertionError("PATCH_UNAVAILABLE must not enter the patch-absent mode")

    summary = run_localization_batch(
        cases, "P_DUAL", tmp_path / "runs", localizer=unexpected_localizer, progress=False,
    )
    result = json.loads(Path(summary["results"]).read_text(encoding="utf-8").splitlines()[0])
    assert result["status"] == "not_applicable"
    assert result["runtime_mode"] == "PATCH_UNAVAILABLE"
    parsed = parse_case(json.loads(cases.read_text(encoding="utf-8")))
    assert not rq3._case_applies_to_treatment(parsed, "P_DUAL/PATCH_ABSENT")


def test_case_checkpoints_resume_completed_work_and_fingerprint_changes(tmp_path: Path, monkeypatch):
    cases_file = tmp_path / "cases.jsonl"
    _write_cases(cases_file, 3)
    calls = []

    def interrupted(case, config_id, *, inventory_cache=None):
        calls.append(case.case_id)
        if case.case_id == "case-1":
            raise RuntimeError("simulated interruption")
        return RQ3LocalizationResult(
            case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id, config_id=config_id,
            runtime_mode="DEFAULT", output_type="ranked", status="complete",
            candidate_ids=[], candidate_count=0,
        )

    first = run_localization_batch(cases_file, "D_LEX", tmp_path / "runs", localizer=interrupted, progress=False)
    assert first["completed"] == 2 and first["failed"] == 1
    retried = []

    def resumed(case, config_id, *, inventory_cache=None):
        retried.append(case.case_id)
        return RQ3LocalizationResult(
            case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id, config_id=config_id,
            runtime_mode="DEFAULT", output_type="ranked", status="complete",
            candidate_ids=[], candidate_count=0,
        )

    second = run_localization_batch(cases_file, "D_LEX", tmp_path / "runs", localizer=resumed, progress=False)
    assert retried == ["case-1"]
    assert second["completed"] == 3 and second["failed"] == 0
    assert second["run_id"] == first["run_id"]
    uninterrupted = run_localization_batch(cases_file, "D_LEX", tmp_path / "uninterrupted", localizer=resumed, progress=False)
    resumed_rows = [json.loads(line) for line in Path(second["results"]).read_text(encoding="utf-8").splitlines()]
    uninterrupted_rows = [json.loads(line) for line in Path(uninterrupted["results"]).read_text(encoding="utf-8").splitlines()]
    stable = lambda rows: {
        row["case_id"]: (row["status"], row["candidate_ids"], row["predictions"], row["fingerprint"])
        for row in rows
    }
    assert stable(resumed_rows) == stable(uninterrupted_rows)
    changed = cases_file.read_text(encoding="utf-8").replace("request fetch without timeout", "different vulnerability query")
    cases_file.write_text(changed, encoding="utf-8")
    third = run_localization_batch(cases_file, "D_LEX", tmp_path / "runs", localizer=resumed, progress=False)
    assert third["run_id"] != second["run_id"]
    changed_config = run_localization_batch(cases_file, "D_SEM", tmp_path / "runs", localizer=resumed, progress=False)
    assert changed_config["run_id"] != third["run_id"]
    from f_vra.core.config import settings
    monkeypatch.setattr(settings, "embedding_max_workers", 2)
    changed_workers = run_localization_batch(
        cases_file, "D_LEX", tmp_path / "runs", localizer=resumed, progress=False,
    )
    assert changed_workers["run_id"] != second["run_id"]


def test_compatibility_resume_reuses_old_successes_and_retries_only_failures(tmp_path: Path, monkeypatch):
    from f_vra.core.config import settings

    cases_file = tmp_path / "cases.jsonl"
    _write_cases(cases_file, 3)

    def first_attempt(case, config_id, *, inventory_cache=None):
        if case.case_id == "case-1":
            raise RuntimeError("temporary model failure")
        return RQ3LocalizationResult(
            case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id, config_id=config_id,
            runtime_mode="DEFAULT", output_type="ranked", status="complete",
            candidate_count=1,
            predictions=[{"qualified_name": "Client.fetch", "rank": 1}],
        )

    output_root = tmp_path / "runs"
    first = run_localization_batch(cases_file, "D_SEM", output_root, localizer=first_attempt, progress=False)
    prior_summary = Path(first["results"]).parent / "summary.json"
    assert first["completed"] == 2 and first["failed"] == 1
    calls = []

    def retry_failed(case, config_id, *, inventory_cache=None):
        calls.append(case.case_id)
        return RQ3LocalizationResult(
            case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id, config_id=config_id,
            runtime_mode="DEFAULT", output_type="ranked", status="complete",
            candidate_count=1,
            predictions=[{"qualified_name": "Client.fetch", "rank": 1}],
        )

    monkeypatch.setattr(settings, "embedding_max_workers", 2)
    continued = run_localization_batch(
        cases_file, "D_SEM", output_root, resume_from_summary=prior_summary,
        localizer=retry_failed, progress=False,
    )

    assert calls == ["case-1"]
    assert continued["run_id"] == first["run_id"]
    assert continued["completed"] == 3 and continued["failed"] == 0
    assert continued["compatibility_resume"]["reused_completed_cases"] == 2
    assert continued["compatibility_resume"]["mixed_execution_settings"] is True
    assert (prior_summary.parent / "summary.before_compatibility_resume.json").is_file()
    rows = [json.loads(line) for line in Path(continued["results"]).read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 4  # three original records, plus one retry; old checkpoint was appended to, not replaced
    assert rows[-1]["metadata"]["embedding_execution"]["max_workers"] == 2


def test_checkpoint_resume_reuses_successes_after_embedding_settings_change(tmp_path: Path, monkeypatch):
    from f_vra.core.config import settings

    cases_file = tmp_path / "cases.jsonl"
    _write_cases(cases_file, 3)
    output_root = tmp_path / "runs"
    calls = []

    def first_attempt(case, config_id, *, inventory_cache=None):
        if case.case_id == "case-1":
            raise RuntimeError("simulated interruption")
        return RQ3LocalizationResult(
            case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id, config_id=config_id,
            runtime_mode="DEFAULT", output_type="ranked", status="complete",
            candidate_count=1,
        )

    monkeypatch.setattr(settings, "embedding_batch_size", 16)
    monkeypatch.setattr(settings, "embedding_max_workers", 1)
    first = run_localization_batch(
        cases_file, "D_SEM", output_root, localizer=first_attempt, progress=False,
    )
    checkpoint_dir = Path(first["results"]).parent
    # An interrupted run has no final summary; the durable case checkpoint is sufficient.
    (checkpoint_dir / "summary.json").unlink()

    def resumed(case, config_id, *, inventory_cache=None):
        calls.append(case.case_id)
        return RQ3LocalizationResult(
            case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id, config_id=config_id,
            runtime_mode="DEFAULT", output_type="ranked", status="complete",
            candidate_count=1,
        )

    monkeypatch.setattr(settings, "embedding_batch_size", 32)
    monkeypatch.setattr(settings, "embedding_max_workers", 2)
    continued = run_localization_batch(
        cases_file, "D_SEM", output_root, resume_from_checkpoint=checkpoint_dir,
        localizer=resumed, progress=False,
    )

    assert calls == ["case-1"]
    assert continued["run_id"] == first["run_id"]
    assert continued["completed"] == 3 and continued["failed"] == 0
    assert continued["compatibility_resume"]["mixed_execution_settings"] is True
    assert continued["compatibility_resume"]["prior_embedding_batch_size"] == 16
    assert continued["compatibility_resume"]["current_embedding_batch_size"] == 32
    assert continued["embedding_settings_scope"] == "newly processed cases"

    # A later restart sees both the original and accelerated settings in one checkpoint.
    (checkpoint_dir / "summary.json").unlink()
    calls.clear()
    restarted = run_localization_batch(
        cases_file, "D_SEM", output_root, resume_from_checkpoint=checkpoint_dir,
        localizer=resumed, progress=False,
    )
    assert calls == []
    assert restarted["completed"] == 3 and restarted["failed"] == 0
    assert restarted["compatibility_resume"]["mixed_execution_settings"] is True
    assert restarted["compatibility_resume"]["prior_execution_settings"] == [
        {"batch_size": 16, "max_workers": 1},
        {"batch_size": 32, "max_workers": 2},
    ]


def test_batch_persists_provider_usage_and_marks_unknown_cost(tmp_path: Path):
    from f_vra.localization.providers.llm_client import record_chat_usage, record_embedding_usage

    cases_file = tmp_path / "cases.jsonl"
    _write_cases(cases_file, 1)

    def instrumented(case, config_id, *, inventory_cache=None):
        record_chat_usage({"usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14}})
        record_embedding_usage({"usage": {"prompt_tokens": 7, "total_tokens": 7}})
        return RQ3LocalizationResult(
            case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id, config_id=config_id,
            runtime_mode="DEFAULT", output_type="ranked", status="complete",
        )

    summary = run_localization_batch(cases_file, "D_LEX", tmp_path / "runs", localizer=instrumented, progress=False)
    row = json.loads(Path(summary["results"]).read_text(encoding="utf-8").splitlines()[0])
    assert row["metadata"]["provider_usage"] == {
        "chat_calls": 1, "chat_prompt_tokens": 11, "chat_completion_tokens": 3,
        "chat_total_tokens": 14, "chat_usage_unreported_calls": 0,
        "embedding_calls": 1, "embedding_input_tokens": 7, "embedding_total_tokens": 7,
        "embedding_usage_unreported_calls": 0, "cost_usd": None,
    }


def test_p_modified_marks_patchless_cases_not_applicable_and_uses_patch_subset_coverage(tmp_path: Path):
    cases_file = tmp_path / "cases.jsonl"
    rows = [
        {"case_id": "patch", "cve_vf_group_id": "CVE-P::sample", "cve_id": "CVE-P",
         "package": "sample", "repo_url": "local", "vulnerable_ref": "fixture",
         "description": "request timeout", "source_path": str(FIXTURE), "patch_available": True,
         "patch_text": "a patch", "verified_vfs": ["Client.fetch"]},
        {"case_id": "no-patch", "cve_vf_group_id": "CVE-N::sample", "cve_id": "CVE-N",
         "package": "sample", "repo_url": "local", "vulnerable_ref": "fixture",
         "description": "request timeout", "source_path": str(FIXTURE), "patch_available": False,
         "verified_vfs": ["Client.fetch"]},
    ]
    cases_file.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    calls = []

    def localizer(case, config_id, *, inventory_cache=None):
        calls.append(case.case_id)
        return RQ3LocalizationResult(
            case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id, config_id=config_id,
            runtime_mode="DEFAULT", output_type="set", status="complete",
            predictions=[{"qualified_name": "Client.fetch", "file_path": "pkg/lib.py", "rank": None}],
            candidate_details=[{"qualified_name": "Client.fetch", "file_path": "pkg/lib.py"}],
            candidate_count=1,
        )

    summary = run_localization_batch(cases_file, "P_MODIFIED", tmp_path / "runs", localizer=localizer, progress=False)
    rows_out = [json.loads(line) for line in Path(summary["results"]).read_text(encoding="utf-8").splitlines()]
    assert calls == ["patch"]
    assert summary["completed"] == 1 and summary["not_applicable"] == 1 and summary["failed"] == 0
    assert next(row for row in rows_out if row["case_id"] == "no-patch")["status"] == "not_applicable"
    quality = summary["localization_quality"][0]
    assert quality["applicable_cases"] == 1
    assert quality["not_applicable_cases"] == 1
    assert quality["Coverage"] == 1.0


def test_case_fingerprint_changes_when_source_snapshot_content_changes(tmp_path: Path):
    source = tmp_path / "source"
    source.mkdir()
    module = source / "mod.py"
    module.write_text("def vulnerable():\n    return 1\n", encoding="utf-8")
    row = {"case_id": "case", "source_path": str(source), "snapshot_id": "stable-declared-id"}
    before, _ = rq3._fingerprint([row], "D_LEX", None)
    module.write_text("def vulnerable():\n    return 2\n", encoding="utf-8")
    after, _ = rq3._fingerprint([row], "D_LEX", None)
    assert before != after


def test_ten_case_fixture_batch_smoke_has_progress_and_durable_results(tmp_path: Path):
    cases_file = tmp_path / "ten-cases.jsonl"
    _write_cases(cases_file, 10)
    command = CliRunner().invoke(app, [
        "eval", "rq3-localize", str(cases_file), "--config", "D_LEX",
        "--output-root", str(tmp_path / "runs"), "--limit", "10",
    ])
    assert command.exit_code == 0, command.output
    summary = json.loads(command.stdout)
    result_rows = [json.loads(line) for line in Path(summary["results"]).read_text(encoding="utf-8").splitlines()]
    assert summary["case_count"] == summary["completed"] == 10
    assert len(result_rows) == 10
    assert len(Path(summary["progress_log"]).read_text(encoding="utf-8").splitlines()) == 10
    assert result_rows[0]["predictions"][0]["qualified_name"] == "Client.fetch"
    assert list((tmp_path / "runs" / "inventory_cache").glob("*.json"))


def test_materialize_git_snapshot_exports_exact_commit_and_reuses_cache(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "RQ3 Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "rq3@example.invalid"], check=True)
    source = repo / "sample.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "sample.py"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "one"], check=True, capture_output=True)
    commit = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    source.write_text("VALUE = 2\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "commit", "-am", "two"], check=True, capture_output=True)
    short_snapshot_root = tmp_path / "short-snapshots"
    snapshot = materialize_git_snapshot(str(repo), commit, tmp_path / "cache", snapshot_root=short_snapshot_root)
    assert snapshot.parent == short_snapshot_root
    assert (snapshot / "sample.py").read_text(encoding="utf-8") == "VALUE = 1\n"
    assert materialize_git_snapshot(str(repo), commit, tmp_path / "cache", snapshot_root=short_snapshot_root) == snapshot


def test_rq3_binding_builds_exact_query_manifests_and_resumes(tmp_path: Path):
    cases_path = tmp_path / "cases.jsonl"
    results_path = tmp_path / "localization.jsonl"
    downstream_path = tmp_path / "downstream.jsonl"
    cases_path.write_text(json.dumps({
        "case_id": "CVE-1::sample", "cve_vf_group_id": "CVE-1::sample", "cve_id": "CVE-1", "package": "sample",
    }) + "\n", encoding="utf-8")
    results_path.write_text(json.dumps({
        "case_id": "CVE-1::sample", "config_id": "D_LEX", "runtime_mode": "DEFAULT", "status": "complete",
        "output_type": "ranked", "predictions": [
            {"qualified_name": "vulnerable", "file_path": "pkg/mod.py", "start_line": 1, "end_line": 2, "rank": 1},
            {"qualified_name": "helper", "file_path": "pkg/mod.py", "start_line": 4, "end_line": 5, "rank": 2},
        ],
    }) + "\n", encoding="utf-8")
    downstream_path.write_text(json.dumps({
        "cve_vf_group_id": "CVE-1::sample", "project": {"repo": "project-a"}, "cve_id": "CVE-1",
    }) + "\n", encoding="utf-8")
    dataset = tmp_path / "dataset"
    dataset.mkdir()
    write_json(dataset / "dataset.json", {"dataset_id": "dataset-test"})
    write_parquet(dataset / "queries.parquet", [{
        "query_id": "query-a", "project_id": "project-a", "cve_id": "CVE-1", "env_id": "env-a",
        "affected_package_id": "pkg-id", "affected_distribution": "sample",
    }])
    write_parquet(dataset / "packages.parquet", [{"package_id": "pkg-id", "distribution": "sample"}])
    write_parquet(dataset / "environments.parquet", [{"env_id": "env-a", "docker_image_digest": "image-a"}])
    output = tmp_path / "rq3_variants.parquet"
    probe_calls = []

    def probe(image, requests):
        probe_calls.append((image, requests))
        return {"anchors": {
            "sample|vulnerable": {"status": "BOUND", "module": "pkg.mod", "file": "pkg/mod.py", "start_line": 1, "end_line": 2, "function_hash": "hash-a"},
            "sample|helper": {"status": "BOUND", "module": "pkg.mod", "file": "pkg/mod.py", "start_line": 4, "end_line": 5, "function_hash": "hash-b"},
        }}

    first = build_rq3_vf_variants(
        cases_path, results_path, downstream_path, dataset, output, probe=probe,
    )
    rows = read_parquet(output)
    assert first["exact_group_joins"] == 1 and first["variants"] == 2
    assert {row["variant"] for row in rows} == {"D_LEX_TOP1", "D_LEX_TOP5"}
    assert sorted(len(row["vf_set"]) for row in rows) == [1, 2]
    second = build_rq3_vf_variants(
        cases_path, results_path, downstream_path, dataset, output, probe=probe,
    )
    assert second["resumed_records"] == 2
    assert len(probe_calls) == 1


def test_downstream_pairing_uses_exact_group_and_run_variant(tmp_path: Path):
    binding = tmp_path / "binding.parquet"
    write_parquet(binding, [{
        "query_id": "query-a", "cve_vf_group_id": "CVE-1::sample",
        "project_id": "project-a", "cve_id": "CVE-1", "variant": "D_LEX_TOP1",
        "config_id": "D_LEX", "runtime_mode": "DEFAULT", "top_k": "1",
    }])
    downstream = tmp_path / "downstream.jsonl"
    downstream.write_text("\n".join(json.dumps(row) for row in [
        {"cve_vf_group_id": "CVE-1::sample", "project": {"repo": "project-a"}, "cve_id": "CVE-1", "ground_truth": {"reachable": "true"}},
        {"cve_vf_group_id": "CVE-1::sample-extra", "project": {"repo": "project-a"}, "cve_id": "CVE-1", "ground_truth": {"reachable": "false"}},
    ]) + "\n", encoding="utf-8")
    run_dir = tmp_path / "eval-run"
    run_dir.mkdir()
    (run_dir / "config.yaml").write_text("run_label: D_LEX_TOP1\n", encoding="utf-8")
    write_parquet(run_dir / "query_results.parquet", [{
        "query_id": "query-a", "decision": "UNREACHABLE", "execution_status": "COMPLETE",
    }])
    output = tmp_path / "pairs.parquet"
    summary = pair_rq3_downstream_runs(binding, downstream, [run_dir], output)
    pairs = read_parquet(output)
    assert summary["paired_rows"] == 1
    assert summary["unmatched_downstream_group_rows"] == 1
    assert pairs[0]["oracle_decision"] == "REACHABLE"
    assert pairs[0]["decision"] == "UNREACHABLE"
