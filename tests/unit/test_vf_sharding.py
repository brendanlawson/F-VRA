from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from f_vra.evaluation.vf_experiment import _resolve_input_path, prepare_vf_inputs
from f_vra.evaluation.vf_metrics import compute_vf_report
from f_vra.evaluation.vf_sharding import (
    _copy_indexed_source,
    _expected_indexed_source_hash,
    _indexed_python_files,
    create_vf_index_shards,
    create_vf_machine_shards,
    merge_vf_machine_shards,
    run_vf_index_shard,
    run_vf_machine_shard,
)
from f_vra.evaluation.rq3 import RQ3LocalizationResult
from f_vra.localization.models import FunctionInfo
from f_vra.localization.code.function_parser import filesystem_path, parse_repository
from f_vra.localization.retrieval.embedding import embedding_scores

FIXTURE = Path(__file__).parents[1] / "fixtures" / "sample_app"
TARGET = {
    "function_id": "pkg/lib.py:Client.fetch",
    "qualified_name": "Client.fetch",
    "file_path": "pkg/lib.py",
}


def _case(case_id: str, snapshot_id: str) -> dict:
    return {
        "case_id": case_id,
        "cve_vf_group_id": f"CVE-{case_id}::sample",
        "cve_id": f"CVE-{case_id}",
        "package": "sample",
        "repo_url": "local",
        "vulnerable_ref": snapshot_id,
        "source_revision_sha": snapshot_id,
        "snapshot_id": snapshot_id,
        "description": "network request without timeout",
        "source_path": str(FIXTURE),
        "eligible": True,
        "patch_available": True,
        "patch_text": "diff --git a/pkg/lib.py b/pkg/lib.py\n",
        "patch_sha": f"patch-{case_id}",
        "patch_status": "VERIFIED",
        "cwe_ids": ["CWE-400"],
        "cwe_text": "uncontrolled resource consumption",
        "verified_vfs": [
            {"file_path": "pkg/lib.py", "qualified_name": "Client.fetch", "label": "root_cause_vf"},
            {"file_path": "pkg/lib.py", "qualified_name": "public_api", "label": "vulnerable_usage_site"},
        ],
    }


def _read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _hash_shard(snapshot_id: str, count: int) -> int:
    digest = hashlib.sha256(snapshot_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % count


def _fake_localizer(case, config_id, *, inventory_cache=None, protocol=None):
    if config_id == "D_SEM":
        metadata = {
            "entity_extraction": {
                "entities": {"attack_vector": "network", "root_cause": "missing timeout"},
                "usable": True,
                "failed": False,
            },
        }
        ranked = TARGET | {"rank": 1, "score": 0.9, "evidence": ["entities"]}
    elif config_id == "P_DUAL":
        rank = 1 if case.patch_available else 3
        metadata = {"candidate_generation": {"candidate_limit": protocol["candidate_limit"]}}
        ranked = TARGET | {"rank": rank, "score": 0.9, "evidence": ["pairwise"]}
    else:
        metadata = {}
        ranked = TARGET | {"rank": 1, "score": 1.0, "evidence": []}
    return RQ3LocalizationResult(
        case_id=case.case_id,
        cve_vf_group_id=case.cve_vf_group_id,
        config_id=config_id,
        runtime_mode="PATCH_PRESENT" if config_id == "P_DUAL" and case.patch_available else "PATCH_ABSENT" if config_id == "P_DUAL" else "DEFAULT",
        output_type="ranked",
        status="complete",
        candidate_ids=[TARGET["function_id"]],
        candidate_details=[TARGET | {"candidate_provenance": "fixture"}],
        predictions=[ranked],
        candidate_count=1,
        raw_candidate_count=4,
        runtime_ms=1.0,
        metadata=metadata,
    )


def test_portable_machine_shards_resume_merge_and_offline_metrics(tmp_path: Path):
    snapshot_a = next(f"snapshot-a-{n}" for n in range(100) if _hash_shard(f"snapshot-a-{n}", 2) == 0)
    snapshot_b = next(f"snapshot-b-{n}" for n in range(100) if _hash_shard(f"snapshot-b-{n}", 2) == 1)
    cases = [
        _case("case-1", snapshot_a),
        _case("case-2", snapshot_a),
        _case("case-3", snapshot_b),
        _case("case-4", snapshot_b),
    ]
    manifest_path = tmp_path / "prepared.jsonl"
    manifest_path.write_text("".join(json.dumps(row) + "\n" for row in cases), encoding="utf-8")
    prepared = prepare_vf_inputs(manifest_path, tmp_path / "full-inputs", workers=2)
    full_inputs = Path(prepared["inputs_dir"])

    shard_summary = create_vf_machine_shards(full_inputs, tmp_path / "shards", shard_count=2)
    assert shard_summary["eligible_case_counts"] == [2, 2]
    assert shard_summary["p_dual_case_counts"] == [2, 2]

    results = []
    failed_once = {"value": False}
    failed_lock = threading.Lock()

    def fail_first_dlex(case, config_id, **kwargs):
        if case.case_id == "case-1" and config_id == "D_LEX":
            with failed_lock:
                if not failed_once["value"]:
                    failed_once["value"] = True
                    raise RuntimeError("fixture provider failure")
        return _fake_localizer(case, config_id, **kwargs)

    for shard in shard_summary["shards"]:
        original_bundle = Path(shard["path"])
        relocated_bundle = tmp_path / "relocated" / shard["shard_id"]
        relocated_bundle.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(original_bundle, relocated_bundle)
        bundle_manifest = json.loads((relocated_bundle / "manifest.json").read_text(encoding="utf-8"))
        shard_manifest = json.loads((relocated_bundle / "shard_manifest.json").read_text(encoding="utf-8"))
        assert bundle_manifest["has_ground_truth"] is False
        assert "ground_truth_path" not in bundle_manifest
        assert not (relocated_bundle / "ground_truth.jsonl").exists()
        assert (relocated_bundle / "sources.tar").is_file()
        assert not (relocated_bundle / "sources").exists()
        assert any(record["path"] == "sources.tar" for record in shard_manifest["files"])
        assert len(shard_manifest["case_ids"]) == 2
        assert all(Path(row["source_path"]).is_absolute() is False for row in _read(relocated_bundle / "d_lex.jsonl") if row["eligible"])
        hidden = _read(relocated_bundle / "p_dual_hidden.jsonl")
        assert all(not {"patch_text", "patch_sha", "patch_status", "patch_available", "cwe_ids", "cwe_text"}.intersection(row) for row in hidden)

        first = run_vf_machine_shard(
            relocated_bundle, tmp_path / "machine-results", run_id="vf-fixture", workers=1,
            case_limit=1, progress=False, localizer=fail_first_dlex,
        )
        assert (relocated_bundle / "sources").is_dir()
        assert first["status"] == "canary"
        assert first["modes"]["D_LEX"]["record_count"] == 1
        if "case-1" in shard_manifest["case_ids"]:
            assert first["modes"]["D_LEX"]["failed"] == 1
        resumed = run_vf_machine_shard(
            relocated_bundle, tmp_path / "machine-results", run_id="vf-fixture", workers=2,
            case_limit=0, progress=False, localizer=_fake_localizer,
        )
        assert resumed["status"] == "complete"
        assert resumed["modes"]["D_LEX"]["record_count"] == len(shard_manifest["case_ids"])
        if "case-1" in shard_manifest["case_ids"]:
            assert resumed["modes"]["D_LEX"]["failed"] == 0
        machine_result = Path(resumed["results_dir"])
        results.append(machine_result)
        for mode in ("D_LEX", "D_SEM", "P_DUAL_PRESENT", "P_DUAL_HIDDEN"):
            compact = _read(machine_result / f"{mode}.jsonl")
            assert len(compact) == len({row["case_id"] for row in compact})

    with pytest.raises(ValueError, match="expected 2 machine results"):
        merge_vf_machine_shards(full_inputs, results[:1], tmp_path / "merged")

    merged = merge_vf_machine_shards(full_inputs, results, tmp_path / "vf-fixture")
    assert merged["status"] == "complete"
    assert merged["result_counts"]["P_DUAL_PRESENT"] == 4
    assert len(_read(tmp_path / "vf-fixture" / "ORACLE.jsonl")) == 4

    report = compute_vf_report(full_inputs, tmp_path / "vf-fixture", tmp_path / "metrics")
    deltas = {row["gt_scope"]: row for row in report["paired_deltas"]}
    assert deltas["root_cause_only"]["paired_cases"] == 4
    assert deltas["root_cause_only"]["DeltaHit@1"] == pytest.approx(1.0)
    assert deltas["root_cause_only"]["DeltaMRR"] == pytest.approx(2 / 3)
    assert (tmp_path / "metrics" / "metrics.csv").is_file()
    assert (tmp_path / "metrics" / "report.md").is_file()


def test_index_shards_reuse_preinstalled_artifacts_and_merge(tmp_path: Path):
    snapshot_a = next(f"index-a-{n}" for n in range(100) if _hash_shard(f"index-a-{n}", 2) == 0)
    snapshot_b = next(f"index-b-{n}" for n in range(100) if _hash_shard(f"index-b-{n}", 2) == 1)
    cases = [_case("index-1", snapshot_a), _case("index-2", snapshot_b)]
    source_manifest = tmp_path / "index-cases.jsonl"
    source_manifest.write_text("".join(json.dumps(row) + "\n" for row in cases), encoding="utf-8")
    prepared = prepare_vf_inputs(source_manifest, tmp_path / "index-inputs", workers=1)
    full_inputs = Path(prepared["inputs_dir"])

    plans = create_vf_index_shards(full_inputs, tmp_path / "plans", shard_count=2)
    assert plans["total_plan_bytes"] < 20_000
    assert plans["eligible_case_counts"] == [1, 1]
    assert all(Path(item["path"]).is_file() for item in plans["shards"])
    assert not list((tmp_path / "plans").rglob("sources.tar"))

    shard_results = []
    for item in plans["shards"]:
        result = run_vf_index_shard(
            full_inputs, Path(item["path"]), tmp_path / "index-results",
            run_id="index-fixture", workers=1, progress=False, localizer=_fake_localizer,
        )
        assert result["status"] == "complete"
        shard_results.append(Path(result["results_dir"]))

    merged = merge_vf_machine_shards(full_inputs, shard_results, tmp_path / "index-fixture")
    assert merged["status"] == "complete"
    assert merged["result_counts"]["D_LEX"] == 2
    assert merged["result_counts"]["P_DUAL_PRESENT"] == 2


def test_resolve_frozen_windows_paths_against_local_vf_artifacts():
    input_id = "vf-input-aa79242b904b7c68"
    inputs_dir = Path(__file__).parents[2] / "experiments" / "vf" / "inputs" / input_id
    if not inputs_dir.is_dir():
        pytest.skip("full local VF artifacts are not present")
    catalogs_dir = inputs_dir / "catalogs"
    source_cache_dir = Path(__file__).parents[2] / "experiments" / "vf" / "source_cache" / "snapshots"
    if not catalogs_dir.is_dir() or not source_cache_dir.is_dir():
        pytest.skip("full local VF artifacts are not present")
    catalog = next(catalogs_dir.glob("*.json"), None)
    source = next(source_cache_dir.iterdir(), None)
    if catalog is None or source is None:
        pytest.skip("full local VF artifacts are not present")
    frozen_catalog = rf"Z:\\old-checkout\\experiments\\vf\\inputs\\{input_id}\\catalogs\\{catalog.name}"
    assert _resolve_input_path(inputs_dir, frozen_catalog) == catalog.resolve()
    frozen_source = rf"Z:\\old-checkout\\experiments\\vf\\source_cache\\snapshots\\{source.name}"
    assert _resolve_input_path(inputs_dir, frozen_source) == source.resolve()


def test_resolve_frozen_user_snapshot_paths_against_local_snapshot_root():
    snapshot_root = Path.home() / "rq3-snapshots"
    if not snapshot_root.is_dir():
        pytest.skip("external RQ3 snapshot cache is not present")
    snapshot = next(path for path in snapshot_root.iterdir() if path.is_dir())
    frozen_path = rf"C:\\old-user\\rq3-snapshots\\{snapshot.name}"
    inputs_dir = Path(__file__).parents[2] / "experiments" / "vf" / "inputs" / "vf-input-aa79242b904b7c68"
    assert _resolve_input_path(inputs_dir, frozen_path) == snapshot.resolve()


def test_two_workers_can_share_embedding_sqlite_cache(tmp_path: Path):
    class FakeEmbeddingBackend:
        model_name = "fixture-embedding"
        provider_name = "fixture"
        base_url = "offline"

        def embed(self, texts):
            return [[float(len(text)), 1.0, 0.5] for text in texts]

    functions = [
        FunctionInfo(
            function_name=f"function_{index}",
            qualname=f"function_{index}",
            file_path=f"pkg/{index}.py",
            start_line=1,
            end_line=2,
            source=f"def function_{index}():\n    return {index}\n",
        )
        for index in range(12)
    ]
    cache_path = tmp_path / "embedding_cache.sqlite"
    backend = FakeEmbeddingBackend()
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(embedding_scores, query, functions, backend=backend, cache_path=cache_path)
            for query in ("network issue", "untrusted input")
        ]
        results = [future.result() for future in futures]
    assert all(len(scores) == len(functions) for scores, _ in results)
    with sqlite3.connect(cache_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM embedding_vectors").fetchone()[0]
    assert count >= len(functions) + 1


def test_source_indexer_reads_files_beyond_windows_260_character_path_limit(tmp_path: Path):
    source_root = tmp_path / "deep-source"
    nested = source_root.joinpath(*(f"module_{index}_" + "x" * 36 for index in range(4)))
    nested_path = filesystem_path(nested)
    nested_path.mkdir(parents=True)
    source_file = nested_path / ("handler_" + "y" * 72 + ".py")
    source_file.write_text("def deep_function():\n    return 1\n", encoding="utf-8")
    assert len(str(source_file)) > 260

    functions = parse_repository(source_root)
    assert [item.function_name for item in functions] == ["deep_function"]
    assert functions[0].file_path.endswith("handler_" + "y" * 72 + ".py")

    copied_root = tmp_path / "portable-bundle" / "sources" / "snapshot"
    source_hash, _, file_count = _copy_indexed_source(source_root, copied_root)
    copied_functions = parse_repository(copied_root)
    assert file_count == 1
    assert len(source_hash) == 64
    assert [item.function_name for item in copied_functions] == ["deep_function"]


def test_shard_source_walker_prunes_indexer_excluded_directories(tmp_path: Path):
    source = tmp_path / "source"
    (source / "pkg").mkdir(parents=True)
    (source / "tests").mkdir()
    (source / "node_modules" / "vendor").mkdir(parents=True)
    (source / "pkg" / "module.py").write_text("def selected(): pass\n", encoding="utf-8")
    (source / "tests" / "test_module.py").write_text("def excluded_test(): pass\n", encoding="utf-8")
    (source / "node_modules" / "vendor" / "module.py").write_text("def excluded_vendor(): pass\n", encoding="utf-8")

    indexed_root = filesystem_path(source)
    assert [path.relative_to(indexed_root).as_posix() for path in _indexed_python_files(source)] == ["pkg/module.py"]


def test_pypi_archive_digest_is_not_treated_as_extracted_source_tree_digest(tmp_path: Path):
    release = tmp_path / "release_snapshots" / "abc123"
    snapshot = tmp_path / "snapshots" / "abc123"
    assert _expected_indexed_source_hash(release, "a" * 64) == ""
    assert _expected_indexed_source_hash(snapshot, "b" * 64) == "b" * 64
