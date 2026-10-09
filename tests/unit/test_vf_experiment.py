from __future__ import annotations

import json
from pathlib import Path

import pytest

from f_vra.evaluation import rq3
from f_vra.evaluation.rq3 import LocalizationStageError, RQ3LocalizationResult
from f_vra.evaluation.vf_experiment import _normalized_source_bytes, _resolve_input_path, prepare_vf_inputs, run_vf_mode
from f_vra.evaluation.vf_metrics import compute_vf_report, normalize_ground_truth

FIXTURE = Path(__file__).parents[1] / "fixtures" / "sample_app"
TARGET = {"function_id": "pkg/lib.py:Client.fetch", "qualified_name": "Client.fetch", "file_path": "pkg/lib.py"}


def _case(case_id: str, *, patch: bool) -> dict:
    return {
        "case_id": case_id,
        "cve_vf_group_id": f"CVE-{case_id}::sample",
        "cve_id": f"CVE-{case_id}",
        "package": "sample",
        "repo_url": "local",
        "vulnerable_ref": "snapshot-ref",
        "source_revision_sha": "snapshot-ref",
        "snapshot_id": "snapshot-ref",
        "description": "network request without timeout",
        "source_path": str(FIXTURE),
        "eligible": True,
        "patch_available": patch,
        "patch_text": "diff --git a/pkg/lib.py b/pkg/lib.py\n" if patch else "",
        "patch_sha": "patch-hash" if patch else "",
        "patch_status": "VERIFIED" if patch else "",
        "cwe_ids": ["CWE-22"],
        "cwe_text": "path traversal detail",
        "verified_vfs": [
            {"file_path": "pkg/lib.py", "qualified_name": "Client.fetch", "label": "root_cause_vf"},
            {"file_path": "pkg/lib.py", "qualified_name": "public_api", "label": "vulnerable_usage_site"},
        ],
    }


def _read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _fake_localizer(case, config_id, *, inventory_cache=None, protocol=None):
    mode = config_id
    if mode == "D_LEX":
        lex_target = {"function_id": "pkg/lib.py:public_api", "qualified_name": "public_api", "file_path": "pkg/lib.py"}
        prediction = lex_target | {"rank": 1, "score": 1.0, "evidence": []}
        metadata = {}
    elif mode == "D_SEM":
        prediction = TARGET | {"rank": 2, "score": 0.75, "evidence": ["semantic"]}
        metadata = {
            "entities": {"attack_vector": "network", "root_cause": "missing timeout"},
            "entity_extraction": {"usable": True, "failed": False, "entities": {"attack_vector": "network", "root_cause": "missing timeout"}},
        }
    elif mode == "P_DUAL":
        rank = 1 if case.patch_available else 3
        prediction = TARGET | {"rank": rank, "score": 0.9, "evidence": []}
        metadata = {"candidate_generation": {"candidate_limit": protocol.get("candidate_limit")}}
    else:
        prediction = TARGET | {"rank": 1, "score": 1.0, "evidence": []}
        metadata = {}
    selected = lex_target if mode == "D_LEX" else TARGET
    return RQ3LocalizationResult(
        case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id, config_id=config_id,
        runtime_mode="PATCH_PRESENT" if mode == "P_DUAL" and case.patch_available else "PATCH_ABSENT" if mode == "P_DUAL" else "DEFAULT",
        output_type="ranked", status="complete", candidate_ids=[selected["function_id"]],
        candidate_details=[selected | {"candidate_provenance": "fake"}], predictions=[prediction],
        candidate_count=1, raw_candidate_count=5, runtime_ms=4.0, metadata=metadata,
    )


def test_prepare_creates_isolated_mode_inputs_and_function_catalog(tmp_path: Path):
    cases = tmp_path / "cases.jsonl"
    cases.write_text(json.dumps(_case("one", patch=True)) + "\n" + json.dumps(_case("two", patch=False)) + "\n", encoding="utf-8")
    prepared = prepare_vf_inputs(cases, tmp_path / "inputs")
    inputs_dir = Path(prepared["inputs_dir"])

    d_lex = _read(inputs_dir / "d_lex.jsonl")
    d_sem = _read(inputs_dir / "d_sem.jsonl")
    present = _read(inputs_dir / "p_dual_present.jsonl")
    hidden = _read(inputs_dir / "p_dual_hidden.jsonl")
    gt = _read(inputs_dir / "ground_truth.jsonl")

    assert [row["case_id"] for row in d_lex] == ["one", "two"]
    assert [row["case_id"] for row in d_sem] == ["one", "two"]
    assert [row["case_id"] for row in present] == [row["case_id"] for row in hidden] == ["one"]
    assert not {"verified_vfs", "root_cause_functions", "cwe_ids", "cwe_text", "patch_text", "patch_sha"}.intersection(d_lex[0])
    assert not {"verified_vfs", "cwe_ids", "cwe_text", "patch_text", "patch_sha", "patch_status", "patch_available"}.intersection(hidden[0])
    assert present[0]["patch_text"]
    assert {anchor["role"] for anchor in gt[0]["vulnerable_functions"]} == {"root_cause_vf", "vulnerable_usage_site"}

    catalog = json.loads(Path(d_lex[0]["catalog_path"]).read_text(encoding="utf-8"))
    assert catalog["schema_version"] == "f_vra.vf.function-catalog.v1"
    assert catalog["function_count"] > 0
    assert all({"function_id", "qualified_name", "module_qualified_name", "source", "lexical_tokens", "ast", "approximate_callers", "approximate_callees"}.issubset(item) for item in catalog["functions"])


def test_code_fingerprints_normalize_windows_and_unix_line_endings(tmp_path: Path):
    source = tmp_path / "module.py"
    source.write_bytes(b"def example():\r\n    return 1\r\n")
    windows_bytes = _normalized_source_bytes(source)
    source.write_bytes(b"def example():\n    return 1\n")
    assert _normalized_source_bytes(source) == windows_bytes


def test_relative_source_manifest_path_resolves_from_repository_when_not_in_input_bundle(tmp_path: Path):
    repository_root = Path(__file__).resolve().parents[2]
    relative_source = FIXTURE.resolve().relative_to(repository_root)
    assert _resolve_input_path(tmp_path / "inputs", relative_source).resolve() == FIXTURE.resolve()


def test_mode_runner_checkpoints_each_case_resumes_and_metrics_are_offline(tmp_path: Path):
    cases = tmp_path / "cases.jsonl"
    cases.write_text(json.dumps(_case("one", patch=True)) + "\n" + json.dumps(_case("two", patch=True)) + "\n", encoding="utf-8")
    prepared = prepare_vf_inputs(cases, tmp_path / "inputs")
    inputs_dir = Path(prepared["inputs_dir"])
    results_root = tmp_path / "results"
    calls = []

    def interrupted(case, config_id, **kwargs):
        calls.append((case.case_id, config_id))
        if case.case_id == "two" and len(calls) <= 2:
            raise RuntimeError("simulated provider failure")
        return _fake_localizer(case, config_id, **kwargs)

    first = run_vf_mode("D_LEX", inputs_dir, results_root, run_id="fixture", localizer=interrupted, progress=False)
    first_rows = _read(Path(first["results"]))
    assert first["completed"] == 1 and first["failed"] == 1
    assert len(first_rows) == 2
    assert len(_read(Path(first["checkpoint"]))) == 2

    second = run_vf_mode("D_LEX", inputs_dir, results_root, run_id="fixture", localizer=interrupted, progress=False)
    assert second["completed"] == 2 and second["failed"] == 0
    assert [case_id for case_id, _ in calls] == ["one", "two", "two"]
    assert len(_read(Path(second["results"]))) == 2

    # Execute the same fake deterministic adapter for each mode. No provider is
    # invoked by the later metrics pass; it reads only these persisted records.
    for mode in ("D_SEM", "P_DUAL_PRESENT", "P_DUAL_HIDDEN", "ORACLE"):
        runner = None if mode == "ORACLE" else _fake_localizer
        run_vf_mode(mode, inputs_dir, results_root, run_id="fixture", localizer=runner, progress=False)
    report = compute_vf_report(inputs_dir, results_root / "fixture", tmp_path / "report")
    by_mode_scope = {(row["mode"], row["gt_scope"]): row for row in report["metrics"]}
    assert by_mode_scope[("D_LEX", "root_cause_only")]["Hit@1"] == 0.0
    assert by_mode_scope[("D_LEX", "all_valid_anchors")]["Hit@1"] == 1.0
    assert by_mode_scope[("P_DUAL_PRESENT", "root_cause_only")]["CandidateRecall@100"] == 1.0
    assert report["paired_deltas"][0]["DeltaHit@1"] == 1.0
    assert report["paired_deltas"][0]["DeltaMRR"] == pytest.approx(2 / 3)
    assert Path(report["artifacts"]["metrics_csv"]).is_file()
    assert Path(report["artifacts"]["report_markdown"]).is_file()


def test_oracle_runner_uses_only_prepared_ground_truth(tmp_path: Path):
    cases = tmp_path / "oracle-cases.jsonl"
    cases.write_text(json.dumps(_case("oracle-only", patch=True)) + "\n", encoding="utf-8")
    prepared = prepare_vf_inputs(cases, tmp_path / "oracle-inputs")
    inputs_dir = Path(prepared["inputs_dir"])
    for artifact_dir in (inputs_dir / "catalogs", inputs_dir / "inventory_cache"):
        for artifact in artifact_dir.iterdir():
            artifact.unlink()

    result = run_vf_mode("ORACLE", inputs_dir, tmp_path / "oracle-results", progress=False)
    rows = _read(Path(result["results"]))
    assert result["completed"] == 1
    assert rows[0]["output_type"] == "ground_truth_set"
    assert rows[0]["vulnerable_functions"]


def test_metrics_report_explicit_denominators_for_partial_and_paired_runs(tmp_path: Path):
    cases = tmp_path / "cases.jsonl"
    cases.write_text(
        json.dumps(_case("one", patch=True)) + "\n"
        + json.dumps(_case("two", patch=True)) + "\n",
        encoding="utf-8",
    )
    prepared = prepare_vf_inputs(cases, tmp_path / "inputs")
    inputs_dir = Path(prepared["inputs_dir"])
    results_dir = tmp_path / "results" / "partial"

    run_vf_mode(
        "D_LEX", inputs_dir, tmp_path / "results", run_id="partial",
        localizer=_fake_localizer, progress=False, case_limit=1,
    )
    run_vf_mode(
        "P_DUAL_PRESENT", inputs_dir, tmp_path / "results", run_id="partial",
        localizer=_fake_localizer, progress=False,
    )

    def fail_one_hidden(case, config_id, **kwargs):
        if case.case_id == "two":
            raise RuntimeError("fixture ranking failure")
        return _fake_localizer(case, config_id, **kwargs)

    run_vf_mode(
        "P_DUAL_HIDDEN", inputs_dir, tmp_path / "results", run_id="partial",
        localizer=fail_one_hidden, progress=False,
    )
    report = compute_vf_report(inputs_dir, results_dir, tmp_path / "report")
    metrics = {
        (row["mode"], row["gt_scope"]): row
        for row in report["metrics"]
    }
    dlex = metrics[("D_LEX", "root_cause_only")]
    assert dlex["RankMetricDenominatorCases"] == 2
    assert dlex["missing_records"] == 1
    assert dlex["RuntimeRecords"] == 1
    assert dlex["RuntimeMsMean"] == pytest.approx(4.0)

    hidden = metrics[("P_DUAL_HIDDEN", "root_cause_only")]
    assert hidden["CandidateRecall@100"] == pytest.approx(0.5)
    assert hidden["CandidateRecallDenominatorCases"] == 2
    assert hidden["failed_records"] == 1
    paired = next(row for row in report["paired_deltas"] if row["gt_scope"] == "root_cause_only")
    assert paired["paired_cases"] == 2
    assert paired["paired_both_complete_records"] == 1
    assert paired["paired_hidden_failed_records"] == 1
    assert "failed and missing records score zero" in report["metric_definitions"]["paired_deltas"]


def test_new_dual_protocol_caps_tracker_candidates_before_pairwise(tmp_path: Path, monkeypatch):
    from f_vra.localization.models import FunctionInfo

    functions = [
        FunctionInfo(
            function_name=f"function_{index}", qualname=f"function_{index}", file_path=f"pkg/{index}.py",
            start_line=1, end_line=2, source=f"def function_{index}():\n    return {index}\n",
        )
        for index in range(140)
    ]
    monkeypatch.setattr(rq3, "load_inventory", lambda *args, **kwargs: (functions, "tree", "inventory"))
    import f_vra.localization.code.tracker as tracker_module
    import f_vra.localization.retrieval.candidates as candidate_module
    import f_vra.localization.sources.patch as patch_module

    monkeypatch.setattr(tracker_module, "track_patch_candidates", lambda fs, patch, use_type_engine=False: {item.identity: {"tracked"} for item in fs})
    monkeypatch.setattr(candidate_module, "lexical_scores", lambda query, fs: {item.identity: 1.0 for item in fs})
    monkeypatch.setattr(rq3, "_strict_semantic_scores", lambda query, fs, **kwargs: ({item.identity: 0.5 for item in fs}, "stub"))
    monkeypatch.setattr(candidate_module, "reciprocal_rank_fusion", lambda lexical, dense: {key: float(index) for index, key in enumerate(lexical)})
    monkeypatch.setattr(patch_module, "parse_patch_text", lambda text: object())
    pairwise_sizes = []

    def pairwise(query, candidates, relevance, evidence):
        pairwise_sizes.append(len(candidates))
        return ({item.identity: 1.0 / (index + 1) for index, item in enumerate(candidates)}, {"used": True})

    monkeypatch.setattr(rq3, "_strict_pairwise", pairwise)
    case = rq3.RQ3CaseInput(
        case_id="case", cve_vf_group_id="CVE::sample", cve_id="CVE", package="sample", repo_url="local",
        vulnerable_ref="ref", description="description", source_path=FIXTURE, patch_available=True,
        patch_text="diff", snapshot_id="snap",
    )
    result = rq3.localize_case(case, "P_DUAL", protocol={"candidate_limit": 100})
    assert pairwise_sizes == [100]
    assert result.candidate_count == 100
    assert result.raw_candidate_count == 140
    assert result.metadata["candidate_generation"]["candidate_limit"] == 100


def test_single_object_ground_truth_and_semantic_no_entity_fails_without_fallback(monkeypatch):
    normalized = normalize_ground_truth({
        "case_id": "single", "verified_vfs": {
            "file_path": "pkg/lib.py", "qualified_name": "Client.fetch", "label": "root_cause_vf",
        },
    })
    assert len(normalized["vulnerable_functions"]) == 1
    assert normalized["vulnerable_functions"][0]["role"] == "root_cause_vf"

    from f_vra.localization.ranking.methods.description import DescriptionEnrichment

    monkeypatch.setattr(rq3, "load_inventory", lambda *args, **kwargs: ([], "tree", "inventory"))
    monkeypatch.setattr(
        "f_vra.localization.ranking.methods.description.enrich_description_with_llm_entities",
        lambda description: DescriptionEnrichment(status="used", text=description, entities={"weakness": "CWE-22"}, model="stub"),
    )
    case = rq3.RQ3CaseInput(
        case_id="case", cve_vf_group_id="CVE::sample", cve_id="CVE", package="sample", repo_url="local",
        vulnerable_ref="ref", description="description", source_path=FIXTURE,
    )
    with pytest.raises(LocalizationStageError, match="no usable attack_vector/root_cause") as captured:
        rq3.localize_case(case, "D_SEM", protocol={"require_av_or_root_cause": True})
    assert captured.value.metadata["entity_extraction"]["failed"] is True


def test_d_sem_extraction_failure_is_a_miss_and_reports_no_fallback(tmp_path: Path):
    cases = tmp_path / "cases.jsonl"
    cases.write_text(json.dumps(_case("one", patch=False)) + "\n", encoding="utf-8")
    inputs_dir = Path(prepare_vf_inputs(cases, tmp_path / "inputs")["inputs_dir"])

    def fail_extraction(case, config_id, **kwargs):
        raise LocalizationStageError(
            "no usable AV/root-cause entities", stage="entity_extraction",
            metadata={"entity_extraction": {"entities": {}, "usable": False, "failed": True}},
        )

    result = run_vf_mode("D_SEM", inputs_dir, tmp_path / "results", run_id="dsem", localizer=fail_extraction, progress=False)
    report = compute_vf_report(inputs_dir, Path(tmp_path / "results") / "dsem", tmp_path / "report")
    row = next(item for item in report["metrics"] if item["mode"] == "D_SEM" and item["gt_scope"] == "root_cause_only")
    assert result["failed"] == 1
    assert row["Hit@1"] == 0.0 and row["MRR"] == 0.0
    assert row["EntityExtractionCoverage"] == 0.0
    assert row["ExtractionFailureRate"] == 1.0
    assert row["FallbackRate"] == 0.0


def test_vf_cli_exposes_separated_prepare_run_and_offline_metrics(monkeypatch, tmp_path: Path):
    from typer.testing import CliRunner

    from f_vra.cli.commands import eval as eval_commands
    from f_vra.cli.main import app

    monkeypatch.setattr(eval_commands, "dispatch_vf_mode", lambda mode, inputs, output, **kwargs: {
        "mode": mode, "completed": 1, "failed": 0,
    })
    monkeypatch.setattr(eval_commands, "compute_vf_report", lambda inputs, results, output: {
        "report": str(output),
    })
    inputs_dir = tmp_path / "inputs"
    inputs_dir.mkdir()
    results_dir = tmp_path / "results"
    results_dir.mkdir()
    runner = CliRunner()
    mode_run = runner.invoke(app, [
        "eval", "vf-run", "D_LEX", str(inputs_dir), "--output-root", str(results_dir), "--no-progress",
    ])
    assert mode_run.exit_code == 0, mode_run.output
    assert json.loads(mode_run.stdout)["mode"] == "D_LEX"
    report = runner.invoke(app, ["eval", "vf-metrics", str(inputs_dir), str(results_dir)])
    assert report.exit_code == 0, report.output
    assert json.loads(report.stdout)["report"].endswith("results\\report")
