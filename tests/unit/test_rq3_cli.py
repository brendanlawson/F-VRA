from __future__ import annotations

import hashlib
import json
from pathlib import Path

from typer.testing import CliRunner

from f_vra.cli.commands import eval as eval_commands
from f_vra.cli.main import app


def test_rq3_prepare_runs_audit_then_freeze(monkeypatch, tmp_path: Path):
    benchmark = tmp_path / "benchmark.jsonl"
    benchmark.write_text("{}\n", encoding="utf-8")
    output = tmp_path / "cases.jsonl"
    calls = []

    def fake_audit(benchmark_path, downstream_path):
        calls.append(("audit", benchmark_path, downstream_path))
        return {"raw_rows": 1, "accepted_rows": 1}

    def fake_freeze(benchmark_path, output_path, **kwargs):
        calls.append(("freeze", benchmark_path, output_path, kwargs))
        return {"status": "FROZEN", "full_batch_ready": True}

    monkeypatch.setattr(eval_commands, "audit_rq3_benchmark", fake_audit)
    monkeypatch.setattr(eval_commands, "freeze_rq3_benchmark", fake_freeze)
    result = CliRunner().invoke(app, [
        "eval", "rq3-prepare", "--benchmark", str(benchmark), "--output", str(output),
        "--materialize-sources", "--materialize-patches",
    ])

    assert result.exit_code == 0, result.output
    assert [item[0] for item in calls] == ["audit", "freeze"]
    assert calls[1][3]["materialize_sources"] is True
    assert calls[1][3]["materialize_patches"] is True
    assert json.loads(result.stdout)["freeze"]["full_batch_ready"] is True


def test_rq3_run_executes_configs_in_order_and_reports(monkeypatch, tmp_path: Path):
    cases = tmp_path / "cases.jsonl"
    case_row = {
        "case_id": "case-a", "cve_vf_group_id": "CVE-1::sample", "cve_id": "CVE-1",
        "package": "sample", "repo_url": "local", "vulnerable_ref": "deadbeef",
        "description": "request fetch", "source_path": str(tmp_path / "source"),
        "verified_vfs": ["Client.fetch"],
    }
    case_bytes = (json.dumps(case_row) + "\n").encode("utf-8")
    cases.write_bytes(case_bytes)
    (tmp_path / "cases.summary.json").write_text(json.dumps({
        "status": "FROZEN",
        "full_batch_ready": True,
        "accepted_rows": 1,
        "cases_sha256": hashlib.sha256(case_bytes).hexdigest(),
    }), encoding="utf-8")
    calls = []

    def fake_batch(cases_path, config_id, output_root, *, limit, resume):
        calls.append((config_id, limit, resume))
        result_path = tmp_path / f"{config_id}.jsonl"
        result_path.write_text(json.dumps({
            "case_id": "case-a", "config_id": config_id, "status": "complete",
            "output_type": "ranked", "candidate_count": 1,
            "candidate_details": [{"qualified_name": "Client.fetch", "file_path": "client.py"}],
            "predictions": [{"qualified_name": "Client.fetch", "rank": 1}],
        }) + "\n", encoding="utf-8")
        return {
            "config_id": config_id,
            "case_count": 1,
            "failed": 0,
            "results": str(result_path),
            "localization_quality": [{"config": config_id, "Hit@1": 1.0}],
        }

    monkeypatch.setattr(eval_commands, "run_localization_batch", fake_batch)
    output_root = tmp_path / "runs"
    report_dir = tmp_path / "report"
    result = CliRunner().invoke(app, [
        "eval", "rq3-run", str(cases),
        "--config", "D_LEX", "--config", "P_MODIFIED",
        "--output-root", str(output_root), "--report-dir", str(report_dir),
    ])

    assert result.exit_code == 0, result.output
    assert calls == [("D_LEX", 0, True), ("P_MODIFIED", 0, True)]
    batch_summary = json.loads((output_root / "batch_summary.json").read_text(encoding="utf-8"))
    assert [row["config_id"] for row in batch_summary["configs"]] == ["D_LEX", "P_MODIFIED"]
    report_quality = json.loads((report_dir / "result_1_localization_quality.json").read_text(encoding="utf-8"))
    assert {row["config"] for row in report_quality} == {"D_LEX", "P_MODIFIED"}
    assert not (report_dir / "result_2_downstream_consequence.json").exists()


def test_rq3_run_reuses_complete_summary_without_reading_large_checkpoint(monkeypatch, tmp_path: Path):
    cases = tmp_path / "cases.jsonl"
    case_row = {
        "case_id": "case-a", "cve_vf_group_id": "CVE-1::sample", "cve_id": "CVE-1",
        "package": "sample", "repo_url": "local", "vulnerable_ref": "deadbeef",
        "description": "request fetch", "source_path": str(tmp_path / "source"),
        "verified_vfs": ["Client.fetch"],
    }
    case_bytes = (json.dumps(case_row) + "\n").encode("utf-8")
    cases.write_bytes(case_bytes)
    (tmp_path / "cases.summary.json").write_text(json.dumps({
        "status": "FROZEN", "full_batch_ready": True, "accepted_rows": 1,
        "cases_sha256": hashlib.sha256(case_bytes).hexdigest(),
    }), encoding="utf-8")

    fingerprint = "a" * 64
    input_hash = "frozen-input-hash"
    monkeypatch.setattr(eval_commands, "_fingerprint", lambda *args: (fingerprint, input_hash))
    output_root = tmp_path / "runs"
    run_id = f"rq3-d_lex-{fingerprint[:16]}"
    run_dir = output_root / run_id
    run_dir.mkdir(parents=True)
    # The resume path may stat this checkpoint, but must not parse its payload.
    (run_dir / "case_results.jsonl").write_text("intentionally-not-json\n", encoding="utf-8")
    quality = [{"config": "D_LEX", "Hit@1": 1.0, "Coverage": 1.0}]
    (run_dir / "summary.json").write_text(json.dumps({
        "run_id": run_id, "run_fingerprint": fingerprint, "dataset_hash": input_hash,
        "config_id": "D_LEX", "case_count": 1, "completed": 1, "failed": 0,
        "ineligible": 0, "not_applicable": 0, "localization_quality": quality,
    }), encoding="utf-8")

    def unexpected_batch(*args, **kwargs):
        raise AssertionError("complete matching run summary should be reused")

    monkeypatch.setattr(eval_commands, "run_localization_batch", unexpected_batch)
    result = CliRunner().invoke(app, [
        "eval", "rq3-run", str(cases), "--config", "D_LEX",
        "--output-root", str(output_root),
    ])

    assert result.exit_code == 0, result.output
    assert "Reusing completed RQ3 family D_LEX" in result.output
    assert json.loads((output_root / "batch_summary.json").read_text(encoding="utf-8"))["configs"][0]["run_id"] == run_id
    report_quality = json.loads((output_root / "report" / "result_1_localization_quality.json").read_text(encoding="utf-8"))
    assert report_quality == quality


def test_rq3_run_routes_explicit_prior_summary_to_compatibility_resume(monkeypatch, tmp_path: Path):
    cases = tmp_path / "cases.jsonl"
    row = {
        "case_id": "case-a", "cve_vf_group_id": "CVE-1::sample", "cve_id": "CVE-1",
        "package": "sample", "repo_url": "local", "vulnerable_ref": "deadbeef",
        "description": "request fetch", "source_path": str(tmp_path / "source"),
        "verified_vfs": ["Client.fetch"],
    }
    case_bytes = (json.dumps(row) + "\n").encode("utf-8")
    cases.write_bytes(case_bytes)
    (tmp_path / "cases.summary.json").write_text(json.dumps({
        "status": "FROZEN", "full_batch_ready": True, "accepted_rows": 1,
        "cases_sha256": hashlib.sha256(case_bytes).hexdigest(),
    }), encoding="utf-8")
    output_root = tmp_path / "runs"
    prior_dir = output_root / "rq3-d_sem-legacy12345678"
    prior_dir.mkdir(parents=True)
    prior_summary = prior_dir / "summary.json"
    prior_summary.write_text("{}", encoding="utf-8")
    observed = {}

    def fake_batch(cases_path, config_id, root, *, limit, resume, **kwargs):
        observed.update(config=config_id, resume_from_summary=kwargs.get("resume_from_summary"))
        result_path = tmp_path / "D_SEM.jsonl"
        result_path.write_text(json.dumps({"case_id": "case-a", "config_id": config_id, "status": "complete"}) + "\n", encoding="utf-8")
        return {"config_id": config_id, "case_count": 1, "failed": 0, "results": str(result_path), "localization_quality": []}

    monkeypatch.setattr(eval_commands, "run_localization_batch", fake_batch)
    result = CliRunner().invoke(app, [
        "eval", "rq3-run", str(cases), "--config", "D_SEM",
        "--output-root", str(output_root), "--resume-from-summary", str(prior_summary), "--no-report",
    ])

    assert result.exit_code == 0, result.output
    assert observed == {"config": "D_SEM", "resume_from_summary": prior_summary}


def test_rq3_run_routes_partial_checkpoint_to_compatibility_resume(monkeypatch, tmp_path: Path):
    cases = tmp_path / "cases.jsonl"
    row = {
        "case_id": "case-a", "cve_vf_group_id": "CVE-1::sample", "cve_id": "CVE-1",
        "package": "sample", "repo_url": "local", "vulnerable_ref": "deadbeef",
        "description": "request fetch", "source_path": str(tmp_path / "source"),
        "verified_vfs": ["Client.fetch"],
    }
    case_bytes = (json.dumps(row) + "\n").encode("utf-8")
    cases.write_bytes(case_bytes)
    (tmp_path / "cases.summary.json").write_text(json.dumps({
        "status": "FROZEN", "full_batch_ready": True, "accepted_rows": 1,
        "cases_sha256": hashlib.sha256(case_bytes).hexdigest(),
    }), encoding="utf-8")
    output_root = tmp_path / "runs"
    checkpoint = output_root / "rq3-d_sem-legacy12345678"
    checkpoint.mkdir(parents=True)
    observed = {}

    def fake_batch(cases_path, config_id, root, *, limit, resume, **kwargs):
        observed.update(config=config_id, resume_from_checkpoint=kwargs.get("resume_from_checkpoint"))
        result_path = tmp_path / "D_SEM.jsonl"
        result_path.write_text(json.dumps({
            "case_id": "case-a", "config_id": config_id, "status": "complete",
            "output_type": "ranked", "candidate_count": 1,
            "candidate_details": [{"qualified_name": "Client.fetch", "file_path": "client.py"}],
            "predictions": [{"qualified_name": "Client.fetch", "rank": 1}],
        }) + "\n", encoding="utf-8")
        return {
            "config_id": config_id, "case_count": 1, "failed": 0,
            "results": str(result_path), "localization_quality": [],
        }

    monkeypatch.setattr(eval_commands, "run_localization_batch", fake_batch)
    result = CliRunner().invoke(app, [
        "eval", "rq3-run", str(cases), "--config", "D_SEM",
        "--output-root", str(output_root), "--resume-from-checkpoint", str(checkpoint),
        "--no-report",
    ])

    assert result.exit_code == 0, result.output
    assert observed == {"config": "D_SEM", "resume_from_checkpoint": checkpoint}


def test_rq3_run_blocks_full_batch_when_freeze_is_not_ready(monkeypatch, tmp_path: Path):
    cases = tmp_path / "cases.jsonl"
    case_bytes = b'{}\n'
    cases.write_bytes(case_bytes)
    (tmp_path / "cases.summary.json").write_text(json.dumps({
        "status": "FROZEN",
        "full_batch_ready": False,
        "accepted_rows": 1,
        "cases_sha256": hashlib.sha256(case_bytes).hexdigest(),
    }), encoding="utf-8")
    called = False

    def fake_batch(*args, **kwargs):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(eval_commands, "run_localization_batch", fake_batch)
    result = CliRunner().invoke(app, [
        "eval", "rq3-run", str(cases), "--config", "D_LEX",
    ])

    assert result.exit_code != 0
    assert not called
    assert "full_batch_ready=true" in result.output


def test_rq3_vf_build_gates_on_summary_for_the_selected_manifest(monkeypatch, tmp_path: Path):
    cases = tmp_path / "prepared_manifest_v3.jsonl"
    cases.write_text("{}\n", encoding="utf-8")
    (tmp_path / "prepared_manifest_v3.summary.json").write_text(
        json.dumps({"status": "FROZEN", "full_batch_ready": True}), encoding="utf-8",
    )
    localized = tmp_path / "localized.jsonl"
    localized.write_text("{}\n", encoding="utf-8")
    downstream = tmp_path / "downstream.jsonl"
    downstream.write_text("{}\n", encoding="utf-8")
    observed = {}

    def fake_preflight(freeze_summary, environment_summary, dataset):
        observed["freeze_summary"] = freeze_summary
        return {"ready": True, "checks": {}}

    def fake_build(cases_path, results, downstream_path, dataset, output, **kwargs):
        observed["cases"] = cases_path
        observed["result"] = results
        return {"variants": 1}

    monkeypatch.setattr(eval_commands, "_rq3_preflight", fake_preflight)
    monkeypatch.setattr(eval_commands, "build_rq3_vf_variants", fake_build)
    result = CliRunner().invoke(app, [
        "eval", "rq3-vf-build", "--cases", str(cases),
        "--localization-results", str(localized), "--downstream", str(downstream),
        "--output", str(tmp_path / "variants.parquet"),
    ])

    assert result.exit_code == 0, result.output
    assert observed["freeze_summary"] == cases.with_name("prepared_manifest_v3.summary.json")
    assert observed["cases"] == cases


def test_rq3_eval_vf_uses_freeze_summary_recorded_by_binding_builder(monkeypatch, tmp_path: Path):
    variants = tmp_path / "variants.parquet"
    variants.write_bytes(b"placeholder")
    freeze_summary = tmp_path / "prepared_manifest_v3.summary.json"
    freeze_summary.write_text("{}", encoding="utf-8")
    variants.with_suffix(".summary.json").write_text(
        json.dumps({"freeze_summary_path": str(freeze_summary)}), encoding="utf-8",
    )
    observed = {}

    class Runner:
        queries = []

        def run(self, output_root, **kwargs):
            return {"run_id": "test-run"}

    monkeypatch.setattr(eval_commands, "read_parquet", lambda path: [
        {"query_id": "q-1", "variant": "D_LEX_TOP1", "vf_set": []},
    ])
    monkeypatch.setattr(eval_commands, "_runner", lambda *args: Runner())

    def fake_preflight(path, environment_summary, dataset):
        observed["freeze_summary"] = path
        return {"ready": True, "checks": {}}

    monkeypatch.setattr(eval_commands, "_rq3_preflight", fake_preflight)
    result = CliRunner().invoke(app, [
        "eval", "vf", str(variants), "--output-root", str(tmp_path / "runs"),
    ])

    assert result.exit_code == 0, result.output
    assert observed["freeze_summary"] == freeze_summary
