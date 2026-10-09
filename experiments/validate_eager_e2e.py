"""Run the EagerShared acceptance check with the real Docker/JARVIS backend."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from f_vra.evaluation.backend import JarvisAdapter
from f_vra.evaluation.io import read_parquet, write_json, write_parquet
from f_vra.evaluation.runner import ExperimentRunner


class SmallFixtureAdapter(JarvisAdapter):
    """Use real inventory, then select the single exported fixture root."""

    def inventory(self, package, env):  # noqa: ANN001
        roots = super().inventory(package, env)
        selected = [root for root in roots if root == "asyncer.create_task_group"]
        if selected != ["asyncer.create_task_group"]:
            raise RuntimeError(f"fixture export missing from real inventory: {selected!r}")
        return selected


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dataset", type=Path, default=Path(".tmp/frozen-dataset2"))
    parser.add_argument("--output", type=Path, default=Path(".tmp/eager-e2e"))
    parser.add_argument("--jarvis-root", type=Path, default=Path("vendor/pythonJaRvis/Jarvis"))
    args = parser.parse_args()

    source_packages = read_parquet(args.source_dataset / "packages.parquet")
    package = next(row for row in source_packages if row["distribution"] == "asyncer")
    environment = next(
        row for row in read_parquet(args.source_dataset / "environments.parquet")
        if row["env_id"] == package["env_id"]
    )
    dataset = args.output / "dataset"
    dataset.mkdir(parents=True, exist_ok=True)
    write_json(dataset / "dataset.json", {"dataset_id": "eager-real-backend-fixture", "protocol_sha256": ""})
    write_parquet(dataset / "projects.parquet", [{"snapshot_id": "fixture-snapshot", "project_id": "fixture"}])
    write_parquet(dataset / "environments.parquet", [environment])
    write_parquet(dataset / "packages.parquet", [package])
    write_parquet(dataset / "queries.parquet", [{
        "query_id": "fixture-query", "candidate_id": "fixture-candidate", "project_id": "fixture",
        "project_snapshot_id": "fixture-snapshot", "env_id": environment["env_id"],
        "cve_id": "CVE-FIXTURE", "affected_package_id": package["package_id"],
        "affected_distribution": "asyncer", "eligibility_reason": "eligible",
        "vf_set": [{"qualified_name": "asyncer._main.get_asynclib"}],
    }])

    runner = ExperimentRunner(dataset, args.jarvis_root)
    runner.adapter = SmallFixtureAdapter(args.jarvis_root)
    runner._project_graph = lambda env: ({
        "usage_index": ["asyncer.create_task_group"], "frontier_complete": True,
        "parse_errors": [], "wall_clock_ms": 0.0,
    }, True)
    runs = args.output / "runs"
    fresh = runner.run(runs, strategy="fresh", order="PROJECT_MAJOR", run_label="eager-e2e-fresh")
    eager = runner.run(runs, strategy="eager_shared", order="PROJECT_MAJOR", run_label="eager-e2e-eager")
    fresh_result = read_parquet(runs / fresh["run_id"] / "query_results.parquet")[0]
    eager_result = read_parquet(runs / eager["run_id"] / "query_results.parquet")[0]
    eager_events = read_parquet(runs / eager["run_id"] / "artifact_events.parquet")
    assert fresh_result["decision"] == eager_result["decision"] == "REACHABLE"
    assert fresh_result["witnesses"] == eager_result["witnesses"]
    assert any(row.get("precomputation") and row.get("event") == "FRAGMENT_BUILD" for row in eager_events)
    assert any(not row.get("precomputation") and row.get("event") == "ARTIFACT_HIT" for row in eager_events)
    assert eager["precomputation_ms"] > 0
    assert eager["cumulative_wall_clock_ms"] >= eager["precomputation_ms"]
    result = {
        "fresh": fresh, "eager": eager, "decision": fresh_result["decision"],
        "witnesses": fresh_result["witnesses"], "checks": "PASS",
    }
    write_json(args.output / "acceptance.json", result)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
