# Experiments

Runnable experiment entry points.

## Reproducible evaluation harness

Install the experiment dependencies and use the `f-vra eval` lifecycle. Raw
Docker, JARVIS, and cache calls are kept behind these commands so every run
records the same contracts and event fields.

```powershell
pip install -e ".[dev,experiments]"

# Freeze commits and the accepted CVE/VF dataset.
f-vra eval freeze --output-dir experiments/dataset/current

# Build immutable project images and derive installed package identities.
f-vra eval build-env --dataset experiments/dataset/current
f-vra eval audit --dataset experiments/dataset/current

# Import manual_label from an XLSX sheet or CSV export as pending candidates.
# auto_reachability is retained only as historical output and is never an oracle label.
f-vra eval oracle-import "C:\path\to\project.xlsx - manual_annotation.csv" --dataset experiments/dataset/current
f-vra eval oracle-review experiments/oracle/reviews.jsonl --dataset experiments/dataset/current

# Check Fresh determinism, run R0-R3, ablations, and reports.
f-vra eval determinism --dataset experiments/dataset/current
f-vra eval compare --dataset experiments/dataset/current --seeds 1:30
f-vra eval ablate --dataset experiments/dataset/current
f-vra eval report --dataset experiments/dataset/current
```

`build-env` permits `--project-id` and `--limit` for smoke tests. A partial
build merges its outputs by project; it never silently replaces other project
rows. Analysis containers run with no network, eight CPUs, and 16 GiB memory.

### Dataset and run contracts

The dataset directory contains `projects`, `environments`, `packages`,
`vulnerabilities`, and `queries` Parquet files plus source, environment, and
eligibility audits. Each run contains:

```text
runs/<run-id>/config.yaml
runs/<run-id>/query_results.parquet
runs/<run-id>/artifact_events.parquet
runs/<run-id>/analysis_events.parquet
runs/<run-id>/environment.json
runs/<run-id>/summary.json
```

Research decisions are `REACHABLE`, `UNREACHABLE`, or `UNKNOWN`. Missing
source, native/dynamic boundaries, parse failures, timeouts, VF mismatches, and
exhausted budgets are explicit `UNKNOWN_*` reasons. Oracle accuracy uses only
labels whose `review_status` is `accepted`; Fresh agreement is reported as a
separate same-backend metric.
