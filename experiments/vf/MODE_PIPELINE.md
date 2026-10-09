# CVE-to-VF mode pipeline

This pipeline prepares immutable, mode-specific inputs, runs one mode at a time, and calculates metrics later from saved records. The existing localizers remain the method implementations; the new adapter enforces the experiment views and the P_DUAL Top-100 protocol.

## Conda environment

The checked-in `environment-vf.yml` describes the Python 3.11 VF runtime and `conda-lock.yml` pins resolved packages for Linux, Windows, and macOS. Create the environment on each machine, then install this repository in editable mode:

```sh
# Run once if conda-lock is not installed in the base Conda installation.
conda install -n base -c conda-forge conda-lock
conda-lock install -n f_vra-vf conda-lock.yml
conda activate f_vra-vf
python -m pip install --no-deps --editable .
```

Configure chat and embedding credentials separately on each worker (for example, in a local `.env`). Never put provider credentials in the input bundles. Use the same model, endpoint, and retrieval settings on every worker and aggregator; the runner fingerprints those settings but not API keys. The aggregator can omit API keys because merge and metrics make no model calls. The first installed package set should be recorded with `conda list --explicit` if the machines need auditing beyond the lock file.

## 1. Prepare inputs and function catalogs

Use the frozen v6 manifest. Preparation checks the eligible source snapshots and vulnerable references, writes a role-preserving `ground_truth.jsonl`, builds a `FunctionCatalog` for each distinct vulnerable source snapshot, and writes separate inputs for D_LEX, D_SEM, P_DUAL_PRESENT, P_DUAL_HIDDEN, and ORACLE. The localizer input files contain no ground-truth labels or CWE fields. P_DUAL_PRESENT and P_DUAL_HIDDEN use the exact same eligible, materialized-patch cohort; the hidden view has no patch payload or patch metadata.

```sh
python -m f_vra.cli.main eval vf-prepare \
  --cases experiments/vf/prepared_manifest_v6.jsonl \
  --output-root experiments/vf/inputs \
  --workers 2
```

Run preparation once on the machine that has the source snapshots. Catalog creation uses two local processes by default; adjust `--workers` to match the preparation machine. For a small provider-free setup, add `--limit 2`; this produces a different immutable input ID and must not be mixed with full-dataset runs. The full output includes the normalized GT, FunctionCatalogs, parser caches, and the five mode input files.

If the matching prepared input ID, FunctionCatalogs, and parser caches are already installed, reuse them and skip preparation; it may rebuild or verify many GB of artifacts.

## 2. Create small case-ID shard plans

Use this path when every machine already has the same prepared input ID, source snapshots, FunctionCatalogs, and parser caches. It reads and hashes only the small frozen mode input files; it does not walk source trees, open every catalog/cache, or copy/rebuild any of those artifacts. Cases are assigned by the first 64 bits of `SHA256(snapshot_id)` modulo the shard count, so cases sharing a snapshot remain together. Each plan contains case IDs, cohort checksums, and the parent input fingerprint only.

```sh
python -m f_vra.cli.main eval vf-shard-plan \
  experiments/vf/inputs/<vf-input-id> \
  --shard-count 6 \
  --output-root experiments/vf/shard-plans/<vf-input-id>
```

Copy only the corresponding `shard_manifest.json` to each machine. Each machine needs the same prepared `manifest.json` and four mode JSONL files under `experiments/vf/inputs/<vf-input-id>`; together these control files are about 49 MB. If absent, transfer those files only, not the source/catalog/cache trees. The source snapshots must remain under the local repository's `experiments/vf/source_cache` plus the external `~/rq3-snapshots` root used by this frozen input; set `F_VRA_RQ3_SNAPSHOT_ROOT` if that external root is elsewhere. Catalog/parser-cache files must remain under that input ID's `catalogs/` and `inventory_cache/` directories. Frozen Windows paths are rebased to these local roots without changing input checksums. The normalized GT is needed only on the aggregation machine.

If one or more machines do not have these source/catalog/cache artifacts, the separate portable flow `eval vf-shard` can copy them into a bundle. That flow is intentionally slower and consumes substantial disk space.

## 3. Run each machine shard

Give every machine the same run ID. Start with `--workers 1` for the provider canary; after checking for repeated 429/timeouts, continue with `--workers 2`. The command runs D_LEX, D_SEM, P_DUAL_PRESENT, then P_DUAL_HIDDEN. It uses a single checkpoint writer while case workers run concurrently, resumes completed records, retries failed records, and keeps PRESENT before HIDDEN so their embedding cache can be reused.

Use `--case-limit 1` for the first canary record in each mode. The runner marks this partial run as `canary`, so it cannot be merged by mistake. Continue with the same run ID and `--case-limit 0` to process the full shard; completed canary rows stay checkpointed and failed rows are retried.

```sh
python -m f_vra.cli.main eval vf-run-index-shard \
  experiments/vf/inputs/<vf-input-id> \
  experiments/vf/shard-plans/<vf-input-id>/machine-001-of-006/shard_manifest.json \
  --run-id vf-v6-main \
  --workers 1 \
  --case-limit 1 \
  --output-root experiments/vf/results

# After inspecting the canary, resume the same run with two case workers.
python -m f_vra.cli.main eval vf-run-index-shard \
  experiments/vf/inputs/<vf-input-id> \
  experiments/vf/shard-plans/<vf-input-id>/machine-001-of-006/shard_manifest.json \
  --run-id vf-v6-main \
  --workers 2 \
  --case-limit 0 \
  --output-root experiments/vf/results
```

Each machine returns `experiments/vf/results/vf-v6-main/machine-XXX-of-YYY/`. Copy that directory back to the aggregation machine. Machine runs do not include normalized GT. D_SEM and both P_DUAL modes use configured providers. P_DUAL caps candidates before pairwise ranking. D_SEM records extraction errors and does not rank when AV/root-cause entities are unavailable.

## 4. Merge and calculate offline metrics

Pass every shard result directory exactly once. Merge verifies the parent input and mode-code fingerprints, the shard-runner fingerprint, shared Conda lock/Python 3.11 identity, provider configuration, shard identities, mode cohorts, and full per-case coverage. It generates ORACLE centrally from normalized GT and does not call a model. Metrics then reads the full inputs and merged results only.

```sh
python -m f_vra.cli.main eval vf-merge \
  experiments/vf/inputs/<vf-input-id> \
  --shard-run-dir experiments/vf/results/vf-v6-main/machine-001-of-006 \
  --shard-run-dir experiments/vf/results/vf-v6-main/machine-002-of-006 \
  --shard-run-dir experiments/vf/results/vf-v6-main/machine-003-of-006 \
  --shard-run-dir experiments/vf/results/vf-v6-main/machine-004-of-006 \
  --shard-run-dir experiments/vf/results/vf-v6-main/machine-005-of-006 \
  --shard-run-dir experiments/vf/results/vf-v6-main/machine-006-of-006 \
  --run-id vf-v6-main \
  --output-root experiments/vf/results

python -m f_vra.cli.main eval vf-metrics \
  experiments/vf/inputs/<vf-input-id> \
  experiments/vf/results/vf-v6-main
```

The metrics command produces `metrics.json`, `metrics.csv`, `report.md`, `paired_deltas.csv`, and `paired_deltas.md`. The report separates `root_cause_only` from `all_valid_anchors`, includes Hit@1/3/5/10 and MRR, case-level P_DUAL CandidateRecall@100 (at least one valid VF in Top-100) plus anchor-level recall, D_SEM extraction coverage/failure/fallback, runtime and provider usage, and paired PRESENT-minus-HIDDEN deltas over common case IDs. Failed or missing records score zero in quality metrics; the tables report status counts and each metric's denominator. Provider token cost remains null when the provider does not expose pricing.
