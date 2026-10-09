# F-VRA

F-VRA (Function-level Vulnerability Reachability Analysis) analyzes Python and
PyPI software to connect disclosed vulnerabilities with vulnerable functions and
determine whether application code can reach them.

The repository contains the rebranded application formerly known as PyShare.
The Python distribution is `f-vra`, the import root is `f_vra`, and the command
line entry point is `f-vra`.

## What F-VRA does

- Resolves CVE/GHSA metadata and candidate patches.
- Indexes Python packages, call graphs, public APIs, and dependency summaries.
- Builds project usage graphs and identifies application entry points.
- Localizes vulnerable functions using lexical, semantic, patch-aware, and
  oracle-backed evaluation modes.
- Composes package summaries and project usage into reachability results.

The main modules are documented in [`docs/`](docs/index.md):

| Area | Documentation |
| --- | --- |
| Vulnerability localization | [`docs/localization.md`](docs/localization.md) |
| Package analysis | [`docs/package-analysis.md`](docs/package-analysis.md) |
| Project analysis | [`docs/project-analysis.md`](docs/project-analysis.md) |
| Reachability | [`docs/reachability.md`](docs/reachability.md) |
| Knowledge base | [`docs/knowledge-base.md`](docs/knowledge-base.md) |
| Evaluation data | [`docs/dataset-card.md`](docs/dataset-card.md) |

## Requirements and installation

F-VRA requires Python 3.11 or newer. From a fresh checkout:

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,experiments]"
```

Verify the installation:

```bash
f-vra --help
python -c "import f_vra; from f_vra.cli.main import app; print(f_vra.__file__)"
pytest
```

The optional `experiments` extra adds the data-analysis dependencies used by
the evaluation pipeline. The vendored JARVIS source under `vendor/` remains in
its original namespace and attribution.

## Basic usage

The CLI exposes the `index`, `localize`, `localization`, `scan`, `status`, and
`eval` command groups:

```bash
f-vra --help
f-vra index --help
f-vra localize --help
f-vra scan --help
f-vra eval --help
```

For module-oriented execution, use the renamed import root:

```bash
python -m f_vra.cli.main eval --help
```

## Configuration and secrets

Copy the example configuration when a provider-backed workflow needs it:

```bash
cp .env.example .env
```

`.env` is ignored by Git. Provider keys and endpoints are read from the
environment; commonly used settings include `LOCAL_LLM_API_KEY`,
`LOCAL_LLM_BASE_URL`, `LOCAL_LLM_MODEL`, `LOCAL_EMBEDDING_API_KEY`,
`LOCAL_EMBEDDING_BASE_URL`, `LOCAL_EMBEDDING_MODEL`, `GITHUB_TOKEN`, and
`NVD_API_KEY`.

F-VRA-specific overrides use the `F_VRA_` prefix, including
`F_VRA_RQ3_SNAPSHOT_ROOT`, `F_VRA_JARVIS_ROOT`, and
`F_VRA_PROJECT_ROOT`. Local caches default below `~/.f_vra/`.

Never commit API keys, access tokens, private keys, or populated `.env` files.
Before publishing a fork, review tracked files and generated logs for secrets.

## Reproducing the vulnerability-function evaluation

The full CVE-to-vulnerable-function workflow is documented in
[`experiments/vf/README.md`](experiments/vf/README.md). The short workflow is:

```bash
python -m f_vra.cli.main eval vf-prepare \
  --cases experiments/vf/prepared_manifest_v6.jsonl \
  --output-root experiments/vf/inputs

python -m f_vra.cli.main eval vf-run D_LEX <inputs-dir> \
  --run-id vf-local --output-root experiments/vf/results

python -m f_vra.cli.main eval vf-metrics <inputs-dir> \
  experiments/vf/results/vf-local
```

The checked-in manifests and JSONL inputs are frozen research artifacts. Some
records contain absolute source paths from the machine that produced them; on
another machine, follow the materialization instructions in the experiment
guide and create a new manifest rather than editing frozen evidence by hand.

For the Conda-based evaluation environment:

```bash
conda env create -f environment-vf.yml
conda activate f-vra-vf
```

## Repository layout

```text
src/f_vra/             Application package and CLI
tests/                 Unit tests and fixtures
docs/                  Module and data documentation
experiments/            Reproducible evaluation workflows
data/                  Benchmarks and scanner artifacts
vendor/pythonJaRvis/   Vendored third-party call-graph dependency
configs/               Local project manifests and examples
```

## Development

Run the test suite from the repository root:

```bash
pytest
```

The project uses a `src/` layout and the test configuration imports
`src/f_vra` directly. Keep generated caches, provider responses, and local
runtime data out of commits; the repository `.gitignore` already excludes the
standard locations.

