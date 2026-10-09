# Snyk Open Source (Python) — install-based, Dockerized Linux run

This is the **install-based** Snyk Open Source (SCA) scan of the 25-project Python benchmark, run in
a Linux container so that platform-specific wheels resolve. It is the counterpart to the
no-install `snyk test --all-projects` run in [`../`](../README.md) (which covered **0** Python
manifests). Here Snyk scans the **same `requirements.pinned.txt`** sets that osv-scanner consumed.

## Method

Image: `python:3.12-slim` + [`uv`](https://github.com/astral-sh/uv) + Snyk CLI v1.1305.2 (standalone
Linux binary). Host Snyk OAuth config mounted read-write for auto-refresh. Per project:

1. `uv venv --seed /venv -p 3.12` — `--seed` ships `pip` into the venv (Snyk's pip plugin shells out
   to it; a pip-less uv venv is what caused `SNYK-CLI-0000` early on).
2. Best-effort install of the pinned closure: `uv pip install --no-deps --only-binary=:all:` (one-shot,
   then per-line tolerant on failure). **Giant GPU/ML wheels are excluded** (`nvidia-*`, `torch`,
   `tensorflow`, …) — hundreds of MB each, effectively never in Snyk's vuln DB, and they hung the
   Docker engine on the first attempt.
3. `pip freeze` → clean `requirements.txt` of what actually installed (seed tooling stripped).
4. `snyk test --file=requirements.txt --command=/venv/bin/python --package-manager=pip
   --skip-unresolved --json-file-output=...` (`--skip-unresolved` tolerates the packages that
   couldn't be installed).

Raw per-project JSON in `json/`, install+scan logs in `logs/`, `summary.csv` (headline),
`compare_osv.csv` (Snyk vs osv-scanner), `run.log` (timeline). Total run ≈ 90 min.

## Coverage

| | |
|---|---|
| Projects scanned (vulns) | **23 / 25** |
| Projects clean | 2 (potpie, wagtail) |
| Projects errored | **0** |
| Pinned packages installed | **5 502 / 6 034 = 91.2 %** |
| GPU/ML wheels excluded | 134 |
| Other install failures | 278 (no wheel for Linux/py3.12, or pin absent from PyPI) |

This is the headline result: **install-based Snyk on Linux recovers full Python SCA coverage**
(23/25 with findings) where the no-install run got nothing.

## Results vs osv-scanner

Snyk reports **vulnerable *paths*** (a CVE reachable via N dependency chains counts N times). For a
fair comparison with osv-scanner, `compare_osv.csv` also collapses to **unique Snyk advisory IDs**.

| Metric | Snyk (install-based) | osv-scanner |
|---|---|---|
| Vulnerable paths | 9 576 | — |
| **Unique advisories** | **1 141** | **1 228** |
| Distinct CVEs | 1 081 | — |
| Severity (unique) | 21 crit · 469 high · 587 med · 64 low | (not summarized) |

**Snyk's unique-advisory total (1 141) lands within ~7 % of osv-scanner (1 228)** — strong
cross-validation of both tools and the inventory. Per project: Snyk == osv on 2 (Checkmk 37=37,
Drakkar 23=23), Snyk higher on 10, osv higher on 13.

- **Where osv is higher** (Open-LLM 53 vs 88, PharMolix 47 vs 94, gpustack 104 vs 150, Misago 91 vs
  127): Snyk's gap traces to the install step — packages it could not install (GPU-excluded or
  no Linux/py3.12 wheel) are invisible to install-based SCA, whereas osv reads them statically.
- **Where Snyk is higher** (clusterfuzz 106 vs 42, Pixelle 126 vs 117, jumpserver 133 vs 121):
  Snyk's database carries advisories (often npm-style GHSA / multiple advisories per package) that
  OSV does not, plus Snyk adds **severity + fix-version** guidance osv-scanner's raw output omits.

See `compare_osv.csv` for the full per-project table.

## Caveats

- **Not 1:1 with osv-scanner.** ~9 % of pinned packages never installed (GPU exclusions + missing
  wheels), so those packages' vulns are absent from Snyk here. osv-scanner remains the authoritative
  full-coverage Python scanner for this benchmark; Snyk install-based is a **cross-check**, not a
  replacement.
- **Python 3.12 only.** A few pins target other interpreters (e.g. need 3.13); those fail to install
  and are skipped. Per-project target-Python venvs would raise coverage marginally.
- **Paths ≠ advisories.** Use the `snyk_unique` column, not `snyk_paths`, when comparing tools.
- Free Snyk plan: this is Snyk **Open Source** only. Snyk **Code** (SAST) stays disabled — see
  [`../README.md`](../README.md).

## Reproduce

```powershell
docker build -t snyk-pip-bench <ctx>     # Dockerfile + run_all.sh
docker run -d --name snyk_bench `
  -v "E:\repos\Benchmark_F-VRA\_inventory:/inv:ro" `
  -v "E:\repos\Benchmark_F-VRA\_inventory\_scans\snyk\pip-docker:/out" `
  -v "$HOME\.config\configstore:/root/.config/configstore" `
  -v "<uv-cache>:/uvcache" snyk-pip-bench
```
