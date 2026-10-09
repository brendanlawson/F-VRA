# Localization

This module maps a CVE description and an optional patch to likely vulnerable
Python functions.

## Pipeline

1. `sources.py` fetches CVE metadata from OSV or NVD.
2. `sources.py` downloads and parses unified diffs.
3. `function_parser.py` extracts Python functions, methods, calls, and names.
4. `tracker.py` expands patch hits through calls and changed configuration.
5. `candidates.py` combines BM25 and provider embeddings with Reciprocal Rank Fusion.
6. `ranking.py` combines retrieval relevance, patch evidence, and optional
   LLM pairwise ranking.
7. `service.py` returns the final JSON-compatible report.

## Configuration

```env
LOCAL_LLM_API_KEY=
LOCAL_LLM_BASE_URL=https://quatmo-api.iahn.hanoi.vn/v1
LOCAL_LLM_MODEL=qwen3-coder
LOCAL_EMBEDDING_API_KEY=
LOCAL_EMBEDDING_BASE_URL=https://quatmo-api.iahn.hanoi.vn/v1
LOCAL_EMBEDDING_MODEL=qwen3-embedding
GITHUB_TOKEN=
NVD_API_KEY=
```

`LOCAL_LLM_API_KEY` enables LLM-based description enrichment and pairwise
ranking. `LOCAL_EMBEDDING_API_KEY` is optional: when it is empty, embeddings use
`LOCAL_LLM_API_KEY`. `LOCAL_EMBEDDING_BASE_URL` should point to the same
OpenAI-compatible `/v1` endpoint when the provider serves embeddings there.
Without embedding configuration, candidate retrieval falls back to BM25 and
reports that fallback in `metadata.retrieval`.

## Run The Full Pipeline

Patch-present mode:

```powershell
f-vra localize CVE-2023-32681 `
  --auto-resolve-patch `
  --top-k 20 `
  --output .\report.json
```

If `--repository` is omitted or the path does not exist, F-VRA tries to infer
a GitHub repository from OSV/NVD references and clones it into
`repo_cache_dir` automatically.

Manual patch:

```powershell
f-vra localize `
  --repository .\requests `
  --description "Proxy credentials may leak during HTTPS redirects" `
  --patch .\fix.patch `
  --top-k 20
```

Patch-absent mode:

```powershell
f-vra localize CVE-2023-32681 `
  --top-k 20
```

Pass `--pairwise` to use the configured local LLM for pairwise ranking, and
`--no-embeddings` to test lexical retrieval in isolation.

## Test Each Stage

Metadata:

```powershell
f-vra localization metadata CVE-2023-32681 --provider osv
f-vra localization metadata CVE-2023-32681 --provider nvd --raw
```

Patch discovery and parsing:

```powershell
f-vra localization patch CVE-2023-32681 --output .\patch.diff
f-vra localization patch --patch .\patch.diff
f-vra localization patch --url https://github.com/OWNER/REPO/commit/SHA
```

AST extraction:

```powershell
f-vra localization parse --repository .\requests --limit 30
```

Patch tracking:

```powershell
f-vra localization track `
  --repository .\requests `
  --patch .\patch.diff `
  --max-depth 2
```

Candidate retrieval:

```powershell
f-vra localization retrieve `
  --repository .\requests `
  --description "Proxy credentials leak during HTTPS redirect" `
  --top-k 20
```

The retrieval output exposes `bm25_score`, `embedding_score`, and
`fused_score`. Check `embedding_status` before interpreting the fused ranking.

Full diagnostic run:

```powershell
f-vra localization run `
  --repository .\requests `
  --cve CVE-2023-32681 `
  --patch .\patch.diff `
  --top-k 20
```

## Python API

```python
from pathlib import Path

from f_vra.localization import LocalizationRequest
from f_vra.localization.service import localize_vulnerable_functions

report = localize_vulnerable_functions(
    LocalizationRequest(
        cve_id="CVE-2023-32681",
        repository_path=Path("./requests"),
        auto_resolve_patch=True,
        top_k=20,
    )
)

print(report.mode)
print(report.to_dict()["candidates"])
```

## Tests

```powershell
pytest tests/unit/test_localization.py
```

Network calls are mocked in unit tests. Manual metadata, patch, embedding, and
localization commands are the end-to-end checks for OSV, NVD, GitHub, and the
configured local LLM provider.
