# CVE-to-VF localization: tái lập thí nghiệm

README này mô tả pipeline độc lập để định vị vulnerable function từ CVE. Pipeline có năm mode: `D_LEX`, `D_SEM`, `P_DUAL_PRESENT`, `P_DUAL_HIDDEN` và `ORACLE`. Mỗi mode chạy riêng, lưu một record cho mỗi case trong JSONL; `vf-metrics` chỉ đọc artifacts đã lưu và không gọi model.

Phạm vi này chưa gồm `P_MODIFIED`, binding sang reachability hoặc downstream RQ3.

## 1. Tạo môi trường Conda

Các lệnh dưới đây dùng Bash trên Linux/macOS. Sau khi clone repository và vào thư mục làm việc (thay đường dẫn mẫu bằng đường dẫn checkout của bạn), tạo environment một lần:

```bash
cd /path/to/f_vra
conda create --name f_vra-vf --channel conda-forge python=3.12 pip git
conda activate f_vra-vf
python -m pip install --upgrade pip
python -m pip install --editable '.[experiments]'
```

`python` và `python -m pip` ở các bước sau phải là Python trong environment vừa activate. Xác nhận trước khi chạy:

```bash
python --version
python -c 'import sys, f_vra; print(sys.executable); print(f_vra.__file__)'
python -m f_vra.cli.main eval vf-prepare --help
python -m f_vra.cli.main eval vf-run --help
python -m f_vra.cli.main eval vf-metrics --help
```

`pyproject.toml` yêu cầu Python >=3.11; hướng dẫn này dùng Python 3.12. Cài package dạng editable để lệnh `python -m f_vra.cli.main` dùng code trong checkout hiện tại.

## 2. Chuẩn bị manifest và source snapshot

Pipeline cần manifest đã freeze, source snapshot đúng `vulnerable_ref`, patch đã materialize và adjudication của benchmark. File `prepared_manifest_v6.jsonl` hiện có `source_path` tuyệt đối từ máy tạo artifact; vì vậy chỉ dùng trực tiếp khi những đường dẫn đó tồn tại trên máy hiện tại.

Trên máy mới/Linux, tạo manifest với đường dẫn snapshot cục bộ. Lệnh sau dùng benchmark và adjudication trong repository, materialize source/patch theo các revision đã chốt, và ghi sang file mới để giữ nguyên manifest v6 gốc:

```bash
python -W ignore::SyntaxWarning -m f_vra.cli.main eval rq3-prepare \
  --benchmark data/benchmarks/vf_benchmark_finalized.jsonl \
  --downstream data/benchmarks/f_vra_downstream_reachability_benchmark.jsonl \
  --output experiments/vf/prepared_manifest_repro.jsonl \
  --snapshot-cache experiments/vf/source_cache \
  --patch-cache experiments/vf/patches \
  --snapshot-root experiments/vf/materialized_snapshots \
  --adjudication experiments/vf/adjudication.json \
  --materialize-sources \
  --materialize-patches
```

Đây là bước có thể tải nhiều repository và patch, cần mạng và dung lượng đĩa. Giữ nguyên benchmark, adjudication và các `vulnerable_ref`; không dùng `--reuse-manifest-from` nếu manifest nguồn chứa đường dẫn của máy khác. Kiểm tra JSON summary trả về có `full_batch_ready: true`, `status: FROZEN`, và không có source/patch thiếu trước khi tiếp tục.

Nếu các source snapshot đã tồn tại và manifest trỏ đúng đến chúng, bỏ qua `rq3-prepare` và đặt `CASES` tới manifest đó. Ví dụ trên cùng máy tạo artifact:

```bash
CASES=experiments/vf/prepared_manifest_v6.jsonl
```

## 3. Tạo input snapshots riêng cho từng mode

`vf-prepare` chuẩn hóa ground truth giữ nguyên `role`, tạo `FunctionCatalog` từ source snapshot và đóng băng năm input views. `--limit` lấy prefix xác định của manifest, không lấy mẫu ngẫu nhiên. Dùng 4 case để tái lập cohort nhỏ đã được kiểm tra; bỏ `--limit 4` (hoặc đặt `--limit 0`) để chuẩn bị toàn bộ manifest.

```bash
CASES=experiments/vf/prepared_manifest_v6.jsonl
INPUTS_ROOT=experiments/vf/inputs
PREPARED_JSON="$(python -W ignore::SyntaxWarning -m f_vra.cli.main eval vf-prepare \
  --cases "$CASES" \
  --output-root "$INPUTS_ROOT" \
  --limit 4)"
INPUTS_DIR="$(printf '%s' "$PREPARED_JSON" | python -c 'import json, sys; print(json.load(sys.stdin)["inputs_dir"])')"
printf 'Prepared inputs: %s\n' "$INPUTS_DIR"
```

Nếu vừa chạy bước 2, đổi `CASES` thành `experiments/vf/prepared_manifest_repro.jsonl`. Lưu lại `inputs_dir` được in ra; nó có dạng `experiments/vf/inputs/vf-input-<id>`. Mỗi `input_id` là snapshot riêng, không sửa tay JSONL hoặc manifest sau khi đã chuẩn bị.

Input D_LEX/D_SEM không chứa patch/CWE; P_DUAL_PRESENT và P_DUAL_HIDDEN dùng cùng cohort có patch hợp lệ, còn HIDDEN không chứa patch hay CWE. ORACLE chứa input phục vụ control.

## 4. Cấu hình và kiểm tra provider

`D_LEX` và `ORACLE` không cần LLM/embedding. `D_SEM` cần chat completion để trích AV/root-cause và embedding để xếp hạng; cả hai mode P_DUAL cần embedding retrieval và LLM pairwise ranking. API phải tương thích OpenAI chat completions; embedding endpoint cần hỗ trợ embeddings.

Tạo file cấu hình cục bộ rồi điền endpoint/model/key do bạn quản lý:

```bash
cp .env.example .env
```

Trong `.env`, cấu hình các trường cần dùng:

```dotenv
LOCAL_LLM_API_KEY=<your-chat-api-key>
LOCAL_LLM_BASE_URL=<openai-compatible-chat-base-url>
LOCAL_LLM_MODEL=<chat-model>
LOCAL_EMBEDDING_API_KEY=<embedding-api-key>
LOCAL_EMBEDDING_BASE_URL=<openai-compatible-embedding-base-url>
LOCAL_EMBEDDING_MODEL=<embedding-model>
```

Nếu cùng một key dùng cho hai endpoint, `LOCAL_EMBEDDING_API_KEY` có thể để trống để dùng `LOCAL_LLM_API_KEY`. Không commit `.env`, không ghi API key vào log. `GITHUB_TOKEN` và `NVD_API_KEY` có thể cấu hình khi bước freeze cần truy cập dịch vụ tương ứng.

Để kiểm tra thật endpoint trước khi chạy mode tốn chi phí, chạy probe dưới đây. Probe gửi một chat request và một embedding request; nó có thể phát sinh phí nhỏ:

```bash
python - <<'PY'
from f_vra.core.config import settings
from f_vra.localization.providers.llm_client import chat_available
from f_vra.localization.ranking.methods.description import enrich_description_with_llm_entities
from f_vra.localization.retrieval.embedding import LocalEmbeddingBackend

assert chat_available(), 'LOCAL_LLM_* chưa cấu hình đầy đủ'
extraction = enrich_description_with_llm_entities(
    'A remote unauthenticated request can traverse directories using ../ paths.'
)
entities = extraction.entities or {}
assert extraction.status.startswith('used'), extraction.status
assert entities.get('attack_vector') or entities.get('root_cause'), entities
vectors = LocalEmbeddingBackend().embed(['VF localization readiness probe'])
assert len(vectors) == 1 and len(vectors[0]) > 0
print('chat_model:', settings.llm_model)
print('embedding_model:', settings.embedding_model)
print('embedding_dimensions:', len(vectors[0]))
PY
```

Với D_SEM, extraction lỗi hoặc không có `attack_vector`/`root_cause` được ghi là failed; runner không fallback sang D_LEX.

## 5. Chạy từng mode

Chạy mode tuần tự với cùng `RUN_ID` để gom kết quả trong cùng thư mục. Tạo `RUN_ID` mới cho một lần chạy/model configuration mới:

```bash
set -euo pipefail
RUN_ID="vf-$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_ROOT=experiments/vf/results

python -W ignore::SyntaxWarning -m f_vra.cli.main eval vf-run D_LEX "$INPUTS_DIR" --run-id "$RUN_ID" --output-root "$RESULTS_ROOT"
python -W ignore::SyntaxWarning -m f_vra.cli.main eval vf-run D_SEM "$INPUTS_DIR" --run-id "$RUN_ID" --output-root "$RESULTS_ROOT"
python -W ignore::SyntaxWarning -m f_vra.cli.main eval vf-run P_DUAL_PRESENT "$INPUTS_DIR" --run-id "$RUN_ID" --output-root "$RESULTS_ROOT"
python -W ignore::SyntaxWarning -m f_vra.cli.main eval vf-run P_DUAL_HIDDEN "$INPUTS_DIR" --run-id "$RUN_ID" --output-root "$RESULTS_ROOT"
python -W ignore::SyntaxWarning -m f_vra.cli.main eval vf-run ORACLE "$INPUTS_DIR" --run-id "$RUN_ID" --output-root "$RESULTS_ROOT"

RESULTS_DIR="$RESULTS_ROOT/$RUN_ID"
```

Ý nghĩa các mode:

- `D_LEX`: CVE description và FunctionCatalog; lexical/tVSM ranking.
- `D_SEM`: description cộng AV/root-cause extraction và semantic retrieval.
- `P_DUAL_PRESENT`: description, source và patch; patch tracker/BM25/embedding tạo tối đa 100 candidates trước pairwise ranking.
- `P_DUAL_HIDDEN`: description và source, không patch/CWE; BM25/embedding tạo tối đa 100 candidates trước cùng pairwise ranker.
- `ORACLE`: lưu đúng tập ground truth làm control, không chạy localization.

P_DUAL có thể chạy lâu vì ranker thực hiện nhiều LLM pairwise comparisons. Kiểm tra quota, giới hạn tốc độ và chi phí trước khi chạy cohort lớn. Không dùng `--limit` ở runner: cohort được cố định lúc `vf-prepare`.

Mỗi record hoàn tất được ghi vào checkpoint. Chạy lại cùng mode, `RUN_ID`, input và code để tiếp tục; record hoàn tất được giữ, record lỗi được thử lại. Dùng `RUN_ID` mới khi đổi provider/model/endpoint, input hoặc code. Fingerprint hiện không khóa các biến cấu hình provider, vì vậy không tái sử dụng run ID sau khi đổi model.

Giữ nguyên input directory giữa các mode: cache embedding dùng chung dưới `inputs_dir` nên chạy mode sau có thể là warm-cache, ảnh hưởng runtime và usage được báo cáo. Đừng xóa cache giữa các mode nếu muốn giữ phép so sánh paired nhất quán.

## 6. Tính metrics offline

Metrics chỉ đọc mode inputs, ground truth và JSONL kết quả; lệnh này không gọi model:

```bash
python -W ignore::SyntaxWarning -m f_vra.cli.main eval vf-metrics \
  "$INPUTS_DIR" \
  "$RESULTS_DIR"
```

Report được ghi vào `$RESULTS_DIR/report/`: `metrics.json`, `metrics.csv`, `report.md`, `paired_deltas.csv` và `paired_deltas.md`. Nó báo cáo `root_cause_only` và `all_valid_anchors`; Hit@1/3/5/10, MRR; CandidateRecall@100 cho P_DUAL; extraction coverage/failure/fallback cho D_SEM; runtime, calls, tokens và PRESENT-minus-HIDDEN paired deltas trên các case chung. `TokenCostUsd` là null nếu provider không trả giá.

Kiểm tra mỗi mode có đủ record và không còn lỗi:

```bash
for mode in D_LEX D_SEM P_DUAL_PRESENT P_DUAL_HIDDEN ORACLE; do
  printf '\n--- %s ---\n' "$mode"
  cat "$RESULTS_DIR/$mode.summary.json"
done
```

Record-level outputs là `$RESULTS_DIR/<MODE>.jsonl`, mỗi dòng một case. `<MODE>.checkpoint.jsonl` lưu lần thử gần nhất để resume; `.meta.json` và `.summary.json` lưu fingerprint và trạng thái chạy.

## 7. Đọc kết quả đã lưu

Để tái tạo report hiện có mà không chạy model, dùng input/result artifacts đã lưu:

```bash
INPUTS_DIR=experiments/vf/inputs/vf-input-bf01f089773cbb7d
RESULTS_DIR=experiments/vf/results/vf-v6-real4-20261003
python -W ignore::SyntaxWarning -m f_vra.cli.main eval vf-metrics \
  "$INPUTS_DIR" \
  "$RESULTS_DIR"
```

Run `vf-v6-real4-20261003` dùng bốn case thật đầu tiên. Các per-case outputs được tái sử dụng từ run thật `vf-v6-real5-20261003` sau khi xác nhận input của bốn case chung giống nhau; finalization không gọi model lại. Một lần chạy mới với `RUN_ID` khác sẽ gửi request thật đến các provider.

## 8. Artifact cần giữ để tái lập

```text
experiments/vf/
├── prepared_manifest_*.jsonl        # frozen cases; source_path gắn với máy tạo
├── inputs/<input-id>/
│   ├── manifest.json                # hashes/counts cho input views và catalogs
│   ├── ground_truth.jsonl
│   ├── d_lex.jsonl, d_sem.jsonl, oracle.jsonl
│   ├── p_dual_present.jsonl, p_dual_hidden.jsonl
│   ├── catalogs/                    # source index đã freeze
│   ├── inventory_cache/             # parser/index cache
│   └── embedding_cache.sqlite       # embedding vectors dùng chung giữa modes
└── results/<run-id>/
    ├── <MODE>.jsonl                 # kết quả compact, mỗi dòng một record
    ├── <MODE>.checkpoint.jsonl      # log để resume
    ├── <MODE>.meta.json
    ├── <MODE>.summary.json
    └── report/                      # metrics offline
```

Để lưu một lần chạy có thể kiểm toán, giữ manifest, thư mục input, toàn bộ result JSONL/checkpoint/meta/summary, report, commit code, model name/version và endpoint configuration (không lưu secret). So sánh thời gian/usage cần ghi rõ cache nóng hay lạnh.

## Lưu ý về artifacts hiện có

- `prepared_manifest_v6.jsonl` trong artifact hiện tại chứa `source_path` tuyệt đối trên Windows. Chuyển sang Linux/macOS cần materialize snapshot tại máy đó và tạo manifest mới; không chạy trực tiếp nếu source path không tồn tại.
- `source_content_sha256` trống trong manifest v6. `vulnerable_ref`, snapshot identity và hash catalog được ghi trong manifest, nhưng điều này chưa thay thế việc lưu content hash cho toàn bộ source tree.
- Một số function declaration cùng file và qualified name tạo `function_id` trùng trong catalog; điều này thể hiện trong kết quả D_LEX/D_SEM. Các record vẫn lưu line range, nhưng candidate count khi đó là số declaration được index, không phải số function ID duy nhất. Cần sửa identity theo vị trí dòng và tái chạy trước khi diễn giải số candidate của benchmark lớn.
- Chạy lại bằng provider/model khác, cache khác hoặc trên source snapshot được materialize lại là một lần chạy mới; không ghép nó vào run cũ khi tính paired deltas.

## 9. Chạy shard trên nhiều máy

Khi máy worker không có `source_cache`, `catalogs` hoặc `inventory_cache`, dùng
portable machine shard. Không dùng `vf-run-index-shard` trong trường hợp đó:
lệnh index chỉ mang case ID và yêu cầu các artifact đã cài sẵn trên từng máy.

Trên máy điều phối, tạo shard từ **cùng một** thư mục input đã freeze:

```bash
python -m f_vra.cli.main eval vf-shard "$INPUTS_DIR" --shard-count 6 --output-root experiments/vf/shards
```

Chuyển nguyên thư mục `machine-001-of-006` tương ứng tới mỗi worker. Portable
bundle chứa `sources.tar`, `catalogs/`, `inventory_cache/`, các mode input và
manifest checksum; runner giải nén source khi bắt đầu. Worker không cần bản
`source_cache` của máy tạo bundle. Giữ `.env` riêng trên mỗi máy và cấu hình
cùng provider, model, endpoint cùng retrieval settings; không chuyển API key
trong bundle.

Trên mỗi worker, dùng cùng commit Git, cùng `conda-lock.yml`, cùng Python
major/minor và **cùng `RUN_ID`**. Bắt đầu bằng canary; lần chạy đầy đủ tiếp tục
trên đúng run ID đó:

```bash
python -m f_vra.cli.main eval vf-run-shard /path/to/machine-001-of-006 --output-root experiments/vf/results --run-id vf-cross-machine-v1 --workers 1 --case-limit 1 --no-progress

# Sau khi canary được xem xét, tiếp tục cùng run ID với toàn bộ shard:
python -m f_vra.cli.main eval vf-run-shard /path/to/machine-001-of-006 --output-root experiments/vf/results --run-id vf-cross-machine-v1 --workers 1 --case-limit 0 --no-progress
```

Canary được đánh dấu `status: canary` và chưa thể merge. Chép kết quả của từng
worker về máy điều phối, rồi merge với thư mục **đầy đủ** `$INPUTS_DIR` và một
`--shard-run-dir` cho mỗi shard. Merge kiểm tra input ID/hash, shard coverage,
code fingerprint, Python major/minor, lockfile và provider configuration.
Ví dụ với sáu shard:

```bash
python -m f_vra.cli.main eval vf-merge "$INPUTS_DIR" --output-root experiments/vf/merged --run-id vf-cross-machine-v1 \
  --shard-run-dir experiments/vf/results/vf-cross-machine-v1/machine-001-of-006 \
  --shard-run-dir experiments/vf/results/vf-cross-machine-v1/machine-002-of-006 \
  --shard-run-dir experiments/vf/results/vf-cross-machine-v1/machine-003-of-006 \
  --shard-run-dir experiments/vf/results/vf-cross-machine-v1/machine-004-of-006 \
  --shard-run-dir experiments/vf/results/vf-cross-machine-v1/machine-005-of-006 \
  --shard-run-dir experiments/vf/results/vf-cross-machine-v1/machine-006-of-006
```

Các file kết quả dùng chung hợp đồng: mỗi dòng trong `<MODE>.jsonl` và
`<MODE>.checkpoint.jsonl` có `schema_version: f_vra.vf.anchor-result.v1`;
`<MODE>.summary.json` dùng `f_vra.vf.mode-run-summary.v1` và ghi tên file
tương đối so với thư mục run. `shard_run_manifest.json` dùng
`f_vra.vf.machine-run.v2`; các đường dẫn artifact trong đó cũng tương đối,
nên manifest có cùng cấu trúc trên Windows, Linux và macOS. Runtime, số token,
trạng thái và nội dung dự đoán là dữ liệu quan sát được nên có thể khác giữa
các worker.
