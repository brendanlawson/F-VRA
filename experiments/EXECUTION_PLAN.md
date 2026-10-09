# Kế hoạch hoàn thiện và chạy nền tảng thí nghiệm F-VRA

## 1. Mục tiêu

Hoàn thiện harness, đóng băng dữ liệu và chạy toàn bộ protocol cho ba câu hỏi nghiên cứu:

- **RQ1:** so sánh package exposure, usage filter và Fresh với oracle đã adjudicate.
- **RQ2:** đo lợi ích và chi phí của bốn policy R0–R3 dưới nhiều thứ tự workload.
- **RQ3:** đo ảnh hưởng của sai số VF với ba nguồn VF đã đóng băng.

Kết quả cuối phải tái lập được từ snapshot, environment, config và event log. Không dùng các báo cáo reachability cũ làm oracle hoặc làm kết quả chính nếu chúng không có provenance tới snapshot mới.

## 2. Nguyên tắc không thay đổi trong quá trình chạy

1. Project graph và package graph đều dùng cùng backend JARVIS đã pin.
2. AST adapter cố định được dùng cho mọi policy để kiểm kê function, alias và external edge.
3. Build environment được phép truy cập mạng. Mọi analysis container chạy `--network=none`, 8 CPU và 16 GiB RAM.
4. `PackageID` phụ thuộc distribution, version, source hash, wheel hash/tag, ABI/platform, JARVIS commit, AST adapter và analysis config.
5. Import root chỉ là ánh xạ đến distribution. Import root không được dùng làm cache identity.
6. Chỉ version nằm trong affected range và có package tương ứng trong installed manifest mới tạo query đủ điều kiện.
7. `POTENTIALLY_REACHABLE` và mọi frontier không đầy đủ phải được xuất thành `UNKNOWN` với lý do cụ thể.
8. Thiếu source, native/dynamic boundary, parse failure, budget hoặc timeout không được tạo kết luận `UNREACHABLE`.
9. Chi phí eager precomputation luôn nằm trong cumulative cost. Project graph cost được đo và báo cáo riêng như chi phí chung của environment.
10. Chỉ oracle label có `review_status=accepted` mới được dùng để tính accuracy.

## 3. Trạng thái tại thời điểm lập kế hoạch

Ngày kiểm tra: **2026-09-19**.

### 3.1 Đã hoàn thành và kiểm thử

- Các immutable model và canonical SHA-256 identity.
- Freeze 28 project snapshot, 247 CVE và 811 project–CVE candidate trong smoke dataset.
- Environment image chứa target runtime và JARVIS Python 3.8 riêng biệt.
- Installed manifest, package source hash, wheel metadata, import-root mapping và VF source binding.
- Artifact compatibility key, content hash validation và rejection reason.
- Bốn policy `Fresh`, `ProjectLocal`, `EagerShared`, `ProgressiveShared` ở mức code.
- Runner ba trạng thái `REACHABLE | UNREACHABLE | UNKNOWN`.
- CLI `freeze`, `build-env`, `audit`, `oracle-import`, `oracle-review`, `fresh`, `determinism`, `compare`, `ablate`, `vf`, `report`.
- Nguồn manual annotation ghép một-một 811/811 candidate sau chuẩn hóa package và version; verdict chỉ lấy từ `manual_label`, không lấy từ `auto_reachability`.
- Project graph và package fragment đã chạy E2E trong container không mạng.
- Fresh, ProjectLocal và ProgressiveShared đã cho cùng verdict và witness trên smoke fixture thực.
- Hai lần build liên tiếp environment mẫu cho cùng installed manifest hash.
- Toàn bộ test suite: **66/66 passed**.

### 3.2 Chưa hoàn thành

- Chưa có runner chính thức cho `package_exposure` và `usage_filter` của RQ1.
- EagerShared chưa chạy E2E trên Docker fixture thực.
- Cluster bootstrap đã có hàm nhưng chưa được nối vào report chính.
- Chưa có builder đóng băng ba manifest VF V0/V1/V2 và chưa tính VF input recall.
- Figure generator mới sinh cumulative cost; chưa đủ funnel, overlap, work saved, break-even, transition matrix và VF-error figures.
- Artifact trong `.tmp` chỉ là smoke artifact, không phải artifact chính thức.
- Mới build thành công 1/28 environment smoke.
- Environment smoke có 7 candidate nhưng không package nào được cài ở affected version, nên có 0 query đủ điều kiện.
- 811 oracle label đều còn `pending_review`; 2 label thiếu reason và 3 reachable label thiếu witness.
- Chưa chạy Fresh reference, determinism gate, R0–R3 matrix, ablation hoặc VF study trên dataset chính thức.

## 4. Thứ tự thực hiện bắt buộc

Không chuyển phase khi acceptance gate của phase trước chưa đạt. Nếu một gate thất bại, lưu audit và sửa nguyên nhân trước khi chạy tiếp.

## P0 — Đóng băng protocol và phạm vi entrypoint

### Việc cần làm

- Chốt project entrypoint có bao gồm test và maintenance scripts hay không.
- Chốt environment profile cho từng loại lockfile: production/main dependencies là mặc định.
- Chốt cách xử lý dependency chỉ xuất hiện trong dev/optional group.
- Chốt `AST_ADAPTER_VERSION`, fragment schema version, JARVIS commit và analysis config.
- Ghi các quyết định trên vào config/protocol manifest có hash.

### Quy tắc cho dev/optional dependencies

Không tự động cài thêm dependency chỉ để khôi phục đủ 811 query. Nếu package chỉ xuất hiện trong lockfile nhưng không có trong environment profile đã chốt, candidate phải giữ trong audit với trạng thái không đủ điều kiện. Nếu số query đủ điều kiện quá thấp để trả lời RQ, phải sửa định nghĩa environment bằng một protocol revision có version, rồi freeze lại toàn bộ dataset.

### Artifact

- `experiments/protocol/protocol-v1.yaml`
- `experiments/protocol/entrypoint-policy.md`
- Hash protocol được ghi vào dataset manifest và run config.

### Gate hoàn tất

- Không còn lựa chọn phương pháp chưa được ghi rõ.
- Thay đổi protocol sau gate này buộc tạo dataset version mới.

## P1 — Hoàn thiện các method còn thiếu trước khi chạy tốn kém

### P1.1 RQ1 baselines

Triển khai hai method có output cùng schema với Fresh:

- `package_exposure`: dự đoán từ installed affected package/version.
- `usage_filter`: dự đoán từ project graph và import-root/distribution mapping.

Thêm CLI dự kiến:

```powershell
f-vra eval baselines --dataset experiments/dataset/current
```

### P1.2 EagerShared E2E

- Chạy inventory và eager materialization trên fixture package nhỏ.
- Xác minh precompute event có `precomputation=true`.
- Xác minh cumulative cost gồm precomputation.
- So decision và witness với Fresh trên transitive fixture.

### P1.3 Metrics và report

- Nối cluster bootstrap theo `project_id` cho metric phụ thuộc nhiều query cùng project.
- Thêm query metadata cần thiết vào `query_results.parquet`.
- Sinh đầy đủ:
  - impact funnel;
  - accuracy/coverage table;
  - workload overlap;
  - cumulative wall và CPU cost;
  - cumulative function work;
  - work saved;
  - break-even;
  - verdict transition matrix;
  - VF input error và downstream impact figures.

### P1.4 VF manifests

Tạo builder sinh ba input bất biến:

- `V0_ORACLE`: VF đã adjudicate.
- `V1_PATCH`: VF patch-derived đã freeze.
- `V2_LOCALIZER`: output của localizer hiện có trên cùng snapshot.

Mỗi anchor phải có package ID, module, qualified name, file, span, function hash và provenance.

### P1.5 Run registry và resume

- Tạo run registry chứa run ID, dataset ID, protocol hash, strategy, order, seed, trạng thái và output path.
- Lệnh chạy dài phải bỏ qua run đã hoàn thành với cùng config hash.
- Run thất bại phải được đánh dấu, không được ghi đè run hoàn thành.

### Test bắt buộc

- RQ1 baseline fixture.
- Eager precompute cost fixture.
- Cluster bootstrap deterministic seed fixture.
- VF recall/precision fixture.
- Resume và duplicate-run rejection fixture.

### Gate hoàn tất

- Full test suite pass.
- Fresh, ProjectLocal, EagerShared và ProgressiveShared cùng decision/witness trên transitive fixture.
- Report smoke sinh đủ tất cả bảng và figure yêu cầu.

## P2 — Tạo dataset chính thức

Smoke artifact trong `.tmp` không được dùng cho báo cáo. Tạo dataset chính thức sau khi P0–P1 ổn định.

```powershell
f-vra eval freeze `
  --output-dir experiments/dataset/current `
  --projects configs/local_projects.json `
  --benchmark data/final/cve_vf_benchmark_accepted.jsonl
```

### Kiểm tra

- 28/28 project checkout đúng commit.
- Tracked worktree sạch.
- Manifest không chứa đường dẫn tuyệt đối cũ.
- 811 candidate và 247 vulnerability được tạo.
- Dataset ID, project snapshot ID và source hash không đổi khi freeze lặp lại.

### Gate hoàn tất

- `snapshot_audit.parquet`: 28 `READY`.
- `dataset.json`: project count 28, candidate count 811.
- Hai lần freeze cho cùng ID và cùng row counts.

## P3 — Build và kiểm toán đủ 28 environment

Chạy theo batch nhỏ trước, sau đó mới mở rộng toàn bộ.

```powershell
# Batch đầu để phát hiện lỗi theo loại lockfile
f-vra eval build-env --dataset experiments/dataset/current --limit 3
f-vra eval audit --dataset experiments/dataset/current

# Build từng project lỗi hoặc các project còn lại
f-vra eval build-env `
  --dataset experiments/dataset/current `
  --project-id <project-id>

# Khi các loại lockfile đều ổn định
f-vra eval build-env --dataset experiments/dataset/current
f-vra eval audit --dataset experiments/dataset/current
```

### Mỗi environment phải lưu

- OCI image digest.
- Target Python version và JARVIS Python version.
- Lockfile type/hash hoặc generated lock.
- Installed distribution manifest và hash.
- Dependency edges từ installed metadata.
- PackageID cho mọi distribution.
- Package source audit và import-root mapping.
- VF binding audit.
- Query eligibility audit.

### Reproducibility check

Chọn ít nhất một project cho mỗi loại lockfile và build lại hai lần. Hai lần phải có cùng installed manifest và PackageID. Nếu khác:

- lưu `manifest_diff.json`;
- xác định distribution thay đổi;
- không chuyển sang P4 cho đến khi diff được giải thích hoặc protocol được version lại.

### Gate hoàn tất

- 28/28 environment `READY`, hoặc mọi exception đã được protocol cho phép và liệt kê rõ.
- Không có import-root collision chưa giải quyết.
- Mọi package source mismatch có `reuse_rejected_reason` hoặc source status cụ thể.
- Có bảng tổng hợp số candidate theo từng eligibility status.

## P4 — Đánh giá quy mô query đủ điều kiện

Sau khi build đủ 28 environment, tính funnel trước khi adjudicate hàng loạt:

1. 811 candidate ban đầu.
2. Affected package thực sự được cài.
3. Installed version nằm trong affected range.
4. Source có thể phân tích.
5. VF bind đúng source/span/hash.
6. Query đủ điều kiện chạy.

### Quyết định tại gate

- Nếu đủ query và đủ phân tầng cho RQ: tiếp tục P5.
- Nếu không thể tạo 300–400 oracle label đủ điều kiện: dừng và sửa protocol/environment profile bằng version mới.
- Không dùng candidate không đủ điều kiện để bù số lượng accuracy oracle.

### Artifact

- `query_eligibility.parquet`
- `eligibility_summary.json`
- `eligibility_funnel.csv`
- Danh sách project/package cần sửa mapping hoặc source.

## P5 — Import và adjudicate oracle

```powershell
f-vra eval oracle-import `
  "C:\Users\iamwu\Downloads\project.xlsx - manual_annotation.csv" `
  --dataset experiments/dataset/current
```

### Import gate

- 811/811 dòng ghép một-một theo project+CVE.
- Sáu package alias gộp được chuẩn hóa đúng.
- Package và version khớp candidate đã freeze.
- Verdict oracle chỉ lấy từ `manual_label`; `auto_reachability` là output cũ và bị bỏ qua.
- Manual annotation chỉ tạo oracle candidate `pending_review`.

### Review ưu tiên

1. Sửa 2 label thiếu reason.
2. Bổ sung provenance cho label đủ điều kiện còn thiếu annotator.
3. Review toàn bộ reachable candidate đủ điều kiện.
4. Review unreachable candidate theo strata project, package, dependency type và VF multiplicity.
5. Ba reachable thiếu witness nằm ngoài population đủ điều kiện; giữ lại trong audit nhưng không dùng bù accuracy oracle.
6. Bổ sung mẫu đến 300–400 accepted label nếu số nhãn manual đạt gate chưa đủ.

### Điều kiện accept

- Reachable: witness tồn tại trên source đã pin và đi đến đúng VF anchor.
- Unreachable: frontier đã được duyệt đầy đủ, không có parse/source/native/dynamic/budget/timeout boundary chưa giải quyết.
- Mọi label có reviewer, thời điểm review và evidence.

```powershell
f-vra eval oracle-review `
  experiments/oracle/reviews.jsonl `
  --dataset experiments/dataset/current
```

### Gate hoàn tất

- 300–400 accepted label đủ điều kiện, hoặc toàn bộ population đủ điều kiện nếu nhỏ hơn nhưng protocol đã được sửa và ghi rõ.
- Không accepted label nào thiếu provenance/evidence.

## P6 — Fresh reference và determinism gate

### P6.1 Fresh toàn bộ query

```powershell
f-vra eval fresh `
  --dataset experiments/dataset/current `
  --output-root experiments/runs
```

### P6.2 Determinism 10% × 3

```powershell
f-vra eval determinism `
  --dataset experiments/dataset/current `
  --output-root experiments/runs `
  --fraction 0.1 `
  --seed 17
```

### So sánh ba lần

- decision;
- witness;
- actual function-analysis count;
- unique function count;
- materialized edge count.

Wall time, CPU time và RSS được phép dao động nhưng phải được lưu để kiểm tra outlier.

### Gate hoàn tất

- `mismatch_count=0` cho các trường semantic/work bắt buộc.
- Mọi timeout/parse/backend failure được phân loại thành `UNKNOWN_*`.
- Fresh run trở thành same-backend reference; không được gọi là ground truth.

## P7 — RQ1

Chạy ba method trên cùng query population và cùng oracle gate:

1. `package_exposure`;
2. `usage_filter`;
3. `Fresh`.

### Metrics

- precision, recall, F1, FNR;
- coverage;
- Wilson interval cho tỷ lệ;
- cluster bootstrap theo project;
- agreement riêng với Fresh;
- impact funnel và verdict transitions.

### Gate hoàn tất

- Accuracy chỉ dùng accepted oracle.
- Agreement với Fresh được trình bày riêng, không trộn với accuracy.
- Baseline output có cùng query IDs và decision enum.

## P8 — RQ2: chạy R0–R3

### Matrix chính

- 4 strategies: Fresh, ProjectLocal, EagerShared, ProgressiveShared.
- `PROJECT_MAJOR`.
- `CVE_MAJOR`.
- `RANDOM` với seed 1–30.
- Tổng cộng: `4 × (2 + 30) = 128` run chính.

```powershell
f-vra eval compare `
  --dataset experiments/dataset/current `
  --output-root experiments/runs `
  --strategy fresh `
  --strategy project_local `
  --strategy eager_shared `
  --strategy progressive_shared `
  --order PROJECT_MAJOR `
  --order CVE_MAJOR `
  --order RANDOM `
  --seeds 1:30
```

### Watchdog

- 300 giây mỗi fragment.
- 600 giây mỗi query.
- Timeout phải thành `UNKNOWN_TIMEOUT`.
- Không đặt root/depth cap trong phép so sánh chính.

### Metrics

- cumulative wall time và CPU time;
- actual function work và unique functions;
- edge count;
- amortized query cost;
- reuse rate và cache hit rate;
- storage đọc/ghi;
- work saved;
- break-even query;
- verdict transition matrix;
- project graph cost riêng.

### Gate hoàn tất

- 128 config hash duy nhất đã hoàn thành hoặc có failure record.
- Chỉ policy thay đổi giữa R0–R3.
- Eager precompute xuất hiện trong event log và cumulative cost.

## P9 — Ablation

```powershell
f-vra eval ablate `
  --dataset experiments/dataset/current `
  --output-root experiments/runs
```

### Cấu hình

- Sharing on/off.
- Eager/progressive.
- Root budget: 20, 40, 60, 100, vô hạn.
- Depth: 1, 2, 3, 4, vô hạn.
- Fallback expansion.

### Quy tắc

- Frontier bị cap mà chưa kết luận phải là `UNKNOWN_BUDGET`.
- Witness display limit chỉ giới hạn path hiển thị, không giới hạn reachability search.

### Gate hoàn tất

- Mỗi ablation có config và event log riêng.
- Có curve accuracy/coverage/cost theo budget và depth.

## P10 — RQ3: VF uncertainty

```powershell
f-vra eval vf `
  experiments/vf/vf_variants.parquet `
  --dataset experiments/dataset/current `
  --output-root experiments/runs
```

### Metrics

- VF input precision/recall so với V0.
- Downstream impact precision/recall.
- Decision flip rate.
- Transition matrix giữa V0, V1 và V2.
- Trường hợp VF sai nhưng impact verdict không đổi.
- Trường hợp VF đúng nhưng backend vẫn `UNKNOWN`.

### Gate hoàn tất

- Cả ba variant dùng cùng query population, snapshot và environment.
- Mismatch source/span/hash thành `UNKNOWN_VF_MISMATCH`.

## P11 — Sinh report chính thức

```powershell
f-vra eval report `
  --dataset experiments/dataset/current `
  --output-dir results/experiment_report
```

### Output bắt buộc

- `report.json`
- `report.md`
- `run_summary.csv`
- accuracy/coverage tables
- impact funnel
- workload overlap figure
- cumulative wall/CPU cost figure
- cumulative function-work figure
- work-saved figure
- break-even figure/table
- verdict-transition heatmap
- VF-error figures

### Kiểm tra report

- Recompute metric từ event-level artifact và đối chiếu summary.
- Wilson interval đúng denominator.
- Bootstrap sampling theo project, không theo query độc lập.
- Không có accuracy row dùng `pending_review` oracle.
- Mọi figure có dataset ID, protocol hash và run selection trong metadata/caption.

## P12 — Đóng gói khả năng tái lập

### Lưu trữ

- Dataset manifest và protocol manifest.
- Environment manifests và OCI digests.
- Oracle import/review audit.
- VF variant manifests.
- Run registry.
- Config, query results, analysis events và artifact events của mọi run.
- Report source tables và figures.
- Git commit của F-VRA và JARVIS.

### Final acceptance

- Một máy mới có thể dựng lại ít nhất một project từ snapshot và tạo cùng installed manifest/PackageID.
- Một representative query có thể chạy lại và cho cùng decision/witness/work counters.
- Report có thể sinh lại chỉ từ frozen dataset và run artifacts.
- Không cần dựa vào CSV hoặc report cũ không có provenance.

## 5. Artifact layout chính thức

```text
experiments/
  protocol/
    protocol-v12.yaml
    entrypoint-policy.md
  dataset/current/
    dataset.json
    projects.parquet
    environments.parquet
    packages.parquet
    vulnerabilities.parquet
    query_candidates.parquet
    queries.parquet
    snapshot_audit.parquet
    environment_audit.parquet
    package_source_audit.parquet
    query_eligibility.parquet
    eligibility_summary.json
    eligibility_funnel.csv
    eligibility_issues.parquet
    import_root_audit.parquet
    reproducibility_summary.json
    oracle_labels.parquet
    oracle_import_audit.parquet
    oracle_source_audit.json
    oracle_review_queue.parquet
    oracle_review_queue_eligible.csv
    project_graphs/
    images/
  oracle/
    reviews.jsonl
  vf/
    vf_variants.parquet
    vf_variant_audit.parquet
  runs/
    <run-id>/
      config.yaml
      query_results.parquet
      artifact_events.parquet
      analysis_events.parquet
      environment.json
      summary.json
  run_registry.parquet
results/
  experiment_report/
```

## 6. Progress checklist

- [x] P0 protocol và entrypoint scope đã freeze.
- [x] P1 RQ1 baselines hoàn thiện.
- [x] P1 EagerShared E2E pass.
- [x] P1 bootstrap và full figures được nối vào report.
- [x] P1 VF manifest builder hoàn thiện.
- [x] P1 run registry/resume hoàn thiện.
- [x] P2 official dataset freeze 28/28.
- [x] P3 environment build 28/28.
- [x] P3 reproducibility và import-root audit pass.
- [x] P4 eligibility funnel được duyệt.
- [x] P5 `manual_label` import ghép 811/811 và review queue đã tạo; `auto_reachability` bị bỏ qua.
- [ ] P5 oracle có 300–400 accepted label hợp lệ.
- [ ] P6 Fresh toàn bộ query hoàn thành.
- [ ] P6 determinism 10% × 3 pass.
- [ ] P7 RQ1 hoàn thành.
- [ ] P8 128 RQ2 run hoàn thành.
- [ ] P9 ablation hoàn thành.
- [ ] P10 VF study hoàn thành.
- [ ] P11 report chính thức được kiểm tra.
- [ ] P12 reproducibility package hoàn thành.

### Bằng chứng P0–P1 (2026-09-19)

- Protocol: `experiments/protocol/protocol-v12.yaml`; hash được đưa vào dataset ID, environment analysis config và run config. V2 thêm toolchain hệ thống. V3 cố định Docker context và uv workspace. V4 chọn minor thấp nhất tương thích. V5 freeze Poetry lock đã regenerate. V6 thêm override lock legacy. V7 sửa probe chạy trên Python 3.8. V8 đọc `python_requires` từ setup metadata, chọn Poetry theo lock schema và chuyển null-byte parse thành unknown. V9 lưu đường dẫn PEP 420 namespace và mở rộng mọi provider của import root dùng chung. V10 bỏ cài local project khi replay installed manifest. V11 ghi exception regenerate stale Poetry 2.1 lock của Robyn. V12 định nghĩa `source_hash` chỉ từ Python source; native binary là unknown boundary và dùng metadata cùng ABI/platform. Mỗi revision đều freeze dataset mới theo quy tắc P0.
- RQ1: CLI `f-vra eval baselines` sinh `package_exposure` và `usage_filter` theo cùng schema với Fresh.
- Eager E2E: `experiments/validate_eager_e2e.py`; kết quả tại `.tmp/eager-e2e/acceptance.json` xác nhận decision và witness bằng Fresh, có precompute build, artifact hit và cumulative cost chứa precompute.
- Report smoke: `.tmp/report-smoke/` có funnel, accuracy/coverage CSV, workload overlap, cumulative wall/CPU/function work, work saved, break-even, verdict transition và VF-error figure.
- VF: CLI `f-vra eval vf-build` đóng băng V0/V1/V2 và bind anchor theo source của environment; `f-vra eval vf` tính input precision/recall và downstream flips.
- Resume: registry theo config hash ghi `RUNNING | COMPLETE | FAILED`; lệnh determinism dùng ba run label độc lập.
- Kiểm thử: 66/66 test pass; bao phủ baseline, eager precompute cost, cluster bootstrap, VF metrics, resume, namespace multi-provider, PEP 420 path, source-only hash, replay không cài local project, stale Poetry lock, eligibility filtering, CSV `manual_label` isolation và oracle acceptance gate.
- P2: protocol-v12 official dataset ID `b5b367e9c162dcfbb7fd72de3e815f96833a7dcfe1efb491db1caa01c5690a23`; hai lần freeze (`experiments/dataset/current` và `.tmp/freeze-repeat-p2-v12`) đều có 28 project, 247 vulnerability, 811 candidate, 28 snapshot `READY` và cùng toàn bộ snapshot ID.

### Bằng chứng P3–P5 import v12, lịch sử (2026-09-20)

- P3 environment: `environment_audit.parquet` có 28 `READY`; 2.272 installed distribution được materialize, trong đó 2.259 có Python source, 9 native-only và 4 package không có import mapping.
- P3 import roots: `import_root_audit.parquet` có 2.223 root, 15 collision đều là `RESOLVED_MULTI_PROVIDER_EXPANSION`, 0 collision chưa giải quyết.
- P3 reproducibility: `reproducibility_summary.json` là `PASS`. Hai rebuild cho Poetry (`laurentS__slowapi`) và uv (`fastapi__asyncer`) giữ nguyên manifest và PackageID. Hai build `--no-cache` bằng recipe pip gốc cho requirements (`alerta__alerta`) cùng manifest hash và 40 PackageID; replay khác frontend bị từ chối và giữ riêng trong `reproducibility_replay_diagnostic.json`.
- P4 funnel: 811 candidate → 666 package installed → 656 affected version/source available → 362 VF bound/query eligible. Population gồm 24 project, 31 package, 119 direct, 243 transitive và đủ mục tiêu oracle 300–400.
- P5 import: CSV hash `b45741f217347ddcea19a390dd4973284f0f5cfa9b98c3ca60afc56b79ba22fa`; ghép 811/811 và lấy verdict duy nhất từ `manual_label`: 144 reachable, 667 unreachable. `auto_reachability` bị bỏ qua; 583/811 dòng khác nhãn manual và audit xác nhận 0 imported mismatch. Eligible queue có 362 dòng: 83 reachable và 279 unreachable. Toàn bộ label vẫn ở `pending_review`; trong population eligible có 2 reason thiếu và 1 annotator thiếu.

### Bằng chứng P2–P5 v13 lock-universe, hiện hành (2026-09-21)

- Snapshot: 28/28 checkout đúng commit trong `configs/local_projects.json` và sạch đối với tracked files. Dataset `experiments/dataset/v13-lock-universe` có ID `e58e59be7d70949d67b2718a94062325c825f0ea7afeb830fa9236facd3a40eb`, 247 vulnerability và 811 candidate.
- Resolver: không regenerate lock và không cài pin từ CSV lịch sử. `uv.lock`, `poetry.lock`, `Pipfile.lock` hoặc requirements trong đúng commit là nguồn materialization. CSV `resolved_packages.csv` chỉ tạo `affected_package_expectations.parquet` để audit.
- Profile: uv dùng toàn bộ group/extra khi tương thích. Workspace có extras xung đột dùng toàn bộ workspace package ở nhóm main, không ghép extras xung đột. Poetry materialize exact pin từ lock gốc, lọc marker theo Linux/x86_64/CPython target. Analysis vẫn chạy offline.
- Environment: 28/28 `READY`; 3.032 installed distribution, 3.000 có Python source, 16 native boundary và 16 package không có import mapping. Import-root audit có 3.053 root, 24 collision đều được mở rộng mọi source provider, 0 collision chưa giải quyết.
- Reproducibility: `reproducibility_summary.json` là `PASS`. Poetry, requirements.txt và uv đều build hai lần với manifest hash và toàn bộ PackageID giống baseline. Wheel metadata hash bỏ duy nhất trường `Generator` không semantic; source hash, version, tag, ABI và platform vẫn tham gia identity.
- Eligibility: 811 candidate → 756 affected package installed → 755 environment-version compatible/source available → 571 VF bound/query eligible, tăng 209 query so với v12. Trạng thái còn lại: 171 `UNKNOWN_VF_MISMATCH`, 13 `UNKNOWN_SOURCE`, 1 `ENVIRONMENT_LOCK_VARIANT_MISMATCH`, 55 `AFFECTED_PACKAGE_NOT_INSTALLED`. File manual có 0 version mismatch; trạng thái lock variant chỉ mô tả OCI Linux chọn một variant khác với version đã annotate.
- 55 missing row đều thuộc DB-GPT, gồm 21 package/version có trong `uv.lock` nhưng nằm ngoài all-workspace main profile. Các extras và accelerator profile của DB-GPT có conflict, nên muốn bao phủ 55 dòng này phải freeze nhiều environment variant; không được ép tất cả vào một OCI environment.
- Một environment lock-variant mismatch còn lại là Cinnamon/torch: manual row và scanner observation đều đúng ở 2.2.2; cùng `uv.lock` chọn 2.2.2 cho macOS x86_64 và 2.8.0 cho Linux OCI. Artifact đối chiếu chi tiết: `experiments/dataset/v13-lock-universe/ELIGIBILITY_RECONCILIATION.md`, `eligibility_reconciliation.csv` và `eligibility_reconciliation.json`.
- Oracle import: ghép 811/811 từ CSV hash `b45741f217347ddcea19a390dd4973284f0f5cfa9b98c3ca60afc56b79ba22fa`; verdict chỉ lấy từ `manual_label` (144 reachable, 667 unreachable), bỏ qua `auto_reachability`. Có 571 dòng eligible cho review; 811 label vẫn `pending_review`.

## 7. Việc cần làm ngay tiếp theo

Theo thứ tự:

1. Chốt có mở rộng protocol thành nhiều environment variant cho 55 dòng DB-GPT hay giữ một all-workspace main environment. Nếu giữ protocol hiện tại, 55 dòng tiếp tục ở audit và không vào accuracy population.
2. Human reviewer adjudicate 571 dòng trong `oracle_review_queue_eligible.csv` theo `experiments/oracle/REVIEW_GUIDE.md`; chọn 300–400 dòng phân tầng và hoàn thiện reason, annotator, witness/frontier evidence còn thiếu.
3. Áp dụng decision log bằng `f-vra eval oracle-review` và xác nhận 300–400 accepted label có đủ reviewer, timestamp và evidence.
4. Sau khi P5 pass, chạy Fresh toàn population và determinism 10% × 3.
5. Chạy RQ1, 128 run RQ2, ablation, VF study, report và reproducibility package theo P7–P12.

## 8. Điều kiện phải dừng để review protocol

Dừng trước khi chạy phase tiếp theo nếu xảy ra một trong các trường hợp:

- Snapshot hoặc installed manifest không deterministic.
- Số query đủ điều kiện không đủ cho oracle target.
- Package/VF mapping có collision hoặc mismatch chưa giải quyết.
- Fresh determinism có bất kỳ semantic/work mismatch nào.
- Eager precomputation không được hạch toán.
- Một policy trả `UNREACHABLE` khi frontier có source, native, parse, budget hoặc timeout boundary.
- Report trộn accuracy oracle với agreement against Fresh.

Mọi thay đổi sau một gate đã freeze phải tạo protocol/dataset version mới thay vì sửa âm thầm artifact cũ.
