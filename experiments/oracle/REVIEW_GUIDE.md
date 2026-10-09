# Hướng dẫn adjudicate oracle

## Population cần review

- Workbook đã ghép đúng 811/811 dòng theo `project_id + cve_id`.
- Có 362 candidate đạt toàn bộ eligibility gate. Đây là population dùng cho accuracy oracle và nằm trong mục tiêu 300–400, vì vậy review toàn bộ 362 dòng.
- File làm việc: `experiments/dataset/current/oracle_review_queue_eligible.csv`.
- File quyết định mẫu: `experiments/oracle/reviews.template.jsonl`.

## Thứ tự review

1. Ba dòng priority 1: hai dòng thiếu reason và một dòng thiếu annotator trong population đủ điều kiện.
2. 80 reachable còn lại.
3. 279 unreachable theo project, package, dependency type và VF multiplicity.

Ba reachable thiếu witness trong workbook không thuộc population đủ điều kiện hiện tại. Chúng vẫn nằm trong queue 811 dòng và không được dùng để bù accuracy oracle.

## Điều kiện accepted

Mỗi JSON object dùng `candidate_id` hoặc `query_id` và phải có:

- `review_status`: `accepted`, `rejected` hoặc `pending_review`;
- `evidence`: mô tả evidence đã kiểm tra trên snapshot đã pin;
- `reviewer`: tên hoặc định danh reviewer;
- `reviewed_at`: timestamp ISO 8601.

Với `REACHABLE`, giữ witness trong oracle candidate và đặt `witness_validated: true` sau khi xác minh đường đi tới đúng VF anchor.

Với `UNREACHABLE`, đặt `frontier_complete: true` chỉ khi đã xác nhận không còn source, native, dynamic, parse, budget hoặc timeout boundary bị chặn.

Không accept candidate có `query_eligible=false`. CLI sẽ từ chối quyết định thiếu evidence, reviewer, timestamp, witness validation hoặc frontier completeness.

## Áp dụng quyết định

```powershell
Copy-Item experiments/oracle/reviews.template.jsonl experiments/oracle/reviews.jsonl
# Điền các quyết định sau khi review.
f-vra eval oracle-review experiments/oracle/reviews.jsonl --dataset experiments/dataset/current
f-vra eval audit --dataset experiments/dataset/current
```

P6 chỉ bắt đầu khi 300–400 label đã accepted và không label nào thiếu provenance/evidence.
