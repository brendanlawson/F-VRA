"""
annotate_vf.py  (prompt v2)
================================================================================
Annotation pipeline cho Bucket A (Tier 1, pm ≤ 5) và bất kỳ bucket nào khác
sau khi rank.

Prompt v2 thay đổi so với v1:
  • Label set mới: root_cause_vf / vulnerable_usage_site / discard / review
  • Quy tắc 7 Python-only: non-Python/generated → bắt buộc discard
  • Quy tắc 8: vf_not_in_candidates flag
  • Output thêm: vf_qualified_name, mapping_type, evidence_level,
    vf_not_in_candidates, summary  (field "labels" đổi thành "per_candidate")
  • per_candidate dùng "reasoning" thay "reason"; confidence nâng lên group-level

Chạy:
  python scripts/annotate_vf.py                  # annotate toàn bộ Bucket A
  python scripts/annotate_vf.py --limit 10       # chỉ 10 groups đầu (test)
  python scripts/annotate_vf.py --dry-run        # xem prompt, không gọi API
  python scripts/annotate_vf.py --resume         # tiếp tục từ checkpoint
  python scripts/annotate_vf.py --bucket-file data/annotation_buckets/tier2_ready_after_rank.jsonl
"""

import argparse
import json
import os
import random
import re
import sys
import time
import traceback
from pathlib import Path

import requests

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

# ── Cấu hình ─────────────────────────────────────────────────────────────────
BASE_DIR           = Path(__file__).resolve().parents[2]
BUCKET_A_FILE      = BASE_DIR / "data" / "interim" / "annotations" / "current_cve_vf" / "annotation_buckets" / "tier1_ready.jsonl"
CAND_FILE          = BASE_DIR / "data" / "interim" / "current_cve_vf" / "current_candidate_functions.jsonl"
# Artifacts — source code và diff (giống prepare_annotation_batches.py)
MODIFIED_FUNCS_DIR = BASE_DIR / "data" / "interim" / "current_cve_vf" / "modified_functions"
PATCH_DIFFS_DIR    = BASE_DIR / "artifacts" / "patch_diffs"
ANNOTATION_QUEUE_FILE = BASE_DIR / "data" / "interim" / "annotations" / "current_cve_vf" / "current_annotation_queue.jsonl"
OUT_DIR            = BASE_DIR / "data" / "interim" / "annotations"
OUT_DIR.mkdir(parents=True, exist_ok=True)
RESULT_FILE        = OUT_DIR / "vf_annotations.jsonl"
CKPT_FILE          = OUT_DIR / ".checkpoint_vf_annotations.json"


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_dotenv(BASE_DIR / ".env")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENROUTER_HTTP_REFERER = os.environ.get("OPENROUTER_HTTP_REFERER", "https://linhvoice.io.vn/")
OPENROUTER_X_TITLE = os.environ.get("OPENROUTER_X_TITLE", "LinhVoice")
OPENROUTER_URL     = "https://openrouter.ai/api/v1/chat/completions"
#nvidia/nemotron-3-ultra-550b-a55b:free
#openai/gpt-oss-120b:free
DEFAULT_MODEL = os.environ.get("OPENROUTER_MODEL", "anthropic/claude-sonnet-5")

DELAY_BETWEEN_CALLS = 3.0     # tăng từ 1.5s — nhiều model :free giới hạn RPM rất thấp
MAX_RETRIES         = int(os.environ.get("OPENROUTER_MAX_RETRIES", "3"))
RETRY_DELAY         = 10      # fixed delay giữa các lần retry (không tăng dần)
RETRY_JITTER        = 0.2     # +/- 20% ngẫu nhiên, tránh nhiều group retry đồng loạt

MAX_DESCRIPTION_CHARS = 3000

MAX_CANDIDATES_PER_PROMPT = 10
MAX_CODE_LINES            = 500
MAX_DIFF_CHARS            = 30000   # trim diff per group — giống batch cũ
ANNOTATE_MIN_TOKENS       = int(os.environ.get("ANNOTATE_MIN_TOKENS", "3000"))
ANNOTATE_MAX_TOKENS       = int(os.environ.get("ANNOTATE_MAX_TOKENS", "8192"))

# Extensions nhận diện non-Python (dùng để cảnh báo trong prompt)
# Lưu ý: đây chỉ là danh sách hỗ trợ tạo cảnh báo nhanh (fast-path). Logic
# thật sự dùng WHITELIST — chỉ coi là "Python source hợp lệ" khi ext == .py
# (hoặc rỗng/không xác định, khi đó flag "unknown" để model tự kiểm tra),
# TUYỆT ĐỐI KHÔNG mặc định "an toàn" cho ext lạ không có trong danh sách.
NON_PYTHON_EXTS = {".c", ".cpp", ".cc", ".h", ".hpp", ".js", ".jsx", ".ts",
                   ".tsx", ".java", ".go", ".rs", ".rb", ".cs", ".kt",
                   ".php", ".swift", ".m", ".mm", ".scala", ".lua", ".pl",
                   ".sh", ".bash", ".ps1", ".bat", ".sql", ".proto",
                   ".yaml", ".yml", ".json", ".xml", ".html", ".css",
                   ".dart", ".groovy", ".vue", ".tf", ".dockerfile"}
# Extension "gần Python" nhưng KHÔNG phải pure executable Python source
# theo Rule 7 (stub/type-only/Cython) → luôn discard, không cần xét thêm.
PYTHON_NON_SOURCE_EXTS = {".pyi", ".pyx", ".pxd"}
# Suffix markers: file KẾT THÚC bằng chuỗi này (ví dụ foo_pb2.py)
GENERATED_SUFFIX_MARKERS = ("_pb2.py", "_pb2_grpc.py", "_generated.py", "_gen.py")
# Prefix markers: file BẮT ĐẦU bằng chuỗi này (ví dụ generated_client.py)
GENERATED_PREFIX_MARKERS = ("generated_",)
GENERATED_HEADERS = ("# generated by", "# do not edit", "# auto-generated",
                     "# this file is auto")


# ── Prompt v2 ─────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a Python security researcher annotating a CVE-to-Vulnerable-Function \
benchmark dataset. You get a CVE advisory, patch diff, and candidate \
functions extracted at the vulnerable commit. Classify each candidate with \
one of 4 labels, then give a group-level verdict.

─── LABELS ────────────────────────────────────────────────────────────────
root_cause_vf         — the function's OWN algorithmic logic builds/contains \
the unsafe artifact (missing validation, unsafe deserialization, path \
traversal, SQL injection, eval/pickle on untrusted input). Bug exists \
independent of any specific API call. Pure Python only (Rule 7).
vulnerable_usage_site — function passes unsanitized/sensitive data as an \
ARGUMENT to an otherwise-safe external API (e.g. LOG.info, self.msg, \
os.system, subprocess, template rendering) without sanitizing it first. The \
flaw is in the call, not the API and not the function's core algorithm. \
Pure Python only (Rule 7).
discard               — pure dispatcher/router; patch-added helper not \
present at vulnerable_ref; test/docs/config/migration; non-Python or \
generated source (Rule 7); pure refactor/logging-only change; unrelated code.
review                — cannot decide with available evidence; state exactly \
what's missing.

─── RULES ─────────────────────────────────────────────────────────────────
1. Never label a patch-added function (absent at vulnerable_ref) as \
root_cause_vf/vulnerable_usage_site.
2. Dispatcher that only calls the real sink → discard; label the sub-\
function instead.
3. Never label tests/docs/release-scripts/formatting/logging-only/generated \
code as vulnerable.
4. root_cause_vf vs vulnerable_usage_site — DIAGNOSTIC TEST: did the fix
change WHAT is called/how the result is used (algorithm), or only WHAT DATA
is passed into an unchanged call? If the fix only masks/redacts/wraps an
argument while the same call (LOG.info(...), self.msg(...), etc.) stays
unchanged → vulnerable_usage_site, even though the leak happens inside this
function. If the fix rewrites the unsafe construction logic itself (e.g.
adds path normalization + containment check, replaces string-concat SQL
with parameterized query) → root_cause_vf. Apply per call-site, not to the
whole function's complexity. EXCEPTION: eval/exec/pickle.loads/os.system/
subprocess with shell=True on untrusted input is ALWAYS root_cause_vf even
if the fix only adds input sanitization before the same call — these are
inherently-dangerous constructs, not safe APIs.
5. mapping_type: single_vf | multiple_independent_vfs (independent Python \
functions, each independently triggerable) | multi_function_behavior \
(several functions, same code path) | patch_variant_duplicate (backport of \
another advisory, same VF) | ambiguous.
6. Evidence priority: patch_diff > poc/test > maintainer note > advisory \
description; if description conflicts with patch/source, trust patch/\
source. Do NOT claim a hunk is "truncated" or "likely" modifies a function \
unless you can actually see that function changed in the given patch_diff — \
if you can't see it, use "review" and say what's missing.
7. [PYTHON-ONLY] Never assign root_cause_vf/vulnerable_usage_site to non-\
pure-Python source. Mandatory discard (reasoning must include \
"reason: non_python_source — <ext/type>") if: extension isn't .py; file is \
a generated stub (_pb2.py, *_generated.py, *_gen.py, or header says \
"Generated by"/"DO NOT EDIT"/"AUTO-GENERATED"); source is minified; or body \
is only pass/.../type annotations with no logic. If ALL candidates are \
non-Python, set vf_not_in_candidates=true.
8. If the true VF is clearly not among the candidates, set \
vf_not_in_candidates=true and name the suspected function/file in \
annotation_note.

─── OUTPUT (JSON only — no markdown fences, no preamble) ──────────────────
{
  "group_id": "<group_id>",
  "per_candidate": [
    {
      "qualified_name": "<name>",
      "label": "root_cause_vf|vulnerable_usage_site|discard|review",
      "reasoning": "<1-2 sentences citing the specific diff hunk/line; no \
guessing (Rule 6); if Rule 7 discard, start with \
'reason: non_python_source — <ext/type>'>"
    }
  ],
  "vf_qualified_name": "<qualified_name of best Python VF candidate, or null>",
  "mapping_type": "single_vf|multiple_independent_vfs|multi_function_behavior|\
patch_variant_duplicate|ambiguous",
  "evidence_level": "patch_verified|poc_verified|maintainer_confirmed|\
advisory_explicit|weak_or_uncertain",
  "confidence": "high|medium|low",
  "vf_not_in_candidates": false,
  "summary": "<1 sentence: root cause of this vulnerability>",
  "annotation_note": "<empty unless vf_not_in_candidates=true, \
patch_variant_duplicate, evidence_level=weak_or_uncertain, or many \
non-Python candidates>"
}
"""


# ── Artifact loaders (source + diff) ────────────────────────────────────────

def _safe_dir(s: str) -> str:
    import re
    return re.sub(r"[^A-Za-z0-9_.-]", "_", s)


def load_modified_source(group_id: str) -> dict[str, str]:
    """
    Load qualified_name -> source từ artifacts/modified_functions/<gid>/modified.jsonl.
    Đây là source ở vulnerable_ref — cần thiết để model thấy code trước khi patch.
    Trả về dict rỗng nếu file không tồn tại.
    """
    mod_file = MODIFIED_FUNCS_DIR / _safe_dir(group_id) / "modified.jsonl"
    if not mod_file.exists():
        return {}
    result = {}
    with open(mod_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                qn = rec.get("qualified_name", "")
                if qn:
                    result[qn] = rec.get("source", "")
            except json.JSONDecodeError:
                pass
    return result


def split_diff_by_file(diff_text: str) -> list[tuple[str, str]]:
    """
    Tách 1 diff text (có thể nhiều file) thành list (first_line, full_block).
    Dùng để đảm bảo KHÔNG file nào bị cắt mất hoàn toàn khi truncate.
    """
    import re as _re
    if not diff_text:
        return []
    parts = _re.split(r"(?=^diff --git )", diff_text, flags=_re.MULTILINE)
    blocks: list[tuple[str, str]] = []
    for part in parts:
        part = part.strip("\n")
        if not part.startswith("diff --git"):
            continue
        blocks.append((part.splitlines()[0], part))
    return blocks


def build_diff_excerpt(diff_text: str, max_chars: int) -> tuple[str, bool]:
    """
    Cắt diff theo TỪNG FILE (chia budget đều), KHÔNG cắt thô theo ký tự
    toàn cục. Bug cũ: diff_text[:MAX_DIFF_CHARS] cắt từ đầu, nên file đứng
    sau trong alphabet (ví dụ django/http/__init__.py sau django/contrib/...)
    có thể bị mất 100% mà model không hề biết — dẫn đến model tự suy luận
    sai "file này không bị patch". Fix: mọi file luôn còn ít nhất header +
    1 phần hunk, có note rõ ràng nếu bị cắt — không bao giờ biến mất im lặng.
    """
    if len(diff_text) <= max_chars:
        return diff_text, False

    blocks = split_diff_by_file(diff_text)
    if not blocks:
        # Không parse được theo file (định dạng lạ) — fallback cắt thô,
        # nhưng vẫn cảnh báo rõ để model không tin nhầm là "đầy đủ".
        return diff_text[:max_chars], True

    budget_per_file = max(max_chars // len(blocks), 250)
    out_parts: list[str] = []
    for header, block in blocks:
        if len(block) <= budget_per_file:
            out_parts.append(block)
        else:
            n_omitted = len(block) - budget_per_file
            out_parts.append(
                block[:budget_per_file]
                + f"\n... [{n_omitted} chars OMITTED — file IS part of this "
                  f"patch, only hunk truncated for length, do not assume "
                  f"unmodified]"
            )
    return "\n".join(out_parts), True


def load_diff_excerpt(group_id: str, diff_sha: str | None = None) -> tuple[str, bool]:
    """
    Load diff text từ artifacts/patch_diffs/<gid>/*.diff.
    Ưu tiên file khớp diff_sha_used; nếu không có, NỐI TẤT CẢ file .diff
    tìm được trong dir (bug cũ chỉ lấy file đầu tiên rồi break — bỏ sót
    diff của các file khác nếu patch_diffs lưu nhiều file riêng).
    Trả về (diff_text, was_truncated).
    """
    diff_dir = PATCH_DIFFS_DIR / _safe_dir(group_id)
    diff_text = ""

    if diff_sha:
        df = diff_dir / f"{diff_sha[:12]}.diff"
        if df.exists():
            try:
                diff_text = df.read_text(encoding="utf-8", errors="replace")
            except Exception:
                pass

    if not diff_text and diff_dir.exists():
        diff_parts = []
        for df in sorted(diff_dir.glob("*.diff")):
            try:
                diff_parts.append(df.read_text(encoding="utf-8", errors="replace"))
            except Exception:
                continue
        diff_text = "\n".join(diff_parts)

    return build_diff_excerpt(diff_text, MAX_DIFF_CHARS)


# ── Helpers: Python-only pre-check ───────────────────────────────────────────

def _is_likely_non_python(fn: dict, resolved_source: str | None = None) -> tuple[bool, str]:
    """
    Kiểm tra sơ bộ candidate có khả năng non-Python/generated/không-có-logic
    không. Trả về (is_non_python, reason_hint) để thêm vào prompt context.
    Script không tự discard — để model quyết định theo Rule 7.

    QUAN TRỌNG:
    - Dùng WHITELIST cho extension: chỉ .py mới được coi là "pure Python
      source hợp lệ". Extension lạ/không nằm trong NON_PYTHON_EXTS KHÔNG
      được mặc định là an toàn — vẫn bị flag "unknown extension" để model
      tự kiểm tra kỹ theo Rule 7, tránh bug cũ (silently pass qua).
    - `resolved_source` PHẢI là nguồn source đã resolve giống hệt logic
      hiển thị cho model (source_lk trước, rồi mới tới fn["source"/"source_code"/
      "code"]). Nếu gọi hàm này mà không truyền resolved_source, nó sẽ tự
      resolve lại y hệt để không bao giờ lệch với phần hiển thị — tránh bug
      cũ: pre-check đọc fn.get("source_code") trong khi phần hiển thị đọc
      source_lk, khiến candidate có source nằm trong source_lk (rất phổ biến)
      bị NHẦM là "stub-only body" dù thực ra có đầy đủ logic.
    """
    fp = (fn.get("file_path") or "").lower()
    ext = Path(fp).suffix if fp else ""

    if not fp:
        return True, "missing file_path — cannot verify source is Python, review manually"

    if ext in NON_PYTHON_EXTS:
        return True, f"non-Python file ({ext})"

    if ext in PYTHON_NON_SOURCE_EXTS:
        return True, f"not executable Python source ({ext} — stub/type-only/Cython)"

    if ext != ".py":
        # Extension không nằm trong whitelist .py và cũng không khớp danh
        # sách non-Python đã biết → KHÔNG được coi là an toàn, chỉ là chưa
        # nhận diện được. Flag rõ để model tự xác minh, đúng tinh thần Rule 7.
        return True, f"unrecognized extension ({ext or 'none'}) — verify Python source manually"

    # ext == ".py" từ đây trở xuống
    base = Path(fp).name
    if any(base.endswith(m) for m in GENERATED_SUFFIX_MARKERS):
        return True, "generated Python stub (filename suffix pattern)"
    if any(base.startswith(m) for m in GENERATED_PREFIX_MARKERS):
        return True, "generated Python stub (filename prefix pattern)"

    source = resolved_source if resolved_source is not None else (
        fn.get("source") or fn.get("source_code") or fn.get("code") or "")

    if not source or source.startswith("[SOURCE_MISSING"):
        # Không có source để kiểm tra — KHÔNG suy diễn là stub, để model
        # (hoặc pipeline) xử lý như "review", tránh false positive "stub".
        return False, ""

    src_head = source[:300].lower()
    if any(h in src_head for h in GENERATED_HEADERS):
        return True, "generated Python stub (file header)"

    # Chỉ pass / ... / docstring / type annotations, không có logic thật
    body = source.strip()
    body_lines = [l.strip() for l in body.splitlines()
                  if l.strip() and not l.strip().startswith("#")]
    non_trivial = [l for l in body_lines
                   if l not in ("pass", "...", "")
                   and not l.startswith("def ")
                   and not l.startswith("class ")
                   and not l.startswith("@")
                   and not (l.startswith('"""') or l.startswith("'''"))
                   and ":" not in l[:20]]
    if body_lines and not non_trivial:
        return True, "stub-only body (pass/.../docstring/type annotations, no real logic)"

    return False, ""


# ── Prompt builder ────────────────────────────────────────────────────────────

def build_user_prompt(group_id: str, cand_rec: dict,
                      source_lk: dict[str, str],
                      diff_text: str, diff_truncated: bool,
                      max_candidates: int = MAX_CANDIDATES_PER_PROMPT) -> str:
    """
    Xây dựng user prompt đầy đủ cho 1 group.

    cand_rec = 1 record từ candidate_functions_v2.jsonl — file này gộp sẵn
    advisory metadata + danh sách candidates trong cùng 1 object/group_id.
    Nếu cand_rec đến từ rank_candidates_bucket_b.py, candidates ĐÃ được sắp
    xếp theo _rank_score giảm dần — cắt ở đây chỉ là an toàn lần 2, không
    làm thay đổi thứ tự.

    Thứ tự thông tin trong prompt (từ quan trọng nhất):
      1. Advisory context  — CVE ID, package, CWE, description
      2. Patch diff        — evidence cao nhất, model nhìn diff để biết gì thay đổi
      3. Candidates        — source ở vulnerable_ref kèm file_path, start_line
    """
    pkg_raw       = cand_rec.get("package")
    pkg           = pkg_raw.get("name") if isinstance(pkg_raw, dict) else (pkg_raw or "unknown")
    vuln_desc     = (cand_rec.get("vulnerability_description")
                     or cand_rec.get("description") or "")
    cwe           = cand_rec.get("cwe_ids") or []
    cve_id        = group_id.split("::")[0]
    vulnerable_ref= cand_rec.get("vulnerable_ref", "")
    fixed_ref     = cand_rec.get("fixed_ref", "")
    modified_files= cand_rec.get("modified_files") or []
    references    = cand_rec.get("references") or []
    aliases       = cand_rec.get("aliases") or {}
    affected_versions = cand_rec.get("affected_versions") or ""
    fixed_versions = cand_rec.get("fixed_versions") or ""
    repo_url      = cand_rec.get("repo_url") or ""
    fix_commits   = cand_rec.get("fix_commits") or []
    pre_evidence_level = cand_rec.get("pre_evidence_level") or cand_rec.get("evidence_level") or ""
    judged_evidence_level = cand_rec.get("judged_evidence_level") or ""
    evidence_reasoning = cand_rec.get("evidence_reasoning") or cand_rec.get("judge_reasoning") or ""

    # Lấy candidates — hỗ trợ cả 2 hình thái đã thấy trong dữ liệu thật:
    # "candidates": [...] (list trực tiếp) hoặc "candidates": {"patch_modified"/
    # "patch_extended": [...]} (dict lồng, một số group cũ).
    candidates_raw: list[dict] = []
    cands_obj = cand_rec.get("candidates") or {}
    if isinstance(cands_obj, dict):
        candidates_raw = (cands_obj.get("patch_modified")
                          or cands_obj.get("patch_extended") or [])
    elif isinstance(cands_obj, list):
        candidates_raw = cands_obj
    candidates_raw = candidates_raw[:max_candidates]

    # ── Cross-check modified_files vs file thực tế trong diff ──────────────
    # Bug đã gặp: modified_files (metadata) thiếu file so với diff thật
    # (django/http/__init__.py bị thiếu trong 1 group thực tế) → model tin
    # nhầm "file X không bị patch". Luôn ưu tiên diff, cảnh báo rõ nếu lệch.
    diff_file_paths: list[str] = []
    for header, _ in split_diff_by_file(diff_text):
        m = re.match(r"diff --git a/(.+?) b/(.+)$", header)
        if m:
            diff_file_paths.append(m.group(2))
    files_missing_from_metadata = [f for f in diff_file_paths if f not in modified_files]

    lines: list[str] = []

    # ── 1. Advisory context ───────────────────────────────────────────────────
    lines += [
        f"CVE ID        : {cve_id}",
        f"Package       : {pkg}",
    ]
    if cwe:
        lines.append(f"CWE           : {', '.join(str(c) for c in cwe)}")
    if repo_url:
        lines.append(f"Repo URL      : {repo_url}")
    if vulnerable_ref:
        lines.append(f"Vulnerable ref: {vulnerable_ref}")
    if fixed_ref:
        lines.append(f"Fixed ref     : {fixed_ref}")
    if affected_versions:
        lines.append(f"Affected vers.: {affected_versions}")
    if fixed_versions:
        lines.append(f"Fixed versions: {fixed_versions}")
    if pre_evidence_level:
        lines.append(f"Pre-evidence  : {pre_evidence_level}")
    if judged_evidence_level:
        lines.append(f"Judged evidence: {judged_evidence_level}")
    if evidence_reasoning:
        lines.append(f"Evidence note : {evidence_reasoning[:1000]}")
    if modified_files:
        lines.append(f"Modified files: {', '.join(modified_files[:8])}"
                     + (" ..." if len(modified_files) > 8 else ""))
    if files_missing_from_metadata:
        lines.append(
            f"⚠ WARNING: the PATCH DIFF below also modifies "
            f"{', '.join(files_missing_from_metadata[:5])} — these files are "
            f"NOT listed in 'Modified files' above (metadata is incomplete "
            f"for this group). TRUST THE DIFF, not the file list above, when "
            f"deciding whether a candidate's file was touched by the patch."
        )
    if len(vuln_desc) > MAX_DESCRIPTION_CHARS:
        vuln_desc = (
            vuln_desc[:MAX_DESCRIPTION_CHARS]
            + "\n\n...[truncated]..."
        )
    lines.append(
        "\nAdvisory description:\n"
        + (vuln_desc or "[missing]")
    )

    lines.append("\nAliases:")
    if aliases:
        lines.append(json.dumps(aliases, ensure_ascii=False, sort_keys=True)[:3000])
    else:
        lines.append("[none]")

    lines.append("\nReferences:")
    if references:
        for idx, ref in enumerate(references, start=1):
            if idx > 80:
                lines.append(f"... [{len(references) - 80} references omitted for length]")
                break
            if isinstance(ref, dict):
                category = ref.get("category") or ref.get("type") or ""
                url = ref.get("url") or ""
                lines.append(f"- [{category}] {url}")
            else:
                lines.append(f"- {ref}")
    else:
        lines.append("[none]")

    lines.append("\nFix commits:")
    if fix_commits:
        for idx, commit in enumerate(fix_commits, start=1):
            if idx > 20:
                lines.append(f"... [{len(fix_commits) - 20} commits omitted for length]")
                break
            if isinstance(commit, dict):
                lines.append(
                    "- "
                    + json.dumps(
                        {
                            "sha": commit.get("sha"),
                            "url": commit.get("url"),
                            "diff_path": commit.get("diff_path"),
                            "has_source_changes": commit.get("has_source_changes"),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                )
            else:
                lines.append(f"- {commit}")
    else:
        lines.append("[none]")

    # ── 2. Patch diff ─────────────────────────────────────────────────────────
    if diff_text:
        trunc_note = (" [some files below had their hunk truncated for "
                      "length — each is marked inline with an explicit "
                      "OMITTED note; a function NOT shown is still possibly "
                      "modified, do not assume otherwise without that note]"
                      if diff_truncated else "")
        lines += [
            f"\n{'─'*60}",
            f"PATCH DIFF{trunc_note}:",
            f"{'─'*60}",
            "```diff",
            diff_text,
            "```",
        ]
    else:
        lines.append("\n[No patch diff available — rely on source and description]")

    # ── 3. Candidates ─────────────────────────────────────────────────────────
    # Resolve source TRƯỚC cho mọi candidate — dùng đúng 1 nguồn xuyên suốt
    # cho cả pre-check non-Python lẫn phần hiển thị, tránh bug cũ (pre-check
    # đọc fn.get("source_code") trong khi hiển thị đọc source_lk, khiến
    # candidate có source nằm trong source_lk bị nhầm là "stub-only").
    resolved_sources: list[str] = []
    for fn in candidates_raw:
        qname = fn.get("qualified_name") or fn.get("name") or ""
        src = (source_lk.get(qname)
              or fn.get("source") or fn.get("source_code") or fn.get("code")
              or "")
        resolved_sources.append(src or "[SOURCE_MISSING — label as review if needed]")

    # Pre-check non-Python để cảnh báo model
    non_py_flags = [_is_likely_non_python(fn, src)
                    for fn, src in zip(candidates_raw, resolved_sources)]
    non_py_count = sum(1 for is_np, _ in non_py_flags if is_np)
    if non_py_count:
        lines.append(
            f"\n⚠ Pre-check: {non_py_count}/{len(candidates_raw)} candidates "
            f"appear non-Python, generated, or unverifiable (missing/unknown "
            f"extension, no source) — apply Rule 7 carefully. If unable to "
            f"confirm a flagged candidate is pure Python source, prefer "
            f"'review' over guessing."
        )

    lines.append(f"\n{'─'*60}")
    lines.append(f"CANDIDATE FUNCTIONS AT vulnerable_ref ({len(candidates_raw)} total):")
    lines.append(f"{'─'*60}\n")

    for i, fn in enumerate(candidates_raw, 1):
        qname      = fn.get("qualified_name") or fn.get("name") or f"candidate_{i}"
        file_path  = fn.get("file_path") or ""
        start_line = fn.get("start_line")
        end_line   = fn.get("end_line")
        partition  = fn.get("partition", "")
        rank_score = fn.get("rank_score")
        ext        = Path(file_path).suffix if file_path else ".py"

        source = resolved_sources[i - 1]

        # Giới hạn code lines
        code_lines = source.splitlines()
        if len(code_lines) > MAX_CODE_LINES:
            code_lines = (code_lines[:MAX_CODE_LINES]
                          + [f"... [{len(code_lines)-MAX_CODE_LINES} lines truncated]"])
        source_short = "\n".join(code_lines)

        # Non-Python hint (đã tính sẵn ở trên, cùng nguồn source_short)
        is_np, np_reason = non_py_flags[i - 1]
        hint = f"  ⚠ {np_reason}" if is_np else ""

        # Metadata header
        loc = f" L{start_line}–{end_line}" if start_line and end_line else ""
        meta_parts = [f"partition={partition}"] if partition else []
        if rank_score is not None:
            meta_parts.append(f"rank={rank_score:.3f}")
        meta = f"  [{', '.join(meta_parts)}]" if meta_parts else ""

        lang = ext.lstrip(".") if ext not in (".py", "") else "python"

        lines.append(f"[{i}] {qname}{hint}{meta}")
        if file_path:
            lines.append(f"    File: {file_path}{loc}")
        lines.append(f"```{lang}\n{source_short}\n```\n")

    lines.append(
        f"Classify all {len(candidates_raw)} candidates. "
        f"Use the patch diff above as primary evidence. "
        f"Respond ONLY with the JSON object — no markdown fences, no preamble."
    )
    return "\n".join(lines)


# ── API call ──────────────────────────────────────────────────────────────────

class QuotaExhaustedError(RuntimeError):
    """Model hết quota/credit — retry vô ích, cần dừng cả batch, không phải
    chỉ group hiện tại."""
    pass


def _sleep_retry(retry_after: float | None = None) -> float:
    """
    Thời gian chờ trước khi retry. Ưu tiên Retry-After từ server nếu có;
    ngược lại dùng RETRY_DELAY cố định + jitter nhỏ (tránh nhiều group
    retry đồng loạt), KHÔNG tăng dần theo attempt — giữ tốc độ annotate
    nhanh khi số lượng sample lớn.
    """
    wait = retry_after if retry_after is not None else RETRY_DELAY
    jitter = wait * RETRY_JITTER
    wait = max(1.0, wait + random.uniform(-jitter, jitter))
    time.sleep(wait)
    return wait


def parse_json_object(content: str) -> dict:
    text = content.strip()
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:].strip()
    start = text.find("{")
    if start < 0:
        raise json.JSONDecodeError("No JSON object found", text, 0)

    depth = 0
    in_string = False
    escaped = False
    for idx in range(start, len(text)):
        char = text[idx]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                candidate = text[start:idx + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
                    return json.loads(repaired)
    candidate = text[start:]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
        return json.loads(repaired)


def call_openrouter(user_prompt: str, model: str, num_candidates: int = 1) -> dict:
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type":  "application/json",
        "HTTP-Referer":  OPENROUTER_HTTP_REFERER,
        "X-Title":       OPENROUTER_X_TITLE,
    }
    # Nemotron-3-Ultra là reasoning model — mặc định nó viết phần suy luận
    # ("Let me analyze...") ngay trong content trước khi in JSON, ăn hết
    # max_tokens khiến JSON luôn bị cắt cụt với group nhiều candidates.
    # Tắt reasoning mode để model in thẳng JSON, và cấp max_tokens động
    # theo số candidates — giống llm_fill_annotator.py.
    dynamic_max_tokens = min(ANNOTATE_MAX_TOKENS, max(ANNOTATE_MIN_TOKENS, num_candidates * 150 + 500))
    payload = {
        "model":       model,
        "messages":    [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_prompt},
        ],
        "temperature": 0.1,
        "max_tokens":  dynamic_max_tokens,
        "reasoning":   {"enabled": False},
    }

    last_error = ""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(OPENROUTER_URL, headers=headers,
                                 json=payload, timeout=60)

            if resp.status_code in {402, 429}:
                # Đọc Retry-After header nếu server cung cấp — đáng tin hơn
                # backoff tự đoán.
                retry_after = None
                ra_header = resp.headers.get("Retry-After") or resp.headers.get("retry-after")
                if ra_header:
                    try:
                        retry_after = float(ra_header)
                    except ValueError:
                        retry_after = None

                # Đọc body để phân biệt "rate limit tạm thời" (nên retry) vs
                # "hết quota" (retry vô ích, nên fail sớm thay vì tốn hết
                # MAX_RETRIES × backoff cho 1 group không thể thành công).
                err_msg = ""
                try:
                    err_body = resp.json()
                    err_msg = json.dumps(err_body.get("error", err_body), ensure_ascii=False)[:300]
                except Exception:
                    err_msg = resp.text[:300]

                quota_markers = ("quota", "daily limit", "insufficient_quota",
                                 "exceeded your", "credits")
                is_quota_exhausted = any(m in err_msg.lower() for m in quota_markers)

                if resp.status_code == 402 or is_quota_exhausted:
                    raise QuotaExhaustedError(
                        f"Quota/credit exhausted for model '{model}' — retry sẽ "
                        f"không giúp ích, cần đổi model hoặc nạp credit. "
                        f"Server: {err_msg}"
                    )

                wait = _sleep_retry(retry_after)
                print(f"    Rate limit (429) — attempt {attempt}/{MAX_RETRIES}, "
                      f"waited {wait:.1f}s"
                      f"{' [Retry-After honored]' if retry_after else ' [fixed delay]'} "
                      f"— {err_msg[:120]}")
                continue

            resp.raise_for_status()
            resp_json = resp.json()
            if "choices" not in resp_json:
                # Server trả 200 nhưng thiếu 'choices' (lỗi tạm thời, content
                # filter, hoặc payload lỗi phía model) — log để debug rồi để
                # except bên dưới xử lý retry thay vì crash cả group.
                print(f"    ⚠ Response thiếu 'choices': {json.dumps(resp_json, ensure_ascii=False)[:300]}")
                raise KeyError("choices")
            choice = resp_json["choices"][0]
            content = (choice["message"]["content"] or "").strip()
            finish_reason = choice.get("finish_reason")
            if finish_reason == "length":
                print(f"    ⚠ Response bị cắt do max_tokens (finish_reason=length, "
                      f"{len(content)} chars). Cần tăng max_tokens hoặc giảm số candidates.")
            if not content:
                raise json.JSONDecodeError("Empty content from model", "", 0)
            # Strip markdown fence nếu model vẫn bọc
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:].strip()
            # Nếu model vẫn lỡ viết preamble/reasoning trước JSON (dù đã tắt
            # reasoning mode), cắt bỏ mọi thứ trước dấu "{" đầu tiên — giống
            # llm_fill_annotator.py.
            if not content.startswith("{"):
                brace_idx = content.find("{")
                if brace_idx > 0:
                    print(f"    ⚠ Phát hiện preamble trước JSON ({brace_idx} ký tự) — đã cắt bỏ")
                    content = content[brace_idx:]
            try:
                return parse_json_object(content)
            except json.JSONDecodeError as e:
                print(f"    ⚠ JSON parse lỗi, raw content (đầu/cuối 300 ký tự):")
                print(f"      HEAD: {content[:300]!r}")
                print(f"      TAIL: {content[-300:]!r}")
                raise
        except QuotaExhaustedError:
            raise  # quota exhausted — không retry, đẩy lên caller ngay
        except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
            last_error = str(e)
            print(f"    Attempt {attempt} failed: {e}")
            if attempt < MAX_RETRIES:
                _sleep_retry()
    detail = f": {last_error}" if last_error else ""
    raise RuntimeError(f"No valid response after {MAX_RETRIES} retries{detail}")


# ── Validate & normalize output ───────────────────────────────────────────────

VALID_LABELS        = {"root_cause_vf", "vulnerable_usage_site", "discard", "review"}
VALID_MAPPING_TYPES = {"single_vf", "multiple_independent_vfs",
                       "multi_function_behavior", "patch_variant_duplicate", "ambiguous"}
VALID_EVIDENCE      = {"patch_verified", "poc_verified", "maintainer_confirmed",
                       "advisory_explicit", "weak_or_uncertain"}
VALID_CONF          = {"high", "medium", "low"}


def normalize_result(raw: dict, group_id: str, model: str) -> dict:
    """
    Chuẩn hóa output của model về schema v2 đầy đủ.
    Không raise — điền giá trị mặc định nếu thiếu field để không crash pipeline.
    """
    out = dict(raw)
    out["group_id"]      = group_id
    out["model"]         = model
    out["annotation_ts"] = int(time.time())

    # per_candidate — đảm bảo list, mỗi item có đủ field
    per_cand = out.get("per_candidate") or []
    cleaned  = []
    for item in per_cand:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label", "review")).lower()
        if label not in VALID_LABELS:
            label = "review"
        cleaned.append({
            "qualified_name": item.get("qualified_name", ""),
            "label":          label,
            "reasoning":      item.get("reasoning") or item.get("reason", ""),
        })
    out["per_candidate"] = cleaned

    # Group-level fields với fallback
    out["vf_qualified_name"]    = out.get("vf_qualified_name")
    out["mapping_type"]         = (out.get("mapping_type", "ambiguous")
                                   if out.get("mapping_type") in VALID_MAPPING_TYPES
                                   else "ambiguous")
    out["evidence_level"]       = (out.get("evidence_level", "weak_or_uncertain")
                                   if out.get("evidence_level") in VALID_EVIDENCE
                                   else "weak_or_uncertain")
    out["confidence"]           = (out.get("confidence", "low")
                                   if out.get("confidence") in VALID_CONF else "low")
    out["vf_not_in_candidates"] = bool(out.get("vf_not_in_candidates", False))
    out["summary"]              = out.get("summary", "")
    out["annotation_note"]      = out.get("annotation_note", "")

    return out


# ── Checkpoint helpers ────────────────────────────────────────────────────────

def load_checkpoint(ckpt_file: Path) -> set[str]:
    if ckpt_file.exists():
        return set(json.loads(ckpt_file.read_text(encoding="utf-8")))
    return set()


def save_checkpoint(done: set[str], ckpt_file: Path) -> None:
    ckpt_file.write_text(
        json.dumps(sorted(done), ensure_ascii=False), encoding="utf-8"
    )


def load_jsonl(path: Path) -> list[dict]:
    out = []
    if not path.exists():
        print(f"⚠️  File không tồn tại: {path.resolve()}")
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s:
                try:
                    out.append(json.loads(s))
                except json.JSONDecodeError:
                    pass
    return out


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bucket-file", default=str(BUCKET_A_FILE))
    parser.add_argument("--cand-file",   default=str(CAND_FILE),
                        help="File candidate (group_id->candidates). Mặc định "
                             "CAND_FILE; dùng để trỏ vào file đã rank cho "
                             "bucket B, ví dụ candidate_functions_v2_bucketB_ranked.jsonl")
    parser.add_argument("--out-file",    default=str(RESULT_FILE),
                        help="File kết quả annotation. ĐỔI khi chạy bucket khác "
                             "bucket A, nếu không sẽ GHI ĐÈ vf_annotations_tier1.jsonl")
    parser.add_argument("--ckpt-file",   default=str(CKPT_FILE),
                        help="File checkpoint cho --resume. Đổi cùng --out-file "
                             "để tránh lẫn checkpoint giữa các bucket")
    parser.add_argument(
        "--audit-file",
        default=str(BASE_DIR / "data" / "interim" / "current_cve_vf" / "audits" / "annotation_run_audit.json"),
        help="File audit tong ket lan chay annotation",
    )
    parser.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES_PER_PROMPT,
                        help="Số candidate tối đa đưa vào prompt/group. Bucket A "
                             "dùng default (10); bucket B cần giá trị cao hơn — "
                             "rank_candidates_bucket_b.py sẽ gợi ý giá trị phù hợp")
    parser.add_argument("--model",       default=DEFAULT_MODEL)
    parser.add_argument("--limit",       type=int, default=None)
    parser.add_argument("--dry-run",     action="store_true")
    parser.add_argument("--resume",      action="store_true")
    parser.add_argument("--skip-gid",    action="append", default=[],
                        help="group_id cần bỏ qua (có thể lặp lại nhiều lần). "
                             "Ví dụ: --skip-gid \"CVE-2026-7813::pgadmin4\"")
    args = parser.parse_args()

    if not args.dry_run and not OPENROUTER_API_KEY:
        print("❌ Thiếu OPENROUTER_API_KEY:")
        print("   set OPENROUTER_API_KEY=sk-or-...")
        return

    bucket_items = load_jsonl(Path(args.bucket_file))
    cand_records = load_jsonl(Path(args.cand_file))
    queue_records = load_jsonl(ANNOTATION_QUEUE_FILE)

    queue_by_gid = {
        r["group_id"]: r
        for r in queue_records
    }
    cand_by_gid  = {r["group_id"]: r for r in cand_records}
    out_file  = Path(args.out_file)
    ckpt_file = Path(args.ckpt_file)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    if args.limit:
        bucket_items = bucket_items[:args.limit]

    print(f"Model        : {args.model}")
    print(f"Groups       : {len(bucket_items)}")
    print(f"Output       : {out_file}")
    print(f"Dry-run      : {args.dry_run}")
    print(f"Prompt ver   : v2 (root_cause_vf / vulnerable_usage_site / Python-only rule)")
    print(f"Candidates   : {args.cand_file} ({len(cand_records)} records)")
    print(f"Max cand/grp : {args.max_candidates}")
    print(f"Source dir   : {MODIFIED_FUNCS_DIR}")
    print(f"Diff dir     : {PATCH_DIFFS_DIR}")
    print()

    done_gids: set[str] = set()
    if args.resume:
        done_gids = load_checkpoint(ckpt_file)
        print(f"Resume: {len(done_gids)} groups already done")

    result_mode = "a" if (args.resume and out_file.exists()) else "w"
    result_fh   = open(out_file, result_mode, encoding="utf-8")
    stats = {"ok": 0, "skip": 0, "error": 0, "no_source": 0, "no_diff": 0}

    try:
        skip_gids = set(args.skip_gid)

        for i, item in enumerate(bucket_items, 1):
            gid = item["group_id"]

            if gid in skip_gids:
                print(f"[{i}/{len(bucket_items)}] ⏭ SKIP (--skip-gid) {gid}")
                stats["skip"] += 1
                continue

            if gid in done_gids:
                stats["skip"] += 1
                continue

            cand_rec = cand_by_gid.get(gid)
            if not cand_rec:
                print(f"[{i}/{len(bucket_items)}] ⚠ SKIP {gid} — no candidate record")
                stats["skip"] += 1
                continue

            # Load source + diff từ artifacts (giống prepare_annotation_batches.py)
            source_lk        = load_modified_source(gid)
            diff_text, diff_truncated = load_diff_excerpt(gid, cand_rec.get("diff_sha_used"))
            if not source_lk:
                stats["no_source"] += 1
            if not diff_text:
                stats["no_diff"] += 1

            # FIX: nếu cand_rec đến từ rank_candidates_bucket_b.py, dùng
            # ngưỡng RIÊNG của group đó (đủ để không cắt mất candidate
            # exact_overlap) thay vì 1 số --max-candidates chung cho cả
            # bucket — group nhỏ vẫn giữ prompt nhỏ, không bị thổi phồng
            # bởi ngưỡng cần cho vài group lớn nhất (vd 92).
            group_max = max(
                args.max_candidates,
                cand_rec.get("_rank_suggested_max_candidates", 0)
            )
            # Enrich candidate metadata from annotation queue
            queue_rec = queue_by_gid.get(gid)
            cand_rec = dict(cand_rec)

            def _merge_prompt_metadata(src: dict | None) -> None:
                if not src:
                    return
                keys = [
                    "description",
                    "vulnerability_description",
                    "references",
                    "aliases",
                    "affected_versions",
                    "fixed_versions",
                    "repo_url",
                    "vulnerable_ref",
                    "fixed_ref",
                    "fix_commits",
                    "cwe_ids",
                    "pre_evidence_level",
                    "judged_evidence_level",
                    "material_status",
                    "material_gaps",
                    "evidence_level",
                ]
                for key in keys:
                    value = src.get(key)
                    if value not in (None, "", [], {}):
                        cand_rec[key] = value
                if src.get("judge_reasoning"):
                    cand_rec["evidence_reasoning"] = src["judge_reasoning"]
                elif src.get("evidence_reasoning"):
                    cand_rec["evidence_reasoning"] = src["evidence_reasoning"]

            _merge_prompt_metadata(queue_rec)
            _merge_prompt_metadata(item)
            user_prompt = build_user_prompt(
                gid, cand_rec, source_lk, diff_text, diff_truncated,
                max_candidates=group_max
            )
            # Số candidate thật sự đưa vào prompt (đọc lại từ dòng header
            # "CANDIDATE FUNCTIONS AT vulnerable_ref (N total):") — dùng để
            # tính dynamic max_tokens cho nemotron (reasoning model).
            _m = re.search(r"CANDIDATE FUNCTIONS AT vulnerable_ref \((\d+) total\)", user_prompt)
            num_candidates = int(_m.group(1)) if _m else 1

            # ── Dry-run ──────────────────────────────────────────────────────
            if args.dry_run:
                print(f"\n{'='*70}")
                print(f"[{i}] {gid}")
                print(f"{'─'*70}")
                print(user_prompt[:2500])
                if len(user_prompt) > 2500:
                    print(f"... [truncated — total {len(user_prompt)} chars]")
                if i >= 3:
                    print("\n[dry-run: showing first 3 groups, stopping]")
                    break
                continue

            # ── Real call ────────────────────────────────────────────────────
            print(f"[{i}/{len(bucket_items)}] {gid} ", end="", flush=True)
            t0 = time.time()
            try:
                raw    = call_openrouter(user_prompt, args.model, num_candidates)
                result = normalize_result(raw, gid, args.model)
                result["prompt_chars"] = len(user_prompt)
                elapsed = time.time() - t0

                result_fh.write(json.dumps(result, ensure_ascii=False) + "\n")
                result_fh.flush()
                done_gids.add(gid)
                save_checkpoint(done_gids, ckpt_file)
                stats["ok"] += 1

                n  = len(result["per_candidate"])
                rc = sum(1 for c in result["per_candidate"]
                         if c["label"] == "root_cause_vf")
                us = sum(1 for c in result["per_candidate"]
                         if c["label"] == "vulnerable_usage_site")
                flag = " ⚠vf_missing" if result["vf_not_in_candidates"] else ""
                print(f"✓  {n} cands | rc={rc} us={us} | "
                      f"{result['confidence']} | {result['evidence_level']}"
                      f"{flag}  [{elapsed:.1f}s]")

            except QuotaExhaustedError as e:
                print(f"✗  QUOTA EXHAUSTED: {e}")
                err_rec = {
                    "group_id":            gid,
                    "model":               args.model,
                    "annotation_ts":       int(time.time()),
                    "error":               str(e),
                    "per_candidate":       [],
                    "vf_qualified_name":   None,
                    "mapping_type":        None,
                    "evidence_level":      None,
                    "confidence":          None,
                    "vf_not_in_candidates": False,
                    "summary":             "",
                    "annotation_note":     "",
                }
                result_fh.write(json.dumps(err_rec, ensure_ascii=False) + "\n")
                result_fh.flush()
                stats["error"] += 1
                print(f"\n⚠ Dừng batch — model '{args.model}' đã hết quota/credit. "
                      f"Đã annotate {stats['ok']} groups trước khi dừng. "
                      f"Dùng --resume sau khi đổi model hoặc nạp credit để "
                      f"tiếp tục từ đây.")
                break

            except Exception as e:
                print(f"✗  ERROR: {e}")
                traceback.print_exc()
                err_rec = {
                    "group_id":            gid,
                    "model":               args.model,
                    "annotation_ts":       int(time.time()),
                    "error":               str(e),
                    "per_candidate":       [],
                    "vf_qualified_name":   None,
                    "mapping_type":        None,
                    "evidence_level":      None,
                    "confidence":          None,
                    "vf_not_in_candidates": False,
                    "summary":             "",
                    "annotation_note":     "",
                }
                result_fh.write(json.dumps(err_rec, ensure_ascii=False) + "\n")
                result_fh.flush()
                stats["error"] += 1

            time.sleep(DELAY_BETWEEN_CALLS)

    finally:
        result_fh.close()

    print(f"\n{'='*55}")
    print(f"Done     : {stats['ok']} ok / {stats['skip']} skip / {stats['error']} error")
    print(f"No source: {stats['no_source']} groups (source_lk empty — check modified_functions dir)")
    print(f"No diff  : {stats['no_diff']} groups (diff empty — check patch_diffs dir)")
    print(f"Output   : {out_file}")
    audit_file = Path(args.audit_file)
    audit_file.parent.mkdir(parents=True, exist_ok=True)
    audit_file.write_text(
        json.dumps(
            {
                "model": args.model,
                "bucket_file": args.bucket_file,
                "candidate_file": args.cand_file,
                "out_file": str(out_file),
                "requested_group_count": len(bucket_items),
                "annotated_count": stats["ok"],
                "skipped_count": stats["skip"],
                "error_count": stats["error"],
                "no_source_count": stats["no_source"],
                "no_diff_count": stats["no_diff"],
                "dry_run": args.dry_run,
                "resume": args.resume,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    print(f"Audit    : {audit_file}")
    if stats["error"]:
        print(f"⚠ {stats['error']} errors — re-run with --resume to retry")


if __name__ == "__main__":
    main()
