"""Prepared, per-mode CVE-to-VF experiment inputs and durable execution."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sys
import textwrap
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from pathlib import Path
from pathlib import PureWindowsPath
from typing import Any, Callable

from f_vra.evaluation.io import write_json
from f_vra.evaluation.vf_metrics import MODES, normalize_ground_truth

MODE_INPUT_NAMES = {
    "D_LEX": "d_lex.jsonl",
    "D_SEM": "d_sem.jsonl",
    "P_DUAL_PRESENT": "p_dual_present.jsonl",
    "P_DUAL_HIDDEN": "p_dual_hidden.jsonl",
    "ORACLE": "oracle.jsonl",
}
PATCH_FIELDS = {
    "patch_text", "patch_sha", "patch_status", "patch_available", "patch_content_sha256",
    "patch_base_sha", "patch_fix_artifact_sha256", "patch_sha_adjudicated", "patch_sha_original",
}
CWE_FIELDS = {"cwe_ids", "cwe_id", "cwe_text", "cwe_source", "cwe_text_source"}
COMMON_INPUT_FIELDS = (
    "case_id", "cve_vf_group_id", "cve_id", "package", "repo_url", "vulnerable_ref",
    "description", "source_path", "snapshot_id", "source_content_sha256", "source_revision_sha",
    "eligible", "ineligible_reason",
)


@dataclass
class AnchorResult:
    """Stable serialized contract shared by every VF mode runner."""

    case_id: str
    cve_vf_group_id: str
    mode: str
    method: str
    status: str
    output_type: str = "ranked"
    runtime_mode: str = "DEFAULT"
    runtime_ms: float = 0.0
    raw_candidate_count: int = 0
    candidate_count: int = 0
    candidate_ids: list[str] = field(default_factory=list)
    candidate_details: list[dict[str, Any]] = field(default_factory=list)
    ranked_candidates: list[dict[str, Any]] = field(default_factory=list)
    predictions: list[dict[str, Any]] = field(default_factory=list)
    llm_calls: int = 0
    token_usage: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        extra = value.pop("extra")
        value["schema_version"] = "f_vra.vf.anchor-result.v1"
        value.update(extra)
        return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _normalized_source_bytes(path: Path) -> bytes:
    """Normalize text line endings before cross-platform source fingerprints."""
    text = path.read_text(encoding="utf-8")
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                row = json.loads(line)
                if not isinstance(row, dict):
                    raise ValueError(f"{path}:{line_number}: expected a JSON object")
                rows.append(row)
    return rows


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def _mode_common(row: dict[str, Any], mode: str, catalog_path: str | None) -> dict[str, Any]:
    result = {key: row.get(key) for key in COMMON_INPUT_FIELDS if key in row}
    result.update({
        "schema_version": "f_vra.vf.mode-input.v1",
        "mode": mode,
        "case_id": str(row.get("case_id") or row.get("group_id") or row.get("cve_vf_group_id") or ""),
        "cve_vf_group_id": str(row.get("cve_vf_group_id") or row.get("group_id") or ""),
        "snapshot_id": str(row.get("snapshot_id") or row.get("vulnerable_ref") or ""),
        "eligible": _case_eligible(row),
        "ineligible_reason": str(row.get("ineligible_reason") or row.get("evaluation_ineligible_reason") or ""),
    })
    if catalog_path:
        result["catalog_path"] = catalog_path
    return result


def _case_eligible(row: dict[str, Any]) -> bool:
    return bool(row.get("eligible", True)) and not bool(
        row.get("evaluation_ineligible_reason") or row.get("ineligible_reason")
    )


def _catalog_rows(functions: list[Any]) -> list[dict[str, Any]]:
    """Enrich the parser's exact-snapshot index with stable inspection fields."""
    from f_vra.evaluation.rq3 import _module_qualified_name

    by_qualname = {item.qualname: item for item in functions}
    by_simple: dict[str, list[Any]] = {}
    for item in functions:
        by_simple.setdefault(item.function_name, []).append(item)
    callers: dict[str, set[str]] = {item.identity: set() for item in functions}
    callees: dict[str, set[str]] = {item.identity: set() for item in functions}
    for caller in functions:
        for raw_name in caller.calls:
            target = by_qualname.get(raw_name)
            if target is None:
                matches = by_simple.get(raw_name.split(".")[-1], [])
                target = matches[0] if len(matches) == 1 else None
            if target is not None and target.identity != caller.identity:
                callees[caller.identity].add(target.identity)
                callers[target.identity].add(caller.identity)

    result = []
    for function in functions:
        try:
            tree = ast.parse(textwrap.dedent(function.source))
            ast_info = {
                "parse_status": "parsed",
                "node_types": sorted({type(node).__name__ for node in ast.walk(tree)}),
                "call_names": sorted({
                    name for node in ast.walk(tree) if isinstance(node, ast.Call)
                    if (name := _ast_name(node.func))
                }),
            }
        except (SyntaxError, ValueError, TypeError) as exc:
            ast_info = {"parse_status": "unavailable", "error_type": type(exc).__name__}
        result.append({
            "function_id": function.identity,
            "qualified_name": function.qualname,
            "module_qualified_name": _module_qualified_name(function),
            "file_path": function.file_path.replace("\\", "/"),
            "start_line": function.start_line,
            "end_line": function.end_line,
            "source": function.source,
            "lexical_tokens": re.findall(r"[A-Za-z_][A-Za-z_0-9]*|\d+(?:\.\d+)?|[^\w\s]", function.source),
            "ast": ast_info,
            "approximate_callers": sorted(callers[function.identity]),
            "approximate_callees": sorted(callees[function.identity]),
            "calls": sorted(function.calls),
            "referenced_names": sorted(function.referenced_names),
            "assigned_names": sorted(function.assigned_names),
            "parameter_names": sorted(function.parameter_names),
        })
    return result


def _ast_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _ast_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _prepare_one_function_catalog(payload: dict[str, Any]) -> dict[str, Any]:
    """Build one independent snapshot catalog; safe to execute in a child process."""
    from f_vra.evaluation.rq3 import load_inventory

    row = payload["row"]
    source_path = Path(payload["source_path"]).resolve()
    inputs_dir = Path(payload["inputs_dir"])
    snapshot_id = str(row.get("snapshot_id") or row.get("vulnerable_ref") or "")
    source_hash = str(row.get("source_content_sha256") or row.get("source_artifact_sha256") or "")
    functions, indexed_source_hash, inventory_hash = load_inventory(
        source_path, inputs_dir / "inventory_cache", source_identity=snapshot_id,
        source_content_sha256=source_hash,
    )
    parser_hash = str(payload["parser_sha256"])
    cache_key = _sha256(f"{snapshot_id}\0{parser_hash}".encode("utf-8"))
    inventory_cache_path = inputs_dir / "inventory_cache" / f"{cache_key}.json"
    catalog_name = _sha256(f"{snapshot_id}\0{inventory_hash}".encode("utf-8"))[:24] + ".json"
    catalog_path = inputs_dir / "catalogs" / catalog_name
    write_json(catalog_path, {
        "schema_version": "f_vra.vf.function-catalog.v1",
        "case_source_identity": snapshot_id,
        "vulnerable_ref": str(row.get("vulnerable_ref") or ""),
        "source_revision_sha": str(row.get("source_revision_sha") or ""),
        "source_content_sha256": source_hash,
        "source_path": str(source_path),
        "indexed_source_identity": indexed_source_hash,
        "inventory_hash": inventory_hash,
        "inventory_cache_path": str(inventory_cache_path.resolve()),
        "function_count": len(functions),
        "functions": _catalog_rows(functions),
    })
    return {
        "source_key": (snapshot_id, str(source_path)),
        "catalog_name": catalog_name,
        "catalog_path": str(catalog_path.resolve()),
        "source_identity": snapshot_id,
        "inventory_hash": inventory_hash,
        "function_count": len(functions),
        "sha256": _sha256(catalog_path.read_bytes()),
    }


def prepare_vf_inputs(
    cases_path: Path,
    inputs_root: Path,
    *,
    limit: int = 0,
    workers: int = 1,
) -> dict[str, Any]:
    """Freeze separate patch-safe mode inputs and a role-preserving GT file."""
    import f_vra.localization.code.function_parser as function_parser

    if workers < 1:
        raise ValueError("workers must be at least one")
    rows = _read_jsonl(cases_path)
    if limit > 0:
        rows = rows[:limit]
    ids = [str(row.get("case_id") or row.get("group_id") or row.get("cve_vf_group_id") or "") for row in rows]
    if any(not value for value in ids) or len(ids) != len(set(ids)):
        raise ValueError("prepared input must have unique, non-empty case_id values")
    missing_groups = [str(row.get("case_id") or "") for row in rows if not str(row.get("cve_vf_group_id") or row.get("group_id") or "").strip()]
    if missing_groups:
        raise ValueError(f"prepared input lacks exact cve_vf_group_id for cases: {missing_groups[:10]}")

    invalid = []
    for row in rows:
        if not _case_eligible(row):
            continue
        source_value = str(row.get("source_path") or "").strip()
        source = Path(source_value) if source_value else None
        if source is None or not source.is_dir():
            invalid.append(f"{row.get('case_id')}: source snapshot is missing: {source_value or '(empty source_path)'}")
        vulnerable_ref = str(row.get("vulnerable_ref") or "").strip()
        source_revision = str(row.get("source_revision_sha") or "").strip()
        if not vulnerable_ref:
            invalid.append(f"{row.get('case_id')}: vulnerable_ref is missing")
        if vulnerable_ref and source_revision and vulnerable_ref != source_revision:
            invalid.append(f"{row.get('case_id')}: vulnerable_ref does not match source_revision_sha")
    if invalid:
        raise ValueError("input preparation failed:\n" + "\n".join(invalid[:20]))

    parser_path = Path(function_parser.__file__).resolve()
    identity_payload = {
        "schema": "f_vra.vf.prepared-inputs.v1",
        "catalog_schema": "f_vra.vf.function-catalog.v1",
        "python_runtime": f"{sys.version_info.major}.{sys.version_info.minor}",
        "source_sha256": _sha256(cases_path.read_bytes()),
        "parser_sha256": _sha256(parser_path.read_bytes()),
        "preparer_sha256": _sha256(Path(__file__).read_bytes()),
        "limit": limit,
        "case_ids": ids,
    }
    input_id = "vf-input-" + _sha256(json.dumps(identity_payload, sort_keys=True).encode("utf-8"))[:16]
    inputs_dir = inputs_root / input_id
    inputs_dir.mkdir(parents=True, exist_ok=True)
    catalog_dir = inputs_dir / "catalogs"

    unique_sources: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        if not _case_eligible(row):
            continue
        source_path = Path(str(row.get("source_path") or "")).resolve()
        snapshot_id = str(row.get("snapshot_id") or row.get("vulnerable_ref") or "")
        source_key = (snapshot_id, str(source_path))
        source_hash = str(row.get("source_content_sha256") or row.get("source_artifact_sha256") or "")
        existing = unique_sources.get(source_key)
        if existing and str(existing.get("source_content_sha256") or existing.get("source_artifact_sha256") or "") != source_hash:
            raise ValueError(f"shared snapshot has conflicting source checksums: {snapshot_id}")
        unique_sources.setdefault(source_key, row)

    catalog_tasks = [
        {
            "row": row,
            "source_path": source_path,
            "inputs_dir": str(inputs_dir),
            "parser_sha256": identity_payload["parser_sha256"],
        }
        for (_, source_path), row in unique_sources.items()
    ]
    catalog_results = []
    if workers == 1:
        catalog_results = [_prepare_one_function_catalog(task) for task in catalog_tasks]
    else:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(_prepare_one_function_catalog, task) for task in catalog_tasks]
            for future in as_completed(futures):
                catalog_results.append(future.result())
    catalog_by_source: dict[tuple[str, str], str] = {}
    catalog_metadata: dict[str, dict[str, Any]] = {}
    for result in catalog_results:
        catalog_by_source[tuple(result["source_key"])] = str(result["catalog_path"])
        catalog_metadata[str(result["catalog_name"])] = {
            "source_identity": result["source_identity"],
            "inventory_hash": result["inventory_hash"],
            "function_count": result["function_count"],
            "sha256": result["sha256"],
        }

    mode_rows: dict[str, list[dict[str, Any]]] = {mode: [] for mode in MODES}
    ground_truth = []
    for row in rows:
        case_id = str(row.get("case_id") or row.get("group_id") or row.get("cve_vf_group_id") or "")
        gt_row = normalize_ground_truth(row)
        ground_truth.append(gt_row)
        source_path = Path(str(row.get("source_path") or "")).resolve() if row.get("source_path") else None
        snapshot_id = str(row.get("snapshot_id") or row.get("vulnerable_ref") or "")
        source_key = (snapshot_id, str(source_path)) if source_path else (snapshot_id, "")
        catalog_path = catalog_by_source.get(source_key)
        for mode in ("D_LEX", "D_SEM"):
            item = _mode_common(row, mode, catalog_path)
            mode_rows[mode].append(item)
        patch_text = str(row.get("patch_text") or "")
        patch_available = bool(row.get("patch_available", bool(patch_text))) and bool(patch_text.strip())
        patch_status = str(row.get("patch_status") or "")
        paired_eligible = _case_eligible(row)
        paired_eligible = paired_eligible and patch_available and patch_status != "ADJUDICATED_PATCH_UNAVAILABLE"
        if paired_eligible:
            present = _mode_common(row, "P_DUAL_PRESENT", catalog_path)
            present.update({
                "patch_available": True,
                "patch_text": patch_text,
                "patch_sha": str(row.get("patch_sha") or ""),
                "patch_status": patch_status,
            })
            mode_rows["P_DUAL_PRESENT"].append(present)
            hidden = _mode_common(row, "P_DUAL_HIDDEN", catalog_path)
            # No patch key, availability bit, hash, status, or CWE metadata
            # enters this view. parse_case's absent-patch default dispatches it.
            mode_rows["P_DUAL_HIDDEN"].append(hidden)
        oracle = _mode_common(row, "ORACLE", catalog_path)
        mode_rows["ORACLE"].append(oracle)

    for mode, mode_input_rows in mode_rows.items():
        forbidden = CWE_FIELDS | (PATCH_FIELDS if mode != "P_DUAL_PRESENT" else set())
        for item in mode_input_rows:
            leaked = forbidden.intersection(item)
            if leaked:
                raise AssertionError(f"{mode} input leaked forbidden fields: {sorted(leaked)}")
    gt_path = inputs_dir / "ground_truth.jsonl"
    _write_jsonl(gt_path, ground_truth)
    mode_hashes = {}
    for mode, mode_input_rows in mode_rows.items():
        path = inputs_dir / MODE_INPUT_NAMES[mode]
        _write_jsonl(path, mode_input_rows)
        mode_hashes[mode] = _sha256(path.read_bytes())
    manifest = {
        "schema_version": "f_vra.vf.prepared-inputs.v1",
        "input_id": input_id,
        "python_runtime": identity_payload["python_runtime"],
        "source_manifest": str(cases_path.resolve()),
        "source_manifest_sha256": identity_payload["source_sha256"],
        "parser_sha256": identity_payload["parser_sha256"],
        "preparer_sha256": identity_payload["preparer_sha256"],
        "preparation_workers": workers,
        "case_count": len(rows),
        "ground_truth_path": "ground_truth.jsonl",
        "ground_truth_sha256": _sha256(gt_path.read_bytes()),
        "mode_inputs": MODE_INPUT_NAMES,
        "mode_input_sha256": mode_hashes,
        "mode_counts": {mode: len(mode_input_rows) for mode, mode_input_rows in mode_rows.items()},
        "catalogs": catalog_metadata,
    }
    write_json(inputs_dir / "manifest.json", manifest)
    return {**manifest, "inputs_dir": str(inputs_dir.resolve())}


def _read_inputs_manifest(inputs_dir: Path) -> dict[str, Any]:
    manifest_path = inputs_dir / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"input directory lacks manifest.json: {inputs_dir}")
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def _resolve_input_path(inputs_dir: Path, value: str | Path) -> Path:
    """Resolve a frozen artifact path, including portable paths inside bundles.

    Full prepared inputs may refer to source snapshots with repository-relative
    paths from the source manifest. Prefer bundle-local paths (the sharded form)
    and fall back to the checked-out repository only when the local artifact is
    absent. This keeps relocated shards self-contained while allowing the
    preparation host to build those shards from its source cache.
    """
    raw_value = str(value)
    path = Path(raw_value)
    if path.is_absolute() and path.exists():
        return path.resolve()
    root = inputs_dir.resolve()
    # Prepared mode inputs and catalogs may have been frozen on a different
    # operating system. Rebase their known artifact suffixes onto this checkout
    # without rewriting the frozen files or changing their fingerprints.
    windows_parts = tuple(part for part in PureWindowsPath(raw_value).parts if part not in {"\\", "/"})
    normalized_parts = tuple(part for part in path.parts if part not in {"/", "\\"})
    for parts in (windows_parts, normalized_parts):
        lowered = tuple(part.lower() for part in parts)
        input_index = next((i for i, part in enumerate(lowered) if part == root.name.lower()), None)
        if input_index is not None and input_index + 1 < len(parts):
            suffix = Path(*parts[input_index + 1:])
            rebased = (root / suffix).resolve()
            if rebased.exists():
                return rebased
        snapshot_index = next((i for i, part in enumerate(lowered) if part == "rq3-snapshots"), None)
        if snapshot_index is not None and snapshot_index + 1 < len(parts):
            from f_vra.core.config import settings

            snapshot_root = Path(settings.f_vra_rq3_snapshot_root).expanduser().resolve()
            rebased = (snapshot_root / Path(*parts[snapshot_index + 1:])).resolve()
            try:
                rebased.relative_to(snapshot_root)
            except ValueError:
                continue
            if rebased.exists():
                return rebased
        vf_index = next((i for i in range(len(lowered) - 1) if lowered[i:i + 2] == ("experiments", "vf")), None)
        if vf_index is not None:
            repository_root = Path(__file__).resolve().parents[3]
            rebased = (repository_root / Path(*parts[vf_index:])).resolve()
            try:
                rebased.relative_to(repository_root)
            except ValueError:
                continue
            if rebased.exists():
                return rebased
    resolved = (root / path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"relative artifact path escapes the prepared bundle: {value}") from exc
    if resolved.exists():
        return resolved

    repository_root = Path(__file__).resolve().parents[3]
    repository_path = (repository_root / path).resolve()
    try:
        repository_path.relative_to(repository_root)
    except ValueError:
        return resolved
    if repository_path.exists():
        return repository_path
    return resolved


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _hash_runner_code(mode: str) -> str:
    from f_vra.evaluation import rq3

    digest = hashlib.sha256()
    for path in (Path(__file__), Path(rq3.__file__)):
        digest.update(_normalized_source_bytes(path))
    mode_module = Path(__file__).parent / "vf_modes" / f"{mode.lower()}.py"
    if mode_module.is_file():
        digest.update(_normalized_source_bytes(mode_module))
    return digest.hexdigest()


def _result_row(mode: str, case_id: str, group_id: str, status: str, **values: Any) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "output_type": "ranked", "runtime_mode": "DEFAULT", "runtime_ms": 0.0,
        "raw_candidate_count": 0, "candidate_count": 0, "candidate_ids": [],
        "candidate_details": [], "ranked_candidates": [], "predictions": [], "llm_calls": 0,
        "token_usage": {}, "metadata": {}, "error": "",
    }
    defaults.update(values)
    contract_fields = {
        "output_type", "runtime_mode", "runtime_ms", "raw_candidate_count", "candidate_count",
        "candidate_ids", "candidate_details", "ranked_candidates", "predictions", "llm_calls",
        "token_usage", "metadata", "error",
    }
    contract = AnchorResult(
        case_id=case_id, cve_vf_group_id=group_id, mode=mode,
        method=str(defaults.pop("method", "ORACLE" if mode == "ORACLE" else "P_DUAL" if mode.startswith("P_DUAL") else mode)),
        status=status,
        **{key: defaults.pop(key) for key in contract_fields},
        extra=defaults,
    )
    return contract.to_dict()


def _portable_mode_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Return the persisted summary with paths relative to its run directory."""
    portable = dict(summary)
    portable["schema_version"] = "f_vra.vf.mode-run-summary.v1"
    portable["artifact_path_base"] = "."
    for field in ("results", "checkpoint"):
        value = portable.get(field)
        if value:
            portable[field] = Path(str(value)).name
    return portable


def _compact_checkpoint(checkpoint: Path, output: Path, ordered_case_ids: list[str]) -> list[dict[str, Any]]:
    latest = {}
    if checkpoint.exists():
        for row in _read_jsonl(checkpoint):
            case_id = str(row.get("case_id") or "")
            if case_id:
                latest[case_id] = row
    compact = [latest[case_id] for case_id in ordered_case_ids if case_id in latest]
    temporary = output.with_suffix(output.suffix + ".tmp")
    output.parent.mkdir(parents=True, exist_ok=True)
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in compact:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(output)
    return compact


def run_vf_mode(
    mode: str,
    inputs_dir: Path,
    results_root: Path,
    *,
    run_id: str | None = None,
    localizer: Callable[..., Any] | None = None,
    progress: bool = True,
    workers: int = 1,
    case_limit: int = 0,
    case_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Execute one mode with a single durable writer and optional case workers."""
    from tqdm import tqdm
    from f_vra.evaluation.rq3 import RQ3LocalizationResult, parse_case

    mode = mode.upper()
    if mode not in MODES:
        raise ValueError(f"unsupported VF mode {mode!r}; choose {MODES}")
    if workers < 1:
        raise ValueError("workers must be at least one")
    if case_limit < 0:
        raise ValueError("case_limit cannot be negative")
    manifest = _read_inputs_manifest(inputs_dir)
    input_name = (manifest.get("mode_inputs") or {}).get(mode)
    if not input_name:
        raise ValueError(f"prepared inputs do not contain mode {mode}")
    input_path = inputs_dir / input_name
    rows = _read_jsonl(input_path)
    if _sha256(input_path.read_bytes()) != (manifest.get("mode_input_sha256") or {}).get(mode):
        raise ValueError(f"prepared mode input changed after freezing: {input_path}")
    if any(item.get("mode") != mode for item in rows):
        raise ValueError(f"mode field mismatch in {input_path}")
    if case_ids is not None:
        available_ids = {str(item.get("case_id") or "") for item in rows}
        missing_ids = sorted(case_ids - available_ids)
        if missing_ids:
            raise ValueError(f"requested case IDs are absent from {mode} input: {missing_ids[:5]}")
        selected_rows = [item for item in rows if str(item.get("case_id") or "") in case_ids]
    else:
        selected_rows = rows
    selected_case_count = len(selected_rows)
    if case_limit:
        selected_rows = selected_rows[:case_limit]
    catalogs = manifest.get("catalogs") or {}
    # A canary should validate only the records it will attempt. Full runs
    # still validate every catalog/cache because selected_rows == rows.
    if mode != "ORACLE":
        verified_catalogs: set[Path] = set()
        for item in selected_rows:
            if not bool(item.get("eligible", True)):
                continue
            catalog_path_value = str(item.get("catalog_path") or "")
            catalog_file = _resolve_input_path(inputs_dir, catalog_path_value) if catalog_path_value else None
            if catalog_file is None or not catalog_file.is_file():
                raise ValueError(f"ready FunctionCatalog is missing for {item.get('case_id')}")
            if catalog_file in verified_catalogs:
                continue
            verified_catalogs.add(catalog_file)
            catalog_info = catalogs.get(catalog_file.name) or {}
            if _sha256(catalog_file.read_bytes()) != catalog_info.get("sha256"):
                raise ValueError(f"FunctionCatalog changed after preparation: {catalog_path_value}")
            catalog = json.loads(catalog_file.read_text(encoding="utf-8"))
            cache_value = str(catalog.get("inventory_cache_path") or "")
            index_cache_path = _resolve_input_path(inputs_dir, cache_value) if cache_value else None
            if index_cache_path is None or not index_cache_path.is_file():
                raise ValueError(f"FunctionCatalog parser cache is missing: {index_cache_path}")
            index_cache = json.loads(index_cache_path.read_text(encoding="utf-8"))
            if index_cache.get("inventory_hash") != catalog.get("inventory_hash"):
                raise ValueError(f"FunctionCatalog parser cache does not match catalog: {catalog_file}")
    if mode in {"D_LEX", "D_SEM", "P_DUAL_HIDDEN"}:
        for item in rows:
            if CWE_FIELDS.intersection(item):
                raise ValueError(f"{mode} input contains CWE fields")
            if PATCH_FIELDS.intersection(item):
                raise ValueError(f"{mode} input contains patch fields")
    if mode == "P_DUAL_PRESENT" and any(not item.get("patch_available") or not item.get("patch_text") for item in rows):
        raise ValueError("P_DUAL_PRESENT input has a record without a materialized patch")

    effective_run_id = run_id or str(manifest.get("input_id") or inputs_dir.name)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", effective_run_id):
        raise ValueError("run_id may contain only letters, digits, dot, underscore, and hyphen")
    run_dir = results_root / effective_run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    output_path = run_dir / f"{mode}.jsonl"
    checkpoint_path = run_dir / f"{mode}.checkpoint.jsonl"
    code_fingerprint = _hash_runner_code(mode)
    run_fingerprint = _sha256(
        f"{manifest['input_id']}\0{mode}\0{code_fingerprint}\0{_sha256(input_path.read_bytes())}".encode("utf-8")
    )
    meta_path = run_dir / f"{mode}.meta.json"
    if meta_path.exists():
        previous = json.loads(meta_path.read_text(encoding="utf-8"))
        if previous.get("run_fingerprint") != run_fingerprint:
            raise ValueError(f"existing {mode} run has a different input/code fingerprint; select a new --run-id")
    else:
        write_json(meta_path, {
            "run_id": effective_run_id, "mode": mode, "input_id": manifest["input_id"],
            "input_sha256": _sha256(input_path.read_bytes()), "code_fingerprint": code_fingerprint,
            "run_fingerprint": run_fingerprint,
        })

    latest: dict[str, dict[str, Any]] = {}
    prior_path = checkpoint_path if checkpoint_path.exists() else output_path
    if prior_path.exists():
        prior_rows = _read_jsonl(prior_path)
        for item in prior_rows:
            case_id = str(item.get("case_id") or "")
            if item.get("run_fingerprint") != run_fingerprint:
                raise ValueError(f"existing result contains a different fingerprint: {prior_path}")
            if case_id:
                latest[case_id] = item
        if prior_path == output_path:
            # Recover the durable attempt log if an earlier cleanup retained
            # only the compact per-record results.
            _write_jsonl(checkpoint_path, prior_rows)
    gt_by_case: dict[str, dict[str, Any]] = {}
    if mode == "ORACLE":
        gt_path = _resolve_input_path(inputs_dir, str(manifest.get("ground_truth_path") or "ground_truth.jsonl"))
        if not gt_path.is_file():
            raise FileNotFoundError(f"ORACLE requires the central ground-truth artifact: {gt_path}")
        gt_by_case = {str(item.get("case_id")): item for item in _read_jsonl(gt_path)}
    if localizer is None and mode != "ORACLE":
        from f_vra.evaluation.rq3 import localize_case
        localizer = localize_case

    from f_vra.localization.providers.llm_client import track_provider_usage

    def process_case(input_row: dict[str, Any]) -> dict[str, Any]:
        case_id = str(input_row.get("case_id") or "")
        group_id = str(input_row.get("cve_vf_group_id") or "")
        started = time.perf_counter()
        if not bool(input_row.get("eligible", True)):
            result = _result_row(mode, case_id, group_id, "ineligible", error=str(input_row.get("ineligible_reason") or "case rejected by frozen audit"))
        elif mode == "ORACLE":
            gt = gt_by_case.get(case_id, {})
            anchors = list(gt.get("vulnerable_functions") or [])
            result = _result_row(
                mode, case_id, group_id, "complete" if anchors else "failed",
                output_type="ground_truth_set", vulnerable_functions=anchors,
                error="" if anchors else "ground truth contains no valid anchors",
                candidate_count=len(anchors), raw_candidate_count=len(anchors),
            )
        else:
            provider_usage = None
            try:
                local_input = dict(input_row)
                local_input["source_path"] = str(_resolve_input_path(inputs_dir, str(input_row.get("source_path") or "")))
                case = parse_case(local_input).localizer_input
                protocol: dict[str, Any] = {}
                if mode.startswith("P_DUAL"):
                    protocol["candidate_limit"] = 100
                if mode == "D_SEM":
                    protocol["require_av_or_root_cause"] = True
                with track_provider_usage() as provider_usage:
                    localized: RQ3LocalizationResult = localizer(
                        case,
                        "P_DUAL" if mode.startswith("P_DUAL") else mode,
                        inventory_cache=inputs_dir / "inventory_cache",
                        protocol=protocol,
                    )
                source = localized.to_dict()
                metadata = dict(source.get("metadata") or {})
                usage = provider_usage.to_dict()
                if mode == "D_SEM":
                    entities = metadata.get("entities") or {}
                    extraction = metadata.get("entity_extraction") or {
                        "entities": entities,
                        "status": metadata.get("extractor_status"),
                        "usable": any(str(entities.get(key) or "").strip() for key in ("attack_vector", "root_cause")),
                        "failed": False,
                    }
                    metadata["entity_extraction"] = extraction
                    metadata["fallback_used"] = False
                metadata["provider_usage"] = usage
                result = _result_row(
                    mode, case_id, group_id, source.get("status") or "complete",
                    method=source.get("config_id") or mode,
                    runtime_mode=source.get("runtime_mode") or "DEFAULT",
                    output_type=source.get("output_type") or "ranked",
                    raw_candidate_count=source.get("raw_candidate_count") if source.get("raw_candidate_count") is not None else source.get("candidate_count", 0),
                    candidate_count=source.get("candidate_count", 0),
                    candidate_ids=source.get("candidate_ids") or [],
                    candidate_details=source.get("candidate_details") or [],
                    ranked_candidates=source.get("predictions") or [],
                    predictions=source.get("predictions") or [],
                    runtime_ms=float(source.get("runtime_ms") or (time.perf_counter() - started) * 1000),
                    llm_calls=int(usage.get("chat_calls") or 0), token_usage=usage,
                    metadata=metadata, error=source.get("error") or "",
                    snapshot_hash=source.get("snapshot_hash") or "",
                    inventory_hash=source.get("inventory_hash") or "",
                    method_label=source.get("method_label") or "",
                )
            except Exception as exc:
                metadata = dict(getattr(exc, "metadata", {}) or {})
                usage = provider_usage.to_dict() if provider_usage is not None else {}
                metadata["provider_usage"] = usage
                if mode == "D_SEM":
                    extraction = metadata.get("entity_extraction") or {}
                    if not extraction:
                        extraction = {"entities": {}, "usable": False, "failed": True, "status": "execution_error"}
                    metadata["entity_extraction"] = extraction
                    metadata["fallback_used"] = False
                partial = dict(getattr(exc, "partial_result", {}) or {})
                result = _result_row(
                    mode, case_id, group_id, "failed",
                    method="P_DUAL" if mode.startswith("P_DUAL") else mode,
                    runtime_mode="PATCH_PRESENT" if mode == "P_DUAL_PRESENT" else "PATCH_ABSENT" if mode == "P_DUAL_HIDDEN" else "DEFAULT",
                    output_type="ranked", raw_candidate_count=int(partial.get("raw_candidate_count") or 0),
                    candidate_count=int(partial.get("candidate_count") or len(partial.get("candidate_ids") or [])),
                    candidate_ids=partial.get("candidate_ids") or [],
                    candidate_details=partial.get("candidate_details") or [],
                    ranked_candidates=[], predictions=[],
                    runtime_ms=(time.perf_counter() - started) * 1000,
                    llm_calls=int(usage.get("chat_calls") or 0), token_usage=usage,
                    metadata=metadata, error=f"{type(exc).__name__}: {exc}",
                )

        result["run_fingerprint"] = run_fingerprint
        result["input_id"] = manifest["input_id"]
        result["mode"] = mode
        return result

    pending_rows = [
        input_row for input_row in selected_rows
        if not (latest.get(str(input_row.get("case_id") or "")) or {}).get("status")
        in {"complete", "ineligible", "not_applicable"}
    ]
    attempted = 0

    def persist(result: dict[str, Any]) -> None:
        nonlocal attempted
        _append_jsonl(checkpoint_path, result)
        latest[str(result.get("case_id") or "")] = result
        attempted += 1

    progress_bar = tqdm(total=len(pending_rows), desc=f"VF {mode}", disable=not progress)
    if workers == 1:
        for input_row in pending_rows:
            persist(process_case(input_row))
            progress_bar.update(1)
    else:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=f"vf-{mode.lower()}") as executor:
            futures = [executor.submit(process_case, input_row) for input_row in pending_rows]
            for future in as_completed(futures):
                persist(future.result())
                progress_bar.update(1)
    progress_bar.close()

    ordered_selected_ids = [str(row.get("case_id") or "") for row in selected_rows]
    compact_rows = _compact_checkpoint(checkpoint_path, output_path, ordered_selected_ids)
    statuses = {
        "completed": sum(row.get("status") == "complete" for row in compact_rows),
        "failed": sum(row.get("status") == "failed" for row in compact_rows),
        "ineligible": sum(row.get("status") == "ineligible" for row in compact_rows),
        "not_applicable": sum(row.get("status") == "not_applicable" for row in compact_rows),
    }
    summary = {
        "run_id": effective_run_id, "mode": mode, "input_id": manifest["input_id"],
        "run_fingerprint": run_fingerprint, "case_count": len(selected_rows),
        "record_count": len(compact_rows), "case_limit": case_limit,
        "partial": case_limit > 0 and len(compact_rows) < selected_case_count,
        "attempted_this_invocation": attempted,
        "workers": workers,
        **statuses, "results": str(output_path.resolve()), "checkpoint": str(checkpoint_path.resolve()),
    }
    write_json(run_dir / f"{mode}.summary.json", _portable_mode_summary(summary))
    return summary


def dispatch_vf_mode(
    mode: str,
    inputs_dir: Path,
    results_root: Path,
    *,
    run_id: str | None = None,
    progress: bool = True,
    workers: int = 1,
    case_limit: int = 0,
    case_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Dispatch to a mode-specific runner module."""
    mode = mode.upper()
    if mode not in MODES:
        raise ValueError(f"unsupported VF mode {mode!r}; choose {MODES}")
    if mode == "D_LEX":
        from f_vra.evaluation.vf_modes.d_lex import run
    elif mode == "D_SEM":
        from f_vra.evaluation.vf_modes.d_sem import run
    elif mode == "P_DUAL_PRESENT":
        from f_vra.evaluation.vf_modes.p_dual_present import run
    elif mode == "P_DUAL_HIDDEN":
        from f_vra.evaluation.vf_modes.p_dual_hidden import run
    else:
        from f_vra.evaluation.vf_modes.oracle import run
    return run(
        inputs_dir, results_root, run_id=run_id, progress=progress,
        workers=workers, case_limit=case_limit, case_ids=case_ids,
    )
