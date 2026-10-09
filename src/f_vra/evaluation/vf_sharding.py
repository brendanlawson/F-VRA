"""Portable machine shards and validated merge for CVE-to-VF experiments."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable
from urllib.parse import urlsplit

from f_vra.evaluation.io import write_json
from f_vra.evaluation.vf_experiment import (
    MODE_INPUT_NAMES,
    PATCH_FIELDS,
    CWE_FIELDS,
    _read_inputs_manifest,
    _read_jsonl,
    _resolve_input_path,
    _sha256,
    _normalized_source_bytes,
    _portable_mode_summary,
    _write_jsonl,
    run_vf_mode,
)
from f_vra.evaluation.vf_metrics import MODES

SHARD_MODES = ("D_LEX", "D_SEM", "P_DUAL_PRESENT", "P_DUAL_HIDDEN")
SHARD_SCHEMA = "f_vra.vf.machine-shard.v1"
SHARD_RUN_SCHEMA = "f_vra.vf.machine-run.v2"
INDEX_SHARD_SCHEMA = "f_vra.vf.index-shard.v1"


def _hash_file(path: Path) -> str:
    return _sha256(path.read_bytes())


def _case_id(row: dict[str, Any]) -> str:
    return str(row.get("case_id") or "")


def _expected_indexed_source_hash(source: Path, source_content_sha256: str) -> str:
    """Return a source-tree hash only when the manifest hash describes a tree.

    PyPI release snapshots retain the downloaded archive digest in
    ``source_content_sha256``. The shard contains the extracted/indexed Python
    tree, so its digest is recorded separately and must not be compared to the
    archive hash.
    """
    if any(part.lower() == "release_snapshots" for part in source.parts):
        return ""
    return str(source_content_sha256 or "").strip().lower()


def _provider_config_fingerprint() -> str:
    """Fingerprint effective model/endpoints without recording provider secrets."""
    from f_vra.core.config import settings

    def safe_endpoint(value: str) -> str:
        try:
            parsed = urlsplit(value)
            if not parsed.scheme or not parsed.hostname:
                return _sha256(value.encode("utf-8")) if value else ""
            host = parsed.hostname.lower()
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            if parsed.port is not None:
                host = f"{host}:{parsed.port}"
            return f"{parsed.scheme.lower()}://{host}{parsed.path.rstrip('/')}"
        except (TypeError, ValueError):
            return _sha256(str(value).encode("utf-8")) if value else ""

    payload = {
        "llm_provider": settings.llm_provider,
        "llm_model": settings.llm_model,
        "llm_endpoint": safe_endpoint(settings.llm_base_url),
        # Merge needs to compare public provider configuration without API
        # credentials. Read the configured embedding model/endpoint directly;
        # the runtime properties intentionally hide them when no key is set.
        "embedding_model": os.getenv("EMBEDDING_MODEL_OVERRIDE") or settings.local_embedding_model,
        "embedding_endpoint": safe_endpoint(settings.local_embedding_base_url),
        "bm25_top_k": settings.bm25_top_k,
        "llm_top_k": settings.llm_top_k,
        "llm_batch_size": settings.llm_batch_size,
        "embedding_batch_size": settings.embedding_batch_size,
        "embedding_max_workers": settings.embedding_max_workers,
    }
    return _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _runner_environment_identity() -> dict[str, str]:
    """Capture shard orchestration and locked runtime identity without secrets."""
    from pathlib import Path

    repository_root = Path(__file__).resolve().parents[3]
    lock_path = repository_root / "conda-lock.yml"
    if not lock_path.is_file():
        raise FileNotFoundError(f"VF environment lock is missing: {lock_path}")
    return {
        "shard_runner_fingerprint": _sha256(_normalized_source_bytes(Path(__file__).resolve())),
        "environment_lock_sha256": _sha256(_normalized_source_bytes(lock_path)),
        "python_runtime": f"{sys.version_info.major}.{sys.version_info.minor}",
    }


def _shard_index(row: dict[str, Any], shard_count: int) -> int:
    grouping_id = str(row.get("snapshot_id") or _case_id(row)).strip()
    if not grouping_id:
        raise ValueError("every prepared case needs snapshot_id or case_id for stable sharding")
    value = int.from_bytes(hashlib.sha256(grouping_id.encode("utf-8")).digest()[:8], "big")
    return value % shard_count


def _read_index_shard_inputs(inputs_dir: Path) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    """Read and validate only small frozen input files; never scan source/catalog trees."""
    manifest = _read_inputs_manifest(inputs_dir)
    if not manifest.get("input_id"):
        raise ValueError("prepared input manifest lacks input_id")
    rows = {mode: _input_rows(inputs_dir, manifest, mode) for mode in SHARD_MODES}
    lex_ids = [_case_id(row) for row in rows["D_LEX"]]
    if [_case_id(row) for row in rows["D_SEM"]] != lex_ids:
        raise ValueError("D_SEM cohort differs from D_LEX")
    present_ids = [_case_id(row) for row in rows["P_DUAL_PRESENT"]]
    hidden_ids = [_case_id(row) for row in rows["P_DUAL_HIDDEN"]]
    if present_ids != hidden_ids:
        raise ValueError("P_DUAL_PRESENT and P_DUAL_HIDDEN must have identical ordered case IDs")
    for row in rows["P_DUAL_PRESENT"]:
        if not row.get("patch_available") or not str(row.get("patch_text") or "").strip():
            raise ValueError(f"P_DUAL_PRESENT lacks a valid patch for {_case_id(row)}")
    for row in rows["P_DUAL_HIDDEN"]:
        leaked = (PATCH_FIELDS | CWE_FIELDS).intersection(row)
        if leaked:
            raise ValueError(f"P_DUAL_HIDDEN leaks forbidden fields for {_case_id(row)}: {sorted(leaked)}")
    grouping_ids = {
        _case_id(row): str(row.get("snapshot_id") or _case_id(row)).strip()
        for row in rows["D_LEX"]
    }
    for mode, mode_rows in rows.items():
        for row in mode_rows:
            if grouping_ids.get(_case_id(row)) != str(row.get("snapshot_id") or _case_id(row)).strip():
                raise ValueError(f"snapshot grouping is inconsistent in {mode}: {_case_id(row)}")
    return manifest, rows


def create_vf_index_shards(
    inputs_dir: Path,
    output_root: Path,
    *,
    shard_count: int,
) -> dict[str, Any]:
    """Write tiny deterministic case-ID plans; source and catalog artifacts stay local."""
    if shard_count < 1:
        raise ValueError("shard_count must be at least one")
    inputs_dir = inputs_dir.resolve()
    manifest, rows = _read_index_shard_inputs(inputs_dir)
    parent_manifest_sha = _hash_file(inputs_dir / "manifest.json")
    output_root.mkdir(parents=True, exist_ok=True)
    plans = []
    for shard_index in range(shard_count):
        shard_id = f"machine-{shard_index + 1:03d}-of-{shard_count:03d}"
        case_ids_by_mode = {
            mode: [_case_id(row) for row in mode_rows if _shard_index(row, shard_count) == shard_index]
            for mode, mode_rows in rows.items()
        }
        case_ids = sorted({_case_id(row) for row in rows["D_LEX"] if _shard_index(row, shard_count) == shard_index})
        eligible_case_ids = sorted(
            _case_id(row) for row in rows["D_LEX"]
            if _shard_index(row, shard_count) == shard_index and bool(row.get("eligible", True))
        )
        payload = {
            "schema_version": INDEX_SHARD_SCHEMA,
            "parent_input_id": manifest["input_id"],
            "parent_manifest_sha256": parent_manifest_sha,
            "parent_mode_input_sha256": {
                mode: (manifest.get("mode_input_sha256") or {}).get(mode) for mode in SHARD_MODES
            },
            "assignment": "first_64_bits(SHA256(snapshot_id_or_case_id)) modulo shard_count",
            "shard_id": shard_id,
            "shard_index": shard_index,
            "shard_count": shard_count,
            "case_ids": case_ids,
            "eligible_case_ids": eligible_case_ids,
            "case_ids_by_mode": case_ids_by_mode,
        }
        plan_sha = _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        shard_manifest = {**payload, "plan_sha256": plan_sha}
        plan_dir = output_root / shard_id
        plan_dir.mkdir(parents=True, exist_ok=True)
        plan_path = plan_dir / "shard_manifest.json"
        if plan_path.exists():
            existing = json.loads(plan_path.read_text(encoding="utf-8"))
            if existing.get("plan_sha256") != plan_sha:
                raise FileExistsError(f"a different shard plan already exists: {plan_path}")
        else:
            write_json(plan_path, shard_manifest)
        plans.append({
            "shard_id": shard_id,
            "path": str(plan_path.resolve()),
            "case_count": len(case_ids),
            "eligible_case_count": len(eligible_case_ids),
            "p_dual_case_count": len(case_ids_by_mode["P_DUAL_PRESENT"]),
            "plan_bytes": plan_path.stat().st_size,
            "plan_sha256": plan_sha,
        })
    return {
        "parent_input_id": manifest["input_id"],
        "parent_manifest_sha256": parent_manifest_sha,
        "shard_count": shard_count,
        "assignment": "first_64_bits(SHA256(snapshot_id_or_case_id)) modulo shard_count",
        "eligible_case_counts": [plan["eligible_case_count"] for plan in plans],
        "p_dual_case_counts": [plan["p_dual_case_count"] for plan in plans],
        "total_plan_bytes": sum(plan["plan_bytes"] for plan in plans),
        "shards": plans,
    }


def _input_rows(inputs_dir: Path, manifest: dict[str, Any], mode: str) -> list[dict[str, Any]]:
    filename = (manifest.get("mode_inputs") or {}).get(mode)
    if not filename:
        raise ValueError(f"prepared inputs do not contain {mode}")
    path = _resolve_input_path(inputs_dir, filename)
    expected = (manifest.get("mode_input_sha256") or {}).get(mode)
    if not path.is_file():
        raise FileNotFoundError(f"mode input is missing: {path}")
    if expected and _hash_file(path) != expected:
        raise ValueError(f"prepared mode input changed after freezing: {path}")
    rows = _read_jsonl(path)
    if any(row.get("mode") != mode for row in rows):
        raise ValueError(f"mode input contains records for another mode: {path}")
    ids = [_case_id(row) for row in rows]
    if any(not value for value in ids) or len(ids) != len(set(ids)):
        raise ValueError(f"{mode} input requires unique, non-empty case_id values")
    return rows


def _verify_prepared_inputs(
    inputs_dir: Path,
    *,
    require_ground_truth: bool = True,
    catalog_cache_paths: dict[Path, Path] | None = None,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    manifest = _read_inputs_manifest(inputs_dir)
    if not manifest.get("input_id"):
        raise ValueError("prepared input manifest lacks input_id")
    available_modes = set(manifest.get("mode_inputs") or {})
    needed_modes = set(MODES) if require_ground_truth else set(SHARD_MODES)
    if not needed_modes.issubset(available_modes):
        raise ValueError(f"prepared inputs omit required mode(s): {sorted(needed_modes - available_modes)}")
    rows = {mode: _input_rows(inputs_dir, manifest, mode) for mode in needed_modes}
    lex_ids = [_case_id(row) for row in rows["D_LEX"]]
    for mode in ("D_SEM", "ORACLE") if require_ground_truth else ("D_SEM",):
        if [_case_id(row) for row in rows[mode]] != lex_ids:
            raise ValueError(f"{mode} cohort differs from D_LEX")
    present_ids = [_case_id(row) for row in rows["P_DUAL_PRESENT"]]
    hidden_ids = [_case_id(row) for row in rows["P_DUAL_HIDDEN"]]
    if present_ids != hidden_ids:
        raise ValueError("P_DUAL_PRESENT and P_DUAL_HIDDEN must have identical ordered case IDs")
    for row in rows["P_DUAL_PRESENT"]:
        if not row.get("patch_available") or not str(row.get("patch_text") or "").strip():
            raise ValueError(f"P_DUAL_PRESENT lacks a valid patch for {_case_id(row)}")
    for row in rows["P_DUAL_HIDDEN"]:
        leaked = (PATCH_FIELDS | CWE_FIELDS).intersection(row)
        if leaked:
            raise ValueError(f"P_DUAL_HIDDEN leaks forbidden fields for {_case_id(row)}: {sorted(leaked)}")

    if require_ground_truth:
        gt_path = _resolve_input_path(inputs_dir, str(manifest.get("ground_truth_path") or "ground_truth.jsonl"))
        if not gt_path.is_file():
            raise FileNotFoundError(f"prepared inputs lack normalized ground truth: {gt_path}")
        if manifest.get("ground_truth_sha256") and _hash_file(gt_path) != manifest["ground_truth_sha256"]:
            raise ValueError("normalized ground truth changed after preparation")

    # Verify each frozen FunctionCatalog and parser cache before creating copies.
    catalogs = manifest.get("catalogs") or {}
    seen_catalogs: set[str] = set()
    for mode in SHARD_MODES:
        for row in rows[mode]:
            if not bool(row.get("eligible", True)):
                continue
            catalog_value = str(row.get("catalog_path") or "")
            if not catalog_value:
                raise ValueError(f"eligible case lacks catalog_path: {_case_id(row)}")
            catalog_path = _resolve_input_path(inputs_dir, catalog_value)
            if str(catalog_path) in seen_catalogs:
                continue
            seen_catalogs.add(str(catalog_path))
            info = catalogs.get(catalog_path.name) or {}
            if not catalog_path.is_file() or _hash_file(catalog_path) != info.get("sha256"):
                raise ValueError(f"FunctionCatalog is missing or changed: {catalog_path}")
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            source_path = _resolve_input_path(inputs_dir, str(row.get("source_path") or ""))
            if not source_path.is_dir():
                raise ValueError(f"source snapshot is missing: {source_path}")
            if str(catalog.get("source_path") or ""):
                catalog_source = _resolve_input_path(inputs_dir, str(catalog["source_path"]))
                if catalog_source != source_path:
                    raise ValueError(f"catalog and input source paths differ for {_case_id(row)}")
            cache_path = _resolve_input_path(inputs_dir, str(catalog.get("inventory_cache_path") or ""))
            if not cache_path.is_file():
                raise ValueError(f"FunctionCatalog parser cache is missing: {cache_path}")
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
            if cache.get("inventory_hash") != catalog.get("inventory_hash"):
                raise ValueError(f"parser cache does not match FunctionCatalog: {catalog_path}")
            if catalog_cache_paths is not None:
                catalog_cache_paths[catalog_path] = cache_path
    return manifest, rows


def _indexed_python_files(source_root: Path) -> list[Path]:
    from f_vra.localization.code.function_parser import SKIP_DIRS, filesystem_path

    root = filesystem_path(source_root)
    files: list[Path] = []
    # Prune ignored trees before descending into them. A glob followed by a
    # path filter still walks .venv, tests, build, and node_modules, which can
    # dwarf the actual source copied into a machine bundle.
    for current, directories, filenames in os.walk(root, topdown=True):
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRS)
        files.extend(Path(current) / name for name in filenames if name.endswith(".py"))
    return sorted(files)


def _copy_file_with_hash(source: Path, destination: Path) -> tuple[str, int]:
    """Copy a file and hash the exact bytes while reading them once."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as src, destination.open("wb") as dst:
        while chunk := src.read(1024 * 1024):
            digest.update(chunk)
            dst.write(chunk)
            size += len(chunk)
    shutil.copystat(source, destination)
    return digest.hexdigest(), size


def _copy_indexed_source(
    source: Path,
    destination: Path,
    *,
    indexed_files: list[Path] | None = None,
    file_records: list[dict[str, Any]] | None = None,
    record_prefix: str = "",
) -> tuple[str, int, int]:
    """Copy exactly the Python files considered by the frozen source indexer."""
    from f_vra.localization.code.function_parser import filesystem_path

    source = filesystem_path(source)
    destination = filesystem_path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    files = indexed_files if indexed_files is not None else _indexed_python_files(source)
    digest = hashlib.sha256()
    total_bytes = 0
    for path in files:
        relative_path = path.relative_to(source)
        relative_bytes = relative_path.as_posix().encode("utf-8")
        contents = path.read_bytes()
        digest.update(len(relative_bytes).to_bytes(4, "big"))
        digest.update(relative_bytes)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
        target = destination / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.write_bytes(contents) != len(contents):
            raise IOError(f"short write while copying indexed source file: {target}")
        if file_records is not None:
            bundle_path = "/".join(part for part in (record_prefix, relative_path.as_posix()) if part)
            file_records.append({
                "path": bundle_path,
                "size_bytes": len(contents),
                "sha256": hashlib.sha256(contents).hexdigest(),
            })
        total_bytes += len(contents)
    source_hash = digest.hexdigest()
    return source_hash, total_bytes, len(files)


class _HashingWriter:
    """Hash bytes as a streaming tar writer emits them."""

    def __init__(self, raw: Any) -> None:
        self.raw = raw
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, data: bytes) -> int:
        self.digest.update(data)
        written = self.raw.write(data)
        self.size += written
        return written

    def tell(self) -> int:
        return self.size


def _write_source_archive(
    archive_path: Path,
    source_by_identity: dict[str, Path],
    indexed_files_by_identity: dict[str, list[Path]],
) -> tuple[str, dict[str, str], int, int]:
    """Stream indexed source files into one portable tar instead of creating millions of files."""
    from f_vra.localization.code.function_parser import filesystem_path

    tree_digests: dict[str, str] = {}
    total_source_bytes = 0
    total_files = 0
    with archive_path.open("wb") as raw:
        output = _HashingWriter(raw)
        with tarfile.open(fileobj=output, mode="w|") as archive, ThreadPoolExecutor(max_workers=4) as reader_pool:
            for identity, source_value in sorted(source_by_identity.items()):
                source = filesystem_path(source_value)
                tree_digest = hashlib.sha256()
                files = indexed_files_by_identity[identity]
                for offset in range(0, len(files), 4):
                    batch = files[offset:offset + 4]
                    contents_batch = list(reader_pool.map(Path.read_bytes, batch))
                    for path, contents in zip(batch, contents_batch, strict=True):
                        relative_path = path.relative_to(source).as_posix()
                        relative_bytes = relative_path.encode("utf-8")
                        size = len(contents)
                        tree_digest.update(len(relative_bytes).to_bytes(4, "big"))
                        tree_digest.update(relative_bytes)
                        tree_digest.update(size.to_bytes(8, "big"))
                        tree_digest.update(contents)

                        info = tarfile.TarInfo(f"sources/{identity}/{relative_path}")
                        info.size = size
                        info.mtime = 0
                        info.mode = 0o644
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        archive.addfile(info, io.BytesIO(contents))
                        total_source_bytes += size
                        total_files += 1
                tree_digests[identity] = tree_digest.hexdigest()
        raw.flush()
    return output.digest.hexdigest(), tree_digests, total_source_bytes, total_files


def _extract_source_archive(archive_path: Path, destination: Path) -> None:
    """Extract only regular ``sources/`` members, rejecting traversal and links."""
    from f_vra.localization.code.function_parser import filesystem_path

    staging = Path(tempfile.mkdtemp(prefix=".sources-extract.", dir=destination))
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            for member in archive:
                member_path = PurePosixPath(member.name)
                if (
                    member_path.is_absolute()
                    or "\\" in member.name
                    or ":" in member.name
                    or not member_path.parts
                    or member_path.parts[0] != "sources"
                    or len(member_path.parts) < 3
                    or any(part in {"", ".", ".."} for part in member_path.parts)
                    or not member.isfile()
                ):
                    raise ValueError(f"unsafe source archive member: {member.name}")
                output = staging.joinpath(*member_path.parts)
                filesystem_path(output.parent).mkdir(parents=True, exist_ok=True)
                source_file = archive.extractfile(member)
                if source_file is None:
                    raise ValueError(f"source archive member cannot be read: {member.name}")
                with source_file, filesystem_path(output).open("wb") as target:
                    shutil.copyfileobj(source_file, target, length=1024 * 1024)
        extracted = filesystem_path(staging / "sources")
        if not extracted.is_dir():
            raise ValueError("source archive contains no source files")
        destination_sources = filesystem_path(destination / "sources")
        if destination_sources.exists():
            shutil.rmtree(destination_sources)
        os.replace(extracted, destination_sources)
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def create_vf_machine_shards(
    inputs_dir: Path,
    output_root: Path,
    *,
    shard_count: int,
) -> dict[str, Any]:
    """Create portable per-machine bundles from a full, verified VF input set."""
    if shard_count < 1:
        raise ValueError("shard_count must be at least one")
    inputs_dir = inputs_dir.resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    cache_for_catalog: dict[Path, Path] = {}
    parent_manifest, full_rows = _verify_prepared_inputs(
        inputs_dir, catalog_cache_paths=cache_for_catalog,
    )
    parent_manifest_sha = _hash_file(inputs_dir / "manifest.json")
    parent_id = str(parent_manifest["input_id"])

    lex_rows = full_rows["D_LEX"]
    assignment = {_case_id(row): _shard_index(row, shard_count) for row in lex_rows}
    for mode, mode_rows in full_rows.items():
        for row in mode_rows:
            if assignment.get(_case_id(row)) != _shard_index(row, shard_count):
                raise ValueError(f"snapshot grouping is inconsistent in {mode}: {_case_id(row)}")

    # Resolve only the indexed source, catalogs, and parser cache needed per shard.
    source_for_case: dict[str, Path] = {}
    catalog_for_case: dict[str, Path] = {}
    source_identity_for_case: dict[str, str] = {}
    expected_source_hashes: dict[str, str] = {}
    for row in lex_rows:
        if not bool(row.get("eligible", True)):
            continue
        case_id = _case_id(row)
        source = _resolve_input_path(inputs_dir, str(row.get("source_path") or ""))
        catalog = _resolve_input_path(inputs_dir, str(row.get("catalog_path") or ""))
        source_for_case[case_id] = source
        catalog_for_case[case_id] = catalog
        source_identity_for_case[case_id] = _sha256(
            f"{row.get('snapshot_id') or case_id}\0{source}".encode("utf-8")
        )[:24]
        expected_source_hash = _expected_indexed_source_hash(
            source, str(row.get("source_content_sha256") or ""),
        )
        identity = source_identity_for_case[case_id]
        if expected_source_hash:
            previous_hash = expected_source_hashes.setdefault(identity, expected_source_hash)
            if previous_hash != expected_source_hash:
                raise ValueError(f"shared source identity has conflicting content hashes: {_case_id(row)}")
        if catalog not in cache_for_catalog:
            raise ValueError(f"verified parser cache mapping is missing: {catalog}")

    shard_summaries = []
    expected_copy_bytes = 0
    for shard_index in range(shard_count):
        case_ids = {case_id for case_id, assigned in assignment.items() if assigned == shard_index}
        source_by_identity = {
            source_identity_for_case[case_id]: source_for_case[case_id]
            for case_id in case_ids if case_id in source_for_case
        }
        catalog_paths = {
            catalog_for_case[case_id]
            for case_id in case_ids if case_id in catalog_for_case
        }
        cache_paths = {cache_for_catalog[path] for path in catalog_paths}
        indexed_files_by_identity = {
            identity: _indexed_python_files(source)
            for identity, source in source_by_identity.items()
        }
        expected_copy_bytes += sum(
            path.stat().st_size
            for indexed_files in indexed_files_by_identity.values()
            for path in indexed_files
        )
        expected_copy_bytes += sum(path.stat().st_size for path in catalog_paths)
        expected_copy_bytes += sum(path.stat().st_size for path in cache_paths)
        shard_summaries.append({
            "case_ids": case_ids,
            "source_by_identity": source_by_identity,
            "indexed_files_by_identity": indexed_files_by_identity,
            "catalog_paths": catalog_paths,
            "cache_paths": cache_paths,
        })
    required = int(expected_copy_bytes * 1.05) + 1024 * 1024 * 1024
    free_bytes = shutil.disk_usage(output_root).free
    if free_bytes < required:
        raise OSError(
            f"insufficient free space for portable machine bundles: need about {required} bytes, have {free_bytes}"
        )

    result_shards = []
    source_manifest_name = Path(str(parent_manifest.get("source_manifest") or "prepared_manifest.jsonl")).name
    for shard_index, plan in enumerate(shard_summaries):
        shard_id = f"machine-{shard_index + 1:03d}-of-{shard_count:03d}"
        final_dir = output_root / shard_id
        temp_dir = Path(tempfile.mkdtemp(prefix=f".{shard_id}.", dir=output_root))
        try:
            catalog_dir = temp_dir / "catalogs"
            cache_dir = temp_dir / "inventory_cache"
            catalog_dir.mkdir(parents=True)
            cache_dir.mkdir(parents=True)

            source_rel_by_identity: dict[str, str] = {}
            file_records: list[dict[str, Any]] = []
            for identity in plan["source_by_identity"]:
                source_rel = f"sources/{identity}"
                source_rel_by_identity[identity] = source_rel

            source_archive_path = temp_dir / "sources.tar"
            source_archive_sha, source_hashes, source_bytes, source_file_count = _write_source_archive(
                source_archive_path,
                plan["source_by_identity"],
                plan["indexed_files_by_identity"],
            )
            source_count = len(plan["source_by_identity"])
            file_records.append({
                "path": "sources.tar",
                "size_bytes": source_archive_path.stat().st_size,
                "sha256": source_archive_sha,
            })
            for identity, source in sorted(plan["source_by_identity"].items()):
                expected_source_hash = expected_source_hashes.get(identity)
                if expected_source_hash and expected_source_hash != source_hashes[identity]:
                    raise ValueError(f"indexed source checksum differs from prepared manifest: {source}")

            cache_rel_by_path: dict[Path, str] = {}
            for cache_path in sorted(plan["cache_paths"]):
                target_rel = f"inventory_cache/{cache_path.name}"
                target = temp_dir / target_rel
                if target.exists():
                    source_hash = _hash_file(cache_path)
                    target_hash = _hash_file(target)
                else:
                    source_hash, _ = _copy_file_with_hash(cache_path, target)
                    target_hash = source_hash
                if target_hash != source_hash:
                    target_rel = f"inventory_cache/{_sha256(str(cache_path).encode())[:12]}-{cache_path.name}"
                    target = temp_dir / target_rel
                    source_hash, _ = _copy_file_with_hash(cache_path, target)
                    target_hash = source_hash
                cache_rel_by_path[cache_path] = target_rel
                file_records.append({
                    "path": target_rel,
                    "size_bytes": target.stat().st_size,
                    "sha256": target_hash,
                })

            catalog_rel_by_path: dict[Path, str] = {}
            catalog_metadata: dict[str, dict[str, Any]] = {}
            for catalog_path in sorted(plan["catalog_paths"]):
                catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
                affected_ids = [
                    case_id for case_id in plan["case_ids"]
                    if catalog_for_case.get(case_id) == catalog_path
                ]
                if not affected_ids:
                    raise AssertionError(f"catalog is not referenced by any case: {catalog_path}")
                identity = source_identity_for_case[affected_ids[0]]
                catalog["source_path"] = source_rel_by_identity[identity]
                original_cache = cache_for_catalog[catalog_path]
                catalog["inventory_cache_path"] = cache_rel_by_path[original_cache]
                target_rel = f"catalogs/{catalog_path.name}"
                target = temp_dir / target_rel
                if target.exists():
                    target_rel = f"catalogs/{_sha256(str(catalog_path).encode())[:12]}-{catalog_path.name}"
                    target = temp_dir / target_rel
                catalog_bytes = (json.dumps(catalog, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
                target.write_bytes(catalog_bytes)
                catalog_rel_by_path[catalog_path] = target_rel
                catalog_hash = hashlib.sha256(catalog_bytes).hexdigest()
                catalog_metadata[target.name] = {
                    "source_identity": catalog.get("case_source_identity"),
                    "inventory_hash": catalog.get("inventory_hash"),
                    "function_count": catalog.get("function_count"),
                    "sha256": catalog_hash,
                }
                file_records.append({
                    "path": target_rel,
                    "size_bytes": len(catalog_bytes),
                    "sha256": catalog_hash,
                })

            mode_inputs: dict[str, str] = {}
            mode_hashes: dict[str, str] = {}
            mode_counts: dict[str, int] = {}
            for mode in SHARD_MODES:
                selected = [row for row in full_rows[mode] if assignment[_case_id(row)] == shard_index]
                portable_rows = []
                for original in selected:
                    row = dict(original)
                    case_id = _case_id(row)
                    if bool(row.get("eligible", True)):
                        identity = source_identity_for_case[case_id]
                        row["source_path"] = source_rel_by_identity[identity]
                        row["catalog_path"] = catalog_rel_by_path[catalog_for_case[case_id]]
                    portable_rows.append(row)
                filename = MODE_INPUT_NAMES[mode]
                mode_path = temp_dir / filename
                _write_jsonl(mode_path, portable_rows)
                mode_inputs[mode] = filename
                mode_hashes[mode] = _hash_file(mode_path)
                file_records.append({
                    "path": filename,
                    "size_bytes": mode_path.stat().st_size,
                    "sha256": mode_hashes[mode],
                })
                mode_counts[mode] = len(portable_rows)

            shard_case_ids = sorted(plan["case_ids"])
            eligible_case_ids = {
                _case_id(row) for row in lex_rows if bool(row.get("eligible", True))
            }
            shard_eligible = sorted(set(shard_case_ids) & eligible_case_ids)
            pdual_count = mode_counts["P_DUAL_PRESENT"]
            local_manifest = {
                "schema_version": parent_manifest.get("schema_version", "f_vra.vf.prepared-inputs.v1"),
                "input_id": parent_id,
                "parent_input_id": parent_id,
                "parent_manifest_sha256": parent_manifest_sha,
                "source_manifest": source_manifest_name,
                "source_manifest_sha256": parent_manifest.get("source_manifest_sha256"),
                "parser_sha256": parent_manifest.get("parser_sha256"),
                "preparer_sha256": parent_manifest.get("preparer_sha256"),
                "case_count": len(shard_case_ids),
                "mode_inputs": mode_inputs,
                "mode_input_sha256": mode_hashes,
                "mode_counts": mode_counts,
                "catalogs": catalog_metadata,
                "shard_id": shard_id,
                "shard_count": shard_count,
                "has_ground_truth": False,
            }
            local_manifest_path = temp_dir / "manifest.json"
            write_json(local_manifest_path, local_manifest)
            local_manifest_sha = _hash_file(local_manifest_path)
            file_records.append({
                "path": "manifest.json",
                "size_bytes": local_manifest_path.stat().st_size,
                "sha256": local_manifest_sha,
            })
            file_records.sort(key=lambda record: str(record["path"]))
            total_bytes = sum(int(record["size_bytes"]) for record in file_records)
            shard_manifest = {
                "schema_version": SHARD_SCHEMA,
                "bundle_id": _sha256(json.dumps({
                    "parent_manifest_sha256": parent_manifest_sha,
                    "shard_id": shard_id,
                    "mode_input_sha256": mode_hashes,
                    "file_records": file_records,
                }, sort_keys=True, separators=(",", ":")).encode("utf-8")),
                "parent_input_id": parent_id,
                "parent_manifest_sha256": parent_manifest_sha,
                "parent_mode_input_sha256": {
                    mode: (parent_manifest.get("mode_input_sha256") or {}).get(mode)
                    for mode in SHARD_MODES
                },
                "shard_id": shard_id,
                "shard_index": shard_index,
                "shard_count": shard_count,
                "case_ids": shard_case_ids,
                "eligible_case_ids": shard_eligible,
                "case_ids_by_mode": {
                    mode: [_case_id(row) for row in full_rows[mode] if assignment[_case_id(row)] == shard_index]
                    for mode in SHARD_MODES
                },
                "mode_input_sha256": mode_hashes,
                "local_manifest_sha256": local_manifest_sha,
                "source_count": source_count,
                "source_file_count": source_file_count,
                "indexed_source_bytes": source_bytes,
                "source_tree_sha256": source_hashes,
                "catalog_count": len(catalog_rel_by_path),
                "parser_cache_count": len(cache_rel_by_path),
                "bundle_bytes": total_bytes,
                "files": file_records,
            }
            write_json(temp_dir / "shard_manifest.json", shard_manifest)
            if final_dir.exists():
                existing_manifest = final_dir / "shard_manifest.json"
                if existing_manifest.is_file():
                    existing = json.loads(existing_manifest.read_text(encoding="utf-8"))
                    if existing.get("bundle_id") == shard_manifest["bundle_id"]:
                        shutil.rmtree(temp_dir)
                        result_shards.append({
                            "shard_id": shard_id, "path": str(final_dir.resolve()),
                            "case_count": len(shard_case_ids), "eligible_case_count": len(shard_eligible),
                            "p_dual_case_count": pdual_count, "bundle_bytes": existing.get("bundle_bytes"),
                            "bundle_id": existing.get("bundle_id"), "reused": True,
                        })
                        continue
                raise FileExistsError(f"shard output already exists with different content: {final_dir}")
            os.replace(temp_dir, final_dir)
            result_shards.append({
                "shard_id": shard_id, "path": str(final_dir.resolve()),
                "case_count": len(shard_case_ids), "eligible_case_count": len(shard_eligible),
                "p_dual_case_count": pdual_count, "bundle_bytes": total_bytes,
                "bundle_id": shard_manifest["bundle_id"], "reused": False,
            })
        except Exception:
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
            raise

    return {
        "parent_input_id": parent_id,
        "parent_manifest_sha256": parent_manifest_sha,
        "shard_count": shard_count,
        "assignment": "first_64_bits(SHA256(snapshot_id_or_case_id)) modulo shard_count",
        "eligible_case_counts": [item["eligible_case_count"] for item in result_shards],
        "p_dual_case_counts": [item["p_dual_case_count"] for item in result_shards],
        "estimated_copy_bytes": expected_copy_bytes,
        "shards": result_shards,
    }


def run_vf_machine_shard(
    shard_inputs_dir: Path,
    results_root: Path,
    *,
    run_id: str | None = None,
    workers: int = 2,
    case_limit: int = 0,
    progress: bool = True,
    localizer: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run the four experiment modes on one machine bundle, resuming checkpoints."""
    if workers < 1:
        raise ValueError("workers must be at least one")
    if case_limit < 0:
        raise ValueError("case_limit cannot be negative")
    shard_inputs_dir = shard_inputs_dir.resolve()
    shard_manifest_path = shard_inputs_dir / "shard_manifest.json"
    if not shard_manifest_path.is_file():
        raise FileNotFoundError(f"shard bundle lacks shard_manifest.json: {shard_inputs_dir}")
    shard = json.loads(shard_manifest_path.read_text(encoding="utf-8"))
    if shard.get("schema_version") != SHARD_SCHEMA:
        raise ValueError("unsupported machine shard schema")
    local_manifest_path = shard_inputs_dir / "manifest.json"
    if not local_manifest_path.is_file():
        raise FileNotFoundError(f"portable bundle lacks manifest.json: {shard_inputs_dir}")
    local_manifest = json.loads(local_manifest_path.read_text(encoding="utf-8"))
    if shard.get("parent_input_id") != local_manifest.get("parent_input_id") or shard.get("shard_id") != local_manifest.get("shard_id"):
        raise ValueError("shard manifest and prepared bundle manifest disagree")
    if shard.get("parent_manifest_sha256") != local_manifest.get("parent_manifest_sha256"):
        raise ValueError("shard bundle parent manifest fingerprints disagree")
    expected_bundle_id = _sha256(json.dumps({
        "parent_manifest_sha256": shard.get("parent_manifest_sha256"),
        "shard_id": shard.get("shard_id"),
        "mode_input_sha256": shard.get("mode_input_sha256"),
        "file_records": shard.get("files") or [],
    }, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if shard.get("bundle_id") != expected_bundle_id:
        raise ValueError("portable shard bundle identity checksum mismatch")
    if _hash_file(shard_inputs_dir / "manifest.json") != shard.get("local_manifest_sha256"):
        raise ValueError("portable bundle manifest checksum mismatch")
    source_archive_record = None
    for record in shard.get("files") or []:
        artifact = _resolve_input_path(shard_inputs_dir, str(record.get("path") or ""))
        if not artifact.is_file() or artifact.stat().st_size != int(record.get("size_bytes") or -1):
            raise ValueError(f"portable bundle artifact is missing or changed: {artifact}")
        if _hash_file(artifact) != record.get("sha256"):
            raise ValueError(f"portable bundle artifact checksum mismatch: {artifact}")
        if str(record.get("path") or "") == "sources.tar":
            source_archive_record = record
    if source_archive_record and not (shard_inputs_dir / "sources").is_dir():
        _extract_source_archive(shard_inputs_dir / "sources.tar", shard_inputs_dir)

    manifest, rows = _verify_prepared_inputs(shard_inputs_dir, require_ground_truth=False)
    if "ground_truth_path" in manifest or (shard_inputs_dir / "ground_truth.jsonl").exists():
        raise ValueError("machine bundle must not contain normalized ground truth")
    effective_run_id = run_id or f"vf-{str(shard['parent_input_id']).removeprefix('vf-input-')}"
    if effective_run_id in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", effective_run_id):
        raise ValueError("run_id may contain only letters, digits, dot, underscore, and hyphen")
    machine_result_dir = results_root / effective_run_id / str(shard["shard_id"])
    machine_result_dir.mkdir(parents=True, exist_ok=True)
    run_manifest_path = machine_result_dir / "shard_run_manifest.json"
    provider_config_fingerprint = _provider_config_fingerprint()
    runner_environment_identity = _runner_environment_identity()
    previous = {}
    if run_manifest_path.exists():
        previous = json.loads(run_manifest_path.read_text(encoding="utf-8"))
        if previous.get("bundle_id") != shard.get("bundle_id") or previous.get("parent_manifest_sha256") != shard.get("parent_manifest_sha256"):
            raise ValueError("existing shard results belong to a different prepared bundle")
        if previous.get("provider_config_fingerprint") != provider_config_fingerprint:
            raise ValueError("provider model/endpoint or retrieval settings changed; use a new run ID")
        if any(previous.get(key) != value for key, value in runner_environment_identity.items()):
            raise ValueError("shard runner code or environment lock changed; use a new run ID")
    mode_summaries = dict(previous.get("modes") or {})
    run_manifest = {
        "schema_version": SHARD_RUN_SCHEMA,
        "status": "running",
        "run_id": effective_run_id,
        "shard_id": shard["shard_id"],
        "shard_index": shard["shard_index"],
        "shard_count": shard["shard_count"],
        "bundle_id": shard["bundle_id"],
        "shard_manifest_sha256": _hash_file(shard_manifest_path),
        "parent_input_id": shard["parent_input_id"],
        "parent_manifest_sha256": shard["parent_manifest_sha256"],
        "parent_mode_input_sha256": dict(shard["parent_mode_input_sha256"]),
        "mode_input_sha256": dict(shard["mode_input_sha256"]),
        "provider_config_fingerprint": provider_config_fingerprint,
        **runner_environment_identity,
        "workers": workers,
        "case_limit": case_limit,
        "modes": mode_summaries,
    }
    write_json(run_manifest_path, run_manifest)
    for mode in SHARD_MODES:
        summary = run_vf_mode(
            mode, shard_inputs_dir, results_root / effective_run_id,
            run_id=str(shard["shard_id"]), localizer=localizer, progress=progress,
            workers=workers, case_limit=case_limit,
        )
        mode_meta = json.loads((machine_result_dir / f"{mode}.meta.json").read_text(encoding="utf-8"))
        mode_summaries[mode] = {
            **_portable_mode_summary(summary),
            "code_fingerprint": mode_meta["code_fingerprint"],
            "run_fingerprint": mode_meta["run_fingerprint"],
            "input_sha256": mode_meta["input_sha256"],
            "results_sha256": _hash_file(machine_result_dir / f"{mode}.jsonl"),
            "checkpoint_sha256": _hash_file(machine_result_dir / f"{mode}.checkpoint.jsonl"),
            "meta_sha256": _hash_file(machine_result_dir / f"{mode}.meta.json"),
        }
        run_manifest["modes"] = mode_summaries
        write_json(run_manifest_path, run_manifest)
    run_manifest["status"] = (
        "canary" if any(summary.get("partial") for summary in mode_summaries.values()) else "complete"
    )
    write_json(run_manifest_path, run_manifest)
    return {
        "status": run_manifest["status"],
        "run_id": effective_run_id,
        "shard_id": shard["shard_id"],
        "results_dir": str(machine_result_dir.resolve()),
        "modes": mode_summaries,
    }


def run_vf_index_shard(
    inputs_dir: Path,
    shard_plan: Path,
    results_root: Path,
    *,
    run_id: str | None = None,
    workers: int = 2,
    case_limit: int = 0,
    progress: bool = True,
    localizer: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Run one case-ID plan against locally installed shared input artifacts."""
    if workers < 1:
        raise ValueError("workers must be at least one")
    if case_limit < 0:
        raise ValueError("case_limit cannot be negative")
    inputs_dir = inputs_dir.resolve()
    plan_path = shard_plan.resolve()
    if plan_path.is_dir():
        plan_path = plan_path / "shard_manifest.json"
    if not plan_path.is_file():
        raise FileNotFoundError(f"shard plan does not contain shard_manifest.json: {plan_path}")
    shard = json.loads(plan_path.read_text(encoding="utf-8"))
    if shard.get("schema_version") != INDEX_SHARD_SCHEMA:
        raise ValueError("unsupported index-shard schema")
    plan_payload = {key: value for key, value in shard.items() if key != "plan_sha256"}
    expected_plan_sha = _sha256(json.dumps(plan_payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    if shard.get("plan_sha256") != expected_plan_sha:
        raise ValueError("shard plan checksum mismatch")
    manifest, rows = _read_index_shard_inputs(inputs_dir)
    parent_manifest_sha = _hash_file(inputs_dir / "manifest.json")
    if shard.get("parent_input_id") != manifest.get("input_id"):
        raise ValueError("shard plan was created for a different prepared input_id")
    if shard.get("parent_manifest_sha256") != parent_manifest_sha:
        raise ValueError("shard plan parent manifest checksum differs from local prepared inputs")
    expected_mode_hashes = {
        mode: (manifest.get("mode_input_sha256") or {}).get(mode) for mode in SHARD_MODES
    }
    if shard.get("parent_mode_input_sha256") != expected_mode_hashes:
        raise ValueError("shard plan mode input checksums differ from local prepared inputs")
    shard_index, shard_count = int(shard.get("shard_index", -1)), int(shard.get("shard_count", 0))
    if shard_count < 1 or not 0 <= shard_index < shard_count:
        raise ValueError("shard plan has an invalid index/count")
    expected_case_ids_by_mode = {
        mode: [_case_id(row) for row in mode_rows if _shard_index(row, shard_count) == shard_index]
        for mode, mode_rows in rows.items()
    }
    if shard.get("case_ids_by_mode") != expected_case_ids_by_mode:
        raise ValueError("shard plan case assignment differs from local prepared mode inputs")
    expected_case_ids = sorted(expected_case_ids_by_mode["D_LEX"])
    if shard.get("case_ids") != expected_case_ids:
        raise ValueError("shard plan case IDs do not match its mode assignments")

    effective_run_id = run_id or f"vf-{str(manifest['input_id']).removeprefix('vf-input-')}"
    if effective_run_id in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", effective_run_id):
        raise ValueError("run_id may contain only letters, digits, dot, underscore, and hyphen")
    machine_result_dir = results_root / effective_run_id / str(shard["shard_id"])
    machine_result_dir.mkdir(parents=True, exist_ok=True)
    local_plan_path = machine_result_dir / "shard_manifest.json"
    if local_plan_path.exists() and _hash_file(local_plan_path) != _hash_file(plan_path):
        raise FileExistsError(f"result directory contains a different shard plan: {local_plan_path}")
    if not local_plan_path.exists():
        shutil.copyfile(plan_path, local_plan_path)

    provider_config_fingerprint = _provider_config_fingerprint()
    runner_environment_identity = _runner_environment_identity()
    run_manifest_path = machine_result_dir / "shard_run_manifest.json"
    previous = {}
    if run_manifest_path.exists():
        previous = json.loads(run_manifest_path.read_text(encoding="utf-8"))
        if previous.get("bundle_id") != shard["plan_sha256"] or previous.get("parent_manifest_sha256") != parent_manifest_sha:
            raise ValueError("existing shard results belong to a different case-ID plan")
        if previous.get("provider_config_fingerprint") != provider_config_fingerprint:
            raise ValueError("provider model/endpoint or retrieval settings changed; use a new run ID")
        if any(previous.get(key) != value for key, value in runner_environment_identity.items()):
            raise ValueError("shard runner code or environment lock changed; use a new run ID")
    mode_summaries = dict(previous.get("modes") or {})
    run_manifest = {
        "schema_version": SHARD_RUN_SCHEMA,
        "status": "running",
        "run_id": effective_run_id,
        "shard_id": shard["shard_id"],
        "shard_index": shard_index,
        "shard_count": shard_count,
        "bundle_id": shard["plan_sha256"],
        "shard_plan_sha256": shard["plan_sha256"],
        "shard_manifest_sha256": _hash_file(local_plan_path),
        "shard_input_kind": "shared-local-artifacts",
        "parent_input_id": manifest["input_id"],
        "parent_manifest_sha256": parent_manifest_sha,
        "parent_mode_input_sha256": expected_mode_hashes,
        "mode_input_sha256": expected_mode_hashes,
        "provider_config_fingerprint": provider_config_fingerprint,
        **runner_environment_identity,
        "workers": workers,
        "case_limit": case_limit,
        "modes": mode_summaries,
    }
    write_json(run_manifest_path, run_manifest)
    for mode in SHARD_MODES:
        summary = run_vf_mode(
            mode, inputs_dir, results_root / effective_run_id,
            run_id=str(shard["shard_id"]), localizer=localizer, progress=progress,
            workers=workers, case_limit=case_limit,
            case_ids=set(expected_case_ids_by_mode[mode]),
        )
        mode_meta = json.loads((machine_result_dir / f"{mode}.meta.json").read_text(encoding="utf-8"))
        mode_summaries[mode] = {
            **_portable_mode_summary(summary),
            "code_fingerprint": mode_meta["code_fingerprint"],
            "run_fingerprint": mode_meta["run_fingerprint"],
            "input_sha256": mode_meta["input_sha256"],
            "results_sha256": _hash_file(machine_result_dir / f"{mode}.jsonl"),
            "checkpoint_sha256": _hash_file(machine_result_dir / f"{mode}.checkpoint.jsonl"),
            "meta_sha256": _hash_file(machine_result_dir / f"{mode}.meta.json"),
        }
        run_manifest["modes"] = mode_summaries
        write_json(run_manifest_path, run_manifest)
    run_manifest["status"] = (
        "canary" if any(summary.get("partial") for summary in mode_summaries.values()) else "complete"
    )
    write_json(run_manifest_path, run_manifest)
    return {
        "status": run_manifest["status"],
        "run_id": effective_run_id,
        "shard_id": shard["shard_id"],
        "results_dir": str(machine_result_dir.resolve()),
        "modes": mode_summaries,
    }


def merge_vf_machine_shards(
    full_inputs_dir: Path,
    shard_run_dirs: list[Path],
    output_dir: Path,
) -> dict[str, Any]:
    """Validate exact shard coverage, merge case rows, then create central ORACLE."""
    full_inputs_dir = full_inputs_dir.resolve()
    output_dir = output_dir.resolve()
    if output_dir.name in {".", ".."} or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", output_dir.name):
        raise ValueError("merged result directory name must be a valid run_id")
    # Merge consumes the frozen case files and ground truth. Re-hashing every
    # source, catalog and parser cache here would repeatedly scan tens of GBs;
    # each worker validates the selected catalog/cache before running its case.
    full_manifest, full_rows = _read_index_shard_inputs(full_inputs_dir)
    parent_manifest_sha = _hash_file(full_inputs_dir / "manifest.json")
    gt_path = _resolve_input_path(
        full_inputs_dir, str(full_manifest.get("ground_truth_path") or "ground_truth.jsonl"),
    )
    if not gt_path.is_file():
        raise FileNotFoundError(f"prepared inputs lack normalized ground truth: {gt_path}")
    if full_manifest.get("ground_truth_sha256") and _hash_file(gt_path) != full_manifest["ground_truth_sha256"]:
        raise ValueError("normalized ground truth changed after preparation")
    if not shard_run_dirs:
        raise ValueError("provide one --shard-run-dir for every machine shard")
    run_manifests = []
    for run_dir in shard_run_dirs:
        path = run_dir.resolve() / "shard_run_manifest.json"
        if not path.is_file():
            raise FileNotFoundError(f"shard result directory lacks shard_run_manifest.json: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("status") != "complete":
            raise ValueError(f"machine shard has not finished all four modes: {path.parent}")
        if data.get("parent_input_id") != full_manifest["input_id"] or data.get("parent_manifest_sha256") != parent_manifest_sha:
            raise ValueError(f"machine shard was prepared from a different parent input: {path.parent}")
        if data.get("schema_version") != SHARD_RUN_SCHEMA:
            raise ValueError(f"unsupported shard run manifest: {path}")
        for mode in SHARD_MODES:
            if (data.get("parent_mode_input_sha256") or {}).get(mode) != (full_manifest.get("mode_input_sha256") or {}).get(mode):
                raise ValueError(f"machine shard {mode} input came from a different parent mode artifact: {path.parent}")
        run_manifests.append((path.parent, data))
    counts = {int(data["shard_count"]) for _, data in run_manifests}
    if len(counts) != 1:
        raise ValueError("machine shards have inconsistent shard_count values")
    shard_count = counts.pop()
    if len(run_manifests) != shard_count:
        raise ValueError(f"expected {shard_count} machine results, received {len(run_manifests)}")
    expected_shard_ids = {f"machine-{index + 1:03d}-of-{shard_count:03d}" for index in range(shard_count)}
    actual_shard_ids = [str(data.get("shard_id") or "") for _, data in run_manifests]
    if len(actual_shard_ids) != len(set(actual_shard_ids)) or set(actual_shard_ids) != expected_shard_ids:
        raise ValueError("machine shard results are duplicated or incomplete")
    run_ids = {str(data.get("run_id") or "") for _, data in run_manifests}
    if len(run_ids) != 1 or "" in run_ids or run_ids != {output_dir.name}:
        raise ValueError("all machine results and merged output must use the same run ID")
    provider_configs = {str(data.get("provider_config_fingerprint") or "") for _, data in run_manifests}
    if len(provider_configs) != 1 or "" in provider_configs:
        raise ValueError("machine shards used different or missing model/provider/retrieval configurations")
    runner_fingerprints = {str(data.get("shard_runner_fingerprint") or "") for _, data in run_manifests}
    lock_fingerprints = {str(data.get("environment_lock_sha256") or "") for _, data in run_manifests}
    python_runtimes = {str(data.get("python_runtime") or "") for _, data in run_manifests}
    expected_runtime = _runner_environment_identity()
    if runner_fingerprints != {expected_runtime["shard_runner_fingerprint"]}:
        raise ValueError("machine shards used different shard runner code")
    if lock_fingerprints != {expected_runtime["environment_lock_sha256"]}:
        raise ValueError("machine shards used a different Conda lock")
    if python_runtimes != {expected_runtime["python_runtime"]}:
        raise ValueError("machine shards used a different Python major/minor runtime")

    expected_by_shard: dict[str, dict[str, set[str]]] = {}
    for shard_index in range(shard_count):
        shard_id = f"machine-{shard_index + 1:03d}-of-{shard_count:03d}"
        expected_by_shard[shard_id] = {
            mode: {
                _case_id(row) for row in full_rows[mode]
                if _shard_index(row, shard_count) == shard_index
            }
            for mode in SHARD_MODES
        }
    codes: dict[str, set[str]] = {mode: set() for mode in SHARD_MODES}
    merged: dict[str, list[dict[str, Any]]] = {mode: [] for mode in SHARD_MODES}
    inputs_by_mode_case = {
        mode: {_case_id(row): row for row in full_rows[mode]}
        for mode in SHARD_MODES
    }
    for run_dir, run_manifest in run_manifests:
        shard_id = str(run_manifest["shard_id"])
        if not run_manifest.get("shard_manifest_sha256") or not run_manifest.get("bundle_id"):
            raise ValueError(f"shard run manifest lacks bundle identity/checksum: {run_dir}")
        if run_manifest.get("shard_input_kind") == "shared-local-artifacts":
            local_plan = run_dir / "shard_manifest.json"
            if not local_plan.is_file() or _hash_file(local_plan) != run_manifest.get("shard_manifest_sha256"):
                raise ValueError(f"{shard_id} shard plan is missing or changed: {local_plan}")
            plan_data = json.loads(local_plan.read_text(encoding="utf-8"))
            if plan_data.get("plan_sha256") != run_manifest.get("bundle_id"):
                raise ValueError(f"{shard_id} plan identity differs from its run manifest")
            if plan_data.get("parent_input_id") != full_manifest["input_id"] or plan_data.get("parent_manifest_sha256") != parent_manifest_sha:
                raise ValueError(f"{shard_id} plan belongs to a different prepared input")
            for mode in SHARD_MODES:
                planned_ids = set((plan_data.get("case_ids_by_mode") or {}).get(mode) or [])
                if planned_ids != expected_by_shard[shard_id][mode]:
                    raise ValueError(f"{shard_id} plan has an invalid {mode} cohort")
        for mode in SHARD_MODES:
            meta_path = run_dir / f"{mode}.meta.json"
            result_path = run_dir / f"{mode}.jsonl"
            if not meta_path.is_file() or not result_path.is_file():
                raise FileNotFoundError(f"{shard_id} lacks {mode} result artifacts")
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            declared = (run_manifest.get("modes") or {}).get(mode) or {}
            if _hash_file(meta_path) != declared.get("meta_sha256"):
                raise ValueError(f"{shard_id}/{mode} meta checksum mismatch")
            if _hash_file(result_path) != declared.get("results_sha256"):
                raise ValueError(f"{shard_id}/{mode} result checksum mismatch")
            checkpoint_path = run_dir / f"{mode}.checkpoint.jsonl"
            if not checkpoint_path.is_file() or _hash_file(checkpoint_path) != declared.get("checkpoint_sha256"):
                raise ValueError(f"{shard_id}/{mode} checkpoint checksum mismatch")
            if meta.get("input_id") != full_manifest["input_id"]:
                raise ValueError(f"{shard_id}/{mode} has a different parent input_id")
            if meta.get("input_sha256") != (run_manifest.get("mode_input_sha256") or {}).get(mode):
                raise ValueError(f"{shard_id}/{mode} input fingerprint differs from its shard manifest")
            if meta.get("code_fingerprint") != declared.get("code_fingerprint") or meta.get("run_fingerprint") != declared.get("run_fingerprint"):
                raise ValueError(f"{shard_id}/{mode} result fingerprint differs from its run manifest")
            codes[mode].add(str(meta.get("code_fingerprint") or ""))
            result_rows = _read_jsonl(result_path)
            case_ids = [_case_id(row) for row in result_rows]
            expected_ids = expected_by_shard[shard_id][mode]
            if len(case_ids) != len(set(case_ids)) or set(case_ids) != expected_ids:
                missing = sorted(expected_ids - set(case_ids))[:5]
                extra = sorted(set(case_ids) - expected_ids)[:5]
                raise ValueError(f"{shard_id}/{mode} has duplicate/missing/foreign cases; missing={missing}, extra={extra}")
            for result in result_rows:
                if result.get("input_id") != full_manifest["input_id"] or result.get("run_fingerprint") != meta.get("run_fingerprint"):
                    raise ValueError(f"result row fingerprint mismatch: {shard_id}/{mode}/{_case_id(result)}")
                if result.get("mode") != mode or result.get("status") not in {"complete", "failed", "ineligible", "not_applicable"}:
                    raise ValueError(f"invalid result record: {shard_id}/{mode}/{_case_id(result)}")
                input_row = inputs_by_mode_case[mode][_case_id(result)]
                if result.get("cve_vf_group_id") != input_row.get("cve_vf_group_id"):
                    raise ValueError(f"result group ID mismatch: {shard_id}/{mode}/{_case_id(result)}")
                if not bool(input_row.get("eligible", True)) and result.get("status") != "ineligible":
                    raise ValueError(f"ineligible input has a non-ineligible result: {shard_id}/{mode}/{_case_id(result)}")
                if bool(input_row.get("eligible", True)) and result.get("status") == "ineligible":
                    raise ValueError(f"eligible input was marked ineligible: {shard_id}/{mode}/{_case_id(result)}")
                if mode.startswith("P_DUAL") and (
                    int(result.get("candidate_count") or 0) > 100
                    or len(result.get("candidate_ids") or []) > 100
                    or len(result.get("candidate_details") or []) > 100
                ):
                    raise ValueError(f"P_DUAL candidate limit exceeded: {shard_id}/{mode}/{_case_id(result)}")
            merged[mode].extend(result_rows)
    for mode, fingerprints in codes.items():
        if len(fingerprints) != 1 or "" in fingerprints:
            raise ValueError(f"mode code fingerprint differs between shards: {mode}")
    for mode in SHARD_MODES:
        input_order = {_case_id(row): index for index, row in enumerate(full_rows[mode])}
        merged[mode].sort(key=lambda row: input_order[_case_id(row)])
        expected_ids = {_case_id(row) for row in full_rows[mode]}
        if {_case_id(row) for row in merged[mode]} != expected_ids:
            raise ValueError(f"merged {mode} results do not cover the parent input cohort")

    merge_identity = {
        "parent_input_id": full_manifest["input_id"],
        "parent_manifest_sha256": parent_manifest_sha,
        "shards": sorted((data["shard_id"], data["bundle_id"]) for _, data in run_manifests),
        "code_fingerprints": {mode: next(iter(codes[mode])) for mode in SHARD_MODES},
        "provider_config_fingerprint": next(iter(provider_configs)),
        **expected_runtime,
    }
    merge_fingerprint = _sha256(json.dumps(merge_identity, sort_keys=True).encode("utf-8"))
    marker_path = output_dir / "merge_manifest.json"
    if marker_path.exists():
        previous = json.loads(marker_path.read_text(encoding="utf-8"))
        if previous.get("merge_fingerprint") != merge_fingerprint:
            raise FileExistsError(f"output directory contains a different merged run: {output_dir}")
        return previous
    for mode in SHARD_MODES:
        for filename in (f"{mode}.jsonl", f"{mode}.checkpoint.jsonl"):
            if (output_dir / filename).exists():
                raise FileExistsError(f"unverified merged result already exists: {output_dir / filename}")
    output_dir.mkdir(parents=True, exist_ok=True)
    for mode in SHARD_MODES:
        _write_jsonl(output_dir / f"{mode}.jsonl", merged[mode])
        _write_jsonl(output_dir / f"{mode}.checkpoint.jsonl", merged[mode])
        write_json(output_dir / f"{mode}.meta.json", {
            "run_id": output_dir.name,
            "mode": mode,
            "input_id": full_manifest["input_id"],
            "input_sha256": (full_manifest.get("mode_input_sha256") or {}).get(mode),
            "code_fingerprint": next(iter(codes[mode])),
            "run_fingerprint": merge_fingerprint,
            "merged_shard_run_fingerprints": sorted(
                (data["modes"][mode]["run_fingerprint"] for _, data in run_manifests)
            ),
        })

    # The control contains only normalized GT and is generated centrally, once.
    oracle_summary = run_vf_mode(
        "ORACLE", full_inputs_dir, output_dir.parent,
        run_id=output_dir.name, progress=False, workers=1,
    )
    payload = {
        "schema_version": "f_vra.vf.merged-run.v1",
        "status": "complete",
        "merge_fingerprint": merge_fingerprint,
        **merge_identity,
        "shard_count": shard_count,
        "result_counts": {mode: len(merged[mode]) for mode in SHARD_MODES},
        "oracle": oracle_summary,
    }
    write_json(marker_path, payload)
    return payload
