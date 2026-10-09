"""Research-only RQ3 localization contracts, runners, and metric tables.

The product-facing ``f_vra localize`` path is intentionally untouched. Gold
functions stay on the evaluator side of this module and are never passed to a
localizer implementation.
"""

from __future__ import annotations

import hashlib
import json
import os
import difflib
import posixpath
import shutil
from pathlib import PurePosixPath
import subprocess
import tarfile
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Literal

from tqdm import tqdm

from f_vra.evaluation.io import write_json
from f_vra.localization.models import FunctionInfo

RQ3_CONFIGS = {"D_LEX", "D_SEM", "P_MODIFIED", "P_DUAL"}
RANKED = "ranked"
SET = "set"
PROMPT_VERSION = "rq3-localization-prompts-v1"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return list(_iter_jsonl(path))


def _append_jsonl(path: Path, item: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(item, sort_keys=True, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _normal_path(value: str) -> str:
    return str(value or "").replace("\\", "/").removeprefix("./")


@dataclass(frozen=True)
class RQ3CaseInput:
    """Fields visible to a localization configuration; intentionally no gold."""

    case_id: str
    cve_vf_group_id: str
    cve_id: str
    package: str
    repo_url: str
    vulnerable_ref: str
    description: str
    source_path: Path
    cwe_ids: tuple[str, ...] = ()
    cwe_text: str = ""
    patch_available: bool = False
    patch_text: str = ""
    patch_sha: str = ""
    patch_status: str = ""
    snapshot_id: str = ""
    source_content_sha256: str = ""
    source_revision_sha: str = ""


@dataclass(frozen=True)
class RQ3EvaluationCase:
    """Evaluator-side wrapper. ``verified_vfs`` is stripped before localization."""

    localizer_input: RQ3CaseInput
    verified_vfs: tuple[dict[str, Any] | str, ...] = ()
    eligible: bool = True
    ineligible_reason: str = ""


@dataclass
class RQ3LocalizationResult:
    case_id: str
    cve_vf_group_id: str
    config_id: str
    runtime_mode: str
    output_type: Literal["ranked", "set"]
    status: Literal["complete", "failed", "ineligible", "not_applicable"]
    candidate_ids: list[str] = field(default_factory=list)
    candidate_details: list[dict[str, Any]] = field(default_factory=list)
    predictions: list[dict[str, Any]] = field(default_factory=list)
    candidate_count: int = 0
    raw_candidate_count: int | None = None
    snapshot_hash: str = ""
    inventory_hash: str = ""
    fingerprint: str = ""
    runtime_ms: float = 0.0
    error: str = ""
    method_label: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LocalizationStageError(RuntimeError):
    """A localization failure that retains diagnostics gathered before failure."""

    def __init__(
        self, message: str, *, stage: str, metadata: dict[str, Any] | None = None,
        partial_result: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.metadata = metadata or {}
        self.partial_result = partial_result or {}


def parse_case(row: dict[str, Any]) -> RQ3EvaluationCase:
    """Parse a frozen case row; rejects ambiguous/missing source identity."""
    case_id = str(row.get("case_id") or row.get("group_id") or row.get("cve_vf_group_id") or "").strip()
    group_id = str(row.get("cve_vf_group_id") or row.get("group_id") or "").strip()
    source_path = str(row.get("source_path") or "").strip()
    if not case_id or not group_id:
        raise ValueError("case_id and exact cve_vf_group_id are required")
    cwe_ids = row.get("cwe_ids") or ([row["cwe_id"]] if row.get("cwe_id") else [])
    patch_text = str(row.get("patch_text") or "")
    patch_available = bool(row.get("patch_available", bool(patch_text)))
    case = RQ3CaseInput(
        case_id=case_id,
        cve_vf_group_id=group_id,
        cve_id=str(row.get("cve_id") or row.get("advisory_id") or ""),
        package=str(row.get("package") or row.get("package_name") or ""),
        repo_url=str(row.get("repo_url") or ""),
        vulnerable_ref=str(row.get("vulnerable_ref") or ""),
        description=str(row.get("description") or ""),
        source_path=Path(source_path).resolve() if source_path else Path("__rq3_missing_source_snapshot__").resolve(),
        cwe_ids=tuple(sorted({str(item).upper() for item in cwe_ids if str(item).strip()})),
        cwe_text=str(row.get("cwe_text") or ""),
        patch_available=patch_available,
        patch_text=patch_text,
        patch_sha=str(row.get("patch_sha") or ""),
        patch_status=str(row.get("patch_status") or ""),
        snapshot_id=str(row.get("snapshot_id") or ""),
        source_content_sha256=str(row.get("source_content_sha256") or row.get("source_artifact_sha256") or ""),
        source_revision_sha=str(row.get("source_revision_sha") or ""),
    )
    gold = row.get("verified_vfs") or row.get("root_cause_functions") or []
    return RQ3EvaluationCase(
        localizer_input=case,
        verified_vfs=tuple(gold),
        eligible=bool(row.get("eligible", True)),
        ineligible_reason=str(row.get("ineligible_reason") or ""),
    )


def source_tree_hash(root: Path) -> str:
    """Content hash of Python source files included by the function parser."""
    from f_vra.localization.code.function_parser import SKIP_DIRS, filesystem_path

    root = filesystem_path(root)
    digest = hashlib.sha256()
    files = sorted(
        path for path in root.rglob("*.py")
        if not any(part in SKIP_DIRS for part in path.relative_to(root).parts)
    )
    for path in files:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        contents = path.read_bytes()
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def _function_to_json(function: FunctionInfo) -> dict[str, Any]:
    value = asdict(function)
    for key in ("calls", "referenced_names", "assigned_names", "parameter_names"):
        value[key] = sorted(value[key])
    return value


def _function_from_json(row: dict[str, Any]) -> FunctionInfo:
    for key in ("calls", "referenced_names", "assigned_names", "parameter_names"):
        row[key] = set(row.get(key) or [])
    return FunctionInfo(**row)


def _module_qualified_name(function: FunctionInfo) -> str:
    """Add the source module path for unambiguous installed-package binding."""
    path = PurePosixPath(_normal_path(function.file_path))
    parts = list(path.parts)
    if "src" in parts:
        parts = parts[parts.index("src") + 1:]
    if path.stem == "__init__":
        module_parts = parts[:-1]
    else:
        module_parts = [*parts[:-1], path.stem]
    prefix = ".".join(part for part in module_parts if part)
    return f"{prefix}.{function.qualname}" if prefix else function.qualname


def load_inventory(
    root: Path, cache_dir: Path | None = None, *, source_identity: str = "",
    source_content_sha256: str = "",
) -> tuple[list[FunctionInfo], str, str]:
    """Parse/cache once by immutable snapshot identity and parser implementation."""
    from f_vra.localization.code.function_parser import parse_repository

    if source_identity:
        parser_path = Path(__import__("inspect").getsourcefile(parse_repository) or "")
        parser_hash = _sha256(parser_path.read_bytes()) if parser_path.is_file() else "unknown-parser"
        cache_key = _sha256(f"{source_identity}\0{parser_hash}".encode("utf-8"))
        tree_hash = source_content_sha256 or source_identity
    else:
        tree_hash = source_tree_hash(root)
        cache_key = tree_hash
    cache_path = cache_dir / f"{cache_key}.json" if cache_dir else None
    if cache_path and cache_path.exists():
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        functions = [_function_from_json(item) for item in cached["functions"]]
        return functions, str(cached.get("source_hash") or tree_hash), str(cached["inventory_hash"])
    functions = parse_repository(root)
    inventory_hash = _sha256(json.dumps(
        [_function_to_json(item) for item in functions],
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8"))
    if cache_path:
        write_json(cache_path, {
            "source_identity": source_identity,
            "source_hash": tree_hash,
            "source_tree_hash": tree_hash,
            "inventory_hash": inventory_hash,
            "functions": [_function_to_json(item) for item in functions],
        })
    return functions, tree_hash, inventory_hash


def _expanded_query(case: RQ3CaseInput) -> str:
    description = case.description.strip()
    if not case.cwe_ids:
        return description
    if case.cwe_text.strip():
        return f"{description}\nCWE: {case.cwe_text.strip()}".strip()
    from f_vra.localization.retrieval.expansion import expand_description

    hints = [expand_description("", item).strip() for item in case.cwe_ids]
    return (description + "\n" + " ".join(item for item in hints if item)).strip()


def _with_call_context(functions: list[FunctionInfo]) -> list[FunctionInfo]:
    """Build conservative, repository-local caller/callee context by symbol."""
    import copy

    by_simple: dict[str, list[FunctionInfo]] = defaultdict(list)
    by_qualname = {item.qualname: item for item in functions}
    for function in functions:
        by_simple[function.function_name].append(function)
    callers: dict[str, set[str]] = defaultdict(set)
    callees: dict[str, set[str]] = defaultdict(set)
    for caller in functions:
        for raw_name in caller.calls:
            target = by_qualname.get(raw_name)
            if target is None:
                matches = by_simple.get(raw_name.split(".")[-1], [])
                target = matches[0] if len(matches) == 1 else None
            if target is not None and target.identity != caller.identity:
                callers[target.identity].add(caller.identity)
                callees[caller.identity].add(target.identity)
    by_id = {item.identity: item for item in functions}
    enriched: list[FunctionInfo] = []
    for function in functions:
        clone = copy.copy(function)
        local_callers = sorted(callers[function.identity])
        local_callees = sorted(callees[function.identity])
        context = [
            "local callers: " + ", ".join(by_id[item].qualname for item in local_callers),
            "local callees: " + ", ".join(by_id[item].qualname for item in local_callees),
        ]
        clone.source = function.source + "\n" + "\n".join(context)
        enriched.append(clone)
    return enriched


def _strict_semantic_scores(
    query: str, functions: list[FunctionInfo], *, cache_path: Path | None = None,
) -> tuple[dict[str, float], str]:
    from f_vra.localization.retrieval.embedding import embedding_scores

    scores, model = embedding_scores(query, functions, cache_path=cache_path)
    if not scores or not model or model == "not_run":
        raise RuntimeError("semantic embedding retrieval returned no scores/model")
    return scores, model


def _strict_pairwise(
    query: str,
    candidates: list[FunctionInfo],
    relevance: dict[str, float],
    evidence: dict[str, set[str]],
) -> tuple[dict[str, float], dict[str, Any]]:
    from f_vra.localization.providers.llm_client import chat_available
    from f_vra.localization.ranking.methods.pairwise import PairwiseRankingConfig, pairwise_rank_scores

    if not chat_available():
        raise RuntimeError("pairwise LLM provider is not configured; refusing deterministic fallback")
    scores, metadata = pairwise_rank_scores(
        query, candidates, relevance, evidence,
        config=PairwiseRankingConfig(swiss_rounds=8, finalists=20, use_pairwise=True),
    )
    if not metadata.get("used"):
        raise RuntimeError(f"pairwise LLM ranking did not run: {metadata.get('status', 'unknown status')}")
    return scores, metadata


def localize_case(
    case: RQ3CaseInput, config_id: str, *, inventory_cache: Path | None = None,
    protocol: dict[str, Any] | None = None,
) -> RQ3LocalizationResult:
    """Run one explicit RQ3 family using only the evidence allowed to it."""
    protocol = protocol or {}
    candidate_limit = protocol.get("candidate_limit")
    require_av_or_root_cause = bool(protocol.get("require_av_or_root_cause", False))
    if config_id not in RQ3_CONFIGS:
        raise ValueError(f"unknown RQ3 config {config_id!r}; choose {sorted(RQ3_CONFIGS)}")
    if not case.source_path.is_dir():
        raise FileNotFoundError(f"source snapshot missing: {case.source_path}")
    started = time.perf_counter()
    functions, tree_hash, inventory_hash = load_inventory(
        case.source_path, inventory_cache, source_identity=case.snapshot_id,
        source_content_sha256=case.source_content_sha256,
    )
    result = RQ3LocalizationResult(
        case_id=case.case_id,
        cve_vf_group_id=case.cve_vf_group_id,
        config_id=config_id,
        runtime_mode="DEFAULT",
        output_type=RANKED,
        status="complete",
        snapshot_hash=tree_hash,
        inventory_hash=inventory_hash,
    )
    embedding_cache_path = inventory_cache.parent / "embedding_cache.sqlite" if inventory_cache else None

    def semantic_scores(query: str, candidates: list[FunctionInfo]) -> tuple[dict[str, float], str]:
        if embedding_cache_path is not None:
            return _strict_semantic_scores(query, candidates, cache_path=embedding_cache_path)
        return _strict_semantic_scores(query, candidates)

    by_id = {item.identity: item for item in functions}
    candidate_ids: list[str]
    scores: dict[str, float]
    candidate_pool_ids: list[str] = []
    candidate_pool_scores: dict[str, float] = {}
    evidence: dict[str, set[str]] = {}
    candidate_provenance: dict[str, str] = {}
    raw_candidate_count: int | None = None
    method_label = ""

    if config_id == "D_LEX":
        from f_vra.localization.retrieval.tvsm import rank_tvsm

        ranked = rank_tvsm(case.description, functions)
        candidate_ids = [item.identity for item, _ in ranked]
        scores = {item.identity: score for item, score in ranked}
        raw_candidate_count = len(candidate_ids)
        candidate_provenance = {identity: "description_lexical_ranker" for identity in candidate_ids}
        method_label = "VFDetector-inspired tVSM; no patch/CWE/LLM/embedding"
    elif config_id == "D_SEM":
        from f_vra.localization.ranking.methods.description import enrich_description_with_llm_entities

        enriched = enrich_description_with_llm_entities(case.description)
        if not enriched.status.startswith("used") or not enriched.entities:
            raise LocalizationStageError(
                f"semantic entity extraction failed: {enriched.status}", stage="entity_extraction",
                metadata={"entity_extraction": {
                    "status": enriched.status, "model": enriched.model, "entities": enriched.entities or {},
                    "usable": False, "failed": True,
                }},
            )
        usable_entities = {
            key: str(enriched.entities.get(key) or "").strip()
            for key in ("attack_vector", "root_cause")
        }
        has_usable_entities = any(usable_entities.values())
        if require_av_or_root_cause and not has_usable_entities:
            raise LocalizationStageError(
                "semantic entity extraction returned no usable attack_vector/root_cause",
                stage="entity_extraction",
                metadata={"entities": enriched.entities, "entity_extraction": {
                    "status": enriched.status, "model": enriched.model, "entities": enriched.entities,
                    "usable": False, "failed": True,
                }},
            )
        result.metadata["entities"] = enriched.entities
        result.metadata["extractor_model"] = enriched.model
        result.metadata["entity_extraction"] = {
            "status": enriched.status, "model": enriched.model, "entities": enriched.entities,
            "usable": has_usable_entities, "failed": False,
        }
        # Keep the original CVE description in the retrieval query. Entity
        # extraction supplements the report; it must not replace the evidence
        # the method is intended to localize from.
        query_components = {
            "description": case.description.strip(),
            "attack_vector": enriched.entities.get("attack_vector", "").strip(),
            "root_cause": enriched.entities.get("root_cause", "").strip(),
        }
        query = "\n".join(value for value in query_components.values() if value).strip()
        if not query:
            raise RuntimeError("semantic retrieval query is empty after description/entity extraction")
        contextual = _with_call_context(functions)
        try:
            scores, model = semantic_scores(query, contextual)
        except Exception as exc:
            raise LocalizationStageError(
                f"semantic retrieval failed: {type(exc).__name__}: {exc}", stage="semantic_retrieval",
                metadata=result.metadata,
            ) from exc
        candidate_ids = [item.identity for item in sorted(contextual, key=lambda f: (-scores.get(f.identity, 0.0), f.identity))]
        raw_candidate_count = len(candidate_ids)
        candidate_provenance = {identity: "description_entity_semantic_ranker" for identity in candidate_ids}
        method_label = "VFFinder-inspired AV/root-cause extraction + local call-context semantic retrieval"
        result.metadata.update({
            "retrieval_model": model,
            "retrieval_query": query,
            "retrieval_query_components": query_components,
        })
    elif config_id == "P_MODIFIED":
        from f_vra.localization.sources.patch import parse_patch_text

        if not case.patch_available or not case.patch_text.strip():
            raise RuntimeError("P_MODIFIED requires a frozen fixing patch")
        patch = parse_patch_text(case.patch_text)
        selected: set[str] = set()
        for change in patch.files:
            path = _normal_path(change.file_path)
            old_patch_lines = change.old_lines | change.old_hunk_lines
            for function in functions:
                function_path = _normal_path(function.file_path)
                file_match = function_path == path or function_path.endswith("/" + path) or path.endswith("/" + function_path)
                if file_match and any(function.start_line <= line <= function.end_line for line in old_patch_lines):
                    selected.add(function.identity)
        candidate_ids = sorted(selected)
        scores = {}
        raw_candidate_count = len(candidate_ids)
        candidate_provenance = {identity: "patch_hunk_overlap" for identity in candidate_ids}
        result.output_type = SET
        method_label = "old-side patch-hunk overlap in vulnerable snapshot; unordered set"
    else:
        from f_vra.localization.retrieval.candidates import reciprocal_rank_fusion
        from f_vra.localization.retrieval.candidates import lexical_scores
        from f_vra.localization.code.tracker import track_patch_candidates
        from f_vra.localization.sources.patch import parse_patch_text

        query = _expanded_query(case)
        if case.patch_available:
            result.runtime_mode = "PATCH_PRESENT"
            if not case.patch_text.strip():
                raise RuntimeError("case is marked patch-present but patch_text is empty")
            patch = parse_patch_text(case.patch_text)
            tracker = track_patch_candidates(functions, patch, use_type_engine=False)
            evidence = {key: set(value) for key, value in tracker.items()}
            lexical = lexical_scores(query, functions)
            dense, embedding_model = semantic_scores(query, functions)
            fused = reciprocal_rank_fusion(lexical, dense)
            fused_ids = sorted(fused, key=lambda key: (-fused[key], key))
            candidate_ids = list(tracker)
            for identity in fused_ids:
                if identity not in candidate_ids:
                    candidate_ids.append(identity)
            raw_candidate_count = len(candidate_ids)
            candidate_provenance = {identity: "patch_tracker" for identity in tracker}
            candidate_provenance.update({identity: "bm25_embedding_rrf" for identity in fused_ids if identity not in tracker})
            if candidate_limit is not None:
                for identity in tracker:
                    if identity in fused:
                        candidate_provenance[identity] = "patch_tracker+bm25_embedding_rrf"
            if candidate_limit is None:
                # Preserve the historical RQ3 protocol when no experiment-view
                # adapter opts into the paired 100-candidate cap.
                pool = max(100, len(tracker))
                candidate_ids = list(tracker)
                for identity in fused_ids:
                    if identity not in candidate_ids:
                        candidate_ids.append(identity)
                    if len(candidate_ids) >= min(pool, len(functions)):
                        break
            else:
                pool = max(0, int(candidate_limit))
                candidate_ids = list(tracker)[:pool]
                for identity in fused_ids:
                    if identity not in candidate_ids:
                        if len(candidate_ids) >= min(pool, len(functions)):
                            break
                        candidate_ids.append(identity)
                    if len(candidate_ids) >= min(pool, len(functions)):
                        break
            scores = {identity: fused.get(identity, 0.0) for identity in candidate_ids}
            result.metadata.update({"embedding_model": embedding_model, "tracker_candidates": len(tracker), "tracker_adapter": "Python static call/data-symbol graph; no JARVIS"})
            method_label = "VFArCHE-inspired Python patch tracker + BM25/embedding expansion + LLM pairwise ranking (adaptation)"
        else:
            result.runtime_mode = "PATCH_ABSENT"
            lexical = lexical_scores(query, functions)
            dense, embedding_model = semantic_scores(query, functions)
            fused = reciprocal_rank_fusion(lexical, dense)
            raw_candidate_count = len(fused)
            hidden_limit = 100 if candidate_limit is None else max(0, int(candidate_limit))
            candidate_ids = sorted(fused, key=lambda key: (-fused[key], key))[: min(hidden_limit, len(functions))]
            candidate_provenance = {identity: "bm25_embedding_rrf" for identity in candidate_ids}
            scores = {identity: fused[identity] for identity in candidate_ids}
            evidence_source = (
                "description+CWE-expanded query" if candidate_limit is None
                else "description+CWE-expanded query" if case.cwe_ids
                else "CVE description"
            )
            evidence = {identity: {f"selected by BM25/embedding on {evidence_source}"} for identity in candidate_ids}
            result.metadata.update({"embedding_model": embedding_model, "candidate_model": "BM25+embedding RRF adaptation; no CodeBERT checkpoint"})
            method_label = "VFArCHE-inspired patch-absent BM25/embedding selector + LLM pairwise ranking (adaptation; not CodeBERT reproduction)"
        if not candidate_ids:
            raise RuntimeError("candidate selection returned an empty pool")
        candidate_pool_ids = list(candidate_ids)
        candidate_pool_scores = dict(scores)
        pre_rank_details = [
            {"function_id": identity, "qualified_name": by_id[identity].qualname,
             "module_qualified_name": _module_qualified_name(by_id[identity]),
             "file_path": by_id[identity].file_path,
             "score": float(candidate_pool_scores.get(identity, 0.0)),
             "evidence": sorted(evidence.get(identity, set())),
             "candidate_provenance": candidate_provenance.get(identity, "retrieval_pool")}
            for identity in candidate_pool_ids
        ]
        try:
            pairwise_scores, ranking_metadata = _strict_pairwise(
                query, [by_id[item] for item in candidate_ids], scores, evidence,
            )
        except Exception as exc:
            exc.partial_result = {
                "candidate_ids": candidate_pool_ids,
                "candidate_details": pre_rank_details,
                "candidate_count": len(candidate_pool_ids),
                "raw_candidate_count": raw_candidate_count,
            }
            raise
        scores = pairwise_scores
        candidate_ids = sorted(scores, key=lambda key: (-scores[key], key))
        result.metadata["pairwise"] = ranking_metadata

    all_candidate_ids = list(candidate_pool_ids if config_id == "P_DUAL" else candidate_ids)
    result.candidate_ids = all_candidate_ids
    result.candidate_details = [
        {"function_id": identity, "qualified_name": by_id[identity].qualname,
         "module_qualified_name": _module_qualified_name(by_id[identity]),
         "file_path": by_id[identity].file_path,
         "score": float((candidate_pool_scores if config_id == "P_DUAL" else scores).get(identity, 0.0)),
         "evidence": sorted(evidence.get(identity, set())),
         "candidate_provenance": candidate_provenance.get(identity, "ranked_catalog")}
        for identity in all_candidate_ids
    ]
    result.candidate_count = len(all_candidate_ids)
    result.raw_candidate_count = raw_candidate_count if raw_candidate_count is not None else len(all_candidate_ids)
    if config_id == "P_DUAL":
        result.metadata["candidate_generation"] = {
            "raw_candidate_count": result.raw_candidate_count,
            "candidate_count_before_pairwise": result.candidate_count,
            "candidate_limit": int(candidate_limit) if candidate_limit is not None else None,
            "candidate_provenance_counts": dict(Counter(candidate_provenance.get(identity, "retrieval_pool") for identity in all_candidate_ids)),
        }
    result.method_label = method_label
    if result.output_type == SET:
        result.predictions = [
            {"function_id": identity, "qualified_name": by_id[identity].qualname,
             "module_qualified_name": _module_qualified_name(by_id[identity]),
             "file_path": by_id[identity].file_path, "start_line": by_id[identity].start_line,
             "end_line": by_id[identity].end_line, "score": None, "rank": None,
             "evidence": []}
            for identity in candidate_ids
        ]
    else:
        result.predictions = [
            {"function_id": identity, "qualified_name": by_id[identity].qualname,
             "module_qualified_name": _module_qualified_name(by_id[identity]),
             "file_path": by_id[identity].file_path, "start_line": by_id[identity].start_line,
             "end_line": by_id[identity].end_line, "score": float(scores.get(identity, 0.0)),
             "rank": rank, "evidence": sorted(evidence.get(identity, set()))}
            for rank, identity in enumerate(candidate_ids, 1)
        ]
    result.runtime_ms = (time.perf_counter() - started) * 1000
    return result


def _gold_keys(items: Iterable[dict[str, Any] | str]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for item in items:
        if isinstance(item, str):
            if item.strip():
                keys.add(("", item.strip()))
            continue
        file_path = _normal_path(str(item.get("file_path") or item.get("file") or ""))
        for name in _entity_names(item):
            keys.add((file_path, name))
    return keys


def _entity_names(item: dict[str, Any]) -> set[str]:
    return {
        str(item.get(field) or "").strip()
        for field in ("qualified_name", "qualname", "module_qualified_name", "name")
        if str(item.get(field) or "").strip()
    }


def _prediction_matches(prediction: dict[str, Any], gold: set[tuple[str, str]]) -> bool:
    path = _normal_path(str(prediction.get("file_path") or ""))
    return any((path, name) in gold or ("", name) in gold for name in _entity_names(prediction))


def _case_applies_to_treatment(case: RQ3EvaluationCase, treatment: str) -> bool:
    """Return whether the evidence regime makes a case a valid denominator row."""
    if not case.eligible:
        return False
    config = treatment.split("/", 1)[0]
    localizer_input = case.localizer_input
    if config == "P_MODIFIED":
        return localizer_input.patch_available and bool(localizer_input.patch_text.strip())
    if config == "P_DUAL":
        mode = treatment.partition("/")[2]
        if mode == "PATCH_PRESENT":
            return localizer_input.patch_available and bool(localizer_input.patch_text.strip())
        if mode == "PATCH_ABSENT":
            return not localizer_input.patch_available and localizer_input.patch_status != "ADJUDICATED_PATCH_UNAVAILABLE"
        return False
    return config in {"D_LEX", "D_SEM"}


def localization_quality(cases: list[RQ3EvaluationCase], results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One compact row per config; P_MODIFIED is evaluated as a set, never ranked."""
    def treatment(item: dict[str, Any]) -> str:
        config = str(item.get("config_id") or "UNKNOWN")
        return f"P_DUAL/{item.get('runtime_mode') or 'UNKNOWN'}" if config == "P_DUAL" else config

    by_case_config = {
        (str(item.get("case_id")), treatment(item)): item
        for item in results if item.get("status") == "complete"
    }
    configs = sorted({treatment(item) for item in results})
    output = []
    for config in configs:
        applicable = [case for case in cases if _case_applies_to_treatment(case, config)]
        selected = [case for case in applicable
                    if (case.localizer_input.case_id, config) in by_case_config]
        hits = {k: [] for k in (1, 5)}
        recalls = []
        reciprocal_ranks = []
        set_recalls = []
        candidate_recalls = []
        candidate_counts = []
        for case in selected:
            row = by_case_config[(case.localizer_input.case_id, config)]
            gold = _gold_keys(case.verified_vfs)
            if not gold:
                continue
            predictions = row.get("predictions") or []
            # Candidate recall uses the pre-ranking pool, including pairwise
            # candidates which are not retained among the final predictions.
            candidate_details = row.get("candidate_details") or []
            gold_candidate_count = sum(
                any(
                    gold_name in _entity_names(item)
                    and (not gold_path or _normal_path(str(item.get("file_path") or "")) == gold_path)
                    for item in candidate_details
                )
                for gold_path, gold_name in gold
            )
            candidate_recalls.append(gold_candidate_count / len(gold))
            candidate_counts.append(int(row.get("candidate_count") or len(row.get("candidate_ids") or [])))
            if row.get("output_type") == SET:
                hits_in_set = sum(_prediction_matches(item, gold) for item in predictions)
                set_recalls.append(hits_in_set / len(gold))
                continue
            found_ranks = [
                int(item["rank"]) for item in predictions
                if item.get("rank") is not None and _prediction_matches(item, gold)
            ]
            best_rank = min(found_ranks) if found_ranks else None
            for k in hits:
                hits[k].append(bool(best_rank is not None and best_rank <= k))
            top_five = [item for item in predictions if item.get("rank") is not None and int(item["rank"]) <= 5]
            recalls.append(sum(_prediction_matches(item, gold) for item in top_five) / len(gold))
            reciprocal_ranks.append(1 / best_rank if best_rank else 0.0)
        eligible_count = sum(case.eligible for case in cases)
        coverage = len(selected) / len(applicable) if applicable else None
        output.append({
            "config": config,
            "Hit@1": sum(hits[1]) / len(hits[1]) if hits[1] else None,
            "Hit@5": sum(hits[5]) / len(hits[5]) if hits[5] else None,
            "Recall@5": sum(recalls) / len(recalls) if recalls else None,
            "MRR": sum(reciprocal_ranks) / len(reciprocal_ranks) if reciprocal_ranks else None,
            "SetRecall": sum(set_recalls) / len(set_recalls) if set_recalls else None,
            "Coverage": coverage,
            "CandidateRecall": sum(candidate_recalls) / len(candidate_recalls) if candidate_recalls else None,
            "AvgCandidates": sum(candidate_counts) / len(candidate_counts) if candidate_counts else None,
            "eligible_cases": eligible_count,
            "applicable_cases": len(applicable),
            "not_applicable_cases": eligible_count - len(applicable),
            "completed_cases": len(selected),
        })
    return output


def exact_group_join(
    vf_cases: Iterable[dict[str, Any]], downstream_rows: Iterable[dict[str, Any]],
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[dict[str, Any]]]:
    """Join only by literal cve_vf_group_id; no CVE/package fuzzy fallback."""
    by_group: dict[str, dict[str, Any]] = {}
    for case in vf_cases:
        group_id = str(case.get("cve_vf_group_id") or case.get("group_id") or "")
        if not group_id:
            continue
        if group_id in by_group:
            raise ValueError(f"duplicate VF group id in frozen cases: {group_id}")
        by_group[group_id] = case
    joined: list[tuple[dict[str, Any], dict[str, Any]]] = []
    unmatched: list[dict[str, Any]] = []
    for row in downstream_rows:
        key = str(row.get("cve_vf_group_id") or "")
        case = by_group.get(key)
        if case is None:
            unmatched.append(row)
        else:
            joined.append((case, row))
    return joined, unmatched


def downstream_consequence(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare tri-state reachability, excluding UNKNOWN from binary set metrics."""
    paired = [
        (str(row.get("oracle_decision") or "UNKNOWN").upper(), str(row.get("decision") or "UNKNOWN").upper())
        for row in records
    ]
    valid = [(truth, pred) for truth, pred in paired if truth in {"REACHABLE", "UNREACHABLE"} and pred in {"REACHABLE", "UNREACHABLE"}]
    tp = sum(truth == pred == "REACHABLE" for truth, pred in valid)
    fp = sum(truth == "UNREACHABLE" and pred == "REACHABLE" for truth, pred in valid)
    fn = sum(truth == "REACHABLE" and pred == "UNREACHABLE" for truth, pred in valid)
    truth_positive = sum(truth == "REACHABLE" for truth, _ in valid)
    pred_positive = sum(pred == "REACHABLE" for _, pred in valid)
    intersection = tp
    union = truth_positive + pred_positive - intersection
    unknown = sum(truth == "UNKNOWN" or pred == "UNKNOWN" for truth, pred in paired)
    ratio = lambda n, d: n / d if d else None
    return {
        "compared": len(paired),
        "decisive": len(valid),
        "coverage": ratio(len(valid), len(paired)),
        "downstream_precision": ratio(tp, tp + fp),
        "downstream_recall": ratio(tp, tp + fn),
        "jaccard": intersection / union if union else (1.0 if valid else None),
        "flip_rate": ratio(fp + fn, len(valid)),
        "fp_flip": fp,
        "fn_flip": fn,
        "unknown": unknown,
        "decision_invariant": sum(truth == pred for truth, pred in valid),
    }


def error_propagation(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter()
    for row in records:
        truth = str(row.get("oracle_decision") or "UNKNOWN").upper()
        pred = str(row.get("decision") or "UNKNOWN").upper()
        if truth not in {"REACHABLE", "UNREACHABLE"} or pred not in {"REACHABLE", "UNREACHABLE"}:
            counts["UNKNOWN"] += 1
        elif truth == pred:
            counts["decision_invariant"] += 1
        elif truth == "UNREACHABLE" and pred == "REACHABLE":
            counts["FP_flip"] += 1
        else:
            counts["FN_flip"] += 1
    return {key: counts[key] for key in ("decision_invariant", "FP_flip", "FN_flip", "UNKNOWN")}


def bind_localized_names(
    package_id: str, result: dict[str, Any], bindings: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Convert source names to VFAnchors while retaining every failed binding."""
    anchors, audit = [], []
    for prediction in result.get("predictions") or []:
        name = str(prediction.get("module_qualified_name") or prediction.get("qualified_name") or "")
        bound = bindings.get(name) or {}
        status = str(bound.get("status") or "UNKNOWN_VF_MISMATCH")
        audit.append({"qualified_name": name, "source_qualified_name": str(prediction.get("qualified_name") or ""), "status": status})
        if status != "BOUND":
            continue
        anchors.append({
            "package_id": package_id,
            "module": str(bound.get("module") or ""),
            "qualified_name": name,
            "file": str(bound.get("file") or prediction.get("file_path") or ""),
            "start_line": int(bound.get("start_line") or prediction.get("start_line") or 0),
            "end_line": int(bound.get("end_line") or prediction.get("end_line") or 0),
            "function_hash": str(bound.get("function_hash") or ""),
            "provenance": str(result.get("config_id") or "rq3"),
        })
    return anchors, audit


def build_rq3_vf_variants(
    cases_path: Path,
    localization_results_path: Path | list[Path],
    downstream_path: Path,
    dataset_dir: Path,
    output: Path,
    *,
    budgets: tuple[int, ...] = (1, 5),
    limit: int = 0,
    resume: bool = True,
    probe: Callable[[str, list[dict[str, str]]], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Bind exact-group localization outputs into manifests consumable by eval vf.

    The backend probe is performed only against the frozen installed package
    environment. Binding records are checkpointed per query/config/budget;
    patch-derived sets retain their single ``All`` budget.
    """
    from packaging.utils import canonicalize_name
    from f_vra.evaluation.io import read_json, read_parquet, write_parquet

    case_rows = _jsonl(cases_path)
    localization_paths = localization_results_path if isinstance(localization_results_path, list) else [localization_results_path]
    localization_rows = [row for path in localization_paths for row in _jsonl(path)]
    downstream_rows = _jsonl(downstream_path)
    if limit > 0:
        downstream_rows = downstream_rows[:limit]
    dataset_meta = read_json(dataset_dir / "dataset.json")
    queries = read_parquet(dataset_dir / "queries.parquet")
    packages = {str(row["package_id"]): row for row in read_parquet(dataset_dir / "packages.parquet")}
    environments = {str(row["env_id"]): row for row in read_parquet(dataset_dir / "environments.parquet")}
    by_query_key: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for query in queries:
        package = packages.get(str(query.get("affected_package_id") or ""), {})
        distribution = str(query.get("affected_distribution") or package.get("distribution") or "")
        key = (str(query.get("project_id") or ""), str(query.get("cve_id") or ""), canonicalize_name(distribution))
        by_query_key[key].append(query)
    results_by_case: dict[str, dict[str, Any]] = {}
    for row in localization_rows:
        if row.get("config_id") in RQ3_CONFIGS:
            results_by_case.setdefault(str(row.get("case_id") or ""), {})[str(row["config_id"])] = row
    joined, unmatched = exact_group_join(case_rows, downstream_rows)
    work: dict[tuple[str, str], dict[str, Any]] = {}
    query_audit = []
    for case_row, downstream_row in joined:
        group_id = str(case_row.get("cve_vf_group_id") or case_row.get("group_id") or "")
        project = downstream_row.get("project") or {}
        project_id = str(project.get("repo") or downstream_row.get("project_id") or "")
        cve_id = str(downstream_row.get("cve_id") or case_row.get("cve_id") or "")
        distribution = canonicalize_name(str(case_row.get("package") or case_row.get("package_name") or ""))
        matches = by_query_key.get((project_id, cve_id, distribution), [])
        if len(matches) != 1:
            query_audit.append({
                "cve_vf_group_id": group_id, "project_id": project_id, "cve_id": cve_id,
                "status": "NO_EXACT_QUERY_MATCH" if not matches else "AMBIGUOUS_QUERY_MATCH",
            })
            continue
        query = matches[0]
        case_id = str(case_row.get("case_id") or group_id)
        for config_id, localized in results_by_case.get(case_id, {}).items():
            mode = str(localized.get("runtime_mode") or "DEFAULT")
            method_variant = config_id if config_id != "P_DUAL" else f"P_DUAL_{mode}"
            if config_id == "P_MODIFIED":
                budget_specs: list[tuple[str, list[dict[str, Any]]]] = [("All", localized.get("predictions") or [])]
            else:
                budget_specs = [
                    (str(top_k), (localized.get("predictions") or [])[:top_k])
                    for top_k in budgets
                ]
            for budget, predictions in budget_specs:
                variant = f"{method_variant}_TOP{budget}"
                key = (str(query["query_id"]), variant)
                work[key] = {
                    "query": query, "group_id": group_id, "config_id": config_id,
                    "runtime_mode": mode, "budget": budget, "variant": variant,
                    "distribution": distribution,
                    "predictions": predictions,
                    "localization_status": str(localized.get("status") or "failed"),
                    "package_id": str(query.get("affected_package_id") or ""),
                    "env_id": str(query.get("env_id") or ""),
                }
    input_hashes = {
        "cases": _sha256(cases_path.read_bytes()),
        "localization_results": [_sha256(path.read_bytes()) for path in localization_paths],
        "downstream": _sha256(downstream_path.read_bytes()),
        "dataset_id": str(dataset_meta.get("dataset_id") or ""),
        "budgets": list(budgets), "limit": limit,
        "builder_sha256": _sha256(Path(__file__).read_bytes()),
    }
    binding_fingerprint = _sha256(json.dumps(input_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    checkpoint_dir = output.parent / f".rq3-binding-{binding_fingerprint[:16]}"
    checkpoint_path = checkpoint_dir / "binding_checkpoints.jsonl"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    bound_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    if resume and checkpoint_path.is_file():
        for item in _jsonl(checkpoint_path):
            if item.get("fingerprint") != binding_fingerprint:
                continue
            key = (str(item.get("query_id") or ""), str(item.get("variant") or ""))
            if item.get("execution_status") == "COMPLETE":
                bound_by_key[key] = item
            else:
                bound_by_key.pop(key, None)
    pending_by_env: dict[str, list[tuple[tuple[str, str], dict[str, Any]]]] = defaultdict(list)
    for key, item in work.items():
        if key in bound_by_key:
            continue
        if item["localization_status"] != "complete":
            record = {
                "query_id": key[0], "variant": key[1], "fingerprint": binding_fingerprint,
                "execution_status": "COMPLETE", "status": "LOCALIZATION_FAILED",
                "vf_set": [], "binding_audit": [],
            }
            _append_jsonl(checkpoint_path, record)
            bound_by_key[key] = record
        elif not item["predictions"]:
            record = {
                "query_id": key[0], "variant": key[1], "fingerprint": binding_fingerprint,
                "execution_status": "COMPLETE", "status": "EMPTY_CANDIDATE_SET",
                "vf_set": [], "binding_audit": [],
            }
            _append_jsonl(checkpoint_path, record)
            bound_by_key[key] = record
        else:
            pending_by_env[item["env_id"]].append((key, item))
    if probe is None:
        from f_vra.evaluation.vf import _probe_env

        probe = lambda image, requests: _probe_env(image, requests)
    for env_id, env_items in tqdm(sorted(pending_by_env.items()), desc="RQ3 binding environments"):
        requests = []
        seen = set()
        for _key, item in env_items:
            for prediction in item["predictions"]:
                name = str(prediction.get("module_qualified_name") or prediction.get("qualified_name") or "")
                request_key = (item["distribution"], name)
                if name and request_key not in seen:
                    requests.append({"distribution": request_key[0], "qualified_name": request_key[1]})
                    seen.add(request_key)
        try:
            probed = probe(str(environments[env_id]["docker_image_digest"]), requests)
            probe_error = ""
        except Exception as exc:
            probed = {"anchors": {}}
            probe_error = f"{type(exc).__name__}: {exc}"
        for key, item in tqdm(env_items, desc=f"Bind {env_id}", leave=False):
            if probe_error:
                audit = [{"qualified_name": str(prediction.get("module_qualified_name") or prediction.get("qualified_name") or ""),
                          "source_qualified_name": str(prediction.get("qualified_name") or ""),
                          "status": "BINDING_PROBE_FAILED", "error": probe_error}
                         for prediction in item["predictions"]]
                anchors = []
                status = "BINDING_PROBE_FAILED"
            else:
                name_bindings = {
                    str(prediction.get("module_qualified_name") or prediction.get("qualified_name") or ""): probed.get("anchors", {}).get(
                        item["distribution"] + "|" + str(prediction.get("module_qualified_name") or prediction.get("qualified_name") or ""), {}
                    )
                    for prediction in item["predictions"]
                }
                anchors, audit = bind_localized_names(item["package_id"], {
                    "config_id": item["config_id"], "predictions": item["predictions"],
                }, name_bindings)
                status = "BOUND" if anchors and len(anchors) == len(audit) else "UNKNOWN_VF_MISMATCH"
            record = {
                "query_id": key[0], "variant": key[1], "fingerprint": binding_fingerprint,
                "execution_status": "FAILED" if probe_error else "COMPLETE", "status": status,
                "vf_set": anchors, "binding_audit": audit,
            }
            _append_jsonl(checkpoint_path, record)
            bound_by_key[key] = record
    variant_rows = []
    binding_audit = []
    for key, item in sorted(work.items()):
        record = bound_by_key.get(key) or {
            "status": "BINDING_NOT_RUN", "vf_set": [], "binding_audit": [],
        }
        variant_rows.append({"query_id": key[0], "variant": key[1], "vf_set": record.get("vf_set") or []})
        binding_audit.append({
            "query_id": key[0], "cve_vf_group_id": item["group_id"],
            "project_id": str(item["query"].get("project_id") or ""),
            "cve_id": str(item["query"].get("cve_id") or ""),
            "variant": key[1],
            "config_id": item["config_id"], "runtime_mode": item["runtime_mode"],
            "top_k": item["budget"], "status": record.get("status"),
            "requested": len(item["predictions"]), "bound": len(record.get("vf_set") or []),
            "binding_statuses": record.get("binding_audit") or [],
        })
    write_parquet(output, variant_rows)
    audit_path = output.with_name(output.stem + "_binding_audit.parquet")
    write_parquet(audit_path, binding_audit)
    summary = {
        "binding_fingerprint": binding_fingerprint, "dataset_id": dataset_meta.get("dataset_id"),
        "exact_group_joins": len(joined), "unmatched_downstream_rows": len(unmatched),
        "query_join_failures": len(query_audit), "variants": len(variant_rows),
        "binding_failures": sum(row["status"] != "BOUND" for row in binding_audit),
        "cases_path": str(cases_path),
        "freeze_summary_path": str(cases_path.with_name(f"{cases_path.stem}.summary.json")),
        "manifest": str(output), "audit": str(audit_path),
        "checkpoints": str(checkpoint_path), "resumed_records": len(bound_by_key),
        "query_audit": query_audit,
    }
    write_json(output.with_suffix(".summary.json"), summary)
    write_json(output.with_name(output.stem + "_binding_summary.json"), summary)
    return summary


def pair_rq3_downstream_runs(
    binding_audit_path: Path,
    downstream_benchmark_path: Path,
    run_dirs: list[Path],
    output: Path,
) -> dict[str, Any]:
    """Pair exact-group localization treatments with frozen downstream outcomes."""
    import yaml
    from f_vra.evaluation.io import read_parquet, write_parquet

    bindings = read_parquet(binding_audit_path)
    downstream = _jsonl(downstream_benchmark_path)
    cases = [{"cve_vf_group_id": group} for group in sorted({
        str(row.get("cve_vf_group_id") or "") for row in bindings if row.get("cve_vf_group_id")
    })]
    exact_joined, unmatched = exact_group_join(cases, downstream)
    oracle_by_key: dict[tuple[str, str, str], str] = {}
    for case, row in exact_joined:
        project = row.get("project") or {}
        key = (
            str(case["cve_vf_group_id"]),
            str(project.get("repo") or row.get("project_id") or ""),
            str(row.get("cve_id") or ""),
        )
        raw_truth = (row.get("ground_truth") or {}).get("reachable")
        if raw_truth is True or str(raw_truth).lower() == "true":
            truth = "REACHABLE"
        elif raw_truth is False or str(raw_truth).lower() == "false":
            truth = "UNREACHABLE"
        else:
            truth = "UNKNOWN"
        if key in oracle_by_key and oracle_by_key[key] != truth:
            raise ValueError(f"conflicting downstream oracle labels for exact key {key}")
        oracle_by_key[key] = truth
    binding_by_key = {
        (str(row.get("query_id") or ""), str(row.get("variant") or "")): row
        for row in bindings
    }
    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    unmatched_results = 0
    for run_dir in run_dirs:
        config_path = run_dir / "config.yaml"
        result_path = run_dir / "query_results.parquet"
        if not config_path.is_file() or not result_path.is_file():
            raise FileNotFoundError(f"expected config.yaml and query_results.parquet in {run_dir}")
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        variant = str(config.get("run_label") or "")
        if not variant:
            raise ValueError(f"evaluation run has no run_label: {run_dir}")
        for result in read_parquet(result_path):
            query_id = str(result.get("query_id") or "")
            binding = binding_by_key.get((query_id, variant))
            if binding is None:
                unmatched_results += 1
                continue
            group_id = str(binding.get("cve_vf_group_id") or "")
            project_id = str(binding.get("project_id") or "")
            cve_id = str(binding.get("cve_id") or "")
            truth = oracle_by_key.get((group_id, project_id, cve_id))
            if truth is None:
                unmatched_results += 1
                continue
            config_id = str(binding.get("config_id") or "UNKNOWN")
            mode = str(binding.get("runtime_mode") or "DEFAULT")
            display_config = f"{config_id}/{mode}" if config_id == "P_DUAL" else config_id
            key = (query_id, variant)
            if key in pairs:
                raise ValueError(f"duplicate evaluation result for query/variant {key}; pass one run per variant")
            pairs[key] = {
                "query_id": query_id, "cve_vf_group_id": group_id,
                "project_id": project_id, "config_id": display_config,
                "variant": variant, "top_k": str(binding.get("top_k") or "All"),
                "oracle_decision": truth,
                "decision": str(result.get("decision") or "UNKNOWN"),
                "execution_status": str(result.get("execution_status") or "COMPLETE"),
            }
    expected_keys = {
        (str(row.get("query_id") or ""), str(row.get("variant") or ""))
        for row in bindings
        if (str(row.get("cve_vf_group_id") or ""), str(row.get("project_id") or ""), str(row.get("cve_id") or "")) in oracle_by_key
    }
    missing_results = len(expected_keys - pairs.keys())
    output.parent.mkdir(parents=True, exist_ok=True)
    write_parquet(output, pairs.values())
    summary = {
        "paired_rows": len(pairs), "exact_group_rows": len(exact_joined),
        "unmatched_downstream_group_rows": len(unmatched),
        "unmatched_or_unlabeled_results": unmatched_results,
        "expected_results_missing": missing_results,
        "output": str(output), "binding_audit": str(binding_audit_path),
        "run_dirs": [str(path) for path in run_dirs],
    }
    write_json(output.with_suffix(".summary.json"), summary)
    return summary


def _fingerprint(case_rows: list[dict[str, Any]], config_id: str, limit: int | None) -> tuple[str, str]:
    from f_vra.core.config import settings

    try:
        code_version = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        code_version = "working-tree"
    package_root = Path(__file__).resolve().parents[1]
    code_files = [
        Path(__file__).resolve(),
        package_root / "localization" / "retrieval" / "tvsm.py",
        package_root / "localization" / "retrieval" / "description.py",
        package_root / "localization" / "retrieval" / "embedding.py",
        package_root / "localization" / "retrieval" / "candidates.py",
        package_root / "localization" / "retrieval" / "bm25.py",
        package_root / "localization" / "retrieval" / "expansion.py",
        package_root / "localization" / "ranking" / "methods" / "description.py",
        package_root / "localization" / "ranking" / "methods" / "pairwise.py",
        package_root / "localization" / "providers" / "llm_client.py",
        package_root / "localization" / "code" / "function_parser.py",
        package_root / "localization" / "code" / "tracker.py",
        package_root / "localization" / "sources" / "patch.py",
    ]
    code_hashes = {path.relative_to(package_root).as_posix(): _sha256(path.read_bytes()) for path in code_files if path.is_file()}
    snapshot_hashes: dict[str, str] = {}
    for index, row in enumerate(case_rows):
        case_id = str(row.get("case_id") or row.get("group_id") or row.get("cve_vf_group_id") or index)
        source_value = str(row.get("source_path") or "").strip()
        path = Path(source_value) if source_value else None
        declared = str(row.get("snapshot_id") or row.get("source_snapshot_hash") or "")
        content = str(
            row.get("source_content_sha256") or row.get("source_artifact_sha256")
            or row.get("source_revision_sha") or ""
        )
        if not content and path is not None and path.is_dir():
            content = source_tree_hash(path)
        snapshot_hashes[case_id] = f"{declared}:{content}" if declared else content or "MISSING"
    input_hash = _sha256(json.dumps(
        {"cases": case_rows, "source_snapshots": snapshot_hashes},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8"))
    config = {
        "config_id": config_id, "limit": limit, "input_hash": input_hash,
        "code_version": code_version, "code_hashes": code_hashes,
        "prompt_version": PROMPT_VERSION,
        "llm_model": settings.llm_model,
        "embedding_model": settings.embedding_model,
        "embedding_batch_size": settings.embedding_batch_size,
        "embedding_max_workers": settings.embedding_max_workers,
        "llm_endpoint": settings.local_llm_base_url,
        "embedding_endpoint": settings.embedding_base_url,
    }
    value = _sha256(json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return value, input_hash


def run_localization_batch(
    cases_path: Path,
    config_id: str,
    output_root: Path,
    *,
    limit: int = 0,
    resume: bool = True,
    resume_from_summary: Path | None = None,
    resume_from_checkpoint: Path | None = None,
    localizer: Callable[..., RQ3LocalizationResult] = localize_case,
    progress: bool = True,
) -> dict[str, Any]:
    """Durable per-case run; matching successful cases are reused on restart."""
    from f_vra.core.config import settings

    if config_id not in RQ3_CONFIGS:
        raise ValueError(f"unsupported config {config_id}")
    raw_rows = _jsonl(cases_path)
    if limit > 0:
        raw_rows = raw_rows[:limit]
    case_ids = [str(row.get("case_id") or row.get("group_id") or row.get("cve_vf_group_id") or "") for row in raw_rows]
    if any(not value for value in case_ids) or len(case_ids) != len(set(case_ids)):
        raise ValueError("case manifest must contain unique, non-empty case_id values")
    calculated_fingerprint, input_hash = _fingerprint(raw_rows, config_id, limit or None)
    run_fingerprint = calculated_fingerprint
    run_id = f"rq3-{config_id.lower()}-{run_fingerprint[:16]}"
    compatibility_resume: dict[str, Any] | None = None
    summary_path: Path | None = None
    if resume_from_summary is not None and resume_from_checkpoint is not None:
        raise ValueError("choose either a prior summary or a partial checkpoint, not both")
    if resume_from_summary is not None:
        if not resume:
            raise ValueError("--resume-from-summary requires resume to be enabled")
        summary_path = resume_from_summary.resolve()
        try:
            previous_summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"cannot read prior RQ3 summary {summary_path}: {exc}") from exc
        output_root_resolved = output_root.resolve()
        if not summary_path.parent.resolve().is_relative_to(output_root_resolved):
            raise ValueError("prior summary must be inside the selected output root")
        previous_run_id = str(previous_summary.get("run_id") or "")
        previous_fingerprint = str(previous_summary.get("run_fingerprint") or "")
        if previous_summary.get("config_id") != config_id:
            raise ValueError("prior summary belongs to a different RQ3 configuration")
        if previous_summary.get("dataset_hash") != input_hash:
            raise ValueError("prior summary was created from a different frozen case manifest")
        if int(previous_summary.get("case_count") or 0) != len(raw_rows):
            raise ValueError("prior summary has a different case count; cannot compatibility-resume")
        if (
            not previous_fingerprint
            or previous_run_id != f"rq3-{config_id.lower()}-{previous_fingerprint[:16]}"
        ):
            raise ValueError("prior summary has an invalid run ID/fingerprint pair")
        if summary_path.parent.name != previous_run_id:
            raise ValueError("prior summary path does not match its run ID")
        if not (summary_path.parent / "case_results.jsonl").is_file():
            raise ValueError("prior summary has no case_results.jsonl checkpoint")
        run_fingerprint = previous_fingerprint
        run_id = previous_run_id
        compatibility_resume = {
            "source_run_id": previous_run_id,
            "source_summary": str(summary_path),
            "current_code_fingerprint": calculated_fingerprint,
            "prior_embedding_batch_size": previous_summary.get("embedding_batch_size", 16),
            "prior_embedding_max_workers": previous_summary.get("embedding_max_workers", 1),
            "current_embedding_batch_size": settings.embedding_batch_size,
            "current_embedding_max_workers": settings.embedding_max_workers,
            "mixed_execution_settings": (
                previous_summary.get("embedding_batch_size", 16) != settings.embedding_batch_size
                or previous_summary.get("embedding_max_workers", 1) != settings.embedding_max_workers
                or previous_summary.get("compatibility_resume") is not None
            ),
            "dataset_and_model_name_validation": "required; recorded model mismatches are rejected",
        }
        if previous_summary.get("compatibility_resume"):
            compatibility_resume.update(previous_summary["compatibility_resume"])
            compatibility_resume.update({
                "source_run_id": previous_run_id,
                "source_summary": str(summary_path),
                "current_code_fingerprint": calculated_fingerprint,
                "current_embedding_batch_size": settings.embedding_batch_size,
                "current_embedding_max_workers": settings.embedding_max_workers,
                "mixed_execution_settings": True,
            })
    elif resume_from_checkpoint is not None:
        if not resume:
            raise ValueError("--resume-from-checkpoint requires resume to be enabled")
        checkpoint_dir = resume_from_checkpoint.resolve()
        output_root_resolved = output_root.resolve()
        if checkpoint_dir == output_root_resolved or not checkpoint_dir.is_relative_to(output_root_resolved):
            raise ValueError("partial checkpoint must be inside the selected output root")
        checkpoint_path = checkpoint_dir / "case_results.jsonl"
        if not checkpoint_path.is_file():
            raise ValueError(f"partial checkpoint has no case_results.jsonl: {checkpoint_path}")
        checkpoint_rows = _jsonl(checkpoint_path)
        checkpoint_fingerprints = {str(row.get("run_fingerprint") or "") for row in checkpoint_rows}
        if len(checkpoint_fingerprints) != 1 or not next(iter(checkpoint_fingerprints)):
            raise ValueError("partial checkpoint must contain rows from exactly one fingerprint")
        previous_fingerprint = next(iter(checkpoint_fingerprints))
        previous_run_id = f"rq3-{config_id.lower()}-{previous_fingerprint[:16]}"
        if checkpoint_dir.name != previous_run_id:
            raise ValueError("partial checkpoint directory does not match its config and run fingerprint")
        if any(str(row.get("config_id") or "") != config_id for row in checkpoint_rows):
            raise ValueError("partial checkpoint contains a different RQ3 configuration")
        checkpoint_case_ids = {str(row.get("case_id") or "") for row in checkpoint_rows}
        if not checkpoint_case_ids.issubset(set(case_ids)):
            raise ValueError("partial checkpoint contains cases absent from the current frozen manifest")
        prior_execution_settings = sorted({
            (
                (row.get("metadata") or {}).get("embedding_execution", {}).get("batch_size"),
                (row.get("metadata") or {}).get("embedding_execution", {}).get("max_workers"),
            )
            for row in checkpoint_rows
            if row.get("status") == "complete"
            and (row.get("metadata") or {}).get("embedding_execution")
        }, key=lambda pair: (pair[0] is None, pair[0] or 0, pair[1] or 0))
        if any(
            batch_size is None or max_workers is None or int(batch_size) < 1 or int(max_workers) < 1
            for batch_size, max_workers in prior_execution_settings
        ):
            raise ValueError("partial checkpoint has invalid recorded embedding settings")
        prior_batch_size, prior_max_workers = (
            prior_execution_settings[0] if prior_execution_settings else (None, None)
        )
        run_fingerprint = previous_fingerprint
        run_id = previous_run_id
        compatibility_resume = {
            "source_run_id": previous_run_id,
            "source_checkpoint": str(checkpoint_dir),
            "current_code_fingerprint": calculated_fingerprint,
            "prior_embedding_batch_size": prior_batch_size,
            "prior_embedding_max_workers": prior_max_workers,
            "prior_execution_settings": [
                {"batch_size": batch_size, "max_workers": max_workers}
                for batch_size, max_workers in prior_execution_settings
            ],
            "current_embedding_batch_size": settings.embedding_batch_size,
            "current_embedding_max_workers": settings.embedding_max_workers,
            "mixed_execution_settings": (
                len(prior_execution_settings) > 1
                or prior_batch_size != settings.embedding_batch_size
                or prior_max_workers != settings.embedding_max_workers
            ),
            "dataset_and_model_validation": (
                "frozen manifest hash, case IDs, per-case source fingerprints, and recorded model names"
            ),
        }
    run_dir = (
        resume_from_summary.resolve().parent if resume_from_summary is not None
        else resume_from_checkpoint.resolve() if resume_from_checkpoint is not None
        else output_root / run_id
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    result_path = run_dir / "case_results.jsonl"
    progress_path = run_dir / "progress.jsonl"
    existing: dict[str, dict[str, Any]] = {}
    if resume and result_path.exists():
        checkpoint_bar = tqdm(
            total=result_path.stat().st_size, desc="Loading RQ3 checkpoint",
            unit="B", unit_scale=True, unit_divisor=1024, disable=not progress,
        )
        try:
            with result_path.open("rb") as handle:
                for line in handle:
                    checkpoint_bar.update(len(line))
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    if row.get("run_fingerprint") == run_fingerprint:
                        metadata = row.get("metadata") or {}
                        if row.get("status") == "complete" and config_id == "D_SEM":
                            recorded_models = {
                                "extractor_model": settings.llm_model,
                                "retrieval_model": settings.embedding_model,
                            }
                            for field_name, expected_model in recorded_models.items():
                                recorded_model = str(metadata.get(field_name) or "")
                                if recorded_model and expected_model and recorded_model != expected_model:
                                    raise ValueError(
                                        f"prior checkpoint {field_name}={recorded_model!r} does not match "
                                        f"current model {expected_model!r}"
                                    )
                        existing[str(row.get("case_id"))] = row
        finally:
            checkpoint_bar.close()
    reused_completed_before_execution = sum(
        row.get("status") == "complete" for row in existing.values()
    )
    done_count = sum(
        row.get("status") in {"complete", "ineligible", "not_applicable"}
        for row in existing.values()
    )
    parsed = [parse_case(row) for row in raw_rows]
    bar = tqdm(parsed, desc=f"RQ3 {config_id}", disable=not progress)
    for evaluation_case in bar:
        case = evaluation_case.localizer_input
        case_fingerprint = _sha256(json.dumps(
            {"run": run_fingerprint, "case_id": case.case_id, "snapshot": case.snapshot_id,
             "source_content_sha256": case.source_content_sha256,
             "source_revision_sha": case.source_revision_sha,
             "source_tree_hash": (
                 source_tree_hash(case.source_path)
                 if case.source_path.is_dir() and not case.source_content_sha256 and not case.source_revision_sha
                 else ""
             ),
             "source_path": str(case.source_path)},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8"))
        previous = existing.get(case.case_id)
        if previous and previous.get("status") in {"complete", "ineligible", "not_applicable"} and previous.get("fingerprint") == case_fingerprint:
            continue
        if not evaluation_case.eligible:
            row = RQ3LocalizationResult(
                case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id,
                config_id=config_id, runtime_mode="NOT_RUN", output_type=SET if config_id == "P_MODIFIED" else RANKED,
                status="ineligible", fingerprint=case_fingerprint,
                error=evaluation_case.ineligible_reason or "case rejected by frozen audit",
            ).to_dict()
        elif config_id == "P_DUAL" and case.patch_status == "ADJUDICATED_PATCH_UNAVAILABLE":
            row = RQ3LocalizationResult(
                case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id,
                config_id=config_id, runtime_mode="PATCH_UNAVAILABLE", output_type=RANKED,
                status="not_applicable", fingerprint=case_fingerprint,
                error="canonical patch mapping was adjudicated unavailable; this is not treated as PATCH_ABSENT",
            ).to_dict()
        elif config_id == "P_MODIFIED" and (not case.patch_available or not case.patch_text.strip()):
            row = RQ3LocalizationResult(
                case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id,
                config_id=config_id, runtime_mode="NOT_APPLICABLE", output_type=SET,
                status="not_applicable", fingerprint=case_fingerprint,
                error="P_MODIFIED requires a frozen fixing patch; use P_DUAL/PATCH_ABSENT for patch-absent cases",
            ).to_dict()
        else:
            from f_vra.localization.providers.llm_client import track_provider_usage

            try:
                # This typed object contains no gold VF field by construction.
                with track_provider_usage() as provider_usage:
                    localized = localizer(case, config_id, inventory_cache=output_root / "inventory_cache")
                localized.metadata["provider_usage"] = provider_usage.to_dict()
                if config_id in {"D_SEM", "P_DUAL"}:
                    localized.metadata["embedding_execution"] = {
                        "batch_size": settings.embedding_batch_size,
                        "max_workers": settings.embedding_max_workers,
                    }
                localized.fingerprint = case_fingerprint
                row = localized.to_dict()
            except Exception as exc:  # Persist and continue; never change method on failure.
                mode = "PATCH_PRESENT" if config_id == "P_DUAL" and case.patch_available else (
                    "PATCH_ABSENT" if config_id == "P_DUAL" else "DEFAULT"
                )
                row = RQ3LocalizationResult(
                    case_id=case.case_id, cve_vf_group_id=case.cve_vf_group_id,
                    config_id=config_id, runtime_mode=mode,
                    output_type=SET if config_id == "P_MODIFIED" else RANKED,
                    status="failed", fingerprint=case_fingerprint,
                    error=f"{type(exc).__name__}: {exc}",
                ).to_dict()
                row["metadata"] = {
                    "provider_usage": provider_usage.to_dict(),
                }
                if config_id in {"D_SEM", "P_DUAL"}:
                    row["metadata"]["embedding_execution"] = {
                        "batch_size": settings.embedding_batch_size,
                        "max_workers": settings.embedding_max_workers,
                    }
        row["run_fingerprint"] = run_fingerprint
        _append_jsonl(result_path, row)
        _append_jsonl(progress_path, {
            "case_id": case.case_id, "config_id": config_id, "status": row["status"],
            "fingerprint": case_fingerprint, "completed_at_unix": time.time(),
        })
        previous_status = (existing.get(case.case_id) or {}).get("status")
        existing[case.case_id] = row
        if (
            row["status"] in {"complete", "ineligible", "not_applicable"}
            and previous_status not in {"complete", "ineligible", "not_applicable"}
        ):
            done_count += 1
        bar.set_postfix(status=row["status"], done=done_count)
    all_results = [existing.get(case.localizer_input.case_id) for case in parsed]
    all_results = [row for row in all_results if row is not None]
    table = localization_quality(parsed, all_results)
    summary = {
        "run_id": run_id, "run_fingerprint": run_fingerprint,
        "dataset_hash": input_hash, "config_id": config_id,
        "case_count": len(parsed),
        "completed": sum(row.get("status") == "complete" for row in all_results),
        "failed": sum(row.get("status") == "failed" for row in all_results),
        "ineligible": sum(row.get("status") == "ineligible" for row in all_results),
        "not_applicable": sum(row.get("status") == "not_applicable" for row in all_results),
        "localization_quality": table,
        "results": str(result_path), "progress_log": str(progress_path),
        "embedding_cache": str(output_root / "embedding_cache.sqlite"),
        "embedding_batch_size": settings.embedding_batch_size,
        "embedding_max_workers": settings.embedding_max_workers,
        "embedding_settings_scope": "newly processed cases" if compatibility_resume else "all cases in this run",
        "resume_enabled": resume,
    }
    if compatibility_resume is not None:
        compatibility_resume["reused_completed_cases"] = reused_completed_before_execution
        summary["compatibility_resume"] = compatibility_resume
        previous_summary_backup = run_dir / "summary.before_compatibility_resume.json"
        if resume_from_summary is not None and not previous_summary_backup.exists() and summary_path and summary_path.exists():
            shutil.copy2(summary_path, previous_summary_backup)
    write_json(run_dir / "summary.json", summary)
    write_json(run_dir / "localization_quality.json", table)
    return summary


STRONG_EVIDENCE = {"patch_verified", "poc_verified", "advisory_explicit"}
REJECTED_MAPPING_TYPES = {"ambiguous", "patch_variant_duplicate"}


def audit_rq3_benchmark(benchmark: Path, downstream: Path | None = None) -> dict[str, Any]:
    """Offline acceptance/overlap audit; does not resolve metadata or clone repos."""
    rows = _jsonl(benchmark)
    accepted = [
        row for row in rows
        if str(row.get("ground_truth_evidence") or "") in STRONG_EVIDENCE
        and str(row.get("mapping_type") or "") not in REJECTED_MAPPING_TYPES
    ]
    groups = {str(row.get("group_id") or "") for row in accepted if row.get("group_id")}
    downstream_rows = _jsonl(downstream) if downstream and downstream.exists() else []
    downstream_groups = {str(row.get("cve_vf_group_id") or "") for row in downstream_rows}
    canon_parents = []
    for row in rows:
        if str(row.get("vulnerable_ref") or "").strip():
            continue
        parents = sorted({str(item.get("parent_sha") or "") for item in row.get("patches") or []
                          if item.get("role") == "canonical_fix" and item.get("parent_sha")})
        canon_parents.append({"group_id": row.get("group_id"), "unique_canonical_parent": parents[0] if len(parents) == 1 else None,
                             "status": "RESOLVABLE" if len(parents) == 1 else "INELIGIBLE_AMBIGUOUS_FIX_PARENT"})
    return {
        "raw_rows": len(rows), "accepted_rows": len(accepted),
        "rejected_by_evidence": sum(str(row.get("ground_truth_evidence") or "") not in STRONG_EVIDENCE for row in rows),
        "rejected_by_mapping": sum(str(row.get("mapping_type") or "") in REJECTED_MAPPING_TYPES for row in rows),
        "accepted_groups": len(groups), "rows_missing_vulnerable_ref": len(canon_parents),
        "missing_ref_resolution": canon_parents,
        "accepted_groups_overlapping_downstream": len(groups & downstream_groups),
        "downstream_rows": len(downstream_rows),
        "downstream_rows_matched_exact_group": sum(str(row.get("cve_vf_group_id") or "") in groups for row in downstream_rows),
        "downstream_rows_unmatched_exact_group": sum(str(row.get("cve_vf_group_id") or "") not in groups for row in downstream_rows),
        "cwe_fields_in_raw": sum(bool(row.get("cwe_id") or row.get("cwe_ids")) for row in rows),
        "requires_cwe_resolution": not any(row.get("cwe_id") or row.get("cwe_ids") for row in rows),
        "full_batch_started": False,
    }


def _cwe_from_osv(raw: dict[str, Any]) -> list[str]:
    values: set[str] = set()
    specific = raw.get("database_specific") or {}
    for value in specific.get("cwe_ids") or []:
        text = str(value).upper()
        if text.startswith("CWE-"):
            values.add(text)
    for key in ("cwe", "cwe_id"):
        text = str(specific.get(key) or "").upper()
        if text.startswith("CWE-"):
            values.add(text)
    for affected in raw.get("affected") or []:
        ecosystem = affected.get("ecosystem_specific") or {}
        for value in ecosystem.get("cwe_ids") or []:
            text = str(value).upper()
            if text.startswith("CWE-"):
                values.add(text)
    return sorted(values)


def _resolve_cwe_metadata(cve_id: str) -> dict[str, Any]:
    """Use existing OSV/NVD metadata clients; no model-generated CWE labels."""
    from f_vra.localization.sources.metadata import resolve_nvd, resolve_osv

    try:
        osv = resolve_osv(cve_id)
        if osv:
            cwe_ids = _cwe_from_osv(osv.raw)
            if cwe_ids:
                return {"cwe_ids": cwe_ids, "source": "OSV"}
        nvd = resolve_nvd(cve_id)
        if nvd and nvd.cwe_id:
            return {"cwe_ids": [nvd.cwe_id], "source": "NVD"}
        return {"cwe_ids": [], "source": "none"}
    except Exception as exc:
        return {"cwe_ids": [], "source": "lookup_error", "error": f"{type(exc).__name__}: {exc}"}


def _fetch_cwe_description(cwe_id: str) -> dict[str, str]:
    """Fetch the canonical short/extended text from MITRE's public CWE REST API."""
    import requests

    number = cwe_id.upper().removeprefix("CWE-")
    for entry_type, collection in (("weakness", "Weaknesses"), ("category", "Categories")):
        try:
            response = requests.get(
                f"https://cwe-api.mitre.org/api/v1/cwe/{entry_type}/{number}", timeout=15,
            )
            if response.status_code == 404:
                continue
            response.raise_for_status()
            rows = response.json().get(collection) or []
            if not rows:
                continue
            item = rows[0]
            text = " ".join(
                str(item.get(field) or "").strip()
                for field in ("Name", "Description", "ExtendedDescription")
                if str(item.get(field) or "").strip()
            )
            return {"text": text, "status": "resolved", "source": f"MITRE_CWE_REST/{entry_type}"}
        except (requests.RequestException, ValueError, TypeError) as exc:
            return {"text": "", "status": "lookup_error", "source": "MITRE_CWE_REST",
                    "error": type(exc).__name__}
    return {"text": "", "status": "not_found", "source": "MITRE_CWE_REST"}


def _load_rq3_adjudications(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.is_file():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    rows = document.get("cases", []) if isinstance(document, dict) else document
    if isinstance(rows, dict):
        rows = [dict(value, group_id=key) for key, value in rows.items()]
    if not isinstance(rows, list):
        raise ValueError("adjudication file must contain a cases list or group-id mapping")
    decisions: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not row.get("group_id"):
            raise ValueError("each adjudication must have a group_id")
        group_id = str(row["group_id"])
        if group_id in decisions:
            raise ValueError(f"duplicate adjudication for {group_id}")
        status = str(row.get("status") or "PENDING").upper()
        if status == "APPROVED":
            if not str(row.get("reason") or "").strip() or not row.get("evidence"):
                raise ValueError(f"approved adjudication for {group_id} needs reason and evidence")
            release_pair = isinstance(row.get("source_archive"), dict) and isinstance(row.get("fix_archive"), dict)
            for field_name in ("vulnerable_ref", "patch_base_sha"):
                value = str(row.get(field_name) or "").strip()
                if value and not release_pair and (
                    len(value) not in {40, 64} or any(char not in "0123456789abcdefABCDEF" for char in value)
                ):
                    raise ValueError(f"invalid {field_name} in adjudication for {group_id}")
            patch_sha = str(row.get("patch_sha") or "").strip()
            if patch_sha and not release_pair and (
                len(patch_sha) not in {40, 64} or any(char not in "0123456789abcdefABCDEF" for char in patch_sha)
            ):
                raise ValueError(f"invalid patch_sha in adjudication for {group_id}")
            if patch_sha and not str(row.get("patch_base_sha") or "").strip():
                raise ValueError(f"adjudicated patch_sha for {group_id} needs an explicit patch_base_sha")
            if patch_sha and row.get("patch_unavailable"):
                raise ValueError(f"adjudication for {group_id} cannot both select a patch and mark it unavailable")
            vf_updates = row.get("verified_vf_updates") or {}
            if not isinstance(vf_updates, dict) or any(not isinstance(value, dict) for value in vf_updates.values()):
                raise ValueError(f"verified_vf_updates for {group_id} must map function names to field updates")
            vf_exclusions = row.get("verified_vf_exclusions") or []
            if not isinstance(vf_exclusions, list) or any(not str(value).strip() for value in vf_exclusions):
                raise ValueError(f"verified_vf_exclusions for {group_id} must be a list of function names")
            if release_pair:
                for spec_name in ("source_archive", "fix_archive"):
                    spec = row[spec_name]
                    digest = str(spec.get("sha256") or "")
                    if len(digest) != 64 or any(char not in "0123456789abcdefABCDEF" for char in digest):
                        raise ValueError(f"invalid {spec_name} SHA-256 in adjudication for {group_id}")
                    if not str(spec.get("url") or "").startswith("https://files.pythonhosted.org/"):
                        raise ValueError(f"invalid {spec_name} URL in adjudication for {group_id}")
            if row.get("patch_unavailable") and not str(row.get("patch_unavailable_reason") or "").strip():
                raise ValueError(f"patch_unavailable adjudication for {group_id} needs a reason")
        row["status"] = status
        decisions[group_id] = row
    return decisions


class PatchBaseMismatchError(ValueError):
    """The requested patch base is not a direct parent of the fix commit."""


def _is_full_git_sha(value: str) -> bool:
    return len(value) in {40, 64} and all(char in "0123456789abcdefABCDEF" for char in value)


def _resolve_git_ref_in_mirror(mirror: Path, ref: str) -> str:
    def resolve() -> str:
        result = subprocess.run(
            ["git", "-C", str(mirror), "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}"],
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        if not _is_full_git_sha(result):
            raise ValueError(f"Git ref {ref!r} did not resolve to a full commit SHA")
        return result

    try:
        return resolve()
    except subprocess.CalledProcessError:
        if ref and all(char in "0123456789abcdefABCDEF" for char in ref):
            subprocess.run(
                ["git", "-C", str(mirror), "fetch", "--no-tags", "origin", ref],
                check=True, capture_output=True, text=True,
            )
            return resolve()
        raise


def resolve_git_commit(repo_url: str, ref: str, cache_root: Path) -> str:
    """Resolve a benchmark's full, abbreviated, or parent-expression ref to a commit SHA."""
    if not repo_url.strip() or not ref.strip():
        raise ValueError("repo_url and Git ref are required")
    repo_key = _sha256(repo_url.encode("utf-8"))[:24]
    mirror = cache_root / "mirrors" / f"{repo_key}.git"
    lock = cache_root / "locks" / f"{repo_key}.lock"
    descriptor = _acquire_repo_lock(lock)
    try:
        mirror.parent.mkdir(parents=True, exist_ok=True)
        if not mirror.is_dir():
            subprocess.run(["git", "clone", "--bare", repo_url, str(mirror)], check=True, capture_output=True, text=True)
        return _resolve_git_ref_in_mirror(mirror, ref)
    finally:
        os.close(descriptor)
        lock.unlink(missing_ok=True)


def _git_commit_parents(mirror: Path, commit: str) -> tuple[str, ...]:
    completed = subprocess.run(
        ["git", "-C", str(mirror), "rev-list", "--parents", "-n", "1", commit],
        check=True, capture_output=True, text=True,
    )
    fields = completed.stdout.split()
    if not fields or fields[0] != commit:
        raise ValueError(f"cannot resolve fixing commit {commit}")
    return tuple(fields[1:])


def materialize_git_patch(
    repo_url: str, commit: str, cache_root: Path, base_commit: str | None = None,
) -> Path:
    """Cache an explicit direct-parent -> fix diff, including merge commits."""
    if not repo_url.strip() or not commit.strip():
        raise ValueError("repo_url and fixing commit are required")
    repo_key = _sha256(repo_url.encode("utf-8"))[:24]
    mirror = cache_root / "mirrors" / f"{repo_key}.git"
    lock = cache_root / "locks" / f"{repo_key}.lock"
    descriptor = _acquire_repo_lock(lock)
    try:
        mirror.parent.mkdir(parents=True, exist_ok=True)
        if not mirror.is_dir():
            subprocess.run(["git", "clone", "--bare", repo_url, str(mirror)], check=True, capture_output=True, text=True)
        commit = _resolve_git_ref_in_mirror(mirror, commit)
        parents = _git_commit_parents(mirror, commit)
        if base_commit is None or not base_commit.strip():
            if len(parents) != 1:
                raise PatchBaseMismatchError(
                    f"fix commit {commit} has {len(parents)} parents; an explicit base is required"
                )
            base_commit = parents[0]
        else:
            base_commit = _resolve_git_ref_in_mirror(mirror, base_commit)
        if base_commit not in parents:
            raise PatchBaseMismatchError(
                f"declared patch base {base_commit} is not a direct parent of {commit}; "
                f"actual parents: {', '.join(parents) or '(none)'}"
            )
        patch_path = cache_root / "patches" / f"{repo_key}_{commit}_{base_commit}.patch"
        if patch_path.is_file():
            return patch_path
        completed = subprocess.run(
            ["git", "-C", str(mirror), "diff", "--no-ext-diff", "--no-renames", base_commit, commit, "--"],
            check=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if "@@" not in completed.stdout:
            raise ValueError(f"explicit diff {base_commit}..{commit} produced no text hunks")
        patch_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = patch_path.with_suffix(".patch.tmp")
        temporary.write_text(completed.stdout, encoding="utf-8")
        temporary.replace(patch_path)
        return patch_path
    finally:
        os.close(descriptor)
        lock.unlink(missing_ok=True)


def _extract_archive_safely(
    archive_path: Path, destination: Path, *, strip_top_level: bool = False,
) -> None:
    """Extract only Python files, the complete input surface used by RQ3.

    This also lets Git for Windows materialize repositories containing
    non-source names such as ``aux/`` or timestamped fixture files that NTFS
    cannot represent. Unsafe Python paths still fail closed.
    """
    from f_vra.localization.code.function_parser import SKIP_DIRS

    with tarfile.open(archive_path, "r:*") as archive:
        all_members = {member.name: member for member in archive.getmembers()}
        members = [member for member in all_members.values()
                   if PurePosixPath(member.name).suffix.lower() == ".py"
                   and not any(part in SKIP_DIRS for part in PurePosixPath(member.name).parts)]
        strip_prefix = ""
        if strip_top_level:
            prefixes = {PurePosixPath(member.name).parts[0] for member in members if PurePosixPath(member.name).parts}
            if len(prefixes) != 1:
                raise ValueError("release source archive must have a single top-level directory")
            strip_prefix = next(iter(prefixes))

        def output_name(member_name: str) -> PurePosixPath:
            name = PurePosixPath(member_name)
            if strip_prefix:
                if not name.parts or name.parts[0] != strip_prefix:
                    raise ValueError(f"source archive member escaped top-level directory: {member_name}")
                name = PurePosixPath(*name.parts[1:])
            if name.is_absolute() or not name.parts or ".." in name.parts:
                raise ValueError(f"unsafe Python path in source archive: {member_name}")
            if any(char in name.as_posix() for char in '<>:"|?*') or any(part.endswith((" ", ".")) for part in name.parts):
                raise ValueError(f"Python path is not representable on Windows: {member_name}")
            reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
            if any(part.split(".", 1)[0].upper() in reserved for part in name.parts):
                raise ValueError(f"Python path uses a reserved Windows device name: {member_name}")
            return name

        for member in members:
            output_name(member.name)

        def copy_python_member(member: tarfile.TarInfo, target: Path, chain: set[str]) -> None:
            if member.name in chain:
                raise ValueError(f"cyclic Python link in source archive: {member.name}")
            if member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"cannot read Python source archive member: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with source, target.open("wb") as destination_file:
                    shutil.copyfileobj(source, destination_file)
                return
            if member.issym() or member.islnk():
                link = member.linkname.replace("\\", "/")
                target_name = posixpath.normpath(
                    posixpath.join(posixpath.dirname(member.name), link) if member.issym() else link
                )
                if link.startswith("/") or target_name in {"", ".", ".."} or target_name.startswith("../"):
                    raise ValueError(f"unsafe Python link in source archive: {member.name} -> {member.linkname}")
                linked_member = all_members.get(target_name)
                if linked_member is None:
                    raise ValueError(f"unresolved Python link in source archive: {member.name} -> {member.linkname}")
                copy_python_member(linked_member, target, chain | {member.name})
                return
            raise ValueError(f"unsupported Python source archive member type: {member.name}")

        for member in members:
            relative = output_name(member.name)
            copy_python_member(member, destination.joinpath(*relative.parts), set())


def materialize_release_source(
    url: str, expected_sha256: str, cache_root: Path,
) -> Path:
    """Download and verify a pinned sdist, then export its Python source tree."""
    from urllib.parse import urlparse
    from urllib.request import Request, urlopen

    parsed_url = urlparse(url)
    if parsed_url.scheme != "https" or parsed_url.hostname != "files.pythonhosted.org":
        raise ValueError("adjudicated release archives must be hosted on files.pythonhosted.org over HTTPS")
    if len(expected_sha256) != 64 or any(char not in "0123456789abcdef" for char in expected_sha256.lower()):
        raise ValueError("release archive requires a 64-character SHA-256")
    archive_path = cache_root / "release_archives" / f"{expected_sha256}.tar.gz"
    snapshot_path = cache_root / "release_snapshots" / expected_sha256[:16]
    if snapshot_path.is_dir():
        return snapshot_path
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    if not archive_path.is_file():
        response = urlopen(Request(url, headers={"User-Agent": "f_vra-rq3/1.0"}), timeout=60)
        try:
            payload = response.read(128 * 1024 * 1024 + 1)
        finally:
            response.close()
        if len(payload) > 128 * 1024 * 1024:
            raise ValueError("release archive exceeds 128 MiB safety limit")
        if _sha256(payload) != expected_sha256.lower():
            raise ValueError("downloaded release archive SHA-256 does not match adjudication")
        temporary_archive = archive_path.with_suffix(".tmp")
        temporary_archive.write_bytes(payload)
        temporary_archive.replace(archive_path)
    elif _sha256(archive_path.read_bytes()) != expected_sha256.lower():
        raise ValueError(f"cached release archive hash mismatch: {archive_path}")
    snapshot_path.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{expected_sha256[:8]}-", dir=snapshot_path.parent))
    try:
        _extract_archive_safely(archive_path, staging, strip_top_level=True)
        staging.replace(snapshot_path)
    finally:
        if staging.exists():
            for child in sorted(staging.rglob("*"), reverse=True):
                if child.is_file() or child.is_symlink():
                    child.unlink(missing_ok=True)
                elif child.is_dir():
                    child.rmdir()
            staging.rmdir()
    return snapshot_path


def materialize_release_patch(
    vulnerable_tree: Path, fixed_tree: Path, base_sha256: str, fix_sha256: str, cache_root: Path,
) -> Path:
    """Build a deterministic Python-only diff between two verified release artifacts."""
    patch_path = cache_root / "patches" / f"release_{base_sha256}_{fix_sha256}.patch"
    if patch_path.is_file():
        return patch_path
    before = {path.relative_to(vulnerable_tree).as_posix(): path for path in vulnerable_tree.rglob("*.py")}
    after = {path.relative_to(fixed_tree).as_posix(): path for path in fixed_tree.rglob("*.py")}
    chunks: list[str] = []
    for relative in sorted(set(before) | set(after)):
        old_path, new_path = before.get(relative), after.get(relative)
        old_lines = old_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True) if old_path else []
        new_lines = new_path.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True) if new_path else []
        if old_lines == new_lines:
            continue
        chunks.append(f"diff --git a/{relative} b/{relative}\n")
        chunks.extend(difflib.unified_diff(
            old_lines, new_lines,
            fromfile=f"a/{relative}" if old_path else "/dev/null",
            tofile=f"b/{relative}" if new_path else "/dev/null",
        ))
    patch = "".join(chunks)
    if "@@" not in patch:
        raise ValueError("release artifact comparison produced no Python text hunks")
    patch_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = patch_path.with_suffix(".patch.tmp")
    temporary.write_text(patch, encoding="utf-8")
    temporary.replace(patch_path)
    return patch_path


def freeze_rq3_benchmark(
    benchmark: Path,
    output: Path,
    *,
    downstream: Path | None = None,
    snapshot_map: Path | None = None,
    snapshot_cache: Path | None = None,
    patch_cache: Path | None = None,
    materialize_sources: bool = False,
    materialize_patches: bool = False,
    resolve_cwe: bool = True,
    adjudication: Path | None = None,
    reuse_manifest_from: Path | None = None,
    snapshot_root: Path | None = None,
) -> dict[str, Any]:
    """Freeze accepted case identities, exact fix parents, metadata and gold.

    Source and patch materialization are opt-in because they can fetch large
    external repositories. Without them, rows remain auditable but are marked
    ineligible until their exact artifacts are supplied.
    """
    raw_rows = _jsonl(benchmark)
    reuse_rows: dict[str, dict[str, Any]] = {}
    reuse_summary: dict[str, Any] = {}
    if reuse_manifest_from:
        reuse_summary_path = reuse_manifest_from.with_name(f"{reuse_manifest_from.stem}.summary.json")
        if not reuse_manifest_from.is_file() or not reuse_summary_path.is_file():
            raise ValueError("reuse manifest needs both its JSONL and freeze summary")
        reuse_summary = json.loads(reuse_summary_path.read_text(encoding="utf-8"))
        if reuse_summary.get("cases_sha256") != _sha256(reuse_manifest_from.read_bytes()):
            raise ValueError("reuse manifest changed after its freeze; refusing to reuse artifacts")
        # Reuse is artifact-level, not benchmark-level: a revised benchmark may
        # retain exact source/patch identities while changing descriptions or
        # gold labels. Every artifact is checked against the current row below.
        # Keep the original benchmark digest in the new summary for provenance.
        reuse_rows = {str(row.get("case_id")): row for row in _jsonl(reuse_manifest_from)}
    adjudications = _load_rq3_adjudications(adjudication)
    accepted_rows = [
        row for row in raw_rows
        if str(row.get("ground_truth_evidence") or "") in STRONG_EVIDENCE
        and str(row.get("mapping_type") or "") not in REJECTED_MAPPING_TYPES
    ]
    accepted_rows.sort(key=lambda row: str(row.get("group_id") or ""))
    map_rows = json.loads(snapshot_map.read_text(encoding="utf-8")) if snapshot_map and snapshot_map.exists() else {}
    map_rows = map_rows.get("snapshots", map_rows) if isinstance(map_rows, dict) else {}
    cache_path = output.with_name(output.stem + ".metadata_cache.json")
    reused_metadata_path = reuse_manifest_from.with_name(reuse_manifest_from.stem + ".metadata_cache.json") if reuse_manifest_from else None
    metadata_cache = json.loads(reused_metadata_path.read_text(encoding="utf-8")) if reused_metadata_path and reused_metadata_path.is_file() else {}
    if cache_path.exists():
        metadata_cache.update(json.loads(cache_path.read_text(encoding="utf-8")))
    if reuse_manifest_from and metadata_cache:
        write_json(cache_path, metadata_cache)
    unique_cves = sorted({str(row.get("advisory_id") or row.get("cve_id") or "") for row in accepted_rows} - {""})
    for cve_id in tqdm(unique_cves, desc="RQ3 CWE metadata", disable=not resolve_cwe):
        if cve_id not in metadata_cache or metadata_cache[cve_id].get("source") == "lookup_error":
            metadata_cache[cve_id] = _resolve_cwe_metadata(cve_id) if resolve_cwe else {"cwe_ids": [], "source": "not_resolved"}
            write_json(cache_path, metadata_cache)

    cwe_cache_path = output.with_name(output.stem + ".cwe_cache.json")
    reused_cwe_path = reuse_manifest_from.with_name(reuse_manifest_from.stem + ".cwe_cache.json") if reuse_manifest_from else None
    cwe_cache = json.loads(reused_cwe_path.read_text(encoding="utf-8")) if reused_cwe_path and reused_cwe_path.is_file() else {}
    if cwe_cache_path.exists():
        cwe_cache.update(json.loads(cwe_cache_path.read_text(encoding="utf-8")))
    if reuse_manifest_from and cwe_cache:
        write_json(cwe_cache_path, cwe_cache)
    known_cwes = sorted({
        str(value).upper()
        for row in accepted_rows
        for value in [*(row.get("cwe_ids") or []), *([row["cwe_id"]] if row.get("cwe_id") else []),
                      *(metadata_cache.get(str(row.get("advisory_id") or row.get("cve_id") or ""), {}).get("cwe_ids") or [])]
        if str(value).upper().startswith("CWE-")
    })
    for cwe_id in tqdm(known_cwes, desc="MITRE CWE descriptions", disable=not resolve_cwe):
        if cwe_id not in cwe_cache or cwe_cache[cwe_id].get("status") == "lookup_error":
            cwe_cache[cwe_id] = _fetch_cwe_description(cwe_id) if resolve_cwe else {"text": "", "status": "not_resolved"}
            write_json(cwe_cache_path, cwe_cache)

    frozen, audit_rows = [], []
    reused_source_count = 0
    reused_patch_count = 0
    accepted_ids = {id(row) for row in accepted_rows}
    for row in raw_rows:
        if id(row) in accepted_ids:
            continue
        reasons = []
        if str(row.get("ground_truth_evidence") or "") not in STRONG_EVIDENCE:
            reasons.append("REJECTED_EVIDENCE_LEVEL")
        if str(row.get("mapping_type") or "") in REJECTED_MAPPING_TYPES:
            reasons.append("REJECTED_MAPPING_TYPE")
        audit_rows.append({
            "group_id": str(row.get("group_id") or ""), "status": "REJECTED",
            "reference_status": "NOT_APPLICABLE", "source_status": "NOT_APPLICABLE",
            "patch_status": "NOT_APPLICABLE", "cwe_count": 0,
            "verified_vf_count": 0, "reason": ";".join(reasons),
        })
    for row in tqdm(accepted_rows, desc="Freeze RQ3 cases"):
        group_id = str(row.get("group_id") or "")
        cve_id = str(row.get("advisory_id") or row.get("cve_id") or "")
        decision = adjudications.get(group_id, {})
        decision_approved = decision.get("status") == "APPROVED"
        vulnerable_ref = str(row.get("vulnerable_ref") or "").strip()
        reference_status = "SOURCE_PROVIDED" if vulnerable_ref else "MISSING_VULNERABLE_REF"
        adjudicated_ref = str(decision.get("vulnerable_ref") or "").strip() if decision_approved else ""
        if adjudicated_ref:
            vulnerable_ref = adjudicated_ref
            reference_status = "ADJUDICATED_VULNERABLE_REF"
        source_archive = decision.get("source_archive") if decision_approved else None
        fix_archive = decision.get("fix_archive") if decision_approved else None
        release_pair = isinstance(source_archive, dict) and isinstance(fix_archive, dict)
        if release_pair:
            vulnerable_ref = f"pypi:{decision.get('package_name', row.get('package_name', 'package'))}=={source_archive.get('version')}"
            reference_status = "ADJUDICATED_RELEASE_ARTIFACT"
        if not vulnerable_ref:
            canonical_parents = sorted({
                str(item.get("parent_sha") or "")
                for item in row.get("patches") or []
                if item.get("role") == "canonical_fix" and item.get("parent_sha")
            })
            if len(canonical_parents) == 1:
                vulnerable_ref = canonical_parents[0]
                reference_status = "INFERRED_UNIQUE_CANONICAL_FIX_PARENT"
            else:
                reference_status = "INELIGIBLE_AMBIGUOUS_FIX_PARENT"
        repo_url = str(row.get("repo_url") or "")
        source_ref_original = ""
        source_ref_error = ""
        if materialize_sources and vulnerable_ref and not release_pair and not _is_full_git_sha(vulnerable_ref):
            source_ref_original = vulnerable_ref
            try:
                vulnerable_ref = resolve_git_commit(repo_url, vulnerable_ref, snapshot_cache or output.parent / "source_cache")
            except Exception as exc:
                source_ref_error = f"{type(exc).__name__}:{exc}"
        source_key = f"{repo_url}#{vulnerable_ref}"
        mapped_entry = map_rows.get(group_id) or map_rows.get(source_key)
        source_path = str(mapped_entry.get("path") or "") if isinstance(mapped_entry, dict) else str(mapped_entry or "")
        source_status = "SOURCE_NOT_MATERIALIZED"
        source_verified = False
        source_kind = "git_commit"
        prior = reuse_rows.get(group_id, {})
        prior_path = str(prior.get("source_path") or "")
        if (
            not source_ref_error
            and not release_pair and prior.get("eligible")
            and str(prior.get("repo_url") or "") == repo_url
            and str(prior.get("vulnerable_ref") or "") == vulnerable_ref
            and str(prior.get("source_revision_sha") or "") == vulnerable_ref
            and prior_path and Path(prior_path).is_dir()
        ):
            source_path = prior_path
            source_status = "REUSED_VERIFIED_FROZEN_SNAPSHOT"
            source_verified = True
            reused_source_count += 1
        elif release_pair:
            source_kind = "pypi_sdist"
            release_cache = snapshot_cache or output.parent / "source_cache"
            source_path = str(release_cache / "release_snapshots" / str(source_archive["sha256"])[:16])
            if materialize_sources:
                try:
                    source_path = str(materialize_release_source(
                        str(source_archive["url"]), str(source_archive["sha256"]), release_cache,
                    ))
                    source_status = "MATERIALIZED_VERIFIED_RELEASE_ARCHIVE"
                    source_verified = True
                except Exception as exc:
                    source_status = f"MATERIALIZATION_FAILED:{type(exc).__name__}:{exc}"
            elif Path(source_path).is_dir():
                source_status = "VERIFIED_RELEASE_ARCHIVE_CACHE_HIT"
                source_verified = True
            else:
                source_path = ""
        elif materialize_sources and vulnerable_ref and not source_ref_error:
            try:
                source_path = str(materialize_git_snapshot(
                    repo_url, vulnerable_ref, snapshot_cache or output.parent / "source_cache",
                    snapshot_root=snapshot_root,
                ))
                source_status = "MATERIALIZED_EXACT_COMMIT"
                source_verified = True
            except Exception as exc:
                source_status = f"MATERIALIZATION_FAILED:{type(exc).__name__}:{exc}"
        elif not source_ref_error and source_path and Path(source_path).is_dir() and isinstance(mapped_entry, dict):
            identity_matches = (
                str(mapped_entry.get("repo_url") or "") == repo_url
                and str(mapped_entry.get("commit_sha") or mapped_entry.get("vulnerable_ref") or "") == vulnerable_ref
            )
            source_hash = str(mapped_entry.get("source_hash") or "")
            actual_source_hash = source_tree_hash(Path(source_path))
            hash_matches = bool(source_hash and actual_source_hash == source_hash)
            clean_git_match = False
            try:
                head = subprocess.run(["git", "-C", source_path, "rev-parse", "HEAD"], check=True,
                                      capture_output=True, text=True).stdout.strip()
                dirty = subprocess.run(["git", "-C", source_path, "status", "--porcelain", "--untracked-files=all"],
                                       check=True, capture_output=True, text=True).stdout.strip()
                clean_git_match = head == vulnerable_ref and not dirty
            except (OSError, subprocess.CalledProcessError):
                pass
            source_verified = identity_matches and (hash_matches or clean_git_match)
            source_status = "SOURCE_MAP_IDENTITY_VERIFIED" if source_verified else "SNAPSHOT_MAP_IDENTITY_OR_HASH_MISMATCH"
        elif not source_ref_error and source_path and Path(source_path).is_dir():
            try:
                head = subprocess.run(
                    ["git", "-C", source_path, "rev-parse", "HEAD"],
                    check=True, capture_output=True, text=True,
                ).stdout.strip()
                dirty = subprocess.run(
                    ["git", "-C", source_path, "status", "--porcelain", "--untracked-files=all"],
                    check=True, capture_output=True, text=True,
                ).stdout.strip()
                source_verified = head == vulnerable_ref and not dirty
                source_status = "GIT_HEAD_VERIFIED" if source_verified else "GIT_HEAD_MISMATCH"
            except (OSError, subprocess.CalledProcessError):
                source_status = "SNAPSHOT_MAP_IDENTITY_MISSING"
                source_verified = False
        else:
            source_path = ""
            if source_ref_error:
                source_status = f"SOURCE_REF_RESOLUTION_FAILED:{source_ref_error}"

        canonical_specs = [
            item for item in row.get("patches") or []
            if item.get("role") == "canonical_fix" and item.get("sha")
        ]
        canonical_fix_originals = sorted({str(item.get("sha") or "") for item in canonical_specs})
        adjudicated_fix = str(decision.get("patch_sha") or "").strip() if decision_approved else ""
        if adjudicated_fix and not canonical_fix_originals:
            raise ValueError(f"adjudicated patch_sha for {group_id} has no canonical fix record to override")
        canonical_fixes = [adjudicated_fix] if adjudicated_fix else list(canonical_fix_originals)
        fix_ref_error = ""
        if materialize_patches and len(canonical_fixes) == 1 and not release_pair and not _is_full_git_sha(canonical_fixes[0]):
            try:
                canonical_fixes[0] = resolve_git_commit(
                    repo_url, canonical_fixes[0], snapshot_cache or output.parent / "source_cache",
                )
            except Exception as exc:
                fix_ref_error = f"{type(exc).__name__}:{exc}"
        patch_text = ""
        patch_status = "PATCH_NOT_MATERIALIZED"
        patch_base_sha = ""
        patch_content_sha256 = ""
        patch_fix_artifact_sha256 = ""
        if decision_approved and decision.get("patch_unavailable"):
            patch_status = "ADJUDICATED_PATCH_UNAVAILABLE"
        elif len(canonical_fixes) == 1 and release_pair:
            fix_sha = canonical_fixes[0]
            patch_base_sha = f"pypi:{source_archive.get('version')}@sha256:{source_archive.get('sha256')}"
            patch_fix_artifact_sha256 = str(fix_archive.get("sha256") or "")
            cache_root = snapshot_cache or output.parent / "source_cache"
            cached_patch = cache_root / "patches" / f"release_{source_archive['sha256']}_{fix_archive['sha256']}.patch"
            if materialize_patches:
                try:
                    source_tree = materialize_release_source(
                        str(source_archive["url"]), str(source_archive["sha256"]), cache_root,
                    )
                    fixed_tree = materialize_release_source(
                        str(fix_archive["url"]), str(fix_archive["sha256"]), cache_root,
                    )
                    cached_patch = materialize_release_patch(
                        source_tree, fixed_tree, str(source_archive["sha256"]),
                        str(fix_archive["sha256"]), cache_root,
                    )
                    patch_status = "MATERIALIZED_PYPI_RELEASE_DIFF"
                except Exception as exc:
                    patch_status = f"PATCH_MATERIALIZATION_FAILED:{type(exc).__name__}:{exc}"
            elif cached_patch.is_file():
                patch_status = "PATCH_CACHE_HIT_RELEASE_ARTIFACTS"
            if cached_patch.is_file():
                patch_text = cached_patch.read_text(encoding="utf-8", errors="replace")
                patch_content_sha256 = _sha256(patch_text.encode("utf-8"))
        elif len(canonical_fixes) == 1:
            fix_sha = canonical_fixes[0]
            canonical_spec = next(item for item in canonical_specs if str(item.get("sha") or "") == canonical_fix_originals[0])
            declared_base = str(canonical_spec.get("parent_sha") or "").strip()
            adjudicated_base = str(decision.get("patch_base_sha") or "").strip() if decision_approved else ""
            patch_base_sha = adjudicated_base or declared_base
            cache_root = snapshot_cache or output.parent / "source_cache"
            base_ref_error = ""
            if materialize_patches and patch_base_sha and not _is_full_git_sha(patch_base_sha):
                try:
                    patch_base_sha = resolve_git_commit(repo_url, patch_base_sha, cache_root)
                except Exception as exc:
                    base_ref_error = f"{type(exc).__name__}:{exc}"
            cached_patch = None
            prior_patch = reuse_rows.get(group_id, {})
            prior_patch_text = str(prior_patch.get("patch_text") or "")
            if fix_ref_error:
                patch_status = f"PATCH_FIX_REF_RESOLUTION_FAILED:{fix_ref_error}"
            elif base_ref_error:
                patch_status = f"PATCH_BASE_REF_RESOLUTION_FAILED:{base_ref_error}"
            elif (
                prior_patch.get("patch_available")
                and str(prior_patch.get("repo_url") or "") == repo_url
                and str(prior_patch.get("patch_sha") or "") == fix_sha
                and str(prior_patch.get("patch_base_sha") or "") == patch_base_sha
                and prior_patch.get("patch_status") in {"MATERIALIZED_FIX_DIFF", "REUSED_VERIFIED_FROZEN_FIX_DIFF"}
                and "@@" in prior_patch_text and patch_base_sha
                and str(prior_patch.get("patch_content_sha256") or "")
                == _sha256(prior_patch_text.encode("utf-8"))
            ):
                patch_text = prior_patch_text
                patch_content_sha256 = _sha256(patch_text.encode("utf-8"))
                patch_status = "REUSED_VERIFIED_FROZEN_FIX_DIFF"
                reused_patch_count += 1
            elif materialize_patches:
                try:
                    cached_patch = materialize_git_patch(
                        repo_url, fix_sha, cache_root, patch_base_sha or None,
                    )
                    patch_base_sha = cached_patch.stem.rsplit("_", 1)[-1]
                    patch_status = "MATERIALIZED_FIX_DIFF"
                except Exception as exc:
                    patch_status = f"PATCH_MATERIALIZATION_FAILED:{type(exc).__name__}:{exc}"
            else:
                if patch_base_sha:
                    exact_name = f"{_sha256(repo_url.encode('utf-8'))[:24]}_{fix_sha}_{patch_base_sha}.patch"
                    for cache in (cache_root / "patches", patch_cache):
                        candidate = cache / exact_name if cache else None
                        if candidate and candidate.is_file():
                            cached_patch = candidate
                            break
                    if cached_patch:
                        patch_status = "PATCH_CACHE_HIT_EXACT_BASE"
            if cached_patch and cached_patch.is_file():
                patch_text = cached_patch.read_text(encoding="utf-8", errors="replace")
                patch_content_sha256 = _sha256(patch_text.encode("utf-8"))
        elif canonical_fixes:
            patch_status = "INELIGIBLE_AMBIGUOUS_CANONICAL_FIX"
        else:
            patch_status = "NO_CANONICAL_FIX"

        direct_cwes = row.get("cwe_ids") or ([row["cwe_id"]] if row.get("cwe_id") else [])
        resolved = metadata_cache.get(cve_id, {"cwe_ids": [], "source": "not_resolved"})
        cwe_ids = sorted({str(value).upper() for value in [*direct_cwes, *(resolved.get("cwe_ids") or [])] if str(value).upper().startswith("CWE-")})
        from f_vra.localization.retrieval.expansion import expand_description

        cwe_text_parts = []
        for item in cwe_ids:
            canonical = cwe_cache.get(item, {})
            cwe_text_parts.append(str(canonical.get("text") or expand_description("", item)).strip())
        cwe_text = " ".join(part for part in cwe_text_parts if part).strip()
        gold_rows = decision.get("verified_vfs") if decision_approved and decision.get("verified_vfs") else row.get("root_cause_functions") or []
        gold = [dict(item) for item in gold_rows]
        vf_updates = decision.get("verified_vf_updates", {}) if decision_approved else {}
        vf_exclusions = set(decision.get("verified_vf_exclusions", [])) if decision_approved else set()
        original_gold_names = {str(item.get("qualified_name") or "") for item in gold}
        missing_vf_decisions = (set(vf_updates) | vf_exclusions) - original_gold_names
        if missing_vf_decisions:
            raise ValueError(f"adjudication for {group_id} references unknown verified VF(s): {sorted(missing_vf_decisions)}")
        gold = [
            {**item, **vf_updates.get(str(item.get("qualified_name") or ""), {})}
            for item in gold
            if str(item.get("qualified_name") or "") not in vf_exclusions
        ]
        evaluation_ineligible_reason = (
            str(decision.get("evaluation_ineligible_reason") or "").strip() if decision_approved else ""
        )
        source_eligible = bool(source_verified and source_path and vulnerable_ref and Path(source_path).is_dir())
        eligible = source_eligible and not evaluation_ineligible_reason
        source_content_sha256 = str(source_archive.get("sha256") or "") if release_pair else ""
        ineligible_reason = "" if eligible else (
            evaluation_ineligible_reason or (reference_status if not vulnerable_ref else source_status)
        )
        frozen.append({
            "schema_version": "f_vra.rq3.case.v1", "case_id": group_id,
            "cve_vf_group_id": group_id, "cve_id": cve_id,
            "package": str(row.get("package_name") or ""), "repo_url": repo_url,
            "vulnerable_ref": vulnerable_ref, "reference_status": reference_status,
            "description": str(row.get("description") or ""),
            "cwe_ids": cwe_ids, "cwe_text": cwe_text,
            "cwe_source": "benchmark" if direct_cwes else resolved.get("source", "none"),
            "cwe_text_source": ";".join(sorted({str(cwe_cache.get(item, {}).get("source") or "local_hint") for item in cwe_ids})),
            "source_path": source_path, "source_status": source_status,
            "source_content_sha256": source_content_sha256,
            "source_revision_sha": vulnerable_ref if source_kind == "git_commit" else "",
            "source_ref_original": source_ref_original,
            "source_kind": source_kind,
            "source_artifact_url": str(source_archive.get("url") or "") if release_pair else "",
            "source_artifact_sha256": str(source_archive.get("sha256") or "") if release_pair else "",
            "source_artifact_version": str(source_archive.get("version") or "") if release_pair else "",
            "snapshot_id": (
                _sha256(f"pypi\0{source_archive.get('url')}\0{source_archive.get('sha256')}".encode("utf-8"))
                if release_pair else (_sha256(f"{repo_url}\0{vulnerable_ref}".encode("utf-8")) if vulnerable_ref else "")
            ),
            "patch_available": bool(patch_text), "patch_text": patch_text,
            "patch_sha": canonical_fixes[0] if len(canonical_fixes) == 1 else "",
            "patch_sha_original": canonical_fix_originals[0] if len(canonical_fix_originals) == 1 else "",
            "patch_sha_adjudicated": adjudicated_fix,
            "patch_base_sha": patch_base_sha, "patch_content_sha256": patch_content_sha256,
            "patch_fix_artifact_sha256": patch_fix_artifact_sha256,
            "patch_status": patch_status,
            "verified_vfs": gold, "source_eligible": source_eligible,
            "eligible": eligible, "ineligible_reason": ineligible_reason,
            "evaluation_ineligible_reason": evaluation_ineligible_reason,
            "evidence": str(row.get("ground_truth_evidence") or ""),
            "mapping_type": str(row.get("mapping_type") or ""),
        "adjudication_status": str(decision.get("status") or "NONE"),
            "adjudication_reason": str(decision.get("reason") or ""),
            "reused_from_manifest_sha256": reuse_summary.get("cases_sha256", "") if prior else "",
        })
        audit_rows.append({
            "group_id": group_id, "status": "READY" if eligible else "INELIGIBLE",
            "reference_status": reference_status, "source_status": source_status,
            "patch_status": patch_status, "cwe_count": len(cwe_ids),
            "verified_vf_count": len(gold), "reason": ineligible_reason,
            "adjudication_status": str(decision.get("status") or "NONE"),
        })
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in frozen), encoding="utf-8")
    temporary.replace(output)
    audit_path = output.with_name(output.stem + ".audit.jsonl")
    audit_tmp = audit_path.with_suffix(audit_path.suffix + ".tmp")
    audit_tmp.write_text("".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in audit_rows), encoding="utf-8")
    audit_tmp.replace(audit_path)
    downstream_rows = _jsonl(downstream) if downstream and downstream.exists() else []
    frozen_groups = {row["cve_vf_group_id"] for row in frozen}
    downstream_group_ids = [str(row.get("cve_vf_group_id") or "") for row in downstream_rows]
    cwe_resolution_complete = bool(resolve_cwe) and all(
        metadata_cache.get(cve_id, {}).get("source") not in {None, "not_resolved", "lookup_error"}
        for cve_id in unique_cves
    )
    cwe_text_resolution_complete = bool(resolve_cwe) and all(
        cwe_cache.get(cwe_id, {}).get("status") == "resolved"
        or bool(str(cwe_cache.get(cwe_id, {}).get("text") or ""))
        for cwe_id in known_cwes
    )
    unresolved_patch_count = sum(
        bool(row.get("patch_sha")) and not bool(row.get("patch_available"))
        and row.get("patch_status") != "ADJUDICATED_PATCH_UNAVAILABLE"
        for row in frozen
    )
    patch_unavailable_adjudicated = sum(
        row.get("patch_status") == "ADJUDICATED_PATCH_UNAVAILABLE" for row in frozen
    )
    source_population_ready = all(
        (
            bool(row.get("source_eligible", row["eligible"]))
            and (
                (row.get("source_kind") == "pypi_sdist" and len(str(row.get("source_content_sha256") or "")) == 64)
                or (row.get("source_kind") == "git_commit" and len(str(row.get("source_revision_sha") or "")) in {40, 64})
            )
        ) or row["reference_status"] == "INELIGIBLE_AMBIGUOUS_FIX_PARENT"
        for row in frozen
    )
    summary = {
        "status": "FROZEN", "raw_rows": len(raw_rows), "accepted_rows": len(frozen),
        "eligible_source_cases": sum(bool(row.get("source_eligible", row["eligible"])) for row in frozen),
        "eligible_cases": sum(bool(row["eligible"]) for row in frozen),
        "source_identity_complete": source_population_ready,
        "ineligible_cases": sum(not bool(row["eligible"]) for row in frozen),
        "gold_mapping_excluded_cases": sum(bool(row.get("evaluation_ineligible_reason")) for row in frozen),
        "patch_available_cases": sum(bool(row["patch_available"]) for row in frozen),
        "cwe_resolved_cases": sum(bool(row["cwe_ids"]) for row in frozen),
        "cwe_resolution_complete": cwe_resolution_complete,
        "cwe_text_resolution_complete": cwe_text_resolution_complete,
        "cwe_lookup_errors": sum(metadata_cache.get(cve_id, {}).get("source") == "lookup_error" for cve_id in unique_cves),
        "patches_unmaterialized": unresolved_patch_count,
        "patches_adjudicated_unavailable": patch_unavailable_adjudicated,
        "reused_source_cases": reused_source_count,
        "reused_patch_cases": reused_patch_count,
        "downstream_rows": len(downstream_rows),
        "downstream_rows_matched_exact_group": sum(group_id in frozen_groups for group_id in downstream_group_ids),
        "downstream_rows_unmatched_exact_group": sum(group_id not in frozen_groups for group_id in downstream_group_ids),
        "cases_path": str(output), "cases_sha256": _sha256(output.read_bytes()),
        "benchmark_sha256": _sha256(benchmark.read_bytes()),
        "metadata_cache": str(cache_path), "cwe_metadata_cache": str(cwe_cache_path), "audit_path": str(audit_path),
        "adjudication_path": str(adjudication) if adjudication else "",
        "adjudication_sha256": _sha256(adjudication.read_bytes()) if adjudication and adjudication.is_file() else "",
        "reused_manifest_path": str(reuse_manifest_from) if reuse_manifest_from else "",
        "reused_manifest_sha256": reuse_summary.get("cases_sha256", ""),
        "reused_benchmark_sha256": reuse_summary.get("benchmark_sha256", ""),
        "reuse_benchmark_matches": bool(
            reuse_summary.get("benchmark_sha256")
            and reuse_summary.get("benchmark_sha256") == _sha256(benchmark.read_bytes())
        ) if reuse_manifest_from else None,
        "snapshot_root": str(snapshot_root) if snapshot_root else "",
        "audit_status_counts": dict(Counter(str(row["status"]) for row in audit_rows)),
        "materialize_sources": materialize_sources, "materialize_patches": materialize_patches,
        "full_batch_ready": source_population_ready and cwe_resolution_complete and cwe_text_resolution_complete and unresolved_patch_count == 0 and bool(frozen),
    }
    write_json(output.with_name(output.stem + ".summary.json"), summary)
    return summary


def _acquire_repo_lock(lock_path: Path, timeout_seconds: float = 300.0) -> int:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
            return descriptor
        except FileExistsError:
            try:
                if time.time() - lock_path.stat().st_mtime > 21600:
                    lock_path.unlink()
                    continue
            except FileNotFoundError:
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError(f"timed out waiting for repository snapshot lock {lock_path}")
            time.sleep(0.25)


def materialize_git_snapshot(
    repo_url: str, commit: str, cache_root: Path, *, snapshot_root: Path | None = None,
) -> Path:
    """Export one exact Git commit without switching a shared checkout.

    Repository fetch/export is serialized per URL. The immutable archive is
    expanded into a content-addressed directory, so later localization reads
    never share a mutable checkout.
    """
    if not repo_url.strip() or not commit.strip():
        raise ValueError("repo_url and full vulnerable commit are required")
    repo_key = _sha256(repo_url.encode("utf-8"))[:24]
    snapshot_key = _sha256(f"{repo_url}\0{commit}".encode("utf-8"))
    mirrors = cache_root / "mirrors"
    legacy_snapshots = cache_root / "snapshots"
    snapshots = snapshot_root or legacy_snapshots
    mirror = mirrors / f"{repo_key}.git"
    legacy_destination = legacy_snapshots / snapshot_key
    destination = snapshots / snapshot_key[:16]
    if legacy_destination.is_dir():
        return legacy_destination
    if destination.is_dir():
        return destination
    lock = cache_root / "locks" / f"{repo_key}.lock"
    descriptor = _acquire_repo_lock(lock)
    try:
        if legacy_destination.is_dir():
            return legacy_destination
        if destination.is_dir():
            return destination
        mirror.parent.mkdir(parents=True, exist_ok=True)
        if not mirror.is_dir():
            subprocess.run(["git", "clone", "--bare", repo_url, str(mirror)], check=True, capture_output=True, text=True)
        has_commit = subprocess.run(["git", "-C", str(mirror), "cat-file", "-e", f"{commit}^{{commit}}"], capture_output=True).returncode == 0
        if not has_commit:
            subprocess.run(["git", "-C", str(mirror), "fetch", "--no-tags", "origin", commit], check=True, capture_output=True, text=True)
        snapshots.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".rq3-", dir=snapshots))
        try:
            archive = staging / "snapshot.tar"
            with archive.open("wb") as output:
                subprocess.run(
                    ["git", "-c", "core.protectNTFS=false", "-C", str(mirror), "archive",
                     "--format=tar", commit, "--", ":(glob)**/*.py"],
                    check=True, stdout=output, stderr=subprocess.PIPE,
                )
            tree_dir = staging / "tree"
            tree_dir.mkdir()
            _extract_archive_safely(archive, tree_dir)
            archive.unlink()
            for attempt in range(8):
                try:
                    tree_dir.replace(destination)
                    break
                except PermissionError:
                    if attempt == 7:
                        raise
                    time.sleep(0.15 * (attempt + 1))
        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
        return destination
    finally:
        os.close(descriptor)
        lock.unlink(missing_ok=True)
