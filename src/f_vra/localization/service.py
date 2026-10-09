from __future__ import annotations

import json
from pathlib import Path
from f_vra.core.models import LocalizeResult
from f_vra.localization.retrieval.candidates import select_patch_absent, select_patch_present
from f_vra.localization.retrieval.expansion import expand_description
from f_vra.localization.code.function_parser import parse_repository
from f_vra.localization.sources import (
    ResolvedMetadata,
    clone_or_update,
    download_patch,
    github_commit_from_references,
    github_repo_urls_from_references,
    load_patch,
    parse_patch_text,
    resolve_metadata,
)
from f_vra.localization.models import LocalizationReport, LocalizationRequest
from f_vra.localization.ranking.methods.description import enrich_description_with_llm_entities
from f_vra.localization.ranking.methods.pairwise import PairwiseRankingConfig, pairwise_rank_scores
from f_vra.localization.ranking.ranking import rank_candidates
from f_vra.localization.code.tracker import track_patch_candidates


def _resolve_request_metadata(request: LocalizationRequest) -> ResolvedMetadata:
    if request.cve_description:
        return ResolvedMetadata(
            cve_id=request.cve_id,
            description=request.cve_description,
            cwe_id=request.cwe_id,
            source="manual",
        )
    if not request.cve_id:
        raise ValueError("Either cve_id or cve_description is required")
    resolved = resolve_metadata(request.cve_id)
    if not resolved.description:
        raise ValueError(
            f"Could not resolve a description for {request.cve_id}; "
            "provide cve_description explicitly"
        )
    if request.cwe_id:
        resolved.cwe_id = request.cwe_id
    return resolved


def localize_vulnerable_functions(request: LocalizationRequest) -> LocalizationReport:
    def progress(message: str) -> None:
        if request.progress_callback:
            request.progress_callback(message)

    if request.top_k < 1:
        raise ValueError("top_k must be at least 1")
    if request.candidate_pool_size < request.top_k:
        raise ValueError("candidate_pool_size must be at least top_k")
    if request.tracker_max_depth < 0:
        raise ValueError("tracker_max_depth must be non-negative")
    if request.cve_repeat < 1:
        raise ValueError("cve_repeat must be at least 1")

    progress("Resolving CVE metadata")
    metadata = _resolve_request_metadata(request)
    repository = request.repository_path.resolve() if request.repository_path else None
    repository_source = "local"
    repository_commit = None
    if repository is None or not repository.is_dir():
        references = [*metadata.patch_urls, *metadata.references]
        repo_urls = github_repo_urls_from_references(references)
        if not repo_urls:
            missing = (
                str(repository)
                if repository is not None
                else "no --repository was provided"
            )
            raise NotADirectoryError(
                f"Repository path is not a directory: {missing}. "
                "Could not infer a GitHub repository from CVE metadata; use a "
                "resolvable GitHub-based CVE or call the Python API with "
                "repository_path for a local checkout."
            )
        repository_commit = github_commit_from_references(references)
        progress(
            f"Cloning repository {repo_urls[0]}"
            + (f" at {repository_commit}" if repository_commit else "")
        )
        repository = clone_or_update(repo_urls[0], commit=repository_commit).resolve()
        repository_source = repo_urls[0]

    description = expand_description(
        metadata.description,
        metadata.cwe_id,
        original_repeat=request.cve_repeat,
    )
    description_enrichment = {
        "enabled": request.extract_entities,
        "status": "disabled",
        "model": request.entity_model,
        "entities": {},
    }
    if request.extract_entities:
        progress("Extracting CVE search entities with LLM")
        enriched = enrich_description_with_llm_entities(
            description,
            model=request.entity_model,
        )
        description = enriched.text
        description_enrichment.update(
            {
                "status": enriched.status,
                "model": enriched.model,
                "entities": enriched.entities,
            }
        )
    progress(f"Parsing Python functions under {repository}")
    functions = parse_repository(repository)
    if not functions:
        raise ValueError(f"No Python functions found under {repository}")

    patch_analysis = None
    patch_source = None
    if request.patch_path:
        progress(f"Loading local patch {request.patch_path}")
        patch_analysis, patch_source = load_patch(request.patch_path)
    elif request.auto_resolve_patch:
        if metadata.source == "manual" and request.cve_id:
            progress("Resolving patch metadata")
            metadata = resolve_metadata(request.cve_id)
            if request.cve_description:
                metadata.description = request.cve_description
            if request.cwe_id:
                metadata.cwe_id = request.cwe_id
            description = expand_description(
                metadata.description,
                metadata.cwe_id,
                original_repeat=request.cve_repeat,
            )
        for url in metadata.patch_urls:
            progress(f"Downloading patch candidate {url}")
            downloaded = download_patch(url)
            if downloaded:
                patch_text, patch_source = downloaded
                patch_analysis = parse_patch_text(patch_text)
                break

    if patch_analysis is not None and patch_analysis.files:
        mode = "PATCH_PRESENT"
        progress("Tracking patch-related functions")
        tracker_evidence = track_patch_candidates(
            functions,
            patch_analysis,
            max_depth=request.tracker_max_depth,
            repository_root=repository,
        )
        progress("Selecting candidates with patch evidence and retrieval")
        selection = select_patch_present(
            description,
            functions,
            tracker_evidence,
            pool_size=request.candidate_pool_size,
            use_embeddings=request.use_embeddings,
        )
    else:
        mode = "PATCH_ABSENT"
        progress("Selecting candidates with lexical and semantic retrieval")
        selection = select_patch_absent(
            description,
            functions,
            pool_size=request.candidate_pool_size,
            use_embeddings=request.use_embeddings,
        )

    rerank_metadata: dict[str, str | bool | None] = {}
    pairwise_metadata: dict[str, str | bool | int | None] = {
        "enabled": True,
    }
    progress("Ranking candidates with Swiss/exhaustive pairwise ranking")
    pairwise_scores, pairwise_details = pairwise_rank_scores(
        description,
        selection.candidates,
        selection.relevance_scores,
        selection.evidence,
        config=PairwiseRankingConfig(
            swiss_rounds=request.swiss_rounds,
            finalists=max(request.top_k, request.finalists),
            use_pairwise=request.pairwise,
            model=request.pairwise_model,
        ),
    )
    pairwise_metadata.update(pairwise_details)
    candidates = rank_candidates(
        description,
        selection.candidates,
        selection.relevance_scores,
        selection.evidence,
        top_k=request.top_k,
        use_llm=False,
        use_rerank=False,
        rerank_model=None,
        pairwise_scores=pairwise_scores,
        rerank_metadata=rerank_metadata,
    )
    return LocalizationReport(
        cve_id=request.cve_id or metadata.cve_id,
        cve_description=metadata.description,
        cwe_id=metadata.cwe_id,
        repository_path=str(repository),
        mode=mode,
        patch_source=patch_source,
        metadata_source=metadata.source,
        candidates=candidates,
        metadata={
            "functions_scanned": len(functions),
            "candidate_pool_size": len(selection.candidates),
            "repository_source": repository_source,
            "repository_commit": repository_commit,
            "references": metadata.references,
            "rerank_used": bool(rerank_metadata.get("used")),
            "rerank_status": rerank_metadata.get("status", "disabled"),
            "rerank_source": rerank_metadata.get("source"),
            "rerank_model": rerank_metadata.get("model"),
            "localization_method": "configurable_hybrid_pairwise",
            "candidate_pool_size": request.candidate_pool_size,
            "tracker_max_depth": request.tracker_max_depth,
            "cve_repeat": request.cve_repeat,
            "method_config": {
                "description_strategy": "cve_cwe_repeat",
                "ranking_strategy": "swiss_exhaustive_pairwise",
                "use_embeddings": request.use_embeddings,
                "pairwise": request.pairwise,
                "extract_entities": request.extract_entities,
            },
            "description_enrichment": description_enrichment,
            "pairwise_ranking": pairwise_metadata,
            "retrieval": {
                "strategy": (
                    "hybrid_bm25_embeddings"
                    if selection.embedding_scores
                    else "bm25_fallback"
                ),
                "embedding_status": selection.embedding_status,
                "embedding_model": selection.embedding_model,
            },
        },
    )


def write_report(report: LocalizationReport, output: str | Path) -> None:
    target = Path(output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def localize(
    cve_id: str,
    *,
    description: str = "",
    repo_path: str | Path | None = None,
    top_k: int = 20,
) -> LocalizeResult:
    """Compact localization result for simple Python callers."""
    if repo_path is None:
        return LocalizeResult(cve_id=cve_id, package="", mode="needs_context")
    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id=cve_id,
            cve_description=description or None,
            repository_path=Path(repo_path),
            top_k=top_k,
        )
    )
    names = [candidate.qualname for candidate in report.candidates]
    top = report.candidates[0] if report.candidates else None
    return LocalizeResult(
        cve_id=cve_id,
        package=Path(repo_path).name,
        vf=top.qualname if top else "",
        score=top.score if top else 0.0,
        mode=report.mode,
        candidates=names,
    )
