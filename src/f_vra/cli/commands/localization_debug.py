from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import typer

from f_vra.cli.output.display import console
from f_vra.localization.retrieval.candidates import select_patch_absent
from f_vra.localization.code.function_parser import parse_repository
from f_vra.localization.sources.metadata import (
    ResolvedMetadata,
    download_patch,
    resolve_metadata,
    resolve_nvd,
    resolve_osv,
)
from f_vra.localization.models import LocalizationRequest
from f_vra.localization.sources.patch import PatchAnalysis, load_patch, parse_patch_text
from f_vra.localization.service import localize_vulnerable_functions
from f_vra.localization.code.tracker import track_patch_candidates

app = typer.Typer(help="Inspect each CVE-to-VF pipeline stage", no_args_is_help=True)


def _print_json(data: Any) -> None:
    console.print_json(json.dumps(data, ensure_ascii=False))


def _metadata_dict(metadata: ResolvedMetadata, *, include_raw: bool) -> dict[str, Any]:
    result = {
        "cve_id": metadata.cve_id,
        "source": metadata.source,
        "description": metadata.description,
        "cwe_id": metadata.cwe_id,
        "references": metadata.references,
        "patch_urls": metadata.patch_urls,
    }
    if include_raw:
        result["raw"] = metadata.raw
    return result


def _patch_dict(patch: PatchAnalysis) -> dict[str, Any]:
    return {
        "files": [
            {
                "file_path": change.file_path,
                "old_lines": sorted(change.old_lines),
                "new_lines": sorted(change.new_lines),
                "added_lines": len(change.added),
                "deleted_lines": len(change.deleted),
            }
            for change in patch.files
        ],
        "called_names": sorted(patch.called_names),
        "changed_names": sorted(patch.changed_names),
        "changed_globals": sorted(patch.changed_globals),
    }


@app.command("metadata")
def inspect_metadata(
    cve_id: str = typer.Argument(..., help="CVE ID to resolve"),
    provider: str = typer.Option("auto", "--provider", help="Provider: auto, osv, or nvd"),
    raw: bool = typer.Option(False, "--raw", help="Include raw provider response"),
) -> None:
    provider_name = provider.lower()
    if provider_name == "auto":
        metadata = resolve_metadata(cve_id)
    elif provider_name == "osv":
        metadata = resolve_osv(cve_id) or ResolvedMetadata(cve_id=cve_id)
    elif provider_name == "nvd":
        metadata = resolve_nvd(cve_id) or ResolvedMetadata(cve_id=cve_id)
    else:
        raise typer.BadParameter("provider must be auto, osv, or nvd", param_hint="--provider")

    _print_json(_metadata_dict(metadata, include_raw=raw))
    if metadata.source == "unknown":
        raise typer.Exit(code=1)


@app.command("patch")
def inspect_patch(
    cve_id: Optional[str] = typer.Argument(None, help="CVE ID used to discover patch URLs"),
    url: Optional[str] = typer.Option(None, "--url", help="Download this patch URL directly"),
    patch_path: Optional[Path] = typer.Option(None, "--patch", help="Inspect a local patch"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save downloaded patch"),
) -> None:
    if patch_path:
        analysis, source = load_patch(patch_path)
        patch_text = patch_path.read_text(encoding="utf-8", errors="ignore")
        metadata_source = "manual"
    else:
        urls = [url] if url else []
        metadata_source = "manual"
        if not urls and cve_id:
            metadata = resolve_metadata(cve_id)
            urls = metadata.patch_urls
            metadata_source = metadata.source
        if not urls:
            _print_json({"status": "not_found", "reason": "no patch URL discovered"})
            raise typer.Exit(code=1)

        downloaded = None
        for candidate_url in urls:
            downloaded = download_patch(candidate_url)
            if downloaded:
                break
        if not downloaded:
            _print_json(
                {
                    "status": "download_failed",
                    "metadata_source": metadata_source,
                    "attempted_urls": urls,
                }
            )
            raise typer.Exit(code=1)
        patch_text, source = downloaded
        analysis = parse_patch_text(patch_text)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(patch_text, encoding="utf-8")

    _print_json(
        {
            "status": "ok" if analysis.files else "invalid_patch",
            "metadata_source": metadata_source,
            "source": source,
            "saved_to": str(output.resolve()) if output else None,
            "analysis": _patch_dict(analysis),
        }
    )
    if not analysis.files:
        raise typer.Exit(code=1)


@app.command("parse")
def inspect_parser(
    repository: Path = typer.Option(..., "--repository", "-r", help="Python repository"),
    limit: int = typer.Option(20, "--limit", min=1, help="Maximum functions to print"),
) -> None:
    functions = parse_repository(repository)
    _print_json(
        {
            "repository": str(repository.resolve()),
            "functions_found": len(functions),
            "functions": [
                {
                    "qualname": function.qualname,
                    "file_path": function.file_path,
                    "start_line": function.start_line,
                    "end_line": function.end_line,
                    "is_async": function.is_async,
                    "calls": sorted(function.calls),
                    "referenced_names": sorted(function.referenced_names),
                }
                for function in functions[:limit]
            ],
            "truncated": len(functions) > limit,
        }
    )


@app.command("track")
def inspect_tracker(
    repository: Path = typer.Option(..., "--repository", "-r", help="Python repository"),
    patch_path: Path = typer.Option(..., "--patch", help="Local unified diff/patch"),
    max_depth: int = typer.Option(2, "--max-depth", min=0, help="Call graph expansion depth"),
) -> None:
    functions = parse_repository(repository)
    patch, source = load_patch(patch_path)
    evidence = track_patch_candidates(functions, patch, max_depth=max_depth)
    by_id = {function.identity: function for function in functions}
    _print_json(
        {
            "repository": str(repository.resolve()),
            "patch_source": source,
            "functions_scanned": len(functions),
            "candidates_found": len(evidence),
            "candidates": [
                {
                    "identity": identity,
                    "qualname": by_id[identity].qualname,
                    "file_path": by_id[identity].file_path,
                    "evidence": sorted(items),
                }
                for identity, items in sorted(evidence.items())
            ],
        }
    )


@app.command("retrieve")
def inspect_retrieval(
    repository: Path = typer.Option(..., "--repository", "-r", help="Python repository"),
    description: str = typer.Option(..., "--description", help="Expanded CVE description"),
    top_k: int = typer.Option(20, "--top-k", min=1),
    use_embeddings: bool = typer.Option(True, "--embeddings/--no-embeddings"),
) -> None:
    functions = parse_repository(repository)
    selection = select_patch_absent(
        description,
        functions,
        pool_size=top_k,
        use_embeddings=use_embeddings,
    )
    _print_json(
        {
            "strategy": (
                "hybrid_bm25_embeddings"
                if selection.embedding_scores
                else "bm25_fallback"
            ),
            "embedding_status": selection.embedding_status,
            "embedding_model": selection.embedding_model,
            "results": [
                {
                    "rank": rank,
                    "qualname": function.qualname,
                    "file_path": function.file_path,
                    "bm25_score": selection.lexical_scores.get(function.identity, 0.0),
                    "embedding_score": selection.embedding_scores.get(function.identity),
                    "fused_score": selection.relevance_scores.get(function.identity, 0.0),
                }
                for rank, function in enumerate(selection.candidates, 1)
            ],
        }
    )


@app.command("run")
def inspect_full_run(
    repository: Path = typer.Option(..., "--repository", "-r", help="Python repository"),
    cve_id: Optional[str] = typer.Option(None, "--cve", help="CVE ID"),
    description: Optional[str] = typer.Option(None, "--description", help="CVE description"),
    cwe_id: Optional[str] = typer.Option(None, "--cwe", help="CWE ID"),
    patch_path: Optional[Path] = typer.Option(None, "--patch", help="Local unified diff/patch"),
    auto_resolve_patch: bool = typer.Option(False, "--auto-resolve-patch"),
    top_k: int = typer.Option(20, "--top-k", min=1),
    use_embeddings: bool = typer.Option(True, "--embeddings/--no-embeddings"),
) -> None:
    report = localize_vulnerable_functions(
        LocalizationRequest(
            repository_path=repository,
            cve_id=cve_id,
            cve_description=description,
            cwe_id=cwe_id,
            patch_path=patch_path,
            auto_resolve_patch=auto_resolve_patch,
            top_k=top_k,
            use_embeddings=use_embeddings,
        )
    )
    _print_json(report.to_dict())
