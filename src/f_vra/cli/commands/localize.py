from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer

from f_vra.cli.output.display import console
from f_vra.localization.models import LocalizationRequest
from f_vra.localization.service import localize_vulnerable_functions, write_report


def localize(
    cve_id: Optional[str] = typer.Argument(None, help="CVE ID, e.g. CVE-2024-35195"),
    repository: Optional[Path] = typer.Option(
        None,
        "--repository",
        "-r",
        help="Local Python repository; auto-cloned from CVE metadata when omitted or missing",
    ),
    description: Optional[str] = typer.Option(None, "--description", help="CVE description"),
    cwe_id: Optional[str] = typer.Option(None, "--cwe", help="CWE ID, e.g. CWE-918"),
    patch: Optional[Path] = typer.Option(None, "--patch", help="Local unified diff/patch"),
    auto_resolve_patch: bool = typer.Option(
        False,
        "--auto-resolve-patch",
        help="Resolve metadata and patch references via OSV/NVD/GitHub",
    ),
    top_k: int = typer.Option(20, "--top-k", min=1, help="Number of results"),
    use_embeddings: bool = typer.Option(
        True,
        "--embeddings/--no-embeddings",
        help="Use configured provider embeddings during candidate retrieval",
    ),
    use_llm: bool = typer.Option(
        False,
        "--use-llm",
        help="Legacy: rerank shortlist with the configured chat API",
    ),
    use_rerank: Optional[bool] = typer.Option(
        None,
        "--use-rerank/--no-rerank",
        help="Use the configured chat API to rerank candidates",
    ),
    rerank_model: Optional[str] = typer.Option(
        None,
        "--rerank-model",
        help="Rerank model override",
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write JSON report"),
) -> None:
    def progress(message: str) -> None:
        console.print(f"[cyan]{message}[/cyan]")

    report = localize_vulnerable_functions(
        LocalizationRequest(
            cve_id=cve_id,
            cve_description=description,
            cwe_id=cwe_id,
            repository_path=repository,
            patch_path=patch,
            auto_resolve_patch=auto_resolve_patch,
            top_k=top_k,
            use_llm=use_llm,
            use_rerank=use_rerank,
            rerank_model=rerank_model,
            use_embeddings=use_embeddings,
            progress_callback=progress,
        )
    )
    if output:
        write_report(report, output)
        console.print(f"Report written to {output}")
    else:
        console.print_json(json.dumps(report.to_dict(), ensure_ascii=False))
