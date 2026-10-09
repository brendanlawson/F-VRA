from __future__ import annotations

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, TimeElapsedColumn
from rich.table import Table
from rich.tree import Tree

from f_vra.core.models import IndexResult, LocalizeResult, ScanResult, Verdict

console = Console(legacy_windows=False)


def make_progress() -> Progress:
    return Progress(
        "[progress.description]{task.description}",
        TimeElapsedColumn(),
        console=console,
    )


def print_index_result(result: IndexResult) -> None:
    table = Table(title=f"Index: {result.package}=={result.version}", show_header=True, box=box.ASCII)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Package", f"{result.package}=={result.version}")
    table.add_row("Functions", str(result.functions))
    table.add_row("API count", str(result.api_count))
    table.add_row("Elapsed (s)", f"{result.elapsed_s:.2f}")
    table.add_row("Cached", str(result.cached))
    console.print(table)


def print_localize_result(result: LocalizeResult) -> None:
    table = Table(title=f"Localize: {result.cve_id}", show_header=True, box=box.ASCII)
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("CVE ID", result.cve_id)
    table.add_row("Mode", result.mode)
    table.add_row("Vulnerable function", f"[bold yellow]{result.vf}[/bold yellow]" if result.vf else "[dim]-[/dim]")
    table.add_row("Score", f"{result.score:.3f}")
    table.add_row("Candidates", ", ".join(result.candidates) if result.candidates else "[dim]none[/dim]")
    table.add_row("Cached", str(result.cached))
    console.print(table)


def print_scan_result(result: ScanResult, explain: bool = False) -> None:
    if result.verdict == Verdict.AFFECTED:
        style, title = "red", "REACHABLE"
    elif result.verdict == Verdict.NOT_AFFECTED:
        style, title = "green", "NOT REACHABLE"
    else:
        style, title = "yellow", "UNKNOWN"

    body = (
        f"CVE: {result.cve_id}\n"
        f"Project: {result.project}\n"
        f"Query time: {result.query_time_ms:.1f} ms\n"
        f"LLM invoked: {result.llm_invoked}"
    )
    console.print(Panel(body, title=title, border_style=style))

    if explain and result.call_chain:
        tree = Tree("[bold]Call chain[/bold]")
        node = tree
        for fn in result.call_chain:
            node = node.add(fn)
        console.print(tree)
