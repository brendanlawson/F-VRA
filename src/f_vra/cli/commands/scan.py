import json
import typer
from pathlib import Path
from typing import Optional
from f_vra.cli.output.display import console, print_scan_result
from f_vra.reachability.service import query
from f_vra.core.models import OutputFormat, Verdict

app = typer.Typer(help="[Online] Check if a project is affected by a CVE.")


@app.callback(invoke_without_command=True)
def scan(
    cve:       str            = typer.Option(...,        "--cve",
                                    help="CVE ID, e.g. CVE-2024-35195"),
    project:   Path           = typer.Option(Path("."),  "--project",
                                    help="Project root (default: current dir)"),
    portfolio: Optional[Path] = typer.Option(None,       "--portfolio",
                                    help="YAML file with multiple project paths"),
    explain:   bool           = typer.Option(False,      "--explain",
                                    help="Show call chain (requires Neo4j)"),
    fmt:       OutputFormat   = typer.Option(OutputFormat.table, "--format"),
    output:    Optional[Path] = typer.Option(None,       "--output",
                                    help="Write result to file"),
    fail_on:   bool           = typer.Option(False,      "--fail-on-affected",
                                    help="Exit code 1 if AFFECTED (for CI)"),
):
    projects = _resolve_projects(project, portfolio)

    for proj in projects:
        result = query(
            cve_id=cve, project=proj, vf="", explain=explain
        )

        if fmt == OutputFormat.table:
            print_scan_result(result, explain=explain)
        elif fmt == OutputFormat.json:
            data = _to_dict(result)
            if output:
                output.write_text(json.dumps(data, indent=2))
            else:
                console.print_json(json.dumps(data))
        elif fmt == OutputFormat.sarif:
            console.print("[dim]SARIF output: not implemented yet[/dim]")

        if fail_on and result.verdict == Verdict.AFFECTED:
            raise typer.Exit(1)


def _resolve_projects(project: Path, portfolio: Optional[Path]) -> list[Path]:
    if portfolio and portfolio.exists():
        import yaml
        data = yaml.safe_load(portfolio.read_text())
        return [Path(p["path"]) for p in data.get("projects", [])]
    return [project]


def _to_dict(result) -> dict:
    return {
        "cve_id":        result.cve_id,
        "project":       str(result.project),
        "verdict":       result.verdict.value,
        "vf":            result.vf,
        "entry_points":  result.entry_points,
        "hit_set":       result.hit_set,
        "query_time_ms": result.query_time_ms,
        "llm_invoked":   result.llm_invoked,
    }
