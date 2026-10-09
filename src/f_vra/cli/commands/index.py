import typer
from f_vra.cli.output.display import console, print_index_result, make_progress
from f_vra.analysis.package.service import index_package

app = typer.Typer(help="[Offline] Build PCSG index for a PyPI library.")


@app.callback(invoke_without_command=True)
def index(
    package_version: str  = typer.Argument(..., metavar="pkg==version",
                                help="e.g. requests==2.31.0"),
    force:  bool = typer.Option(False, "--force",  help="Rebuild even if index exists"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM type oracle"),
    neo4j:  bool = typer.Option(False, "--neo4j",  help="Also write to Neo4j"),
):
    if "==" not in package_version:
        console.print("[red]Error:[/red] use format pkg==version")
        raise typer.Exit(1)
    pkg, ver = package_version.split("==", 1)

    with make_progress() as progress:
        task = progress.add_task("Indexing package source...", total=None)
        result = index_package(pkg, ver)
        progress.update(task, description="[green]Index complete[/green]")
    print_index_result(result)
