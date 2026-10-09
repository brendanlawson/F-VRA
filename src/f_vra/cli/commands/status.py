import typer
from typing import Optional
from f_vra.cli.output.display import console
from f_vra.core.config import settings

app = typer.Typer(help="Show indexed libraries.")


@app.callback(invoke_without_command=True)
def status(
    package_version: Optional[str] = typer.Argument(None, metavar="pkg==version"),
):
    index_dir = settings.index_dir
    if not index_dir.exists():
        console.print(
            "[yellow]No index found.[/yellow] Run: f-vra index <pkg==version>"
        )
        return

    entries = sorted(index_dir.glob("*/*"))
    if not entries:
        console.print("[yellow]Index is empty.[/yellow]")
        return

    if package_version:
        console.print(f"[dim]Status for {package_version}: not implemented yet[/dim]")
    else:
        console.print(f"[bold]Indexed packages[/bold] ({len(entries)} versions)")
        for e in entries:
            console.print(f"  {e.parent.name}=={e.name}")
