import typer
from f_vra.cli.commands import eval as eval_cmd
from f_vra.cli.commands import index, localization_debug, localize, scan, status

app = typer.Typer(
    name="f-vra",
    help="Vulnerability Reachability Analysis for Python/PyPI",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

app.add_typer(index.app,    name="index")
app.command(name="localize")(localize.localize)
app.add_typer(localization_debug.app, name="localization")
app.add_typer(scan.app,     name="scan")
app.add_typer(status.app,   name="status")
app.add_typer(eval_cmd.app, name="eval")

if __name__ == "__main__":
    app()
