"""Clean fixture application with no diagnostic findings."""

import click


@click.command()
def cli():
    click.echo("Clean project")
