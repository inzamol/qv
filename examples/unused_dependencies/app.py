"""Application only using click — requests and pyyaml are declared but never imported."""

import click


@click.command()
def hello():
    click.echo("Hello from unused dependencies example!")


if __name__ == "__main__":
    hello()
