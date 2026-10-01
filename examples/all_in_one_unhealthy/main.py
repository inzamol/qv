# pyright: reportMissingImports=false
"""Main app with missing dependencies and circular import references."""

import click
import httpx  # MISSING: triggers DEP-002
from cycle_a import step_a
from pydantic import BaseModel  # MISSING: triggers DEP-002


class HealthResponse(BaseModel):
    status: str


@click.command()
def run():
    _ = httpx.get("https://api.example.com")
    click.echo(f"Running: {step_a()}")


if __name__ == "__main__":
    run()
