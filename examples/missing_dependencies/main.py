# pyright: reportMissingImports=false
"""Sample application using undeclared dependencies httpx and pydantic."""

import click
import httpx
from pydantic import BaseModel


class UserPayload(BaseModel):
    user_id: int
    email: str


@click.command()
@click.argument("user_id", type=int)
def fetch_user(user_id: int) -> None:
    """Fetch user info from API."""
    response = httpx.get(f"https://api.example.com/users/{user_id}")
    if response.status_code == 200:
        user = UserPayload(**response.json())
        click.echo(f"Loaded user: {user.email}")


if __name__ == "__main__":
    fetch_user()
