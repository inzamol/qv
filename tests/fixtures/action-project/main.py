"""Fixture application for action testing containing deliberate findings."""

import httpx  # Missing dependency DEP-002
import pydantic  # Missing dependency DEP-002


def fetch():
    _ = pydantic.BaseModel
    return httpx.get("https://example.com")
