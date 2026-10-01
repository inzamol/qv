# pyright: reportMissingImports=false, reportMissingModuleSource=false
"""Service attempting to import non-existent local submodule."""

# This will trigger IMP-002: Unresolved local import
from .missing_token import verify_token


def handle_request(auth_header: str) -> bool:
    return verify_token(auth_header)
