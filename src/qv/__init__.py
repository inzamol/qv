"""qv - Package-manager-agnostic diagnostic platform for Python projects."""

from __future__ import annotations

import importlib.metadata

try:
    __version__ = importlib.metadata.version("python-qv")
except Exception:
    try:
        __version__ = importlib.metadata.version("qv")
    except Exception:
        __version__ = "0.1.5"
