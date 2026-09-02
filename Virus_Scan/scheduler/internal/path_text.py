"""Canonical scheduler-owned path text projections."""
from __future__ import annotations

from pathlib import Path


def scheduler_posix_path_text(path: Path) -> str:
    """Return scheduler-owned Path text without invoking caller objects."""
    return path.as_posix()


__all__ = ("scheduler_posix_path_text",)
