"""Detection-owned bounded file read contract."""
from __future__ import annotations

from pathlib import Path
from typing import Optional


def read_file_bytes(path: str | Path, max_size: Optional[int] = 5_000_000) -> bytes:
    """Read bytes through an explicit detection boundary without runtime globals."""
    with Path(path).open("rb") as handle:
        if max_size is None or int(max_size) < 0:
            return handle.read()
        return handle.read(int(max_size))


__all__ = ("read_file_bytes",)
