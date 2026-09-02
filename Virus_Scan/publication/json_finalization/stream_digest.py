"""Bounded streaming digest and size accounting."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO


@dataclass(slots=True)
class DigestingBinaryWriter:
    """Write UTF-8 text while computing the exact byte digest and size."""

    stream: BinaryIO
    digest: object = field(default_factory=hashlib.sha256)
    size: int = 0

    def write_text(self, value: str) -> None:
        data = value.encode("utf-8")
        self.stream.write(data)
        self.digest.update(data)
        self.size += len(data)

    def result(self) -> tuple[str, int]:
        return self.digest.hexdigest(), self.size


def file_digest_and_size(path: str | Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            digest.update(block)
    return digest.hexdigest(), size


__all__ = ("DigestingBinaryWriter", "file_digest_and_size")
