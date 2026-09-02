"""Test-only environment override helper with explicit restoration."""
from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator, Mapping
import os


@contextmanager
def temporary_environ(values: Mapping[str, str] | None = None, *, clear: tuple[str, ...] = ()) -> Iterator[None]:
    keys = tuple(dict(values or {}).keys()) + tuple(clear or ())
    previous = {key: os.environ.get(key) for key in keys}
    try:
        for key in clear:
            os.environ.pop(key, None)
        for key, value in dict(values or {}).items():
            os.environ[str(key)] = str(value)
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
