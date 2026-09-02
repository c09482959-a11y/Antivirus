"""Canonical reporting JSON writer ownership.

This module is the reporting-owned boundary for deterministic JSON persistence.
It delegates durable fsync/atomic replacement mechanics to the core JSON I/O
owner, while keeping reporting callers on a statically discoverable module path.
"""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.core.jsonio import atomic_json_save


def write_reporting_json(path: str, payload: Mapping[str, object] | list[object], *, backups: int = 0) -> None:
    """Write a reporting JSON document through the canonical atomic writer."""
    atomic_json_save(str(path), payload, backups=backups)


__all__ = ("write_reporting_json",)
