"""Immutable checkpoint contracts shared across scheduler and publication."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePath

from Virus_Scan.contracts.no_hook_materialization import no_hook_text


@dataclass(frozen=True, slots=True)
class JsonSafeCheckpointDelta:
    """New immutable recovery records for one append-only checkpoint commit."""

    items: tuple[tuple[str, object], ...]
    first_sequence: int
    total_records: int


def checkpoint_key_text(value: object) -> tuple[str, str]:
    """Return one hook-free checkpoint identity or an explicit rejection reason."""
    if isinstance(value, PurePath):
        return PurePath.__str__(value), ""
    return no_hook_text(
        value,
        missing_reason="checkpoint_terminal_key_missing",
        unsupported_reason="checkpoint_terminal_key_unsupported",
    )


__all__ = ("JsonSafeCheckpointDelta", "checkpoint_key_text")
