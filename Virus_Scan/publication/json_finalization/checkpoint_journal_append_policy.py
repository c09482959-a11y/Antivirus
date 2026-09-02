"""Idempotent append policy for committed checkpoint journal mappings."""
from __future__ import annotations

from Virus_Scan.contracts.checkpoint import JsonSafeCheckpointDelta


def checkpoint_append_is_idempotent(
    existing: dict[str, object],
    delta: JsonSafeCheckpointDelta,
) -> bool:
    """Accept exact committed retries and reject divergent overlap or gaps."""
    incoming = {key: record for key, record in delta.items}
    if not incoming:
        return True
    matching = all(dict.get(existing, key) == record for key, record in incoming.items())
    if matching and delta.total_records <= len(existing):
        return True
    if delta.first_sequence != len(existing) + 1:
        raise RuntimeError("checkpoint_journal_sequence_conflict")
    if any(key in existing for key in incoming):
        raise RuntimeError("checkpoint_journal_identity_conflict")
    return False


__all__ = ("checkpoint_append_is_idempotent",)
