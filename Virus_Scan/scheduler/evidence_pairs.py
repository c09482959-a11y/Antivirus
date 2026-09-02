"""Canonical replayable scheduler evidence-pair primitive."""
from __future__ import annotations

JsonEvidencePairs = tuple[tuple[str, object], ...]


def scheduler_evidence_pairs(*pairs: tuple[str, object]) -> JsonEvidencePairs:
    return tuple(pairs)


__all__ = ("JsonEvidencePairs", "scheduler_evidence_pairs")
