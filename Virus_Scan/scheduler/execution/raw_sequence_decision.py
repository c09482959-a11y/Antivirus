"""Replayable raw sequence-number normalization decisions."""
from __future__ import annotations

from dataclasses import dataclass



@dataclass(frozen=True)
class RawSequenceDecision:
    """Replayable raw-result sequence-number normalization decision."""

    seq: int | None
    accepted: bool
    reason: str


def raw_sequence_decision(value: object) -> RawSequenceDecision:
    if value is None:
        return RawSequenceDecision(None, accepted=False, reason="raw_sequence_missing")
    if type(value) is int and type(value) is not bool:
        return RawSequenceDecision(value, accepted=True, reason="raw_sequence_available")
    return RawSequenceDecision(None, accepted=False, reason="raw_sequence_rejected")


__all__ = ("RawSequenceDecision", "raw_sequence_decision")
