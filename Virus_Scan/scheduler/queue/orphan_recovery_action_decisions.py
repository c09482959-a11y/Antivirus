"""Replayable queue orphan-recovery action decisions."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ClaimMetaRemovalDecision:
    """Decision for interpreting claim-sidecar cleanup results."""

    removed: bool
    accepted: bool
    reason: str
    source_type: str


@dataclass(frozen=True, slots=True)
class MoveResultDecision:
    """Decision for interpreting queue atomic move results."""

    succeeded: bool
    accepted: bool
    reason: str
    source_type: str


@dataclass(frozen=True, slots=True)
class ReclaimJobIdentifierDecision:
    """Decision for resolving the externally published reclaim job id."""

    identifier: object
    accepted: bool
    reason: str
    source_key: str
    source_type: str


def claim_meta_removed_decision(result: object) -> ClaimMetaRemovalDecision:
    if type(result) is bool:
        return ClaimMetaRemovalDecision(
            removed=result,
            accepted=True,
            reason="bool_claim_meta_result",
            source_type="bool",
        )
    return ClaimMetaRemovalDecision(
        removed=False,
        accepted=False,
        reason="non_bool_claim_meta_result",
        source_type=type(result).__name__,
    )


def move_result_succeeded_decision(result: object) -> MoveResultDecision:
    if type(result) is bool:
        return MoveResultDecision(
            succeeded=result,
            accepted=True,
            reason="bool_move_result",
            source_type="bool",
        )
    return MoveResultDecision(
        succeeded=False,
        accepted=False,
        reason="non_bool_move_result",
        source_type=type(result).__name__,
    )


def reclaim_job_identifier_decision(job: object) -> ReclaimJobIdentifierDecision:
    if type(job) is not dict:
        return ReclaimJobIdentifierDecision(
            identifier="",
            accepted=False,
            reason="non_dict_job_record",
            source_key="",
            source_type=type(job).__name__,
        )
    for key in ("id", "job_id", "file"):
        value = dict.get(job, key)
        if value is not None:
            return ReclaimJobIdentifierDecision(
                identifier=value,
                accepted=True,
                reason="job_identifier_found",
                source_key=key,
                source_type="dict",
            )
    return ReclaimJobIdentifierDecision(
        identifier="",
        accepted=False,
        reason="job_identifier_missing",
        source_key="",
        source_type="dict",
    )


__all__ = (
    "ClaimMetaRemovalDecision",
    "MoveResultDecision",
    "ReclaimJobIdentifierDecision",
    "claim_meta_removed_decision",
    "move_result_succeeded_decision",
    "reclaim_job_identifier_decision",
)
