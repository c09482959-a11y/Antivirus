"""Canonical in-memory heartbeat progress identity and change detection."""
from __future__ import annotations

from typing import Mapping, TypeAlias

from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value

HeartbeatProgressSignature: TypeAlias = tuple[str, int, int, int]


def heartbeat_progress_signature(
    *,
    stage: str,
    progress_counter: int,
    bytes_processed: int,
    last_progress_ns: int,
) -> HeartbeatProgressSignature:
    """Return the one canonical progress identity used by every heartbeat transport."""

    if type(stage) is not str or not stage:
        raise ValueError("heartbeat_progress_stage_rejected")
    for value, field in (
        (progress_counter, "progress_counter"),
        (bytes_processed, "bytes_processed"),
        (last_progress_ns, "last_progress_ns"),
    ):
        if type(value) is not int or type(value) is bool or value < 0:
            raise ValueError("heartbeat_progress_" + field + "_rejected")
    return (stage, progress_counter, bytes_processed, last_progress_ns)


def heartbeat_progress_changed(
    record: Mapping[str, object],
    signature: HeartbeatProgressSignature,
) -> bool:
    """Return whether the canonical progress identity changed from latest parent state."""

    existing = scheduler_mapping_value(record, "last_progress_signature", default=None)
    comparable = (
        type(existing) is tuple
        and len(existing) == 4
        and type(existing[0]) is str
        and type(existing[1]) is int
        and type(existing[1]) is not bool
        and type(existing[2]) is int
        and type(existing[2]) is not bool
        and type(existing[3]) is int
        and type(existing[3]) is not bool
    )
    return not comparable or existing != signature


__all__ = (
    "HeartbeatProgressSignature",
    "heartbeat_progress_changed",
    "heartbeat_progress_signature",
)
