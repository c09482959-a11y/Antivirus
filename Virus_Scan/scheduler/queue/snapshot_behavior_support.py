"""No-hook support helpers for queue behavior snapshots."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_value_snapshot

SNAPSHOT_COUNT_REPLACEMENT = 0
UNKNOWN_PHASE = "unknown"
SNAPSHOT_ALIASES = (
    ("pending", ("pending",)),
    ("claimed", ("claimed", "active")),
    ("running", ("running", "claimed", "active")),
    ("completed", ("completed", "done", "files_done")),
    ("failed", ("failed", "files_failed")),
    ("quarantined", ("quarantined", "quarantine")),
    ("duplicate_count", ("duplicate_count", "duplicates")),
    ("invalid_record_count", ("invalid_record_count", "invalid")),
    ("orphan_lock_count", ("orphan_lock_count", "orphan_locks")),
    ("emitted_result_count", ("emitted_result_count", "results")),
    ("finalized_count", ("finalized_count", "finalized")),
)


def snapshot_reason(field_name: str) -> str:
    return "queue_snapshot_" + str.__str__(field_name) + "_rejected"


def snapshot_message_text(value: object) -> str:
    return str.__str__(value) if type(value) is str and value else UNKNOWN_PHASE


def snapshot_message_int(value: object, field_name: str) -> int:
    parsed, _reason = no_hook_exact_nonnegative_int(
        value,
        default=SNAPSHOT_COUNT_REPLACEMENT,
        reason=snapshot_reason(field_name),
        allow_exact_text=True,
    )
    return parsed


def snapshot_optional_message_int(value: object, field_name: str) -> int | None:
    if value is None:
        return None
    return snapshot_message_int(value, field_name)


def snapshot_issue(field_name: str, value: object, reason: str) -> Mapping[str, object]:
    return {
        "queue_snapshot_input_rejected": True,
        "field_name": field_name,
        "reason": reason,
        "value": scheduler_value_snapshot(value, field_name=field_name),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_reproduce": True,
    }


def snapshot_count(counts: object, field_name: str, *keys: str) -> tuple[int, tuple[Mapping[str, object], ...]]:
    raw_value: object = 0
    for key in keys:
        value = scheduler_mapping_value(counts, key)
        if value is not None:
            raw_value = value
            break
    value, reason = no_hook_exact_nonnegative_int(
        raw_value,
        default=SNAPSHOT_COUNT_REPLACEMENT,
        reason=snapshot_reason(field_name),
        allow_exact_text=True,
    )
    return ((value, (snapshot_issue(field_name, raw_value, reason),)) if reason else (value, ()))


__all__ = (
    "SNAPSHOT_ALIASES",
    "UNKNOWN_PHASE",
    "snapshot_count",
    "snapshot_issue",
    "snapshot_message_int",
    "snapshot_message_text",
    "snapshot_optional_message_int",
)
