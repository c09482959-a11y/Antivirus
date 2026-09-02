"""Replayable active-claim deferral decisions for orphan recovery."""
from __future__ import annotations

from typing import Mapping, TYPE_CHECKING

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.evidence.process_queue_errors import record_scheduler_suppressed
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping

if TYPE_CHECKING:
    from pathlib import Path


def deferred_claim_state_record(reason: str, *, src: Path, value: object) -> Mapping[str, object]:
    """Build a replay/checkpoint/final-JSON visible active-claim deferral."""
    return immutable_mapping({
        "stage": "process_queue_orphan_claim_state",
        "state": "deferred",
        "error_category": reason,
        "error_source": "scheduler.queue.orphan_recovery_claim_state",
        "message": reason,
        "source": str(src),
        "value_type": no_hook_type_name(value),
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    })


def deferred_claim_state_none(
    reason: str,
    *,
    src: Path,
    value: object,
    sink: list[Mapping[str, object]] | None,
) -> None:
    """Preserve None deferral semantics while making the decision replayable."""
    record = deferred_claim_state_record(reason, src=src, value=value)
    if sink is not None:
        sink.append(record)
    record_scheduler_suppressed(
        "process_queue_orphan_claim_state_deferred",
        RuntimeError(reason),
        extra=record,
    )


__all__ = ("deferred_claim_state_none", "deferred_claim_state_record")
