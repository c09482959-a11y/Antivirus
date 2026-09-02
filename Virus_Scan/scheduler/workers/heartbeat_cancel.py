"""Cooperative cancellation reads from scheduler-owned heartbeat tables."""
from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.workers.heartbeat_support import heartbeat_rejection
from Virus_Scan.scheduler.workers.heartbeat_cancel_steps import (
    cancel_identity,
    heartbeat_cancel_requested,
)
from Virus_Scan.scheduler.workers.shared_heartbeat_evidence import record_shared_heartbeat_failure

HEARTBEAT_CANCEL_NOT_REQUESTED = False


def cooperative_cancel_requested(cancel_table: object, job_id: object, generation: object) -> bool:
    if cancel_table is None:
        return HEARTBEAT_CANCEL_NOT_REQUESTED
    identity = cancel_identity(job_id, generation)
    if type(cancel_table) is not dict or type(identity) is str:
        heartbeat_rejection(
            "cancel_read",
            job_id,
            generation,
            identity if type(identity) is str else "cancel_table_rejected",
        )
        return HEARTBEAT_CANCEL_NOT_REQUESTED
    try:
        return heartbeat_cancel_requested(cancel_table, identity)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_shared_heartbeat_failure(
            operation="cancel_read", job_id=job_id, generation=generation, exc=exc
        )
        return HEARTBEAT_CANCEL_NOT_REQUESTED


__all__ = ("cooperative_cancel_requested",)
