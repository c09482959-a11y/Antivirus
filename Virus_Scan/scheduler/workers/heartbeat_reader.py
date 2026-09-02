"""Shared heartbeat row reader."""
from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.scheduler.workers.heartbeat_read_steps import read_heartbeat_payload
from Virus_Scan.scheduler.workers.heartbeat_support import (
    heartbeat_rejection,
    safe_heartbeat_int,
)
from Virus_Scan.scheduler.workers.shared_heartbeat_evidence import record_shared_heartbeat_failure

HEARTBEAT_READ_UNAVAILABLE = None


def read_shared_heartbeat(
    heartbeat_table: object,
    job_id: object,
    generation: object = None,
) -> dict[str, object] | None:
    jid, jid_reason = safe_heartbeat_int(
        job_id,
        rejection_reason="heartbeat_job_id_rejected",
        non_finite_reason="heartbeat_job_id_non_finite",
    )
    if type(heartbeat_table) is not dict or jid_reason:
        heartbeat_rejection(
            "heartbeat_read",
            job_id,
            generation,
            jid_reason or "heartbeat_table_rejected",
        )
        return HEARTBEAT_READ_UNAVAILABLE
    try:
        return read_heartbeat_payload(heartbeat_table, jid, generation)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_shared_heartbeat_failure(
            operation="heartbeat_read",
            job_id=job_id,
            generation=generation,
            exc=exc,
        )
        return HEARTBEAT_READ_UNAVAILABLE
