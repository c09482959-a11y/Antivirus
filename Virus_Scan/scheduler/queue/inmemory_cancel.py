"""In-memory queue cancellation payload publication ownership."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import MutableMapping, MutableSet

from Virus_Scan.scheduler.queue.inmemory_retry_recovery import (
    publish_cancel_payload,
    replace_with_history_transition,
)


@dataclass(frozen=True, slots=True)
class InMemoryCancelRequest:
    """Internal request for one cooperative cancellation publication."""

    job_records: MutableMapping[int, dict[str, object]]
    terminal: MutableSet[int]
    job_id: int
    reason: object
    cancel_table: object
    cancel_generation: object
    cancel_flags: object
    cancel_stall_poison_mask: int
    pid: object = None


def request_cancel_only(request: InMemoryCancelRequest) -> bool:
    """Publish one cooperative cancellation through the canonical request owner."""
    job_records = request.job_records
    terminal = request.terminal
    job_id = request.job_id
    reason = request.reason
    cancel_table = request.cancel_table
    cancel_generation = request.cancel_generation
    cancel_flags = request.cancel_flags
    cancel_stall_poison_mask = request.cancel_stall_poison_mask
    pid = request.pid
    rec = job_records.get(job_id)
    if not rec or job_id in terminal:
        return False
    gen = int(rec.get("attempt", 0) or 0)
    cancel_publication = publish_cancel_payload(
        job_id=job_id,
        reason=reason,
        generation=gen,
        cancel_table=cancel_table,
        cancel_generation=cancel_generation,
        cancel_flags=cancel_flags,
        flags=int(cancel_stall_poison_mask),
    )
    if cancel_publication.evidence is not None:
        rec["cancel_publication_failed"] = True
        rec["cancel_publication_evidence"] = dict(cancel_publication.evidence.as_record())
    now_cancel = time.time()
    rec["cancel_requested_at"] = now_cancel
    rec["cancel_reason"] = str(reason)
    replace_with_history_transition(
        job_records=job_records,
        job_id=job_id,
        record=rec,
        reason=reason,
        pid=pid,
        now=now_cancel,
        action="cancel_only",
        extra={"cancel_only": True, **cancel_publication.as_history_extra()},
    )
    return True



__all__ = (
    'InMemoryCancelRequest',
    'request_cancel_only',
)
