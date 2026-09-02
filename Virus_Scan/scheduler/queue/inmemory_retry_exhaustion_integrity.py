"""Retry-exhaustion scan-integrity projection owned by the queue retry boundary."""
from __future__ import annotations

from typing import MutableMapping

from Virus_Scan.scheduler.queue.inmemory_retry_contracts import (
    project_retry_contract_failures,
    safe_retry_history,
    safe_retry_int,
)
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_text


def attach_retry_exhaustion_integrity(
    *,
    res: dict[str, object],
    rec: dict[str, object],
    job_records: MutableMapping[int, dict[str, object]],
    job_id: int,
    reason: object,
    old_generation: int,
    pid: object,
    cancel_publication: object,
) -> None:
    """Attach deterministic retry-exhaustion evidence to a worker result."""
    reason_text = scheduler_evidence_text(reason, missing_text="retry_exhausted", field_name="retry_reason")
    res["scheduler_failure_reason"] = reason_text
    res["scheduler_retry_count"] = old_generation
    res["scheduler_history"] = safe_retry_history(
        record=rec,
        job_id=job_id,
        generation=old_generation,
        reason=reason,
    )[-10:]
    job_records[job_id] = rec
    integrity_snapshot = materialize_scheduler_mapping(dict.get(res, "scan_integrity"))
    integrity = integrity_snapshot if type(integrity_snapshot) is dict else {
        "scheduler_scan_integrity_rejected": True,
        "queue_failure": True,
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_reproduce": True,
    }
    worker_pid, rec = safe_retry_int(
        value=0 if pid is None else pid,
        replacement_value=0,
        job_id=job_id,
        generation=old_generation,
        reason=reason,
        field="pid",
        record=rec,
    )
    job_records[job_id] = rec
    worker_failure_evidence = {
        "reason": reason_text,
        "worker_pid": worker_pid,
        "job_id": int(job_id),
        "attempt": old_generation,
        "queue_failure": True,
    }
    integrity["inmemory_worker_failure_evidence"] = worker_failure_evidence
    if reason_text == "worker_exit":
        integrity["inmemory_worker_exit_evidence"] = worker_failure_evidence
    integrity = project_retry_contract_failures(integrity=integrity, record=rec)
    if cancel_publication.evidence is not None:
        integrity.update(cancel_publication.evidence.as_scan_integrity())
        res["retry_cancel_publication_failed"] = True
        res["retry_cancel_publication_evidence"] = dict(cancel_publication.evidence.as_record())
    res["scan_integrity"] = integrity
