"""Queue-owned active claim metadata merge and protection decisions."""
from __future__ import annotations



from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_claim_meta_path as _queue_claim_meta_path
from Virus_Scan.scheduler.runtime.queue_json import read_json_file
from Virus_Scan.scheduler.queue.claim_meta import merge_claim_meta_into_job, read_claim_meta
from Virus_Scan.scheduler.queue.time import queue_now, queue_path_mtime_age
from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as _process_queue_record_suppressed
from Virus_Scan.scheduler.queue.claim_sidecar_policy import active_claim_is_protected


def process_queue_read_claim_meta(claim_path: object) -> object:
    """Read active-claim metadata through queue-authority claim ownership."""
    return read_claim_meta(
        claim_path,
        claim_meta_path=_queue_claim_meta_path,
        now=queue_now,
        report=_process_queue_record_suppressed,
    )


def process_queue_merge_claim_meta_into_job(claim_path: object, current_job: object = None) -> object:
    """Merge sidecar claim metadata into an immutable queue-job view."""
    return merge_claim_meta_into_job(
        claim_path,
        current_job,
        read_claim_meta=process_queue_read_claim_meta,
    )


def _queue_missing_worker_liveness(worker_pid: object) -> bool:
    """Fail closed when worker liveness was not supplied by worker ownership."""
    try:
        text, reason = no_hook_text(
            worker_pid,
            missing_reason="queue_worker_pid_missing",
            unsupported_reason="queue_worker_pid_rejected",
        )
        extra = (
            {"worker_pid": reason, "worker_pid_type": no_hook_type_name(worker_pid)}
            if reason
            else {"worker_pid": text}
        )
        _process_queue_record_suppressed(
            "queue_active_claim_worker_liveness_dependency_missing",
            RuntimeError("queue active-claim protection requires worker-owned liveness callback"),
            fatal=False,
            extra=extra,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as suppressed_exc:
        _ = suppressed_exc
    return False


def process_queue_active_claim_is_protected(
    path: object,
    job: object = None,
    *,
    now: float | None = None,
    grace: float | None = None,
    pid_is_alive: object | None = None,
) -> bool:
    """Return whether an active process-queue claim remains worker-owned."""
    worker_liveness = pid_is_alive if pid_is_alive is not None else _queue_missing_worker_liveness
    return active_claim_is_protected(
        path,
        job,
        now=now,
        grace=grace,
        path_age=lambda claim_path, now=None: queue_path_mtime_age(
            claim_path,
            now=now,
            record_suppressed=_process_queue_record_suppressed,
        ),
        read_json=read_json_file,
        merge_claim_meta=process_queue_merge_claim_meta_into_job,
        pid_is_alive=worker_liveness,
        queue_now=queue_now,
        report=_process_queue_record_suppressed,
    )


__all__ = (
    "_queue_missing_worker_liveness",
    "process_queue_active_claim_is_protected",
    "process_queue_merge_claim_meta_into_job",
    "process_queue_read_claim_meta",
)
