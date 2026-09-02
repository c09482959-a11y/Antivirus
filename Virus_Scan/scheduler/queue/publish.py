"""Process queue admission and durable pending-job publication."""
from Virus_Scan.scheduler.runtime.queue_filesystem import process_weight_for_path as _process_weight_for_path, queue_file_identity_for_path as _queue_file_identity_for_path, queue_job_dirs as _queue_job_dirs
from Virus_Scan.scheduler.queue.identity_index import note_identity_for_queue as _queue_identity_index_note
from Virus_Scan.scheduler.queue.identity import (
    queue_job_identity as _queue_job_identity,
)
from Virus_Scan.scheduler.queue.admission import classify_workload
from Virus_Scan.scheduler.queue.publish_durable import _write_queue_job_json_durable
from Virus_Scan.scheduler.queue.publish_ordering import _process_queue_ordered_items
from Virus_Scan.scheduler.queue.publish_job import ProcessQueuePublishAttemptRequest, ProcessQueuePublishResult, build_process_queue_publish_attempt, publish_locked_process_queue_job
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_path
from Virus_Scan.scheduler.queue.authority import _ensure_process_queue_dirs, process_queue_enqueue_guard as _queue_enqueue_guard
from Virus_Scan.scheduler.queue.identity_lock import acquire_identity_lock_decision as _queue_acquire_identity_lock_decision, release_identity_lock_decision as _queue_release_identity_lock_decision
from Virus_Scan.scheduler.replay.replay_snapshot import hybrid_queue_state_delta as _hybrid_queue_state_delta
from Virus_Scan.scheduler.evidence.process_queue_errors import process_queue_record_suppressed as record_scheduler_suppressed
from Virus_Scan.scheduler.queue.publish_controls import normalize_publish_attempt_result, normalize_queue_slice_controls, process_queue_identity_lock_result, process_queue_publish_result_tuple, publish_identity_failure_extra, queue_slice_item, record_publish_summary

_QUEUE_SLICE_WORKLOAD_CLASS_FIELDS = 4

def _queue_dir_failure_message(queue_dir: object) -> object:
    text = scheduler_evidence_path(queue_dir, field_name="process_queue_dir")
    return "could not create process queue directories: " + text

def _publish_process_queue_attempt(queue_dir: object, pending: object, attempt: object, *, enqueued_identities: object, identity_failure_stage: object, guard_failure_stage: object, index_failure_stage: object, track_state_delta: object=False, lock_conflict_marks_identity: object=False) -> object:
    """Publish one queue admission attempt through bounded per-job ownership."""
    job = attempt.job
    try:
        ident = _queue_job_identity(job, None)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        record_scheduler_suppressed(
            identity_failure_stage,
            exc,
            extra=publish_identity_failure_extra(job),
        )
        return False, False, True
    if ident in enqueued_identities:
        return False, True, False
    lock_decision = _queue_acquire_identity_lock_decision(queue_dir, ident)
    lock, skipped, failed = process_queue_identity_lock_result(
        lock_decision,
        ident,
        record_suppressed=record_scheduler_suppressed,
    )
    if lock is None:
        if skipped and lock_conflict_marks_identity:
            enqueued_identities.add(ident)
        return False, skipped, failed
    outcome = publish_locked_process_queue_job(
        queue_dir=queue_dir,
        pending_dir=pending,
        attempt=attempt,
        identity=ident,
        lock=lock,
        enqueue_guard=_queue_enqueue_guard,
        write_queue_job_json_durable=_write_queue_job_json_durable,
        identity_index_note=_queue_identity_index_note,
        release_identity_lock_decision=_queue_release_identity_lock_decision,
        record_scheduler_suppressed=record_scheduler_suppressed,
        guard_failure_stage=guard_failure_stage,
        identity_index_failure_stage=index_failure_stage,
        release_failure_stage="process_queue_identity_lock_release_unsuccessful",
        state_delta=_hybrid_queue_state_delta if track_state_delta else None,
    )
    published, skipped, failed = process_queue_publish_result_tuple(outcome)
    if published:
        enqueued_identities.add(ident)
        return True, False, failed
    if skipped and lock_conflict_marks_identity:
        enqueued_identities.add(ident)
    return False, skipped, failed
def _write_process_queue_jobs(queue_dir: object, files: object, *, publish_attempt_func: object=_publish_process_queue_attempt) -> object:
    """Create one atomic filesystem job per file for dynamic work stealing."""
    pending, _, _, _ = _queue_job_dirs(queue_dir)
    if not _ensure_process_queue_dirs(queue_dir):
        raise RuntimeError(_queue_dir_failure_message(queue_dir))
    ordered = [(orig_idx, f, cls) for _order, orig_idx, f, cls in _process_queue_ordered_items(files)]
    enqueued_identities = set()
    skipped_duplicates = 0
    failed_publishes = 0
    for order, (orig_idx, f, workload_class) in enumerate(ordered):
        attempt = build_process_queue_publish_attempt(
            ProcessQueuePublishAttemptRequest(
                order=order,
                original_index=orig_idx,
                file_path=f,
                workload_class=workload_class,
                queue_file_identity_for_path=_queue_file_identity_for_path,
                process_weight_for_path=_process_weight_for_path,
            )
        )
        attempt_result = publish_attempt_func(
            queue_dir,
            pending,
            attempt,
            enqueued_identities=enqueued_identities,
            identity_failure_stage="process_queue_identity_failed_closed",
            guard_failure_stage="process_queue_enqueue_guard_exception_failed_closed",
            index_failure_stage="process_queue_identity_index_note_failed",
            track_state_delta=True,
            lock_conflict_marks_identity=False,
        )
        _, skipped, failed = normalize_publish_attempt_result(attempt_result, record_suppressed=record_scheduler_suppressed)
        skipped_duplicates += 1 if skipped else 0
        failed_publishes += 1 if failed else 0
    record_publish_summary(skipped_duplicates, failed_publishes, record_suppressed=record_scheduler_suppressed)
def _write_process_queue_jobs_slice(
    queue_dir: object,
    ordered_items: object,
    cursor: object,
    max_new: object,
    enqueued_identities: object=None,
    *,
    publish_attempt_func: object=_publish_process_queue_attempt,
    record_suppressed: object=record_scheduler_suppressed,
) -> object:
    """Publish at most max_new original file jobs from a pre-sorted list."""
    if enqueued_identities is None:
        enqueued_identities = set()
    pending, _, _, _ = _queue_job_dirs(queue_dir)
    if not _ensure_process_queue_dirs(queue_dir):
        raise RuntimeError(_queue_dir_failure_message(queue_dir))
    cursor, max_new, ordered_snapshot = normalize_queue_slice_controls(
        cursor,
        max_new,
        ordered_items,
        record_suppressed=record_suppressed,
    )
    if max_new <= 0:
        return cursor, 0, 0
    enqueued = 0
    skipped_duplicates = 0
    failed_publishes = 0
    total = len(ordered_snapshot)
    while cursor < total and enqueued < max_new:
        raw_item = ordered_snapshot[cursor]
        cursor += 1
        item = queue_slice_item(raw_item)
        if item is None:
            failure = ValueError("process_queue_slice_item_rejected")
            record_suppressed(
                "process_queue_slice_item_rejected",
                failure,
                extra=publish_identity_failure_extra(raw_item),
            )
            failed_publishes += 1
            continue
        order = item[0]
        orig_idx = item[1]
        f = item[2]
        workload_class = item[3] if len(item) >= _QUEUE_SLICE_WORKLOAD_CLASS_FIELDS else classify_workload(f)
        attempt = build_process_queue_publish_attempt(
            ProcessQueuePublishAttemptRequest(
                order=order,
                original_index=orig_idx,
                file_path=f,
                workload_class=workload_class,
                queue_file_identity_for_path=_queue_file_identity_for_path,
                process_weight_for_path=_process_weight_for_path,
            )
        )
        attempt_result = publish_attempt_func(
            queue_dir,
            pending,
            attempt,
            enqueued_identities=enqueued_identities,
            identity_failure_stage="process_queue_identity_failed_closed",
            guard_failure_stage="process_queue_slice_enqueue_guard_exception_failed_closed",
            index_failure_stage="process_queue_slice_identity_index_note_failed",
            track_state_delta=False,
            lock_conflict_marks_identity=True,
        )
        published, skipped, failed = normalize_publish_attempt_result(attempt_result, record_suppressed=record_suppressed)
        enqueued += 1 if published else 0
        skipped_duplicates += 1 if skipped else 0
        failed_publishes += 1 if failed else 0
    record_publish_summary(skipped_duplicates, failed_publishes, record_suppressed=record_suppressed)
    return cursor, enqueued, skipped_duplicates
# Public queue publication contracts used outside the queue subdomain.
write_process_queue_jobs = _write_process_queue_jobs
write_process_queue_jobs_slice = _write_process_queue_jobs_slice
__all__ = ("_process_queue_ordered_items", "_write_process_queue_jobs", "_write_process_queue_jobs_slice", "_write_queue_job_json_durable")
