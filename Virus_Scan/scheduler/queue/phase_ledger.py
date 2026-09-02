"""Queue-owned phase ledger and finalization transitions.

This module records immutable queue snapshots and constructs finalization state.
It owns reconciliation accounting only and does not execute scanner work.
"""

from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.api import contracts as scheduler_contracts
from Virus_Scan.scheduler.runtime.queue_filesystem import queue_job_dirs as _queue_job_dirs, safe_queue_listdir as _safe_queue_listdir
from Virus_Scan.scheduler.queue.snapshots import QueueBehaviorSnapshot, QueuePhaseLedger
from Virus_Scan.scheduler.queue.publication_state import QueuePublicationState, QueueRunFinalizationState
from Virus_Scan.scheduler.queue.recovery_contracts import QueueWorkerFailureAccounting
from Virus_Scan.scheduler.queue.phase_validation import (
    ResultPublicationValidationRequest,
    _validate_queue_integrity,
    _validate_recovery_decision_batch,
    validate_result_publication,
)
from Virus_Scan.scheduler.queue.integrity_pipeline import queue_integrity_verify_and_repair
from Virus_Scan.scheduler.queue.phase_ledger_inputs import owned_phase_snapshots, owned_string_mapping, owned_worker_failures
from Virus_Scan.scheduler.queue.identity import queue_is_job_json_name as _queue_is_job_json_name
from Virus_Scan.scheduler.runtime.queue_filesystem_listdir_result import queue_listdir_names
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items
from Virus_Scan.scheduler.contracts.evidence_record_support import scheduler_mapping_value
from Virus_Scan.scheduler.internal.evidence_projection import scheduler_evidence_path, scheduler_evidence_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_text

_SEQ_TYPES = (list, tuple, set, frozenset)
_PHASE_LEDGER_INTEGRITY_PIPELINE_OWNER = queue_integrity_verify_and_repair
_WORKER_FAILURE_ACCOUNTING_NOT_CANONICAL = "scheduler worker failure accounting is not immutable/canonical"

def _owned_texts(values: object, field_name: str, *, path: bool = False) -> tuple[str, ...]:
    items = no_hook_sequence_items(values)
    if not items and values is not None and type(values) not in _SEQ_TYPES: items = (values,)
    out = []
    for item in items:
        text = scheduler_evidence_path(item, field_name=field_name) if path else scheduler_evidence_text(item, missing_text="", field_name=field_name)
        if text.strip(): out.append(text)
    return tuple(out)


def _record_result_publication(state: object, result: object, known_jobs: object, claimed_jobs: object, *, worker_id: object = None, worker_ownership: object = None) -> QueuePublicationState:
    """Return a new immutable publication state after validating one result boundary."""
    publication_state = state if isinstance(state, QueuePublicationState) else QueuePublicationState.empty()
    validate_result_publication(
        ResultPublicationValidationRequest(
            result=result,
            known_jobs=known_jobs,
            claimed_jobs=claimed_jobs,
            published_identities=publication_state.job_identities,
            worker_id=worker_id,
            worker_ownership=worker_ownership,
            published_file_identities=publication_state.file_identities,
        )
    )
    publication_result = owned_string_mapping(result, "scheduler result publication input rejected")
    return publication_state.with_publication(publication_result)


def _record_queue_snapshot(queue_dir: object, phase: object, *, integrity_summary: object = None, emitted_result_count: int = 0, finalized_count: int = 0, total: object = None) -> QueueBehaviorSnapshot:
    """Record an immutable before/after snapshot for scheduler queue phases."""
    pending_dir, active_dir, done_dir, failed_dir = _queue_job_dirs(queue_dir)
    quarantine_path = Path(scheduler_evidence_path(queue_dir, field_name="queue_dir")) / "quarantine"

    queue_json_counts: dict[str, int] = {}
    for key, path in (
        ("pending", pending_dir),
        ("claimed", active_dir),
        ("running", active_dir),
        ("completed", done_dir),
        ("failed", failed_dir),
        ("quarantined", quarantine_path),
    ):
        queue_json_counts[key] = sum(
            1
            for name in queue_listdir_names(_safe_queue_listdir(path), context=path)
            if _queue_is_job_json_name(name)
        )

    phase_text, phase_reason = scheduler_text(phase, replacement_text="unknown", unsupported_reason="queue_phase_text_rejected")
    return QueueBehaviorSnapshot.from_counts(
        phase_text if phase_reason == "" and phase_text else "unknown",
        {
            "pending": queue_json_counts["pending"],
            "claimed": queue_json_counts["claimed"],
            "running": queue_json_counts["running"],
            "completed": queue_json_counts["completed"],
            "failed": queue_json_counts["failed"],
            "quarantined": queue_json_counts["quarantined"],
            "duplicate_count": scheduler_int(
                scheduler_mapping_value(integrity_summary, "duplicates", default=0),
                default=0,
                minimum=0,
                reason="queue_integrity_count_rejected",
            )[0],
            "invalid_record_count": scheduler_int(
                scheduler_mapping_value(integrity_summary, "invalid", default=0),
                default=0,
                minimum=0,
                reason="queue_integrity_count_rejected",
            )[0],
            "orphan_lock_count": sum(
                1
                for name in queue_listdir_names(_safe_queue_listdir(active_dir), context=active_dir)
                if (
                    scheduler_evidence_text(name, missing_text="", field_name="queue_claim_name")
                    or "unsupported_queue_claim_name"
                ).endswith((".claim", ".qmeta.json"))
            ),
            "emitted_result_count": emitted_result_count,
            "finalized_count": finalized_count,
            "total": total,
        },
    )


def _validate_worker_lifecycle_cleanup(queue_dir: object, worker_accounting_records: object, *, live_child_workers: object = (), pending_queue_files: object = ()) -> QueueBehaviorSnapshot:
    """Hard-fail finalization when scheduler worker ownership is not fully accounted."""
    live_workers = _owned_texts(live_child_workers, "live_child_worker")
    if live_workers:
        raise scheduler_contracts.SchedulerFinalizationOwnershipError("live child workers", live_workers)
    pending_files = _owned_texts(pending_queue_files, "pending_queue_file", path=True)
    if pending_files:
        raise scheduler_contracts.SchedulerFinalizationOwnershipError("pending queue files", pending_files)
    records = no_hook_sequence_items(worker_accounting_records)
    if not records and worker_accounting_records is not None and type(worker_accounting_records) not in _SEQ_TYPES:
        exception_message = "scheduler worker failure accounting input rejected"
        raise TypeError(exception_message)
    for record in records:
        if not isinstance(record, QueueWorkerFailureAccounting):
            raise TypeError(_WORKER_FAILURE_ACCOUNTING_NOT_CANONICAL)
        record.assert_valid()
    return _finalize_queue_run(queue_dir, total=None)


def _enqueue_queue_jobs(queue_dir: object, previous_snapshot: object = None, *, total: object = None, allow_total_expansion: bool = False) -> QueueBehaviorSnapshot:
    snapshot = _record_queue_snapshot(queue_dir, "enqueue", total=total)
    return _validate_queue_integrity(previous_snapshot, snapshot, allow_total_expansion=allow_total_expansion)


def _claim_ready_jobs(queue_dir: object, previous_snapshot: object = None, *, total: object = None) -> QueueBehaviorSnapshot:
    snapshot = _record_queue_snapshot(queue_dir, "claim", total=total)
    return _validate_queue_integrity(previous_snapshot, snapshot)


def _dispatch_ready_jobs(queue_dir: object, previous_snapshot: object = None, *, total: object = None) -> QueueBehaviorSnapshot:
    snapshot = _record_queue_snapshot(queue_dir, "dispatch", total=total)
    return _validate_queue_integrity(previous_snapshot, snapshot)


def _apply_recovery_decisions(queue_dir: object, decisions: object, previous_snapshot: object = None, *, total: object = None) -> QueueBehaviorSnapshot:
    _validate_recovery_decision_batch(decisions)
    snapshot = _record_queue_snapshot(queue_dir, "recover", total=total)
    return _validate_queue_integrity(previous_snapshot, snapshot)


def _finalize_queue_run(queue_dir: object, previous_snapshot: object = None, *, emitted_result_count: int = 0, finalized_count: int = 0, total: object = None) -> QueueBehaviorSnapshot:
    snapshot = _record_queue_snapshot(
        queue_dir,
        "finalize",
        emitted_result_count=emitted_result_count,
        finalized_count=finalized_count,
        total=total,
    )
    return _validate_queue_integrity(previous_snapshot, snapshot)


def _finalize_queue_run_state(
    queue_dir: object,
    phase_ledger: object,
    publication_state: object,
    worker_accounting_records: object = (),
    *,
    emitted_result_count: int = 0,
    finalized_count: int = 0,
    total: object = None,
) -> QueueRunFinalizationState:
    """Return immutable final scheduler run state after final queue and publication validation."""
    ledger = phase_ledger if isinstance(phase_ledger, QueuePhaseLedger) else QueuePhaseLedger(owned_phase_snapshots(phase_ledger))
    final_snapshot = _finalize_queue_run(
        queue_dir,
        ledger.snapshots[-1] if ledger.snapshots else None,
        emitted_result_count=emitted_result_count,
        finalized_count=finalized_count,
        total=total,
    )
    ledger = ledger.with_snapshot(final_snapshot)
    state = QueueRunFinalizationState(
        phase_ledger=ledger,
        publication_state=publication_state if isinstance(publication_state, QueuePublicationState) else QueuePublicationState.empty(),
        worker_failures=owned_worker_failures(worker_accounting_records),
        emitted_result_count=emitted_result_count,
        finalized_count=finalized_count,
    )
    state.assert_valid()
    return state
