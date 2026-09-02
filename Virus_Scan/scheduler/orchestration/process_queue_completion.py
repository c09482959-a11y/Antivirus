"""Process-queue completion orchestration ownership.

This module owns parent-side process-queue completion after the monitor loop:
worker-exit reconciliation, queue result merge, final partial publication, runtime
cleanup, and strict error escalation.  The execution loop provides immutable
snapshots and receives a deterministic merged-result mapping.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, immutable_tuple
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_bool
from Virus_Scan.scheduler.internal.live_path_entries import freeze_live_scheduler_paths
from Virus_Scan.scheduler.orchestration.process_queue_completion_evidence import (
    attach_scheduler_evidence_to_merged_results as _attach_scheduler_evidence_canonical,
    attach_worker_exit_evidence_to_merged_results as _attach_worker_exit_evidence_canonical,
)
from Virus_Scan.scheduler.orchestration.process_queue_completion_steps import run_process_queue_completion_steps
from Virus_Scan.scheduler.queue.raw_queue_failure_audit import collect_failed_queue_report

_COMPLETION_QUEUE_PUBLIC_CONTRACT = collect_failed_queue_report

_WORKER_OUTPUT_PUBLICATION_BOUNDARY = "finalize_worker_output"
_PROCESS_QUEUE_WORKERS_FAILED = "one or more process queue workers failed"

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path
    from Virus_Scan.scheduler.orchestration.process_queue_worker_pool_state import ProcessQueueParentWorkerPool


@dataclass(frozen=True)
class ProcessQueueCompletionRequest:
    """Immutable request for process-queue completion."""

    queue_dir: Path
    runtime_dir: Path
    worker_pool: ProcessQueueParentWorkerPool
    all_files: tuple[str, ...]
    partial_output_path: str | Path | None
    strict: bool
    had_error: bool
    monitor_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        strict, strict_reason = scheduler_bool(
            self.strict,
            default=False,
            reason="process_queue_completion_strict_rejected",
        )
        had_error, had_error_reason = scheduler_bool(
            self.had_error,
            default=False,
            reason="process_queue_completion_had_error_rejected",
        )
        reasons = tuple(reason for reason in (strict_reason, had_error_reason) if reason)
        if reasons:
            raise ValueError(",".join(reasons))
        object.__setattr__(self, "all_files", freeze_live_scheduler_paths(self.all_files))
        object.__setattr__(self, "strict", strict)
        object.__setattr__(self, "had_error", had_error)
        object.__setattr__(self, "monitor_evidence", immutable_tuple(self.monitor_evidence))


@dataclass(frozen=True)
class ProcessQueueCompletionResult:
    """Immutable process-queue completion result."""

    merged: Mapping[str, object]
    had_error: bool
    worker_exit_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "merged", immutable_mapping(self.merged))
        object.__setattr__(self, "worker_exit_evidence", immutable_tuple(self.worker_exit_evidence))


def complete_process_queue(request: ProcessQueueCompletionRequest) -> ProcessQueueCompletionResult:
    """Reconcile workers, merge queue results, and clean runtime resources."""
    merged, had_error, worker_exit_evidence = run_process_queue_completion_steps(
        request,
        _attach_worker_exit_evidence_to_merged_results,
        _attach_scheduler_evidence_canonical,
    )
    if had_error and request.strict:
        raise RuntimeError(_PROCESS_QUEUE_WORKERS_FAILED)
    return ProcessQueueCompletionResult(
        merged=merged,
        had_error=had_error,
        worker_exit_evidence=worker_exit_evidence,
    )


def _attach_worker_exit_evidence_to_merged_results(
    merged: dict[str, object],
    worker_exit_evidence: tuple[Mapping[str, object], ...],
) -> None:
    """Attach non-clean worker-exit evidence without caller-owned hooks."""
    _attach_worker_exit_evidence_canonical(merged, worker_exit_evidence)
