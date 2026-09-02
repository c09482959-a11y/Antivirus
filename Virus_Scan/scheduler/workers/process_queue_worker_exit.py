"""Process-queue worker-exit reconciliation owner.

This module owns terminal worker exit status reconciliation after the execution
loop has stopped dispatching work.  The execution runner provides the immutable
worker snapshot and wait/error callbacks, while strict failure accounting is
returned as an immutable result.
"""
from __future__ import annotations

from dataclasses import dataclass
import signal
from typing import Callable, Mapping

from Virus_Scan.scheduler.internal.immutable_outputs import immutable_tuple
from Virus_Scan.scheduler.workers.cleanup import os as worker_cleanup_os
from Virus_Scan.scheduler.workers.cleanup_wait_steps import WorkerExitWaitStepContext
from Virus_Scan.scheduler.internal.live_worker_entries import freeze_live_worker_entries
from Virus_Scan.scheduler.workers.process_queue_worker_exit_evidence import (
    _unsupported_worker_exit_result_evidence,
    _worker_exit_bool,
    _worker_exit_infrastructure_failed,
    _worker_exit_int,
    _worker_exit_output_text,
    _worker_exit_result_evidence,
    _worker_exit_status,
    _worker_tuple_parts,
)


@dataclass(frozen=True)
class ProcessQueueWorkerExitRequest:
    procs: tuple[tuple[object, object, object, object], ...]
    strict: bool
    had_error: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "procs", freeze_live_worker_entries(self.procs))


@dataclass(frozen=True)
class ProcessQueueWorkerExitDependencies:
    wait_for_worker_exit: Callable[[object, WorkerExitWaitStepContext], object]
    record_issue: Callable[..., None]
    log_error: Callable[[str], None]


@dataclass(frozen=True)
class ProcessQueueWorkerExitOutput:
    had_error: bool
    exit_evidence: tuple[Mapping[str, object], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "exit_evidence", immutable_tuple(self.exit_evidence))


def reconcile_process_queue_worker_exits(
    request: ProcessQueueWorkerExitRequest,
    deps: ProcessQueueWorkerExitDependencies,
) -> ProcessQueueWorkerExitOutput:
    """Reconcile stopped process-queue workers and preserve strict semantics."""
    had_error, _had_error_reason = _worker_exit_bool(request.had_error, replacement=True)
    strict, _strict_reason = _worker_exit_bool(request.strict, replacement=False)
    exit_evidence: list[Mapping[str, object]] = []
    for position, worker_entry in enumerate(request.procs):
        idx, proc, output, valid_entry = _worker_tuple_parts(worker_entry, position)
        if not valid_entry:
            evidence = _unsupported_worker_exit_result_evidence(
                worker_entry,
                idx=position,
                output=None,
            )
            evidence["worker_exit_tuple_invalid"] = True
            exit_evidence.append(evidence)
            had_error = True
            deps.log_error("process queue worker " + int.__str__(position) + " had invalid exit tuple; status=-1")
            if strict:
                raise RuntimeError("process queue worker " + int.__str__(position) + " failed with status -1")
            continue
        exit_result = deps.wait_for_worker_exit(
            proc,
            WorkerExitWaitStepContext(
                worker_idx=idx,
                output=output,
                timeout_sec=1.0,
                report_issue=deps.record_issue,
                os_ops=None,
                default_os_ops=worker_cleanup_os,
                terminate_signal=signal.SIGTERM,
                kill_signal=getattr(signal, "SIGKILL", signal.SIGTERM),
            ),
        )
        evidence = _worker_exit_result_evidence(exit_result, idx=idx, output=output)
        exit_evidence.append(evidence)
        rc = _worker_exit_status(evidence)
        if _worker_exit_infrastructure_failed(evidence):
            worker_idx, _idx_reason = _worker_exit_int(evidence.get("worker_idx"), position)
            output_text, output_reason = _worker_exit_output_text(evidence.get("worker_output"))
            output_suffix = output_text if output_reason == "" and output_text else "worker_output_unavailable"
            had_error = True
            deps.log_error("process queue worker " + int.__str__(worker_idx) + " ended with infrastructure status " + int.__str__(rc) + "; output=" + output_suffix)
            if strict:
                raise RuntimeError("process queue worker " + int.__str__(worker_idx) + " failed with status " + int.__str__(rc))
    return ProcessQueueWorkerExitOutput(had_error=had_error, exit_evidence=tuple(exit_evidence))
