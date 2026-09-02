"""Canonical process-queue child result commit ownership.

A queue child may publish aggregate worker output only after the queue-owned
per-file result has been durably written and verified.  The aggregate file is
non-authoritative and cannot make a claim terminal by itself.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass

from Virus_Scan.scheduler.workers.child_result_publication import (
    ChildResultPersistRequest,
    WorkerOutputUpdateRequest,
    persist_child_result,
    update_worker_output,
)


@dataclass(frozen=True, slots=True)
class ProcessQueueChildResultCommitRequest:
    queue_dir: object
    claim_path: object
    file_path: str
    result: Mapping[str, object]
    child_results: MutableMapping[str, object]
    worker_output_path: object
    write_result: Callable[[object, object, object, Mapping[str, object]], object]
    report: Callable[[str, BaseException], object]
    log_error: Callable[[str], object]
    recoverable_exceptions: tuple[type[BaseException], ...]
    context: str


def commit_process_queue_child_result(request: ProcessQueueChildResultCommitRequest) -> bool:
    """Durably commit one child result before optional aggregate publication."""
    if not persist_child_result(
        ChildResultPersistRequest(
            queue_dir=request.queue_dir,
            claim_path=request.claim_path,
            file_path=request.file_path,
            result=request.result,
            context=request.context,
            write_result=request.write_result,
            report=request.report,
            recoverable_exceptions=request.recoverable_exceptions,
        )
    ):
        return False
    request.child_results[request.file_path] = request.result
    if request.worker_output_path is None:
        return True
    aggregate_ok = update_worker_output(
        WorkerOutputUpdateRequest(
            worker_output_path=request.worker_output_path,
            file_path=request.file_path,
            result=request.result,
            child_results=request.child_results,
            context=request.context + ".aggregate",
            report=request.report,
        )
    )
    if not aggregate_ok:
        request.log_error(
            "aggregate worker output save failed after verified durable result for "
            + request.file_path
            + "; durable completion remains valid"
        )
    return True


__all__ = (
    "ProcessQueueChildResultCommitRequest",
    "commit_process_queue_child_result",
)
