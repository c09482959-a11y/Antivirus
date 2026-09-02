"""Publication helpers for in-memory result completion."""
from __future__ import annotations

from typing import Callable, MutableMapping

from Virus_Scan.scheduler.evidence.inmemory_partial_results import InMemoryPartialPublicationRequest
from Virus_Scan.scheduler.queue.inmemory_result_completion_contracts import (
    InMemoryCompletedResultPublicationRequest,
)
from Virus_Scan.scheduler.queue.inmemory_result_completion_projection import exact_mapping_count
from Virus_Scan.scheduler.queue.inmemory_result_completion_state import record_suppressed_exception


def attach_result_payload_evidence(
    *,
    result: object,
    record: dict[str, object],
    path: object,
    pid: object,
    container_root: object,
    routing_evidence_context: object,
    routing_evidence_attacher: Callable[..., object],
    attach_result_evidence: Callable[..., object],
    wall_time: Callable[[], float],
) -> object:
    if type(result) is not dict:
        return result
    return attach_result_evidence(
        result=result,
        record=record,
        path=path,
        worker_pid=pid,
        container_root=container_root,
        evidence_context=routing_evidence_context,
        routing_evidence_attacher=routing_evidence_attacher,
        wall_time=wall_time,
    )


def publish_completed_result(
    request: InMemoryCompletedResultPublicationRequest,
    terminal_record: object,
) -> None:
    request.publish_partial_results(
        InMemoryPartialPublicationRequest(
            partial_output_path=request.partial_output_path,
            results=request.results,
            partial_output_every=request.partial_output_every,
            writer=request.partial_writer,
            checkpoint_cache=request.partial_checkpoint_cache,
            log_error=request.log_error,
            recoverable_exceptions=request.recoverable_exceptions,
            terminal_key=request.parts.path,
            terminal_record=terminal_record,
            force=False,
        )
    )


def run_completion_maintenance(request: InMemoryCompletedResultPublicationRequest) -> None:
    request.bulk_scan_maintenance(request.recovery.completed)
    request.log_bulk_progress(
        request.recovery.completed,
        exact_mapping_count(request.job_records),
        file_path=request.parts.path,
        started_at=request.started_at,
        progress_every=request.progress_every,
    )


def _attach_and_store_result(request: InMemoryCompletedResultPublicationRequest) -> object:
    result = attach_result_payload_evidence(
        result=request.parts.result,
        record=request.record,
        path=request.parts.path,
        pid=request.parts.pid,
        container_root=request.container_root,
        routing_evidence_context=request.routing_evidence_context,
        routing_evidence_attacher=request.routing_evidence_attacher,
        attach_result_evidence=request.attach_result_evidence,
        wall_time=request.wall_time,
    )
    retained = request.result_retainer(request.parts.path, result)
    request.results[request.parts.path] = retained
    request.recovery.completed += 1
    request.derived_cache_writer(result)
    return retained


def store_publish_and_maintain_completed_result(
    request: InMemoryCompletedResultPublicationRequest,
) -> None:
    """Store, checkpoint, and maintain one reconciled terminal result."""
    result = _attach_and_store_result(request)
    publish_completed_result(request, result)
    try:
        run_completion_maintenance(request)
    except request.recoverable_exceptions as exc:
        record_suppressed_exception(
            request.suppressed_recorder,
            request.recoverable_exceptions,
            exc,
        )


__all__ = (
    "attach_result_payload_evidence",
    "publish_completed_result",
    "run_completion_maintenance",
    "store_publish_and_maintain_completed_result",
)
