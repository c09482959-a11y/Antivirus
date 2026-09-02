"""Worker-owned child result persistence helpers for raw queue."""
from __future__ import annotations

from Virus_Scan.scheduler.workers.child_result_publication_contracts import ChildResultPersistRequest, WorkerOutputFinalizeRequest, WorkerOutputUpdateRequest
from Virus_Scan.scheduler.workers.child_output_evidence import ChildWorkerOutputPublicationEvidence, ChildWorkerOutputPublicationRequest, record_worker_output_publication_failure
from Virus_Scan.scheduler.workers.child_failure_metadata import (
    build_safe_exception_info,
    safe_exception_info,
    worker_error_result,
)
from Virus_Scan.scheduler.workers.publication_status import (
    safe_publication_context as _safe_context_text,
    safe_publication_status as _safe_publication_status,
)
from Virus_Scan.scheduler.internal.output_publication import write_worker_output_payload

WORKER_PUBLICATION_FAILED = False
_AGGREGATE_PUBLICATION_REJECTED = "aggregate worker output publication rejected"


def _publish_worker_output(
    request: WorkerOutputUpdateRequest | WorkerOutputFinalizeRequest,
    *,
    file_path: object,
    safe_context: str,
    failure_stage: str,
) -> bool:
    if request.worker_output_path is None:
        return True
    if write_worker_output_payload(request.worker_output_path, request.child_results) is True:
        return True
    failure = RuntimeError(_AGGREGATE_PUBLICATION_REJECTED)
    request.report(safe_context + "." + failure_stage, failure)
    record_worker_output_publication_failure(
        ChildWorkerOutputPublicationRequest(
            request.child_results,
            file_path,
            request.worker_output_path,
            safe_context,
            failure_stage,
            failure,
        )
    )
    return WORKER_PUBLICATION_FAILED


def persist_child_result(request: ChildResultPersistRequest) -> bool:
    """Persist a per-file child result and report rejection/exception explicitly."""
    safe_context = _safe_context_text(request.context, replacement_text="worker_result")
    try:
        write_status = request.write_result(request.queue_dir, request.claim_path, request.file_path, request.result)
    except request.recoverable_exceptions as exc:  # bounded by caller/report contract; never silent
        request.report(safe_context + ".result_persist_exception", exc)
        return WORKER_PUBLICATION_FAILED
    ok, status_reason = _safe_publication_status(write_status)
    if status_reason:
        request.report(
            safe_context + ".result_persist_result_rejected",
            RuntimeError(status_reason),
        )
        return WORKER_PUBLICATION_FAILED
    if not ok:
        request.report(
            safe_context + ".result_persist_rejected",
            RuntimeError("durable result writer returned false"),
        )
        return WORKER_PUBLICATION_FAILED
    return True


def update_worker_output(request: WorkerOutputUpdateRequest) -> bool:
    """Update aggregate child output without making it completion authority."""
    safe_context = _safe_context_text(request.context, replacement_text="worker_output")
    return _publish_worker_output(
        request,
        file_path=request.file_path,
        safe_context=safe_context,
        failure_stage="aggregate_write_rejected",
    )


def finalize_worker_output(request: WorkerOutputFinalizeRequest) -> bool:
    """Finalize aggregate worker output through the worker-owned publication path."""
    safe_context = _safe_context_text(request.context, replacement_text="worker_output_final")
    return _publish_worker_output(
        request,
        file_path="__final__",
        safe_context=safe_context,
        failure_stage="aggregate_finalize_failed",
    )


__all__ = ("ChildWorkerOutputPublicationEvidence", "ChildResultPersistRequest", "WorkerOutputFinalizeRequest", "WorkerOutputUpdateRequest", "build_safe_exception_info", "finalize_worker_output", "persist_child_result", "safe_exception_info", "update_worker_output", "worker_error_result")
