"""Worker-owned running-state publication evidence for in-memory jobs."""
from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_evidence import (
    InMemoryWorkerLifecyclePublicationEvidence,
    worker_lifecycle_exception_reason,
)


_REQUEST_FIELD_UNAVAILABLE = object()
_REQUEST_MODULE = "Virus_Scan.scheduler.workers.inmemory_worker_job"
_REQUEST_TYPE = "InMemoryWorkerJobExecutionRequest"


@dataclass(frozen=True, slots=True)
class InMemoryWorkerRequestField:
    """Typed no-hook request-field read result with explicit unavailable evidence."""

    value: object
    unavailable_reason: str = ""


def _request_field(request: object, name: str, *, unavailable_value: object = None) -> InMemoryWorkerRequestField:
    request_type = type(request)
    if request_type is SimpleNamespace:
        value = scheduler_exact_attr(
            request,
            name,
            owner_type=SimpleNamespace,
            default=_REQUEST_FIELD_UNAVAILABLE,
        )
        if value is _REQUEST_FIELD_UNAVAILABLE:
            return InMemoryWorkerRequestField(unavailable_value, str.__add__("missing_inmemory_worker_request_", name))
        return InMemoryWorkerRequestField(value)
    try:
        type_name = type.__getattribute__(request_type, "__name__")
        module_name = type.__getattribute__(request_type, "__module__")
    except (AttributeError, TypeError, RuntimeError):
        return InMemoryWorkerRequestField(unavailable_value, "inmemory_worker_request_type_unavailable")
    if type(type_name) is not str or type(module_name) is not str:
        return InMemoryWorkerRequestField(unavailable_value, "inmemory_worker_request_type_identity_unavailable")
    if type_name != _REQUEST_TYPE or module_name != _REQUEST_MODULE:
        return InMemoryWorkerRequestField(unavailable_value, "unsupported_inmemory_worker_request_type")
    value = scheduler_exact_attr(
        request,
        name,
        module_name=_REQUEST_MODULE,
        type_name=_REQUEST_TYPE,
        default=_REQUEST_FIELD_UNAVAILABLE,
    )
    if value is _REQUEST_FIELD_UNAVAILABLE:
        return InMemoryWorkerRequestField(unavailable_value, str.__add__("missing_inmemory_worker_request_", name))
    return InMemoryWorkerRequestField(value)


def running_publication_evidence(request: object, exc: BaseException, *, report_exc: BaseException | None = None) -> InMemoryWorkerLifecyclePublicationEvidence:
    job_id_field = _request_field(request, "job_id", unavailable_value=0)
    path_field = _request_field(request, "path", unavailable_value=None)
    generation_field = _request_field(request, "generation", unavailable_value=0)
    job_id, job_reason = scheduler_int(
        job_id_field.value,
        minimum=0,
        reason="running_publication_job_id_rejected",
    )
    generation, generation_reason = scheduler_int(
        generation_field.value,
        minimum=0,
        reason="running_publication_generation_rejected",
    )
    return InMemoryWorkerLifecyclePublicationEvidence(
        operation="running",
        job_id=job_id,
        path=path_field.value,
        generation=generation,
        reason=worker_lifecycle_exception_reason(exc),
        report_failed=report_exc is not None,
        report_error=worker_lifecycle_exception_reason(report_exc) if report_exc is not None else "",
        path_unavailable_reason=path_field.unavailable_reason,
        job_id_unavailable_reason=job_id_field.unavailable_reason or job_reason,
        generation_unavailable_reason=generation_field.unavailable_reason or generation_reason,
    )


__all__ = ("running_publication_evidence",)
