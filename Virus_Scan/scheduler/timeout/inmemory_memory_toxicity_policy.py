"""Memory-toxicity policy value parsing and policy evidence ownership."""
from __future__ import annotations

from typing import MutableMapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_evidence_text, scheduler_exception_text, scheduler_float
from Virus_Scan.scheduler.timeout.inmemory_memory_toxicity_evidence import memory_toxicity_evidence


def append_global_memory_toxicity_evidence(*, worker_metrics: object, evidence: object) -> None:
    """Attach memory-toxicity policy evidence to scheduler-owned metrics."""

    if isinstance(worker_metrics, MutableMapping):
        current = tuple(worker_metrics.get("memory_toxicity_policy_evidence") or ())
        worker_metrics["memory_toxicity_policy_evidence"] = (*current, dict(evidence.as_record()))


def coerce_memory_toxicity_float(*, value: object, field: str) -> float:
    """Parse a finite memory-toxicity numeric policy or metric value."""

    parsed, reason = scheduler_float(
        value,
        default=0.0,
        reason="memory_toxicity_float_rejected",
        non_finite_reason="memory_toxicity_float_non_finite",
    )
    if reason:
        field_text = scheduler_evidence_text(
            field,
            missing_text="memory_toxicity_value",
            field_name="memory_toxicity_field",
        )
        raise ValueError(field_text + " " + reason)
    return parsed


def record_memory_toxicity_suppression(*, error: BaseException, recoverable_exceptions: object, record_suppressed: object) -> BaseException:
    """Record a recoverable suppression without hiding the original failure."""

    try:
        record_suppressed("suppressed_exception", error)
    except recoverable_exceptions as record_exc:
        detail = scheduler_exception_text(error)
        record_detail = scheduler_exception_text(record_exc)
        return RuntimeError(detail + "; suppression_record_failed=" + record_detail)
    else:
        return error


def malformed_memory_toxicity_limit_evidence(*, error: BaseException) -> object:
    """Create evidence for malformed global RSS limit policy."""

    return memory_toxicity_evidence(
        pid=0,
        job_id=None,
        reason="worker_memory_toxic_limit_malformed",
        action="read_memory_toxicity_policy",
        rss_mb=0.0,
        error=error,
        source="rss_limit_mb",
    )


__all__ = (
    "append_global_memory_toxicity_evidence",
    "coerce_memory_toxicity_float",
    "malformed_memory_toxicity_limit_evidence",
    "record_memory_toxicity_suppression",
)
