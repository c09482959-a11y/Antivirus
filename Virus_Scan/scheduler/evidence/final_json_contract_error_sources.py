"""Exact scheduler contract status error-source ownership."""
from __future__ import annotations

_CONTRACT_ERROR_SOURCES: tuple[tuple[str, str], ...] = (
    ("timeout_result", "scheduler.evidence.timeout_result"),
    ("timeout_decision", "scheduler.evidence.timeout_decision"),
    ("retry_decision", "scheduler.evidence.retry_decision"),
    ("retry_result", "scheduler.evidence.retry_result"),
    ("retry_exhaustion_result", "scheduler.evidence.retry_exhaustion_result"),
    ("worker_result", "scheduler.evidence.worker_result"),
    ("worker_lifecycle_result", "scheduler.evidence.worker_lifecycle_result"),
    ("worker_snapshot", "scheduler.evidence.worker_snapshot"),
)


def contract_error_source(field: str) -> str:
    if type(field) is not str:
        return "scheduler.evidence.contract_status"
    for known_field, error_source in _CONTRACT_ERROR_SOURCES:
        if field == known_field:
            return error_source
    return "scheduler.evidence.contract_status"


__all__ = ("contract_error_source",)
