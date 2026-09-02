"""Worker-owned evidence for parent-side in-memory worker message failures."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import (
    safe_parent_worker_message_identity,
    safe_worker_evidence_label,
    worker_lifecycle_exception_reason,
)


@dataclass(frozen=True, slots=True)
class InMemoryParentWorkerMessageFailureEvidence:
    """Immutable evidence for malformed or failed parent-side worker messages."""

    message_kind: str
    operation: str
    message_preview: str
    reason: str

    def as_context(self) -> Mapping[str, object]:
        return {
            "inmemory_parent_worker_message_failed": True,
            "inmemory_parent_worker_message_kind": self.message_kind,
            "inmemory_parent_worker_message_operation": self.operation,
            "inmemory_parent_worker_message_preview": self.message_preview,
            "inmemory_parent_worker_message_failure_reason": self.reason,
        }


def record_parent_worker_message_failure(*, operation: object, message: object, exc: BaseException) -> None:
    """Record parent-side worker message failure evidence without caller hooks."""

    message_kind, message_preview = safe_parent_worker_message_identity(message)
    operation_label = safe_worker_evidence_label(operation, replacement_text="worker_message")
    evidence = InMemoryParentWorkerMessageFailureEvidence(
        message_kind=message_kind,
        operation=operation_label,
        message_preview=message_preview,
        reason=worker_lifecycle_exception_reason(exc),
    )
    try:
        record_suppressed_failure(
            str.__add__("inmemory_parent_worker_message_", str.__add__(evidence.operation, "_failed")),
            exc,
            domain="scheduler",
            context=evidence.as_context(),
        )
    except RECOVERABLE_RUNTIME_ERRORS as reporting_exc:
        _ = reporting_exc


__all__ = (
    "InMemoryParentWorkerMessageFailureEvidence",
    "record_parent_worker_message_failure",
)
