"""Worker-owned evidence for in-memory worker lifecycle publication failures."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scheduler.internal.worker_result_boundary import (
    scheduler_owned_mapping_snapshot,
    scheduler_scan_integrity_snapshot,
    scheduler_path_text,
)
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_boundary import (
    existing_lifecycle_reason,
    safe_lifecycle_exception_message,
    safe_lifecycle_int,
    safe_lifecycle_text,
    worker_lifecycle_exception_reason,
)


@dataclass(frozen=True, slots=True)
class InMemoryWorkerLifecyclePublicationEvidence:
    """Immutable evidence for failed worker lifecycle message publication."""

    operation: str
    job_id: int
    path: str
    generation: int
    reason: str
    report_failed: bool = False
    report_error: str = ""
    path_unavailable_reason: str = ""
    reason_unavailable_reason: str = ""
    report_error_unavailable_reason: str = ""
    job_id_unavailable_reason: str = ""
    generation_unavailable_reason: str = ""

    def __post_init__(self) -> None:
        operation, operation_reason = safe_lifecycle_text(
            self.operation,
            replacement_text="worker_lifecycle_publication",
            missing_reason="missing_worker_lifecycle_publication_operation",
            unsupported_reason="unsafe_worker_lifecycle_publication_operation_rejected",
        )
        path, path_reason = scheduler_path_text(self.path)
        reason, reason_unavailable = safe_lifecycle_text(
            self.reason,
            replacement_text="worker_lifecycle_publication_failed",
            missing_reason="missing_worker_lifecycle_publication_reason",
            unsupported_reason="unsafe_worker_lifecycle_publication_reason_rejected",
        )
        report_error, report_error_reason = safe_lifecycle_text(
            self.report_error,
            replacement_text="",
            missing_reason="missing_worker_lifecycle_publication_report_error",
            unsupported_reason="unsafe_worker_lifecycle_publication_report_error_rejected",
        )
        if operation_reason and not reason_unavailable:
            reason_unavailable = operation_reason
        object.__setattr__(self, "operation", operation)
        object.__setattr__(self, "job_id", safe_lifecycle_int(self.job_id))
        object.__setattr__(self, "path", path)
        object.__setattr__(self, "generation", safe_lifecycle_int(self.generation))
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "report_failed", self.report_failed if type(self.report_failed) is bool else False)
        object.__setattr__(self, "report_error", report_error or "")
        object.__setattr__(self, "path_unavailable_reason", existing_lifecycle_reason(self.path_unavailable_reason) or path_reason)
        object.__setattr__(self, "reason_unavailable_reason", existing_lifecycle_reason(self.reason_unavailable_reason) or reason_unavailable)
        object.__setattr__(self, "report_error_unavailable_reason", existing_lifecycle_reason(self.report_error_unavailable_reason) or report_error_reason)
        object.__setattr__(self, "job_id_unavailable_reason", existing_lifecycle_reason(self.job_id_unavailable_reason))
        object.__setattr__(self, "generation_unavailable_reason", existing_lifecycle_reason(self.generation_unavailable_reason))

    def as_scan_integrity(self) -> dict[str, object]:
        evidence: dict[str, object] = {
            "file_failed": True,
            "had_degraded_stage": True,
            "queue_failure": True,
            "worker_lifecycle_publication_failed": True,
            "worker_lifecycle_publication_operation": self.operation,
            "worker_lifecycle_publication_job_id": self.job_id,
            "worker_lifecycle_publication_path": self.path,
            "worker_lifecycle_publication_generation": self.generation,
            "worker_lifecycle_publication_failure_reason": self.reason,
            "allow_learning": False,
        }
        if self.path_unavailable_reason:
            evidence["worker_lifecycle_publication_path_unavailable_reason"] = self.path_unavailable_reason
        if self.job_id_unavailable_reason:
            evidence["worker_lifecycle_publication_job_id_unavailable_reason"] = self.job_id_unavailable_reason
        if self.generation_unavailable_reason:
            evidence["worker_lifecycle_publication_generation_unavailable_reason"] = self.generation_unavailable_reason
        if self.reason_unavailable_reason:
            evidence["worker_lifecycle_publication_reason_unavailable_reason"] = self.reason_unavailable_reason
        if self.report_failed:
            evidence["worker_lifecycle_publication_report_failed"] = True
        if self.report_error:
            evidence["worker_lifecycle_publication_report_error"] = self.report_error[:1000]
        if self.report_error_unavailable_reason:
            evidence["worker_lifecycle_publication_report_error_unavailable_reason"] = self.report_error_unavailable_reason
        return evidence


def _base_lifecycle_failure_result(evidence: InMemoryWorkerLifecyclePublicationEvidence, *, unavailable_reason: str = "") -> dict[str, object]:
    integrity = evidence.as_scan_integrity()
    if unavailable_reason:
        integrity["worker_lifecycle_publication_output_unavailable_reason"] = unavailable_reason
    return {
        "file": evidence.path,
        "tags": ["scanner_failure", "scanner_degraded", "scan_incomplete"],
        "error": evidence.reason,
        "queue_failure": True,
        "worker_lifecycle_publication_failed": True,
        "scheduler_failure_reason": "worker_lifecycle_publication_failed",
        "scan_integrity": integrity,
    }


def annotate_worker_lifecycle_publication_failure(output: object, evidence: InMemoryWorkerLifecyclePublicationEvidence | None) -> object:
    """Attach lifecycle publication evidence to a worker output if possible."""

    if evidence is None:
        return output

    def annotate_result(result: object) -> dict[str, object]:
        annotated = scheduler_owned_mapping_snapshot(result)
        if annotated is None:
            return _base_lifecycle_failure_result(evidence, unavailable_reason="non_materializable_worker_lifecycle_output")
        integrity = scheduler_scan_integrity_snapshot(
            dict.get(annotated, "scan_integrity"),
            unavailable_reason="non_materializable_worker_lifecycle_integrity",
            original_type_field="worker_lifecycle_integrity_original_type",
            unavailable_flag="worker_lifecycle_integrity_unavailable",
            unavailable_reason_field="worker_lifecycle_integrity_unavailable_reason",
        )
        integrity.update(evidence.as_scan_integrity())
        annotated["scan_integrity"] = integrity
        annotated["queue_failure"] = True
        annotated["worker_lifecycle_publication_failed"] = True
        if "scheduler_failure_reason" not in annotated:
            annotated["scheduler_failure_reason"] = "worker_lifecycle_publication_failed"
        return annotated

    if type(output) is tuple and len(output) == 2:
        return (output[0], annotate_result(output[1]))
    snapshot = scheduler_owned_mapping_snapshot(output)
    if snapshot is not None:
        return annotate_result(snapshot)
    return (evidence.path, _base_lifecycle_failure_result(evidence, unavailable_reason="non_materializable_worker_lifecycle_output"))


def build_worker_error_result_evidence(
    path: object,
    exc: BaseException,
    *,
    error_result_exc: BaseException,
) -> dict[str, object]:
    """Build explicit worker failure evidence when the configured error-result factory fails."""

    safe_path, path_reason = scheduler_path_text(path)
    safe_error = safe_lifecycle_exception_message(exc)
    safe_result_error = safe_lifecycle_exception_message(error_result_exc)
    integrity: dict[str, object] = {
        "file_failed": True,
        "had_degraded_stage": True,
        "queue_failure": True,
        "worker_error_result_construction_failed": True,
        "worker_failure_error": safe_error[:1000],
        "worker_error_result_error": safe_result_error[:1000],
        "allow_learning": False,
    }
    if path_reason:
        integrity["worker_error_result_path_unavailable_reason"] = path_reason
    return {
        "file": safe_path,
        "tags": ["scanner_failure", "scanner_degraded", "scan_incomplete"],
        "error": safe_error,
        "queue_failure": True,
        "scheduler_failure_reason": "worker_error_result_construction_failed",
        "scan_integrity": integrity,
    }


__all__ = (
    "InMemoryWorkerLifecyclePublicationEvidence",
    "annotate_worker_lifecycle_publication_failure",
    "build_worker_error_result_evidence",
    "worker_lifecycle_exception_reason",
)
