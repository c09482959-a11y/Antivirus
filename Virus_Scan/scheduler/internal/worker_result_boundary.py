"""No-hook scheduler worker-result boundary evidence helpers."""
from __future__ import annotations

from Virus_Scan.scheduler.internal.mapping_item_lookup import scheduler_str_key_mapping_from_items
from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.scheduler.internal.worker_result_boundary_decisions import (
    scheduler_owned_mapping_decision,
    scheduler_scan_integrity_decision,
)
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


WORKER_RESULT_SCHEMA_FAILURE_REASON = "scheduler_worker_result_schema_failure"


def scheduler_path_text(path: object) -> tuple[str, str]:
    return no_hook_text(
        path,
        missing_reason="missing_scheduler_worker_path",
        unsupported_reason="unsafe_scheduler_worker_path_rejected",
    )


def scheduler_reason_text(
    reason: object, *, replacement_text: str = WORKER_RESULT_SCHEMA_FAILURE_REASON
) -> tuple[str, str]:
    replacement = str.strip(replacement_text) if type(replacement_text) is str else ""
    unavailable_text = replacement or WORKER_RESULT_SCHEMA_FAILURE_REASON
    text, unavailable_reason = no_hook_text(
        reason,
        missing_reason="missing_scheduler_worker_reason",
        unsupported_reason="unsafe_scheduler_worker_reason_rejected",
    )
    if unavailable_reason:
        return unavailable_text, unavailable_reason
    stripped = str.strip(text)
    if not stripped:
        return unavailable_text, "blank_scheduler_worker_reason"
    return stripped, ""


def scheduler_exception_text(exc: object) -> str:
    text, unavailable_reason = no_hook_text(
        exc,
        missing_reason="missing_scheduler_exception_text",
        unsupported_reason="unsafe_scheduler_exception_text_rejected",
    )
    if unavailable_reason:
        return no_hook_type_name(exc)
    stripped = str.strip(text)
    return stripped or no_hook_type_name(exc)


def scheduler_owned_mapping_snapshot(value: object) -> dict[str, object] | None:
    snapshot = scheduler_owned_mapping_decision(value).as_snapshot()
    if snapshot is None:
        return None
    return scheduler_str_key_mapping_from_items(snapshot.items())


def scheduler_scan_integrity_snapshot(value: object, *, unavailable_reason: str, original_type_field: str, unavailable_flag: str = "scan_integrity_unavailable", unavailable_reason_field: str = "scan_integrity_unavailable_reason") -> dict[str, object]:
    """Return exact scan-integrity mapping or explicit unavailable evidence.

    Missing scan integrity is allowed because callers overlay scheduler failure
    evidence immediately. A present but unsupported value must not collapse to an
    empty dict, because that hides worker/scheduler evidence corruption.
    """
    return scheduler_scan_integrity_decision(
        value,
        unavailable_reason=unavailable_reason,
        original_type_field=original_type_field,
        unavailable_flag=unavailable_flag,
        unavailable_reason_field=unavailable_reason_field,
    ).as_snapshot()


@dataclass(frozen=True, slots=True)
class WorkerResultNormalizationEvidence:
    """Immutable evidence for worker-result schema normalization."""

    path: str
    reason: str
    original_type: str
    path_unavailable_reason: str = ""
    reason_unavailable_reason: str = ""
    error_result_failed: bool = False
    error: str = ""

    def as_scan_integrity(self) -> dict[str, object]:
        evidence = {
            "file_failed": True,
            "had_degraded_stage": True,
            "queue_failure": True,
            "worker_result_schema_invalid": True,
            "worker_result_schema_reason": self.reason,
            "worker_result_original_type": self.original_type,
            "allow_learning": False,
        }
        if self.path_unavailable_reason:
            evidence["worker_result_path_unavailable_reason"] = self.path_unavailable_reason
        if self.reason_unavailable_reason:
            evidence["worker_result_reason_unavailable_reason"] = self.reason_unavailable_reason
        if self.error_result_failed:
            evidence["worker_error_result_construction_failed"] = True
        if self.error:
            evidence["worker_error_result_error"] = self.error[:1000]
        return evidence


def worker_result_evidence(path: object, reason: object, result: object) -> tuple[str, str, WorkerResultNormalizationEvidence]:
    safe_path, path_reason = scheduler_path_text(path)
    safe_reason, reason_unavailable = scheduler_reason_text(reason)
    return safe_path, safe_reason, WorkerResultNormalizationEvidence(
        path=safe_path,
        reason=safe_reason,
        original_type=no_hook_type_name(result),
        path_unavailable_reason=path_reason,
        reason_unavailable_reason=reason_unavailable,
    )


def build_worker_result_schema_failure(path: object, result: object, *, worker_error_result: Callable[[str, RuntimeError], dict[str, object]], recoverable_exceptions: tuple[type[BaseException], ...], reason: object) -> dict[str, object]:
    """Return explicit failure evidence for an invalid worker result schema."""
    safe_path, safe_reason, evidence = worker_result_evidence(path, reason, result)
    try:
        normalized = worker_error_result(safe_path, RuntimeError(safe_reason))
    except recoverable_exceptions as exc:
        evidence = WorkerResultNormalizationEvidence(
            path=safe_path,
            reason=safe_reason,
            original_type=no_hook_type_name(result),
            path_unavailable_reason=evidence.path_unavailable_reason,
            reason_unavailable_reason=evidence.reason_unavailable_reason,
            error_result_failed=True,
            error=scheduler_exception_text(exc),
        )
        normalized = {"file": safe_path, "tags": ["scanner_failure", "scanner_degraded", "scan_incomplete"], "error": safe_reason}
    normalized_snapshot = scheduler_owned_mapping_snapshot(normalized)
    if normalized_snapshot is None:
        evidence = WorkerResultNormalizationEvidence(
            path=safe_path,
            reason=safe_reason,
            original_type=no_hook_type_name(result),
            path_unavailable_reason=evidence.path_unavailable_reason,
            reason_unavailable_reason=evidence.reason_unavailable_reason,
            error_result_failed=True,
            error="worker_error_result returned non-materializable mapping",
        )
        normalized_snapshot = {"file": safe_path, "tags": ["scanner_failure", "scanner_degraded", "scan_incomplete"], "error": safe_reason}
    integrity = scheduler_scan_integrity_snapshot(
        dict.get(normalized_snapshot, "scan_integrity"),
        unavailable_reason="non_materializable_worker_result_integrity",
        original_type_field="worker_result_integrity_original_type",
        unavailable_flag="worker_result_integrity_unavailable",
        unavailable_reason_field="worker_result_integrity_unavailable_reason",
    )
    integrity.update(evidence.as_scan_integrity())
    normalized_snapshot["scan_integrity"] = integrity
    normalized_snapshot["queue_failure"] = True
    normalized_snapshot["scheduler_failure_reason"] = safe_reason
    return normalized_snapshot


__all__ = (
    "WorkerResultNormalizationEvidence",
    "build_worker_result_schema_failure",
    "scheduler_exception_text",
    "scheduler_owned_mapping_snapshot",
    "scheduler_path_text",
    "scheduler_reason_text",
    "scheduler_scan_integrity_snapshot",
)
