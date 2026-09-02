"""Worker-owned evidence for aggregate child output publication failures."""
from __future__ import annotations

from dataclasses import dataclass


from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_path_text
from Virus_Scan.scheduler.internal.worker_result_boundary import (
    scheduler_exception_text,
    scheduler_scan_integrity_snapshot,
)


@dataclass(frozen=True, slots=True)
class ChildWorkerResultCountDecision:
    """Replayable count decision for aggregate worker child results."""

    value: int
    reason: str
    mapping_available: bool


@dataclass(frozen=True, slots=True)
class ChildWorkerOutputPublicationEvidence:
    """Immutable evidence that aggregate worker-output publication failed."""

    context: str
    failure_stage: str
    worker_output_path: str
    file_path: str
    reason: str
    child_result_count: int
    child_result_count_reason: str = ""

    def as_scan_integrity(self) -> dict[str, object]:
        integrity = {
            "file_failed": True,
            "had_degraded_stage": True,
            "queue_failure": True,
            "worker_output_publication_failed": True,
            "worker_output_publication_context": self.context,
            "worker_output_publication_stage": self.failure_stage,
            "worker_output_publication_path": self.worker_output_path,
            "worker_output_publication_reason": self.reason[:1000],
            "worker_output_publication_child_result_count": self.child_result_count,
            "allow_learning": False,
        }
        if self.child_result_count_reason:
            integrity["worker_output_publication_child_result_count_unavailable"] = True
            integrity[
                "worker_output_publication_child_result_count_unavailable_reason"
            ] = self.child_result_count_reason
        return integrity

    def as_result_record(self) -> dict[str, object]:
        record = {
            "file": self.file_path or "__scheduler_worker_output_publication_failure__",
            "tags": [],
            "queue_failure": True,
            "scheduler_failure_reason": "worker_output_publication_failed",
            "worker_output_publication_failed": True,
            "worker_output_publication_context": self.context,
            "worker_output_publication_stage": self.failure_stage,
            "worker_output_publication_path": self.worker_output_path,
            "worker_output_publication_reason": self.reason[:1000],
            "worker_output_publication_child_result_count": self.child_result_count,
            "scan_integrity": self.as_scan_integrity(),
        }
        if self.child_result_count_reason:
            record["worker_output_publication_child_result_count_unavailable"] = True
            record[
                "worker_output_publication_child_result_count_unavailable_reason"
            ] = self.child_result_count_reason
        return record


@dataclass(frozen=True, slots=True)
class ChildWorkerOutputPublicationRequest:
    """Canonical request for worker-output publication failure evidence."""

    child_results: object
    file_path: object
    worker_output_path: object
    context: str
    failure_stage: str
    reason: object


def _safe_boundary_text(value: object, *, replacement_text: str, missing_reason: str, unsupported_reason: str) -> tuple[str, str]:
    text, reason = no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)
    if reason:
        return replacement_text, reason
    stripped = str.strip(text)
    if not stripped:
        return replacement_text, "blank_scheduler_publication_text"
    return stripped, ""


def child_worker_result_count_decision(child_results: object) -> ChildWorkerResultCountDecision:
    """Count worker-owned child results or return explicit unavailable evidence."""

    items = no_hook_mapping_items(child_results)
    if items is None:
        return ChildWorkerResultCountDecision(
            value=0,
            reason="worker_output_child_results_mapping_unavailable",
            mapping_available=False,
        )
    return ChildWorkerResultCountDecision(value=len(items), reason="", mapping_available=True)


def record_worker_output_publication_failure(
    request: ChildWorkerOutputPublicationRequest,
) -> ChildWorkerOutputPublicationEvidence:
    """Project aggregate worker-output failure into worker-owned result evidence."""

    safe_context, _context_reason = _safe_boundary_text(
        request.context,
        replacement_text="worker_output",
        missing_reason="missing_worker_output_publication_context",
        unsupported_reason="unsafe_worker_output_publication_context_rejected",
    )
    safe_stage, _stage_reason = _safe_boundary_text(
        request.failure_stage,
        replacement_text="unknown",
        missing_reason="missing_worker_output_publication_stage",
        unsupported_reason="unsafe_worker_output_publication_stage_rejected",
    )
    safe_worker_output_path, _worker_path_reason = scheduler_path_text(
        request.worker_output_path
    )
    safe_file_path, _file_path_reason = scheduler_path_text(request.file_path)
    child_results = request.child_results
    child_count_decision = child_worker_result_count_decision(child_results)
    if isinstance(request.reason, BaseException):
        safe_reason = scheduler_exception_text(request.reason)
    else:
        safe_reason, _reason_unavailable = _safe_boundary_text(
            request.reason,
            replacement_text="worker output publication failed",
            missing_reason="missing_worker_output_publication_reason",
            unsupported_reason="unsafe_worker_output_publication_reason_rejected",
        )
    evidence = ChildWorkerOutputPublicationEvidence(
        context=safe_context,
        failure_stage=safe_stage,
        worker_output_path=safe_worker_output_path,
        file_path=safe_file_path or "__scheduler_worker_output_publication_failure__",
        reason=safe_reason,
        child_result_count=child_count_decision.value,
        child_result_count_reason=child_count_decision.reason,
    )
    if type(child_results) is not dict:
        return evidence
    key = evidence.file_path or "__scheduler_worker_output_publication_failure__"
    existing = dict.get(child_results, key)
    if type(existing) is dict:
        updated = dict(existing)
        integrity = scheduler_scan_integrity_snapshot(
            dict.get(updated, "scan_integrity"),
            unavailable_reason="non_materializable_worker_output_integrity",
            original_type_field="worker_output_integrity_original_type",
            unavailable_flag="worker_output_integrity_unavailable",
            unavailable_reason_field="worker_output_integrity_unavailable_reason",
        )
        integrity.update(evidence.as_scan_integrity())
        updated["scan_integrity"] = integrity
        updated["queue_failure"] = True
        updated["scheduler_failure_reason"] = "worker_output_publication_failed"
        updated["worker_output_publication_failed"] = True
        updated["worker_output_publication_context"] = evidence.context
        updated["worker_output_publication_stage"] = evidence.failure_stage
        updated["worker_output_publication_reason"] = evidence.reason[:1000]
        child_results[key] = updated
    else:
        sentinel = "__scheduler_worker_output_publication_failure__"
        if sentinel in child_results:
            sentinel = sentinel + "_" + int.__str__(evidence.child_result_count)
        child_results[sentinel] = evidence.as_result_record()
    return evidence


__all__ = (
    "ChildWorkerOutputPublicationEvidence",
    "ChildWorkerOutputPublicationRequest",
    "ChildWorkerResultCountDecision",
    "child_worker_result_count_decision",
    "record_worker_output_publication_failure",
)
