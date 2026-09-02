"""Immutable detection-owned cluster label result helpers."""
from __future__ import annotations

from typing import Self, cast

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.detection.evidence.failure_evidence import failure_evidence_payload, recoverable_failure_evidence
from Virus_Scan.detection.models.failure_state import failure_state_records
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot


def _cluster_assignment_label_text(label: object) -> str:
    text, reason = no_hook_text(
        label,
        missing_reason="missing_cluster_assignment_label",
        unsupported_reason="unsafe_cluster_assignment_label_rejected",
    )
    if reason or str.strip(text) == "":
        return "unclustered"
    return str.strip(text)


class ClusterAssignment(str):
    """String-compatible cluster label carrying visible degraded-state evidence."""

    failure_evidence: tuple[dict[str, object], ...]
    degraded: bool
    failure_payload: dict[str, object]
    scan_integrity: dict[str, object]

    def __new__(cls, label: object, failures: object = ()) -> Self:
        obj = cast(Self, str.__new__(cls, _cluster_assignment_label_text(label)))
        records = failure_state_records(failures)
        obj.failure_evidence = records
        obj.degraded = bool(records)
        obj.failure_payload = failure_evidence_payload(records)
        obj.scan_integrity = {
            "ok": not bool(records),
            "degraded": bool(records),
            "failure_count": len(records),
            "json_record_required": any(bool(item.get("json_record_required")) for item in records),
            "replay_record_required": any(bool(item.get("replay_record_required")) for item in records),
            "confidence_degraded": any(bool(item.get("confidence_degraded")) for item in records),
        }
        return obj

    def to_record(self) -> dict[str, object]:
        return {
            "cluster_id": str(self),
            "degraded": bool(self.degraded),
            "failure_evidence": list(self.failure_evidence),
            "scan_integrity": dict(self.scan_integrity),
        }


def cluster_assignment_from_context(context: ModelContextSnapshot) -> ClusterAssignment:
    if type(context) is not ModelContextSnapshot:
        raise TypeError("model_context_snapshot_required")
    cluster_id = context.cluster_context.get("cluster_id")
    return ClusterAssignment(cluster_id or "unclustered", context.failure_evidence)


def failed_cluster_assignment(*, stage_name: str, error: BaseException | str, error_source: str, affected_context: object = "") -> ClusterAssignment:
    return ClusterAssignment(
        "unclustered",
        (
            recoverable_failure_evidence(
                stage_name=stage_name,
                error=error,
                error_source=error_source,
                affected_context=affected_context,
            ),
        ),
    )


__all__ = ("ClusterAssignment", "cluster_assignment_from_context", "failed_cluster_assignment")
