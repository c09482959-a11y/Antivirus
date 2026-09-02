"""Failure evidence helpers for JSON/replay-visible degraded detection states."""

from __future__ import annotations


from Virus_Scan.detection.models.failure_state import (
    DetectionFailureState,
    DetectionRecoverableFailureRequest,
    failure_state_records,
)


def recoverable_failure_evidence(*, stage_name: str, error: BaseException | str, error_source: str, affected_context: object = "") -> DetectionFailureState:
    return DetectionFailureState.from_recoverable_request(
        DetectionRecoverableFailureRequest(
            stage_name=stage_name,
            error=error,
            error_source=error_source,
            affected_context=affected_context,
        )
    )


def failure_evidence_payload(failures: object) -> dict[str, object]:
    records = failure_state_records(failures)
    return {
        "degraded": bool(records),
        "failure_count": len(records),
        "failures": list(records),
        "json_record_required": any(bool(item.get("json_record_required")) for item in records),
        "replay_record_required": any(bool(item.get("replay_record_required")) for item in records),
        "confidence_degraded": any(bool(item.get("confidence_degraded")) for item in records),
    }


__all__ = ("failure_evidence_payload", "recoverable_failure_evidence")
