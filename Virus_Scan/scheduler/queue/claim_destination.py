"""No-hook process-queue claim destination name construction."""
from __future__ import annotations

from typing import Callable

from Virus_Scan.contracts.no_hook_materialization import no_hook_text, no_hook_type_name
from Virus_Scan.runtime.api import record_suppressed_failure
from Virus_Scan.scheduler.internal.immutable_outputs import immutable_mapping, materialize_scheduler_mapping

_CLAIM_DESTINATION_REJECTION = "queue_claim_destination_component_rejected"
_CLAIM_DESTINATION_RECORDER_FAILED = "queue_claim_destination_component_rejection_recorder_failed"


def _claim_component_text(value: object, *, field_name: str, replacement_text: str) -> tuple[str, object | None]:
    text, reason = no_hook_text(
        value,
        missing_reason=field_name + "_missing",
        unsupported_reason=field_name + "_rejected",
    )
    if reason != "" or text == "":
        return str.__str__(replacement_text), immutable_mapping({
            "field_name": field_name,
            "reason": reason or field_name + "_empty",
            "value_type": no_hook_type_name(value),
            "replacement_text": str.__str__(replacement_text),
            "queue_claim_destination_component_rejected": True,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        })
    safe_text = str.__str__(text)
    sanitized = safe_text.replace("/", "_").replace("\\", "_").replace("\x00", "_")
    if sanitized != safe_text or sanitized == "":
        replacement = sanitized or str.__str__(replacement_text)
        return replacement, immutable_mapping({
            "field_name": field_name,
            "reason": field_name + "_path_component_rejected",
            "value_type": no_hook_type_name(value),
            "replacement_text": replacement,
            "queue_claim_destination_component_rejected": True,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        })
    return safe_text, None


def _record_claim_destination_component_rejections(
    issues: tuple[object, ...],
    *,
    record_suppressed: Callable[..., object] | None,
) -> None:
    if not issues or record_suppressed is None:
        return
    extra = materialize_scheduler_mapping(immutable_mapping({
        "queue_claim_destination_component_rejected": True,
        "component_issues": issues,
        "final_json_must_record": True,
        "checkpoint_must_record": True,
        "replay_must_record": True,
    }))
    try:
        record_suppressed(
            _CLAIM_DESTINATION_REJECTION,
            ValueError(_CLAIM_DESTINATION_REJECTION),
            extra=extra,
            fatal=True,
        )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
        try:
            record_suppressed_failure(
                _CLAIM_DESTINATION_RECORDER_FAILED,
                exc,
                domain="scheduler",
                context={
                    "queue_claim_destination_component_rejected": True,
                    "queue_claim_destination_component_rejection_recorder_failed": True,
                    "component_issue_count": len(issues),
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_record": True,
                },
                fatal=True,
            )
        except (OSError, RuntimeError, TypeError, ValueError, KeyError):
            return


def claim_destination_name(
    worker_id: object,
    pending_name: object,
    *,
    worker_pid: object,
    record_suppressed: Callable[..., object] | None = None,
) -> str:
    """Return a deterministic active-claim filename without caller-owned hooks."""
    worker_text, worker_issue = _claim_component_text(
        worker_id,
        field_name="worker_id",
        replacement_text="worker",
    )
    if type(worker_pid) is int and type(worker_pid) is not bool:
        pid_text, pid_issue = int.__str__(worker_pid), None
    else:
        pid_text, pid_issue = "0", immutable_mapping({
            "field_name": "worker_pid",
            "reason": "worker_pid_rejected",
            "value_type": no_hook_type_name(worker_pid),
            "replacement_text": "0",
            "queue_claim_destination_component_rejected": True,
            "final_json_must_record": True,
            "checkpoint_must_record": True,
            "replay_must_record": True,
        })
    name_text, name_issue = _claim_component_text(
        pending_name,
        field_name="pending_name",
        replacement_text="pending_job_rejected.json",
    )
    issues = tuple(issue for issue in (worker_issue, pid_issue, name_issue) if issue is not None)
    _record_claim_destination_component_rejections(issues, record_suppressed=record_suppressed)
    return f"{worker_text}_{pid_text}_{name_text}"


__all__ = ("claim_destination_name",)
