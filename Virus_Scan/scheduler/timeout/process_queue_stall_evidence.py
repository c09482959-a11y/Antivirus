"""Immutable timeout escalation evidence for process-queue stall handling."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.no_hook_diagnostics import (
    scheduler_bool,
    scheduler_error_detail,
    scheduler_float,
    scheduler_int,
    scheduler_tag_texts,
    scheduler_text,
)

def _safe_identity_value(value: object, *, field_name: str, allow_none: bool = False) -> tuple[object, str]:
    if value is None:
        return None, "" if allow_none else field_name + "_missing"
    if type(value) is str:
        return str.__str__(value), ""
    if type(value) is int and type(value) is not bool:
        return value, ""
    if type(value) is float:
        numeric, reason = scheduler_int(value, default=0, reason=field_name + "_rejected")
        if reason:
            return unsupported_scheduler_value_evidence(value, field_name=field_name), reason
        return numeric, ""
    return unsupported_scheduler_value_evidence(value, field_name=field_name), field_name + "_rejected"


@dataclass(frozen=True, slots=True)
class ProcessQueueStallEscalationEvidence:
    """Replay-visible evidence for a process-queue stall escalation event."""

    worker_idx: object
    pid: object
    action: str
    reason: str
    error_category: str
    error_source: str
    detail: str
    elapsed_sec: float
    final_json_must_record: bool = True
    checkpoint_must_record: bool = True
    replay_must_reproduce: bool = True
    materialization_rejections: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        worker_idx, worker_idx_reason = _safe_identity_value(self.worker_idx, field_name="stall_worker_idx")
        pid, pid_reason = _safe_identity_value(self.pid, field_name="stall_pid", allow_none=True)
        action, action_reason = scheduler_text(
            self.action,
            replacement_text="stall_escalation",
            unsupported_reason="stall_action_rejected",
        )
        reason, reason_reason = scheduler_text(
            self.reason,
            replacement_text="process_queue_progress_stalled",
            unsupported_reason="stall_reason_rejected",
        )
        error_category, category_reason = scheduler_text(
            self.error_category,
            replacement_text="RuntimeError",
            unsupported_reason="stall_error_category_rejected",
        )
        error_source, source_reason = scheduler_text(
            self.error_source,
            replacement_text="process_queue_stall_escalation",
            unsupported_reason="stall_error_source_rejected",
        )
        detail, detail_reason = scheduler_text(
            self.detail,
            replacement_text="",
            unsupported_reason="stall_detail_rejected",
        )
        elapsed, elapsed_reason = scheduler_float(
            self.elapsed_sec,
            default=0.0,
            reason="stall_elapsed_rejected",
            non_finite_reason="stall_elapsed_non_finite",
        )
        final_json, final_json_reason = scheduler_bool(
            self.final_json_must_record,
            default=True,
            reason="stall_final_json_flag_rejected",
        )
        checkpoint, checkpoint_reason = scheduler_bool(
            self.checkpoint_must_record,
            default=True,
            reason="stall_checkpoint_flag_rejected",
        )
        replay, replay_reason = scheduler_bool(
            self.replay_must_reproduce,
            default=True,
            reason="stall_replay_flag_rejected",
        )
        explicit_rejections = scheduler_tag_texts(self.materialization_rejections)
        rejections = tuple(
            item
            for item in (
                worker_idx_reason,
                pid_reason,
                action_reason,
                reason_reason,
                category_reason,
                source_reason,
                detail_reason,
                elapsed_reason,
                final_json_reason,
                checkpoint_reason,
                replay_reason,
                *explicit_rejections,
            )
            if item
        )
        object.__setattr__(self, "worker_idx", worker_idx)
        object.__setattr__(self, "pid", pid)
        object.__setattr__(self, "action", action)
        object.__setattr__(self, "reason", reason)
        object.__setattr__(self, "error_category", error_category)
        object.__setattr__(self, "error_source", error_source)
        object.__setattr__(self, "detail", detail[:1000])
        object.__setattr__(self, "elapsed_sec", elapsed)
        object.__setattr__(self, "final_json_must_record", final_json)
        object.__setattr__(self, "checkpoint_must_record", checkpoint)
        object.__setattr__(self, "replay_must_reproduce", replay)
        object.__setattr__(self, "materialization_rejections", rejections)

    def as_record(self) -> Mapping[str, object]:
        context = MappingProxyType(
            {
                "worker_idx": self.worker_idx,
                "pid": self.pid,
                "action": self.action,
                "reason": self.reason,
                "elapsed_sec": self.elapsed_sec,
            }
        )
        record: dict[str, object] = {
            "stage": "process_queue_stall_escalation",
            "worker_idx": self.worker_idx,
            "pid": self.pid,
            "action": self.action,
            "reason": self.reason,
            "error_category": self.error_category,
            "error_source": self.error_source,
            "detail": self.detail,
            "elapsed_sec": self.elapsed_sec,
            "final_json_must_record": self.final_json_must_record,
            "checkpoint_must_record": self.checkpoint_must_record,
            "replay_must_reproduce": self.replay_must_reproduce,
            "timeout_state_affected": True,
            "context": context,
        }
        if self.materialization_rejections:
            record["stall_evidence_materialization_rejections"] = self.materialization_rejections
            record["scheduler_stall_evidence_materialization_failed"] = True
        return MappingProxyType(record)


def stall_escalation_evidence(
    *,
    worker_idx: object,
    pid: object,
    action: str,
    reason: str,
    error: BaseException | str,
    source: str,
    elapsed_sec: float,
) -> ProcessQueueStallEscalationEvidence:
    if isinstance(error, BaseException):
        category = no_hook_type_name(error)
        detail = scheduler_error_detail(error)
        error_rejections = ()
    else:
        detail, detail_reason = scheduler_text(
            error,
            replacement_text="scheduler diagnostic detail unavailable without caller hooks",
            unsupported_reason="stall_error_detail_rejected",
        )
        category = "RuntimeError"
        error_rejections = () if not detail_reason else (detail_reason,)
    return ProcessQueueStallEscalationEvidence(
        worker_idx=worker_idx,
        pid=pid,
        action=action,
        reason=reason,
        error_category=category,
        error_source=source,
        detail=detail,
        elapsed_sec=elapsed_sec,
        materialization_rejections=error_rejections,
    )

__all__ = ("ProcessQueueStallEscalationEvidence", "stall_escalation_evidence")
