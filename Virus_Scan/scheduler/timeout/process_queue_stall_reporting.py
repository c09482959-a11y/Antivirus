"""Timeout-owned reporting helpers for process-queue stall escalation."""
from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_plain_instance_dict, no_hook_type_name
from Virus_Scan.scheduler.internal.immutable_output_support import unsupported_scheduler_value_evidence
from Virus_Scan.scheduler.internal.no_hook_attrs import scheduler_exact_attr
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_int, scheduler_text
from Virus_Scan.scheduler.timeout.process_queue_stall_evidence import stall_escalation_evidence
from Virus_Scan.scheduler.timeout.process_queue_stall_reporting_types import PublicTerminationSnapshotDecision, SchedulerEvidence, SchedulerPidValue, StallEvidenceList, StallIssueRecorder, TerminationSnapshot

PROCESS_QUEUE_STALL_ESCALATION_EXCEPTIONS = (OSError, RuntimeError, TypeError, ValueError, AttributeError)
_SCHEDULER_MODULE_PREFIX = "Virus_Scan.scheduler"
_WORKER_TERMINATION_SUFFIX = ".workers.process_termination"
_WORKER_TERMINATION_MODULE = _SCHEDULER_MODULE_PREFIX + _WORKER_TERMINATION_SUFFIX
_MISSING = object()


def _safe_pid_value(value: object, *, field_name: str = "process_pid") -> SchedulerPidValue:
    if type(value) is int and type(value) is not bool:
        return value
    pid, reason = scheduler_int(value, default=0, reason=field_name + "_rejected")
    if reason:
        return unsupported_scheduler_value_evidence(value, field_name=field_name)
    return pid

def _class_attr_without_descriptor(value: object, name: str) -> object:
    try:
        mro = type.__getattribute__(type(value), "__mro__")
    except (AttributeError, TypeError):
        return _MISSING
    for cls in mro:
        try:
            class_dict = type.__getattribute__(cls, "__dict__")
        except (AttributeError, TypeError):
            return _MISSING
        if type(class_dict) is dict or type(class_dict) is MappingProxyType:
            if name not in class_dict:
                continue
            candidate = class_dict[name]
        else:
            return _MISSING
        if type(candidate) in {str, int}:
            return candidate
        return _MISSING
    return _MISSING

def pid_for_process(proc: object) -> SchedulerPidValue:
    data = no_hook_plain_instance_dict(proc)
    if data is not None and "pid" in data:
        return _safe_pid_value(dict.__getitem__(data, "pid"))
    class_pid = _class_attr_without_descriptor(proc, "pid")
    if class_pid is not _MISSING:
        return _safe_pid_value(class_pid)
    return unsupported_scheduler_value_evidence(proc, field_name="process_pid")

def _result_attr_without_hooks(result: object, name: str) -> tuple[object, bool]:
    data = no_hook_plain_instance_dict(result)
    if data is not None and name in data:
        return dict.__getitem__(data, name), True
    class_value = _class_attr_without_descriptor(result, name)
    if class_value is not _MISSING:
        return class_value, True
    return _MISSING, False

def termination_result_snapshot(result: object, *, replacement_pid: object) -> TerminationSnapshot:
    try:
        module_value = type.__getattribute__(type(result), "__module__")
    except (AttributeError, TypeError):
        module = "unknown_module"
    else:
        module = str.__str__(module_value) if type(module_value) is str else "unknown_module"
    name = no_hook_type_name(result)
    owns_worker_termination = module.startswith("Virus_Scan.scheduler.") and module.endswith(_WORKER_TERMINATION_SUFFIX)
    if owns_worker_termination and name == "WorkerProcessHandleTerminationResult":
        worker_idx, pid, action, requested, completed, reason, error = (
            scheduler_exact_attr(
                result,
                field_name,
                module_name=_WORKER_TERMINATION_MODULE,
                type_name="WorkerProcessHandleTerminationResult",
                default=unsupported_scheduler_value_evidence(result, field_name=field_name),
            )
            for field_name in ("worker_idx", "pid", "action", "requested", "completed", "reason", "error")
        )
        error_text, error_reason = scheduler_text(error, replacement_text="", unsupported_reason="termination_error_rejected")
        evidence: SchedulerEvidence = {"worker_idx": worker_idx, "worker_pid": pid, "worker_action": action, "termination_requested": requested, "termination_completed": completed, "termination_reason": reason, "termination_error": error_text}
        if error_reason:
            evidence["worker_termination_field_rejections"] = (error_reason,)
        return {"supported": True, "pid": pid, "error": error_text, "evidence": evidence}
    if owns_worker_termination and name == "WorkerTerminationResult":
        pid, requested, terminated, reason, error = (
            scheduler_exact_attr(
                result,
                field_name,
                module_name=_WORKER_TERMINATION_MODULE,
                type_name="WorkerTerminationResult",
                default=unsupported_scheduler_value_evidence(result, field_name=field_name),
            )
            for field_name in ("pid", "requested", "terminated", "reason", "error")
        )
        error_text, error_reason = scheduler_text(error, replacement_text="", unsupported_reason="termination_error_rejected")
        evidence = {"worker_pid": pid, "termination_requested": requested, "worker_terminated": terminated, "termination_reason": reason, "termination_error": error_text}
        if error_reason:
            evidence["worker_termination_field_rejections"] = (error_reason,)
        return {"supported": True, "pid": pid, "error": error_text, "evidence": evidence}
    public_error, public_has_error = _result_attr_without_hooks(result, "error")
    public_pid, public_has_pid = _result_attr_without_hooks(result, "pid")
    if public_has_error or public_has_pid:
        error_text, error_reason = scheduler_text(
            public_error,
            replacement_text="",
            unsupported_reason="termination_error_rejected",
        )
        safe_pid = _safe_pid_value(public_pid) if public_has_pid else replacement_pid
        evidence = {"worker_pid": safe_pid, "termination_error": error_text, "termination_result_source": "safe_public_attrs"}
        if error_reason:
            evidence["worker_termination_field_rejections"] = (error_reason,)
        public_decision = PublicTerminationSnapshotDecision(True, {"supported": True, "pid": safe_pid, "error": error_text, "evidence": evidence}, "public_termination_fields_available")
    else:
        public_decision = PublicTerminationSnapshotDecision(False, {}, "public_termination_fields_unavailable")
    if public_decision.available:
        return public_decision.snapshot
    return {"supported": False, "pid": replacement_pid, "error": "unsupported_termination_result", "evidence": unsupported_scheduler_value_evidence(result, field_name="worker_termination_result"), "unavailable_reason": public_decision.reason}

def append_stall_evidence(
    *,
    evidence_records: StallEvidenceList,
    worker_idx: object,
    pid: object,
    action: str,
    reason: str,
    error: BaseException | str,
    source: str,
    elapsed_sec: float,
) -> None:
    materialized = materialize_scheduler_mapping(
        stall_escalation_evidence(
            worker_idx=worker_idx,
            pid=pid,
            action=action,
            reason=reason,
            error=error,
            source=source,
            elapsed_sec=elapsed_sec,
        ).as_record()
    )
    evidence_records.append(materialized if type(materialized) is dict else {"stall_evidence_materialization_failed": True})

def record_stall_issue(
    *,
    record_issue: StallIssueRecorder,
    evidence_records: StallEvidenceList,
    stage: str,
    error: BaseException,
    extra: Mapping[str, object],
    worker_idx: object,
    pid: object,
    action: str,
    elapsed_sec: float,
) -> None:
    extra_snapshot = materialize_scheduler_mapping(extra)
    if type(extra_snapshot) is not dict:
        extra_snapshot = {"scheduler_extra_unavailable": unsupported_scheduler_value_evidence(extra, field_name="stall_issue_extra")}
    try:
        record_issue(stage, error, fatal=False, extra=extra_snapshot)
    except PROCESS_QUEUE_STALL_ESCALATION_EXCEPTIONS as record_exc:
        append_stall_evidence(
            evidence_records=evidence_records,
            worker_idx=worker_idx,
            pid=pid,
            action=(action if type(action) is str else "stall") + "_issue_recording",
            reason=stage,
            error=record_exc,
            source="process_queue_stall_escalation.record_issue",
            elapsed_sec=elapsed_sec,
        )

__all__ = ("PROCESS_QUEUE_STALL_ESCALATION_EXCEPTIONS", "append_stall_evidence", "pid_for_process", "record_stall_issue", "termination_result_snapshot")
