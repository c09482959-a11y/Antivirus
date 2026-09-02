"""Helper ownership for process-queue stall escalation."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.scheduler.internal.no_hook_diagnostics import scheduler_float
from Virus_Scan.scheduler.timeout.process_queue_stall_reporting import (
    PROCESS_QUEUE_STALL_ESCALATION_EXCEPTIONS,
    append_stall_evidence,
    pid_for_process,
    record_stall_issue,
)


def elapsed_seconds_log_text(elapsed_sec: object) -> str:
    safe_elapsed_sec, _reason = scheduler_float(
        elapsed_sec,
        default=0.0,
        minimum=0.0,
        reason="process_queue_stall_elapsed_rejected",
        non_finite_reason="process_queue_stall_elapsed_non_finite",
    )
    return float.__format__(safe_elapsed_sec, ".1f")


def stall_issue_extra(snapshot: Mapping[str, object]) -> Mapping[str, object]:
    evidence = snapshot.get("evidence")
    return evidence if type(evidence) is dict else {}


def record_progress_stall_log(
    *,
    request: object,
    deps: object,
    evidence_records: list[Mapping[str, object]],
) -> None:
    try:
        deps.log_error(
            "bulk scan queue made no checkpoint progress for "
            + elapsed_seconds_log_text(request.elapsed_sec)
            + "s; terminating live workers so incomplete claims can retry/fail cleanly"
        )
    except PROCESS_QUEUE_STALL_ESCALATION_EXCEPTIONS as log_exc:
        append_stall_evidence(
            evidence_records=evidence_records,
            worker_idx="process_queue",
            pid=None,
            action="log_progress_stall",
            reason="process_queue_progress_stalled",
            error=log_exc,
            source="process_queue_stall_escalation.log_error",
            elapsed_sec=request.elapsed_sec,
        )


def record_worker_action_failure(
    *,
    request: object,
    deps: object,
    evidence_records: list[Mapping[str, object]],
    worker_idx: object,
    snapshot: Mapping[str, object],
    action: str,
    stage: str,
    error: RuntimeError,
) -> None:
    append_stall_evidence(
        evidence_records=evidence_records,
        worker_idx=worker_idx,
        pid=snapshot["pid"],
        action=action,
        reason=stage,
        error=error,
        source="process_queue_stall_escalation.worker_terminator",
        elapsed_sec=request.elapsed_sec,
    )
    record_stall_issue(
        record_issue=deps.record_issue,
        evidence_records=evidence_records,
        stage=stage,
        error=error,
        extra=stall_issue_extra(snapshot),
        worker_idx=worker_idx,
        pid=snapshot["pid"],
        action=action,
        elapsed_sec=request.elapsed_sec,
    )


def apply_worker_escalation_action(
    *,
    request: object,
    deps: object,
    evidence_records: list[Mapping[str, object]],
    action: str,
    failure_stage: str,
    termination_snapshot_for_process: object,
) -> int:
    completed = 0
    for worker_idx, proc, _output, _cmd in request.procs:
        try:
            result = deps.worker_terminator(
                worker_idx=worker_idx,
                proc=proc,
                action=action,
                reason="process_queue_progress_stalled",
            )
        except PROCESS_QUEUE_STALL_ESCALATION_EXCEPTIONS as worker_exc:
            append_stall_evidence(
                evidence_records=evidence_records,
                worker_idx=worker_idx,
                pid=pid_for_process(proc),
                action=action,
                reason=failure_stage,
                error=worker_exc,
                source="process_queue_stall_escalation.worker_terminator",
                elapsed_sec=request.elapsed_sec,
            )
            continue
        snapshot = termination_snapshot_for_process(result, proc)
        result_error = snapshot["error"]
        if result_error and result_error != "already_exited":
            record_worker_action_failure(
                request=request,
                deps=deps,
                evidence_records=evidence_records,
                worker_idx=worker_idx,
                snapshot=snapshot,
                action=action,
                stage=failure_stage,
                error=RuntimeError(result_error),
            )
        else:
            completed += 1
    return completed


def sleep_before_kill_escalation(
    *,
    request: object,
    deps: object,
    evidence_records: list[Mapping[str, object]],
) -> None:
    try:
        deps.sleep(1.0)
    except PROCESS_QUEUE_STALL_ESCALATION_EXCEPTIONS as sleep_exc:
        append_stall_evidence(
            evidence_records=evidence_records,
            worker_idx="process_queue",
            pid=None,
            action="stall_escalation_sleep",
            reason="process_queue_progress_stalled",
            error=sleep_exc,
            source="process_queue_stall_escalation.sleep",
            elapsed_sec=request.elapsed_sec,
        )
