from __future__ import annotations

from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping
from Virus_Scan.scheduler.timeout.escalation_engine import (
    ProcessQueueStallEscalationDependencies,
    ProcessQueueStallEscalationRequest,
    terminate_stalled_process_queue_workers,
)
from Virus_Scan.scheduler.timeout.process_queue_stall_evidence import stall_escalation_evidence


class HostileValue:
    touched = 0

    def __str__(self):
        HostileValue.touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        HostileValue.touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, _spec):
        HostileValue.touched += 1
        raise RuntimeError("do not format")

    def __float__(self):
        HostileValue.touched += 1
        raise RuntimeError("do not float")

    def __int__(self):
        HostileValue.touched += 1
        raise RuntimeError("do not int")

    def __bool__(self):
        HostileValue.touched += 1
        raise RuntimeError("do not bool")


class HostileError(RuntimeError):
    touched = 0

    def __str__(self):
        HostileError.touched += 1
        raise RuntimeError("do not stringify error")

    def __repr__(self):
        HostileError.touched += 1
        raise RuntimeError("do not repr error")


class HostileProc:
    touched = 0

    @property
    def pid(self):
        HostileProc.touched += 1
        raise RuntimeError("do not read pid property")


class HostileTerminationResult:
    touched = 0

    @property
    def error(self):
        HostileTerminationResult.touched += 1
        raise RuntimeError("do not read error property")

    @property
    def pid(self):
        HostileTerminationResult.touched += 1
        raise RuntimeError("do not read pid property")

    def as_evidence(self):
        HostileTerminationResult.touched += 1
        raise RuntimeError("do not call as_evidence")


class HostileExtra:
    touched = 0

    def __iter__(self):
        HostileExtra.touched += 1
        raise RuntimeError("do not iterate extra")

    def items(self):
        HostileExtra.touched += 1
        raise RuntimeError("do not call items")


def test_stage1613_stall_evidence_constructor_rejects_hostile_values_without_hooks() -> None:
    HostileValue.touched = 0
    HostileError.touched = 0
    hostile = HostileValue()
    evidence = stall_escalation_evidence(
        worker_idx=hostile,
        pid=hostile,
        action=hostile,  # type: ignore[arg-type]
        reason=hostile,  # type: ignore[arg-type]
        error=HostileError("hidden detail"),
        source=hostile,  # type: ignore[arg-type]
        elapsed_sec=hostile,  # type: ignore[arg-type]
    )

    record = evidence.as_record()
    assert HostileValue.touched == 0
    assert HostileError.touched == 0
    assert record["scheduler_stall_evidence_materialization_failed"] is True
    assert "stall_action_rejected" in record["stall_evidence_materialization_rejections"]
    assert record["worker_idx"]["unsupported_scheduler_value"] is True
    assert record["pid"]["unsupported_scheduler_value"] is True
    assert record["detail"].endswith("without caller hooks")


def test_stage1613_stall_escalation_rejects_hostile_proc_and_termination_result_without_hooks() -> None:
    HostileProc.touched = 0
    HostileTerminationResult.touched = 0
    HostileExtra.touched = 0

    def worker_terminator(*, worker_idx, proc, action, reason):
        return HostileTerminationResult()

    def record_issue(stage, error, *, fatal, extra):
        assert type(extra) is dict
        raise RuntimeError("issue recorder failed")

    result = terminate_stalled_process_queue_workers(
        ProcessQueueStallEscalationRequest(procs=((7, HostileProc(), None, None),), elapsed_sec=1.25),
        ProcessQueueStallEscalationDependencies(
            log_error=lambda _message: None,
            record_issue=record_issue,
            sleep=lambda _seconds: None,
            worker_terminator=worker_terminator,
        ),
    )

    assert HostileProc.touched == 0
    assert HostileTerminationResult.touched == 0
    assert HostileExtra.touched == 0
    assert result.terminated == 0
    assert result.killed == 0
    materialized = tuple(materialize_scheduler_mapping(record) for record in result.evidence)
    reasons = {record["reason"] for record in materialized}
    assert "process_queue_stall_worker_terminate_failed" in reasons
    assert "process_queue_stall_worker_kill_failed" in reasons
    assert any(record["pid"]["unsupported_scheduler_value"] for record in materialized if type(record.get("pid")) is dict)
