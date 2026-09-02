from Virus_Scan.scheduler.timeout.escalation_engine import (
    ProcessQueueStallEscalationDependencies,
    ProcessQueueStallEscalationRequest,
    terminate_stalled_process_queue_workers,
)
from Virus_Scan.scheduler.workers.process_termination import WorkerProcessHandleTerminationResult


class FakeProc:
    pid = 1234


def test_stage756_stall_escalation_dependency_failures_emit_evidence_without_stopping_kill_phase():
    actions = []

    def log_error(_message):
        raise RuntimeError("log unavailable")

    def record_issue(*_args, **_kwargs):
        raise RuntimeError("issue recorder unavailable")

    def sleep(_seconds):
        raise RuntimeError("sleep unavailable")

    def worker_terminator(*, worker_idx, proc, action, reason):
        actions.append(action)
        if action == "terminate":
            raise RuntimeError("terminate callback unavailable")
        return WorkerProcessHandleTerminationResult(worker_idx=int(worker_idx), pid=int(proc.pid), action=action, requested=True, completed=True, reason=reason)

    result = terminate_stalled_process_queue_workers(
        ProcessQueueStallEscalationRequest(procs=((0, FakeProc(), None, None),), elapsed_sec=9.5),
        ProcessQueueStallEscalationDependencies(
            log_error=log_error,
            record_issue=record_issue,
            sleep=sleep,
            worker_terminator=worker_terminator,
        ),
    )

    assert actions == ["terminate", "kill"]
    assert result.killed == 1
    reasons = {record["reason"] for record in result.evidence}
    sources = {record["error_source"] for record in result.evidence}
    assert "process_queue_progress_stalled" in reasons
    assert "process_queue_stall_worker_terminate_failed" in reasons
    assert "process_queue_stall_escalation.log_error" in sources
    assert "process_queue_stall_escalation.worker_terminator" in sources
    assert "process_queue_stall_escalation.sleep" in sources
    assert all(record["final_json_must_record"] for record in result.evidence)
    assert all(record["checkpoint_must_record"] for record in result.evidence)
    assert all(record["replay_must_reproduce"] for record in result.evidence)


def test_stage756_stall_escalation_worker_result_and_issue_record_failures_are_both_evidence():
    def log_error(_message):
        return None

    def record_issue(*_args, **_kwargs):
        raise RuntimeError("issue recorder failed")

    def sleep(_seconds):
        return None

    def worker_terminator(*, worker_idx, proc, action, reason):
        return WorkerProcessHandleTerminationResult(
            worker_idx=int(worker_idx),
            pid=int(proc.pid),
            action=action,
            requested=True,
            completed=False,
            reason=reason,
            error=f"{action}_failed",
        )

    result = terminate_stalled_process_queue_workers(
        ProcessQueueStallEscalationRequest(procs=((2, FakeProc(), None, None),), elapsed_sec=12.0),
        ProcessQueueStallEscalationDependencies(
            log_error=log_error,
            record_issue=record_issue,
            sleep=sleep,
            worker_terminator=worker_terminator,
        ),
    )

    actions = {record["action"] for record in result.evidence}
    reasons = {record["reason"] for record in result.evidence}
    assert "terminate" in actions
    assert "kill" in actions
    assert "terminate_issue_recording" in actions
    assert "kill_issue_recording" in actions
    assert "process_queue_stall_worker_terminate_failed" in reasons
    assert "process_queue_stall_worker_kill_failed" in reasons
    assert result.terminated == 0
    assert result.killed == 0
