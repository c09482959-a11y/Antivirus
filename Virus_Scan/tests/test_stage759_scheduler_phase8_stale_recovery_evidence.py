from __future__ import annotations

from typing import Any, cast

from Virus_Scan.scheduler.orchestration.process_queue_monitor_contracts import ProcessQueueMonitorLoopResult
from Virus_Scan.scheduler.orchestration.process_queue_monitor_iteration_start import MonitorIterationStartResult
from Virus_Scan.scheduler.orchestration.process_queue_monitor_recovery import MonitorRecoveryResult
from Virus_Scan.scheduler.queue.process_queue_stale_recovery import (
    ProcessQueueStaleRecoveryDependencies,
    ProcessQueueStaleRecoveryOutput,
    ProcessQueueStaleRecoveryRequest,
    reconcile_process_queue_stale_recovery,
)


class InjectedRecoveryError(RuntimeError):
    pass


class BadQueueDir:
    def __fspath__(self):
        raise InjectedRecoveryError("queue path failed")

    def __str__(self):
        return "bad://queue"


def _noop_bool(*args, **kwargs):
    return False


def test_phase8_stale_recovery_reclaim_failed_return_becomes_immutable_evidence():
    result = reconcile_process_queue_stale_recovery(
        ProcessQueueStaleRecoveryRequest(
            queue_dir=BadQueueDir(),
            progress_stall_sec=12.5,
            per_file_timeout_sec=3.0,
            raw_stage_progress_state={},
        ),
        ProcessQueueStaleRecoveryDependencies(
            raw_stage_progress_recent=_noop_bool,
            file_has_recent_raw_owner_progress=_noop_bool,
            worker_liveness_checker=lambda *args, **kwargs: None,
            worker_terminator=lambda *args, **kwargs: None,
            log_error=lambda message: None,
            recoverable_exceptions=(InjectedRecoveryError,),
        ),
    )

    assert isinstance(result, ProcessQueueStaleRecoveryOutput)
    assert result.recovered["reclaim_failed"] is True
    assert len(result.evidence) == 1
    evidence = dict(result.evidence[0])
    assert evidence["stage"] == "process_queue_stale_recovery_reclaim_failed"
    assert evidence["timeout_failure"] is True
    assert evidence["queue_recovery_failure"] is True
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True


def test_phase8_stale_recovery_log_failure_is_also_evidence():
    result = reconcile_process_queue_stale_recovery(
        ProcessQueueStaleRecoveryRequest(
            queue_dir="/tmp/unused",
            progress_stall_sec=15.0,
            per_file_timeout_sec=4.0,
            raw_stage_progress_state={},
        ),
        ProcessQueueStaleRecoveryDependencies(
            raw_stage_progress_recent=cast(Any, None),
            file_has_recent_raw_owner_progress=cast(Any, None),
            worker_liveness_checker=lambda *args, **kwargs: None,
            worker_terminator=lambda *args, **kwargs: None,
            log_error=lambda message: (_ for _ in ()).throw(RuntimeError("log failed")),
            recoverable_exceptions=(RuntimeError,),
        ),
    )

    stages = [dict(record)["stage"] for record in result.evidence]
    assert stages == ["process_queue_stale_recovery_failed", "process_queue_stale_recovery_log_failed"]
    assert result.recovered["recovery_failed"] == 1


def test_phase8_monitor_recovery_result_has_stale_recovery_evidence_field():
    assert "stale_recovery_evidence" in MonitorRecoveryResult.__dataclass_fields__


def test_phase8_monitor_contracts_carry_stale_recovery_evidence_forward():
    assert "stale_recovery_evidence" in MonitorIterationStartResult.__dataclass_fields__
    assert "timeout_retry_evidence" in ProcessQueueMonitorLoopResult.__dataclass_fields__
