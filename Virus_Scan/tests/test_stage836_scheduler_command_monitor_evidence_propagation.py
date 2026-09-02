from __future__ import annotations

from dataclasses import FrozenInstanceError

from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section
from Virus_Scan.scheduler.orchestration.process_queue_monitor_contracts import ProcessQueueMonitorLoopResult
from Virus_Scan.scheduler.timeout.process_queue_monitor_policy import process_queue_monitor_policy
from Virus_Scan.scheduler.timeout.process_queue_stall_evidence import stall_escalation_evidence

RECOVERABLE = (OSError, RuntimeError, TypeError, ValueError, OverflowError)


def test_stage836_monitor_loop_result_returns_immutable_timeout_config_evidence_and_projects_final_json():
    policy = process_queue_monitor_policy(
        env={
            "UMIGE_QUEUE_MONITOR_SLEEP_SEC": "0",
            "UMIGE_QUEUE_PROGRESS_STALL_SEC": "bad-stall",
        },
        configured_per_file_timeout_sec="bad-timeout",
        recoverable_exceptions=RECOVERABLE,
    )
    result = ProcessQueueMonitorLoopResult(
        had_error=False,
        timeout_retry_evidence=(),
        timeout_config_evidence=tuple(policy.timeout_config_evidence),
    )

    assert result.timeout_config_evidence
    assert result.timeout_config_evidence[0]["stage"] == "process_queue_monitor_timeout_config"
    assert result.timeout_config_evidence[0]["final_json_must_record"] is True
    assert result.timeout_config_evidence[0]["checkpoint_must_record"] is True
    assert result.timeout_config_evidence[0]["replay_must_reproduce"] is True
    try:
        result.timeout_config_evidence = ()
    except FrozenInstanceError:
        pass
    else:  # pragma: no cover
        raise AssertionError("monitor result must be immutable")

    scheduler = build_final_json_scheduler_section({"timeout_config_evidence": result.timeout_config_evidence})
    assert scheduler is not None
    assert scheduler["scheduler_status"] == "degraded"
    assert scheduler["timeout_decisions"]
    assert scheduler["evidence"][0]["checkpoint_must_record"] is True
    assert scheduler["evidence"][0]["replay_must_record"] is True


def test_stage836_monitor_loop_result_returns_stall_escalation_evidence_once_and_projects_final_json():
    evidence = stall_escalation_evidence(
        worker_idx=2,
        pid=12345,
        action="terminate",
        reason="process_queue_progress_stalled",
        error="terminate requested after monitor stall",
        source="process_queue_stall_escalation.worker_terminator",
        elapsed_sec=91.5,
    ).as_record()
    result = ProcessQueueMonitorLoopResult(had_error=True, timeout_retry_evidence=(evidence,))

    assert len(result.timeout_retry_evidence) == 1
    stored = result.timeout_retry_evidence[0]
    assert stored["stage"] == "process_queue_stall_escalation"
    assert stored["action"] == "terminate"
    assert stored["final_json_must_record"] is True
    assert stored["checkpoint_must_record"] is True
    assert stored["replay_must_reproduce"] is True

    scheduler = build_final_json_scheduler_section({"timeout_retry_evidence": result.timeout_retry_evidence})
    assert scheduler is not None
    assert scheduler["scheduler_status"] == "degraded"
    assert len(scheduler["evidence"]) == 1
    assert scheduler["timeout_decisions"]
    assert scheduler["evidence"][0]["context"]["action"] == "terminate"
