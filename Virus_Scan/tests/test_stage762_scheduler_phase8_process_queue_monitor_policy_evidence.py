from __future__ import annotations

from Virus_Scan.scheduler.orchestration.process_queue_monitor_runtime import build_process_queue_monitor_runtime_state
from Virus_Scan.scheduler.timeout.process_queue_monitor_policy import process_queue_monitor_policy

RECOVERABLE = (OSError, RuntimeError, TypeError, ValueError, OverflowError)


def test_stage762_process_queue_monitor_policy_invalid_timeout_config_records_evidence():
    policy = process_queue_monitor_policy(
        env={
            "UMIGE_QUEUE_MONITOR_SLEEP_SEC": "bad-sleep",
            "UMIGE_QUEUE_PROGRESS_STALL_SEC": "nan",
            "UMIGE_QUEUE_DRAIN_TERMINATE_SEC": "bad-idle",
            "UMIGE_QUEUE_MONITOR_HEARTBEAT_SEC": "inf",
        },
        configured_per_file_timeout_sec="bad-timeout",
        recoverable_exceptions=RECOVERABLE,
    )

    assert policy.monitor_sleep_sec == 1.0
    assert policy.per_file_timeout_sec == 300.0
    assert policy.progress_stall_sec == 600.0
    assert policy.idle_grace_sec == 45.0
    assert policy.monitor_heartbeat_sec == 30.0
    settings = {record["setting"] for record in policy.timeout_config_evidence}
    assert settings == {
        "UMIGE_QUEUE_MONITOR_SLEEP_SEC",
        "UMIGE_PER_FILE_TIMEOUT_SEC",
        "UMIGE_QUEUE_PROGRESS_STALL_SEC",
        "UMIGE_QUEUE_DRAIN_TERMINATE_SEC",
        "UMIGE_QUEUE_MONITOR_HEARTBEAT_SEC",
    }
    for evidence in policy.timeout_config_evidence:
        assert evidence["stage"] == "process_queue_monitor_timeout_config"
        assert evidence["timeout_failure"] is True
        assert evidence["final_json_must_record"] is True
        assert evidence["checkpoint_must_record"] is True
        assert evidence["replay_must_reproduce"] is True
        try:
            evidence["stage"] = "mutated"
        except TypeError:
            pass
        else:  # pragma: no cover
            raise AssertionError("monitor timeout config evidence must be immutable")


def test_stage762_monitor_runtime_state_carries_monitor_timeout_config_evidence():
    state = build_process_queue_monitor_runtime_state(
        configured_per_file_timeout_sec=20,
        env={"UMIGE_QUEUE_MONITOR_SLEEP_SEC": "bad-sleep"},
        current_time=lambda: 100.0,
    )

    assert state.timeout_config_evidence
    assert state.timeout_config_evidence[0]["setting"] == "UMIGE_QUEUE_MONITOR_SLEEP_SEC"
    assert state.timeout_config_evidence[0]["final_json_must_record"] is True
