from __future__ import annotations

from Virus_Scan.scheduler.timeout.inmemory_timeout_config import build_inmemory_timeout_config
from Virus_Scan.scheduler.timeout.process_queue_monitor_policy import process_queue_monitor_policy

RECOVERABLE = (OSError, RuntimeError, TypeError, ValueError, OverflowError)


def test_stage763_inmemory_timeout_subminimum_values_record_clamp_evidence():
    config = build_inmemory_timeout_config(
        {
            "UMIGE_INMEMORY_MAX_JOB_RETRIES": "-2",
            "UMIGE_INMEMORY_QUEUED_START_TIMEOUT_SEC": "1",
            "UMIGE_INMEMORY_ASSIGNED_START_TIMEOUT_SEC": "2",
            "UMIGE_INMEMORY_HEARTBEAT_STALE_SEC": "3",
            "UMIGE_INMEMORY_PROGRESS_STALE_SEC": "4",
            "UMIGE_INMEMORY_CANCEL_GRACE_SEC": "5",
        },
        per_file_timeout_sec=0,
    )

    assert config.base_file_timeout_seconds == 1
    assert config.max_job_retries == 0
    assert config.queued_start_timeout_seconds == 300.0
    assert config.assigned_start_timeout_seconds == 300.0
    assert config.heartbeat_stale_seconds == 60.0
    assert config.progress_stale_seconds == 120.0
    assert config.cancel_grace_seconds == 30.0
    settings = {record["setting"] for record in config.config_evidence}
    assert settings == {
        "per_file_timeout_sec",
        "UMIGE_INMEMORY_MAX_JOB_RETRIES",
        "UMIGE_INMEMORY_QUEUED_START_TIMEOUT_SEC",
        "UMIGE_INMEMORY_ASSIGNED_START_TIMEOUT_SEC",
        "UMIGE_INMEMORY_HEARTBEAT_STALE_SEC",
        "UMIGE_INMEMORY_PROGRESS_STALE_SEC",
        "UMIGE_INMEMORY_CANCEL_GRACE_SEC",
    }
    for record in config.config_evidence:
        assert record["timeout_failure"] is True
        assert record["final_json_must_record"] is True
        assert record["checkpoint_must_record"] is True
        assert record["replay_must_reproduce"] is True
        assert "below minimum" in record["detail"]
        try:
            record["stage"] = "mutated"
        except TypeError:
            pass
        else:  # pragma: no cover
            raise AssertionError("timeout clamp evidence must be immutable")


def test_stage763_process_queue_monitor_subminimum_timeout_values_record_evidence():
    policy = process_queue_monitor_policy(
        env={
            "UMIGE_QUEUE_MONITOR_SLEEP_SEC": "0.01",
            "UMIGE_QUEUE_PROGRESS_STALL_SEC": "1",
            "UMIGE_QUEUE_DRAIN_TERMINATE_SEC": "1",
            "UMIGE_QUEUE_MONITOR_HEARTBEAT_SEC": "0",
        },
        configured_per_file_timeout_sec=1,
        recoverable_exceptions=RECOVERABLE,
    )

    assert policy.monitor_sleep_sec == 0.2
    assert policy.per_file_timeout_sec == 30.0
    assert policy.progress_stall_sec == 60.0
    assert policy.idle_grace_sec == 5.0
    assert policy.monitor_heartbeat_sec == 1.0
    settings = {record["setting"] for record in policy.timeout_config_evidence}
    assert settings == {
        "UMIGE_QUEUE_MONITOR_SLEEP_SEC",
        "UMIGE_PER_FILE_TIMEOUT_SEC",
        "UMIGE_QUEUE_PROGRESS_STALL_SEC",
        "UMIGE_QUEUE_DRAIN_TERMINATE_SEC",
        "UMIGE_QUEUE_MONITOR_HEARTBEAT_SEC",
    }
    for record in policy.timeout_config_evidence:
        assert record["stage"] == "process_queue_monitor_timeout_config"
        assert record["timeout_failure"] is True
        assert record["final_json_must_record"] is True
        assert record["checkpoint_must_record"] is True
        assert record["replay_must_reproduce"] is True
        assert "below minimum" in record["detail"]

from Virus_Scan.scheduler.timeout.inmemory_memory_policy import build_inmemory_worker_memory_policy


def test_stage763_inmemory_memory_policy_nonfinite_and_subminimum_values_record_evidence():
    for raw_value in ("nan", "inf", "0", "-1"):
        policy = build_inmemory_worker_memory_policy({"UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB": raw_value})
        assert policy.rss_limit_mb == 2048.0
        assert policy.config_evidence
        evidence = policy.config_evidence[0]
        assert evidence["setting"] == "UMIGE_INMEMORY_WORKER_RSS_LIMIT_MB"
        assert evidence["timeout_failure"] is True
        assert evidence["final_json_must_record"] is True
        assert evidence["checkpoint_must_record"] is True
        assert evidence["replay_must_reproduce"] is True
