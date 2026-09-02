from __future__ import annotations

from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_setup import _attach_timeout_config_evidence_to_job_records
from Virus_Scan.scheduler.timeout.inmemory_timeout_config import build_inmemory_timeout_config


def test_stage762_invalid_inmemory_timeout_env_records_immutable_evidence_without_abort():
    config = build_inmemory_timeout_config(
        {
            "UMIGE_INMEMORY_MAX_JOB_RETRIES": "bad-int",
            "UMIGE_INMEMORY_QUEUED_START_TIMEOUT_SEC": "nan",
            "UMIGE_INMEMORY_ASSIGNED_START_TIMEOUT_SEC": "bad-float",
            "UMIGE_INMEMORY_HEARTBEAT_STALE_SEC": "inf",
            "UMIGE_INMEMORY_PROGRESS_STALE_SEC": "bad-progress",
            "UMIGE_INMEMORY_CANCEL_GRACE_SEC": "bad-cancel",
        },
        per_file_timeout_sec="bad-timeout",
    )

    assert config.max_job_retries == 5
    assert config.base_file_timeout_seconds == 20
    assert config.queued_start_timeout_seconds == 400.0
    assert config.assigned_start_timeout_seconds == 400.0
    assert config.heartbeat_stale_seconds == 120.0
    assert config.progress_stale_seconds == 240.0
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
    for evidence in config.config_evidence:
        assert evidence["stage"] == "inmemory_timeout_config"
        assert evidence["timeout_failure"] is True
        assert evidence["final_json_must_record"] is True
        assert evidence["checkpoint_must_record"] is True
        assert evidence["replay_must_reproduce"] is True
        try:
            evidence["stage"] = "mutated"
        except TypeError:
            pass
        else:  # pragma: no cover
            raise AssertionError("timeout config evidence must be immutable")


def test_stage762_timeout_config_evidence_attaches_to_job_history_for_replay():
    config = build_inmemory_timeout_config(
        {"UMIGE_INMEMORY_CANCEL_GRACE_SEC": "bad-cancel"},
        per_file_timeout_sec=20,
    )
    job_records = {
        0: {"history": (), "state": "pending"},
        1: {"history": (), "state": "pending"},
    }

    _attach_timeout_config_evidence_to_job_records(job_records, tuple(config.config_evidence))

    for record in job_records.values():
        assert record["timeout_config_evidence_recorded"] is True
        assert record["timeout_config_evidence"]
        assert record["timeout_config_evidence"][0]["setting"] == "UMIGE_INMEMORY_CANCEL_GRACE_SEC"
        assert record["timeout_config_evidence"][0]["final_json_must_record"] is True
        assert record["history"][-1]["action"] == "timeout_config_evidence"
        assert record["history"][-1]["timeout_config_evidence"]["checkpoint_must_record"] is True
