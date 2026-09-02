from __future__ import annotations

from Virus_Scan.scheduler.timeout.process_queue_monitor_policy import process_queue_monitor_policy


def test_stage766_monitor_sleep_upper_clamp_emits_timeout_config_evidence():
    policy = process_queue_monitor_policy(
        env={"UMIGE_QUEUE_MONITOR_SLEEP_SEC": "99"},
        configured_per_file_timeout_sec=300.0,
        recoverable_exceptions=(RuntimeError, TypeError, ValueError, OverflowError),
    )

    assert policy.monitor_sleep_sec == 5.0
    evidence = tuple(policy.timeout_config_evidence)
    matching = [item for item in evidence if item.get("setting") == "UMIGE_QUEUE_MONITOR_SLEEP_SEC"]
    assert matching
    assert "above maximum 5.0" in str(matching[0].get("detail"))
    assert matching[0]["final_json_must_record"] is True
    assert matching[0]["checkpoint_must_record"] is True
    assert matching[0]["replay_must_reproduce"] is True
