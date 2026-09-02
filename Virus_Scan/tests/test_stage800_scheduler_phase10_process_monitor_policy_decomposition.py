from __future__ import annotations

import inspect
from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.scheduler.timeout import process_queue_monitor_policy as policy_module
from Virus_Scan.scheduler.timeout import process_queue_monitor_evidence as evidence_module
from Virus_Scan.scheduler.timeout.process_queue_monitor_evidence import monitor_timeout_config_evidence
from Virus_Scan.scheduler.timeout.process_queue_monitor_policy import process_queue_monitor_policy
from Virus_Scan.scheduler.timeout.process_queue_monitor_values import monitor_float_config


RECOVERABLE = (Exception,)


def test_stage800_monitor_policy_keeps_timeout_evidence_immutable_after_decomposition() -> None:
    policy = process_queue_monitor_policy(
        env={
            "UMIGE_QUEUE_MONITOR_SLEEP_SEC": "bad-sleep",
            "UMIGE_PER_FILE_TIMEOUT_SEC": "5",
            "UMIGE_QUEUE_PROGRESS_STALL_SEC": "0",
            "UMIGE_QUEUE_DRAIN_TERMINATE_SEC": "1",
            "UMIGE_QUEUE_MONITOR_HEARTBEAT_SEC": "0",
        },
        configured_per_file_timeout_sec=0,
        recoverable_exceptions=RECOVERABLE,
    )

    assert policy.monitor_sleep_sec == 1.0
    assert policy.per_file_timeout_sec == 30.0
    assert policy.progress_stall_sec >= 60.0
    assert policy.idle_grace_sec == 5.0
    assert policy.monitor_heartbeat_sec == 1.0
    assert policy.timeout_config_evidence
    assert all(isinstance(item, Mapping) for item in policy.timeout_config_evidence)
    assert {item["setting"] for item in policy.timeout_config_evidence} >= {
        "UMIGE_QUEUE_MONITOR_SLEEP_SEC",
        "UMIGE_PER_FILE_TIMEOUT_SEC",
        "UMIGE_QUEUE_PROGRESS_STALL_SEC",
        "UMIGE_QUEUE_DRAIN_TERMINATE_SEC",
        "UMIGE_QUEUE_MONITOR_HEARTBEAT_SEC",
    }


def test_stage800_monitor_policy_facade_no_longer_owns_low_level_evidence_or_float_parsing() -> None:
    source = inspect.getsource(policy_module)

    assert "MappingProxyType" not in source
    assert "math.isfinite" not in source
    assert "monitor_float_config" in source
    assert "record_monitor_minimum_if_needed" in source
    assert "monitor_timeout_config_evidence" not in source


def test_stage800_monitor_value_and_evidence_modules_are_timeout_owned_boundaries() -> None:
    evidence = monitor_timeout_config_evidence(
        setting="UMIGE_QUEUE_MONITOR_SLEEP_SEC",
        raw_value="nan",
        replacement_value=1.0,
        error=ValueError("bad"),
    )
    parsed = monitor_float_config(
        setting="UMIGE_QUEUE_MONITOR_SLEEP_SEC",
        raw_value="nan",
        replacement=1.0,
        recoverable_exceptions=RECOVERABLE,
    )

    assert isinstance(evidence, MappingProxyType)
    assert evidence["final_json_must_record"] is True
    assert parsed.value == 1.0
    assert parsed.evidence[0]["replay_must_reproduce"] is True


def test_stage1792_monitor_minimum_maximum_evidence_wrappers_stay_deleted() -> None:
    source = inspect.getsource(evidence_module)

    assert "def monitor_minimum_evidence" not in source
    assert "def monitor_maximum_evidence" not in source
    assert "monitor_minimum_evidence" not in evidence_module.__all__
    assert "monitor_maximum_evidence" not in evidence_module.__all__
