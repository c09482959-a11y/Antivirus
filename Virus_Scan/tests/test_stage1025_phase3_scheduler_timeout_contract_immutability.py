from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_running_budget import (
    RunningTimeoutBudgetState,
    build_running_timeout_budget_state,
)
from Virus_Scan.scheduler.timeout.process_queue_monitor_values import MonitorSettingValue


def test_running_timeout_budget_state_deep_freezes_direct_constructor_budget_info() -> None:
    caller_budget = {"timeout_budget": 12, "nested": {"values": ["before"]}}
    state = RunningTimeoutBudgetState(
        pid=123,
        running_at=1,
        last_heartbeat=2,
        last_progress=3,
        heartbeat_age=4,
        progress_age=5,
        budget_info=caller_budget,
        heartbeat_budget=6,
        progress_budget=7,
        hard_budget=8,
    )

    caller_budget["timeout_budget"] = 99
    caller_budget["nested"]["values"].append("after")

    assert isinstance(state.budget_info, Mapping)
    assert state.budget_info["timeout_budget"] == 12
    assert state.budget_info["nested"]["values"] == ("before",)


def test_running_timeout_budget_builder_detaches_queue_record_timeout_budget() -> None:
    record = {
        "pid": 456,
        "running_at": 10,
        "last_heartbeat": 11,
        "last_progress_time": 12,
        "timeout_budget": {"timeout_budget": 20, "stall_budget": 21, "nested": {"items": ["original"]}},
    }
    state = build_running_timeout_budget_state(
        jid="job-1",
        rec=record,
        now=30,
        heartbeat_stale_sec=2,
        progress_stale_sec=3,
        base_pf_timeout=4,
        timeout_retry_evidence=[],
        record_scheduler_suppressed=lambda _stage, _exc: None,
        recoverable_exceptions=(Exception,),
    )

    record["timeout_budget"]["timeout_budget"] = 999
    record["timeout_budget"]["nested"]["items"].append("mutated")

    assert state.hard_budget == 20.0
    assert state.budget_info["timeout_budget"] == 20
    assert state.budget_info["nested"]["items"] == ("original",)


def test_monitor_setting_value_freezes_direct_constructor_evidence() -> None:
    evidence = {"stage": "monitor", "nested": {"items": ["before"]}}
    value = MonitorSettingValue(value=4, evidence=(evidence,))

    evidence["nested"]["items"].append("after")

    assert value.value == 4.0
    assert value.evidence[0]["nested"]["items"] == ("before",)
