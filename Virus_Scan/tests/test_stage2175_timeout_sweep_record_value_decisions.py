from __future__ import annotations

from types import SimpleNamespace

from Virus_Scan.scheduler.timeout.inmemory_timeout_record_value_decisions import (
    TimeoutRecordValueDecision,
    TimeoutSharedHeartbeatValueDecision,
    timeout_record_value_decision,
    timeout_shared_heartbeat_value_decision,
)
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_result import build_inmemory_timeout_sweep_result


class HostileValue:
    touched = 0
    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("iter")
    def __len__(self):
        type(self).touched += 1
        raise AssertionError("len")
    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("bool")
    def __str__(self):
        type(self).touched += 1
        raise AssertionError("str")
    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("repr")


def test_stage2175_timeout_record_value_decisions_are_replayable() -> None:
    assert timeout_record_value_decision({"attempt": 3}, "attempt") == TimeoutRecordValueDecision(3, "timeout_record_field_present", "attempt", True, True)
    assert timeout_record_value_decision({}, "attempt") == TimeoutRecordValueDecision(None, "timeout_record_field_absent", "attempt", False, True)
    assert timeout_record_value_decision(object(), "attempt") == TimeoutRecordValueDecision(None, "unsupported_timeout_record_mapping", "attempt", False, False)


def test_stage2175_shared_heartbeat_value_decisions_are_no_hook_and_replayable() -> None:
    HostileValue.touched = 0
    hostile = HostileValue()
    assert timeout_shared_heartbeat_value_decision(hostile, "observed") == TimeoutSharedHeartbeatValueDecision(None, "shared_heartbeat_field_absent", "observed", False, True)
    assert timeout_shared_heartbeat_value_decision(object(), "observed") == TimeoutSharedHeartbeatValueDecision(None, "unsupported_shared_heartbeat_result", "observed", False, False)
    assert timeout_shared_heartbeat_value_decision(SimpleNamespace(observed=7), "observed") == TimeoutSharedHeartbeatValueDecision(7, "shared_heartbeat_field_present", "observed", True, True)
    assert timeout_shared_heartbeat_value_decision({"cancel_requested": 3}, "cancel_requested") == TimeoutSharedHeartbeatValueDecision(3, "shared_heartbeat_field_present", "cancel_requested", True, True)
    assert HostileValue.touched == 0


def test_stage2175_timeout_sweep_result_values_are_preserved() -> None:
    result = build_inmemory_timeout_sweep_result(
        evaluated=1, queued_waits=0, assigned_waits=0, hard_timeouts=0, orphaned_workers=0, progress_stalls=0, cancelled_after_stall=0,
        shared_heartbeat_result=SimpleNamespace(observed=2, cancel_requested=1), timeout_retry_evidence=(), timeout_reporting_failures=[],
    )
    assert result.shared_heartbeats_observed == 2
    assert result.shared_heartbeat_cancel_requests == 1
