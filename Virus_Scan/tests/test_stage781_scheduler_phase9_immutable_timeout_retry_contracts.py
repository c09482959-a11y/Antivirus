from __future__ import annotations

import pytest

from Virus_Scan.scheduler.orchestration.inmemory_parent_maintenance import InMemoryMaintenanceResult
from Virus_Scan.scheduler.queue.inmemory_retry_contracts import InMemoryRetryDecision
from Virus_Scan.scheduler.runtime.queue_json import make_json_safe
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep import InMemoryTimeoutSweepResult


def test_stage781_retry_decision_evidence_is_immutable_and_json_safe():
    source = {"stage": "retry_boundary", "nested": {"attempt": 1}}

    decision = InMemoryRetryDecision(False, 0, (source,))
    source["stage"] = "mutated_after_boundary"
    source["nested"]["attempt"] = 9

    assert decision.evidence[0]["stage"] == "retry_boundary"
    assert decision.evidence[0]["nested"]["attempt"] == 1
    with pytest.raises(TypeError):
        decision.evidence[0]["stage"] = "illegal_mutation"
    assert make_json_safe({"evidence": decision.evidence}) == {
        "evidence": [{"stage": "retry_boundary", "nested": {"attempt": 1}}]
    }


def test_stage781_timeout_sweep_evidence_is_immutable_and_json_safe():
    source = {"stage": "timeout_boundary", "attempt": 2}

    result = InMemoryTimeoutSweepResult(
        evaluated=1,
        queued_waits=0,
        assigned_waits=0,
        hard_timeouts=1,
        orphaned_workers=0,
        progress_stalls=0,
        cancelled_after_stall=0,
        timeout_retry_evidence=(source,),
    )
    source["stage"] = "mutated_after_boundary"

    assert result.timeout_retry_evidence[0]["stage"] == "timeout_boundary"
    with pytest.raises(TypeError):
        result.timeout_retry_evidence[0]["stage"] = "illegal_mutation"
    assert make_json_safe(result.timeout_retry_evidence) == [
        {"stage": "timeout_boundary", "attempt": 2}
    ]


def test_stage781_parent_maintenance_evidence_is_immutable_and_json_safe():
    retry_record = {"stage": "maintenance_retry_boundary", "final_json_must_record": True}
    reporting_record = {"stage": "maintenance_reporting_boundary", "checkpoint_must_record": True}

    result = InMemoryMaintenanceResult(
        last_log=10.0,
        last_progress_total=4,
        timeout_retry_evidence=(retry_record,),
        timeout_reporting_failures=(reporting_record,),
    )
    retry_record["stage"] = "mutated_after_boundary"
    reporting_record["stage"] = "mutated_after_boundary"

    assert result.timeout_retry_evidence[0]["stage"] == "maintenance_retry_boundary"
    assert result.timeout_reporting_failures[0]["stage"] == "maintenance_reporting_boundary"
    with pytest.raises(TypeError):
        result.timeout_retry_evidence[0]["stage"] = "illegal_mutation"
    assert make_json_safe(result.timeout_retry_evidence) == [
        {"stage": "maintenance_retry_boundary", "final_json_must_record": True}
    ]
    assert make_json_safe(result.timeout_reporting_failures) == [
        {"stage": "maintenance_reporting_boundary", "checkpoint_must_record": True}
    ]
