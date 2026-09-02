from __future__ import annotations

import pytest

from Virus_Scan.scheduler.internal.immutable_outputs import FrozenSchedulerMapping
from Virus_Scan.scheduler.orchestration.finalization import SchedulerPipelineFinalizationRequest
from Virus_Scan.scheduler.orchestration.scheduler_serial_mode import SchedulerSerialModeResult
from Virus_Scan.scheduler.queue.inmemory_empty_drain import InMemoryEmptyDrainRecoveryDecision
from Virus_Scan.scheduler.timeout.escalation_engine import ProcessQueueStallEscalationResult
from Virus_Scan.scheduler.timeout.inmemory_memory_policy import InMemoryWorkerMemoryPolicy
from Virus_Scan.scheduler.timeout.inmemory_timeout_config import InMemoryTimeoutConfig
from Virus_Scan.scheduler.timeout.process_queue_monitor_policy import ProcessQueueMonitorPolicy
from Virus_Scan.scheduler.workers.inmemory_raw_plan import InMemoryRawPlan


def _assert_frozen_mapping(value):
    assert isinstance(value, FrozenSchedulerMapping)
    with pytest.raises(TypeError):
        value["mutated"] = True  # type: ignore[index]


def test_scheduler_finalization_request_freezes_results_recursively():
    source = {"file": {"scan_integrity": {"degraded": True}}}
    request = SchedulerPipelineFinalizationRequest(
        results=source,
        scheduler_mode="process",
        strict=False,
        process_shard=False,
        freeze_existing_baselines=True,
        profile_policy_snapshot=None,
    )

    source["file"]["scan_integrity"]["degraded"] = False

    _assert_frozen_mapping(request.results)
    nested = request.results["file"]
    _assert_frozen_mapping(nested)
    integrity = nested["scan_integrity"]
    _assert_frozen_mapping(integrity)
    assert integrity["degraded"] is True


def test_scheduler_serial_result_freezes_results_recursively():
    source = {"a.exe": {"tags": ["one", "two"]}}
    result = SchedulerSerialModeResult(results=source)
    source["a.exe"]["tags"].append("late")

    _assert_frozen_mapping(result.results)
    record = result.results["a.exe"]
    _assert_frozen_mapping(record)
    assert record["tags"] == ("one", "two")


def test_inmemory_raw_plan_freezes_planned_jobs():
    jobs = [{"collector": "a", "meta": {"chunk": 1}}, {"collector": "b"}]
    plan = InMemoryRawPlan(
        identity="id",
        ext=".bin",
        effective_stage="binary",
        file_id="file-1",
        jobs=tuple(jobs),
        local_workers=1,
        deadline=10.0,
    )
    jobs[0]["meta"]["chunk"] = 99

    assert isinstance(plan.jobs[0], FrozenSchedulerMapping)
    assert isinstance(plan.jobs[0]["meta"], FrozenSchedulerMapping)
    assert plan.jobs[0]["meta"]["chunk"] == 1


def test_phase9_evidence_outputs_freeze_nested_mappings():
    evidence = [{"stage": "x", "nested": {"a": 1}}]
    objects = [
        InMemoryEmptyDrainRecoveryDecision(0, 1, 0, tuple(evidence)),
        ProcessQueueStallEscalationResult(0, 0, tuple(evidence)),
        InMemoryWorkerMemoryPolicy(2048.0, tuple(evidence)),
        InMemoryTimeoutConfig(1, 30, 300.0, 300.0, 60.0, 120.0, 30.0, tuple(evidence)),
        ProcessQueueMonitorPolicy(1.0, 30.0, 300.0, 45.0, 30.0, tuple(evidence)),
    ]
    evidence[0]["nested"]["a"] = 2

    fields = [
        objects[0].evidence,
        objects[1].evidence,
        objects[2].config_evidence,
        objects[3].config_evidence,
        objects[4].timeout_config_evidence,
    ]
    for frozen_tuple in fields:
        assert isinstance(frozen_tuple[0], FrozenSchedulerMapping)
        assert isinstance(frozen_tuple[0]["nested"], FrozenSchedulerMapping)
        assert frozen_tuple[0]["nested"]["a"] == 1
