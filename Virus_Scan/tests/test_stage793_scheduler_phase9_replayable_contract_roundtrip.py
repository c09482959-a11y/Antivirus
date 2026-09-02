from __future__ import annotations

from typing import Any

import pytest

from Virus_Scan.scheduler.context.config_snapshot import SchedulerConfigSnapshot
from Virus_Scan.scheduler.context.dependency_snapshot import SchedulerDependencySnapshot
from Virus_Scan.scheduler.context.runtime_snapshot import SchedulerRuntimeSnapshot
from Virus_Scan.scheduler.context.writable_paths import SchedulerWritablePaths
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.queue_snapshot import QueueSnapshot
from Virus_Scan.scheduler.contracts.replay_result import ReplaySnapshot
from Virus_Scan.scheduler.contracts.retry_result import RetryDecision
from Virus_Scan.scheduler.contracts.scheduler_result import SchedulerResult
from Virus_Scan.scheduler.contracts.timeout_result import TimeoutResult
from Virus_Scan.scheduler.contracts.worker_result import WorkerSnapshot


def test_phase9_scheduler_result_round_trips_typed_snapshots_for_replay() -> None:
    evidence_context: dict[str, Any] = {"retry": ["exhausted"], "timeout": {"budget": 5}}
    evidence = SchedulerEvidenceRecord(
        stage="queue",
        state="degraded",
        error_category="retry_exhaustion",
        error_source="queue.retry_policy",
        message="retry budget exhausted",
        context=evidence_context,
        queue_id="queue-1",
        job_id="job-1",
        worker_id="worker-1",
        path="sample.bin",
        retry_state_affected=True,
        timeout_state_affected=True,
    )
    result = SchedulerResult(
        status="degraded",
        results={"sample.bin": {"tags": ["timeout"]}},
        summary={"count": 1},
        evidence=(evidence,),
        queue_snapshot=QueueSnapshot(phase="merge", pending=0, active=0, done=0, failed=1),
        worker_snapshot=WorkerSnapshot(live_count=0, workers=({"worker_id": "worker-1", "state": "dead"},)),
        timeout_result=TimeoutResult(timed_out=True, elapsed_sec=5.1, budget_sec=5, stage="worker"),
        retry_decision=RetryDecision(retry_allowed=False, exhausted=True, attempt=2, max_attempts=2),
        replay_snapshot=ReplaySnapshot(replay_id="before", records=({"job_id": "job-1"},)),
    )

    evidence_context["retry"].append("caller_mutation")
    encoded = result.as_dict()
    replay_boundary = result.as_replay_snapshot("final")
    decoded = SchedulerResult.from_mapping(encoded)

    assert decoded.as_dict() == encoded
    assert decoded.evidence[0].context["retry"] == ("exhausted",)
    assert encoded["snapshots"]["queue"]["failed"] == 1
    assert replay_boundary.records[0]["snapshots"]["retry"]["exhausted"] is True
    assert replay_boundary.evidence[0]["retry_state_affected"] is True


def test_phase9_context_snapshots_round_trip_without_caller_owned_mutability() -> None:
    config = SchedulerConfigSnapshot.from_mapping({"workload_limits": {"raw": [1]}})
    runtime = SchedulerRuntimeSnapshot.from_mapping({"process_policy": {"spawn": ["safe"]}, "active_flags": ["raw"]})
    dependency = SchedulerDependencySnapshot.from_mapping({"public_contracts": ["scheduler.api.runner"], "evidence": [{"missing": ["none"]}]})
    writable = SchedulerWritablePaths.from_mapping({"metadata": {"external": ["runtime"]}})

    encoded_config = config.as_dict()
    encoded_runtime = runtime.as_dict()
    encoded_dependency = dependency.as_dict()
    encoded_writable = writable.as_dict()

    assert SchedulerConfigSnapshot.from_mapping(encoded_config).workload_limits["raw"] == (1,)
    assert SchedulerRuntimeSnapshot.from_mapping(encoded_runtime).process_policy["spawn"] == ("safe",)
    assert SchedulerDependencySnapshot.from_mapping(encoded_dependency).public_contracts == ("scheduler.api.runner",)
    assert SchedulerWritablePaths.from_mapping(encoded_writable).metadata["external"] == ("runtime",)


def test_phase9_scheduler_result_rejects_untyped_optional_snapshots() -> None:
    with pytest.raises(TypeError):
        SchedulerResult(queue_snapshot={"phase": "mutable"})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        SchedulerResult(worker_snapshot={"live_count": 1})  # type: ignore[arg-type]
