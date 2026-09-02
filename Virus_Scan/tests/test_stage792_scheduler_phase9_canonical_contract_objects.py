from __future__ import annotations

from typing import Any, cast

import pytest

from Virus_Scan.scheduler.context.config_snapshot import SchedulerConfigSnapshot
from Virus_Scan.scheduler.context.dependency_snapshot import SchedulerDependencySnapshot
from Virus_Scan.scheduler.context.runtime_snapshot import SchedulerRuntimeSnapshot
from Virus_Scan.scheduler.context.writable_paths import SchedulerWritablePaths
from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.queue_claim import QueueClaim
from Virus_Scan.scheduler.contracts.queue_snapshot import (
    QueueIntegrityResult,
    QueueMergeResult,
    QueueRecoveryResult,
    QueueSnapshot,
)
from Virus_Scan.scheduler.contracts.replay_result import ReplayComparisonResult, ReplaySnapshot
from Virus_Scan.scheduler.contracts.retry_result import RetryDecision, RetryExhaustionResult
from Virus_Scan.scheduler.contracts.scheduler_result import SchedulerResult
from Virus_Scan.scheduler.contracts.timeout_result import TimeoutResult
from Virus_Scan.scheduler.contracts.worker_result import WorkerIdentity, WorkerResult, WorkerSnapshot
from Virus_Scan.scheduler.internal.immutable_outputs import materialize_scheduler_mapping


def _assert_mapping_is_frozen(mapping) -> None:
    with pytest.raises(TypeError):
        mapping["late"] = "mutation"


def test_phase9_context_snapshots_freeze_mutable_constructor_inputs() -> None:
    workload_limits = {"raw": {"cap": 2}}
    environment = {"UMIGE": ["1"]}
    runtime_policy = {"spawn": {"mode": "process"}}
    worker_capacity = {"workers": [1]}
    dependencies = {"scanner": object()}
    evidence = [{"dependency": ["missing"]}]
    path_metadata = {"reason": ["external"]}

    config = cast(Any, SchedulerConfigSnapshot)(
        scheduler="PROCESS",
        max_workers="2",
        per_file_timeout_sec="3.5",
        progress_every="4",
        workload_limits=workload_limits,
        environment=environment,
    )
    runtime = cast(Any, SchedulerRuntimeSnapshot)(
        root="root",
        runtime_dir="runtime",
        queue_dir="queue",
        frozen=1,
        onefile=0,
        process_policy=runtime_policy,
        worker_capacity=worker_capacity,
        active_flags=["raw"],
    )
    dependency = cast(Any, SchedulerDependencySnapshot)(
        bindings=dependencies,
        public_contracts=["scheduler.api.runner"],
        missing_dependencies=["optional"],
        evidence=evidence,
    )
    writable = cast(Any, SchedulerWritablePaths)(
        runtime_dir="runtime",
        queue_dir="queue",
        checkpoint_dir="checkpoint",
        evidence_dir="evidence",
        temp_dir="temp",
        metadata=path_metadata,
    )

    workload_limits["raw"]["cap"] = 99
    environment["UMIGE"].append("mutated")
    runtime_policy["spawn"]["mode"] = "mutated"
    worker_capacity["workers"].append(2)
    dependencies["late"] = object()
    evidence[0]["dependency"].append("mutated")
    path_metadata["reason"].append("mutated")

    assert config.scheduler == "process"
    assert config.max_workers == 2
    assert config.workload_limits["raw"]["cap"] == 2
    assert config.environment["UMIGE"] == ("1",)
    assert runtime.process_policy["spawn"]["mode"] == "process"
    assert runtime.worker_capacity["workers"] == (1,)
    assert runtime.active_flags == ("raw",)
    assert sorted(dependency.bindings.keys()) == ["scanner"]
    assert dependency.evidence[0]["dependency"] == ("missing",)
    assert writable.metadata["reason"] == ("external",)
    _assert_mapping_is_frozen(config.workload_limits)
    _assert_mapping_is_frozen(runtime.process_policy)
    _assert_mapping_is_frozen(writable.metadata)


def test_phase9_queue_worker_timeout_retry_replay_result_contracts_are_immutable_and_json_safe() -> None:
    metadata = {"nested": {"value": [1]}}
    evidence = [{"failure": ["initial"]}]
    results = {"file.bin": {"tags": ["a"]}}

    snapshot = cast(Any, QueueSnapshot)("claim", pending="1", active="2", done="3", failed="4", metadata=metadata, evidence=evidence)
    claim = cast(Any, QueueClaim)("job-1", file="file.bin", worker_id="worker-1", generation="2", attempt="1", metadata=metadata)
    integrity = cast(Any, QueueIntegrityResult)(ok=1, snapshot=snapshot, failures=evidence)
    recovery = cast(Any, QueueRecoveryResult)(recovered="1", orphaned="2", snapshot=snapshot, evidence=evidence)
    merge = cast(Any, QueueMergeResult)(merged=results, missing_results=evidence, evidence=evidence)
    worker_identity = cast(Any, WorkerIdentity)("worker-1", pid="123", generation="2")
    worker_snapshot = cast(Any, WorkerSnapshot)(live_count="1", workers=({"worker": ["worker-1"]},), evidence=evidence)
    worker_result = cast(Any, WorkerResult)(worker_identity, success=1, result=results["file.bin"], failures=evidence)
    timeout = cast(Any, TimeoutResult)(timed_out=1, elapsed_sec="5.5", budget_sec="5", stage="worker", evidence=evidence)
    retry = cast(Any, RetryDecision)(retry_allowed=0, exhausted=1, attempt="2", max_attempts="2", reason="timeout", evidence=evidence)
    exhaustion = cast(Any, RetryExhaustionResult)(job_id="job-1", evidence=evidence)
    replay_snapshot = cast(Any, ReplaySnapshot)(replay_id="run-1", records=({"file": ["file.bin"]},), evidence=evidence)
    replay_comparison = cast(Any, ReplayComparisonResult)(True, replay_snapshot, replay_snapshot, mismatches=evidence)
    scheduler_evidence = SchedulerEvidenceRecord(stage="queue", context=metadata)
    scheduler_result = SchedulerResult(status="degraded", results=results, summary={"count": [1]}, evidence=(scheduler_evidence,))

    metadata["nested"]["value"].append(99)
    evidence[0]["failure"].append("mutated")
    results["file.bin"]["tags"].append("mutated")

    assert snapshot.metadata["nested"]["value"] == (1,)
    assert snapshot.evidence[0]["failure"] == ("initial",)
    assert claim.metadata["nested"]["value"] == (1,)
    assert integrity.failures[0]["failure"] == ("initial",)
    assert recovery.evidence[0]["failure"] == ("initial",)
    assert merge.merged["file.bin"]["tags"] == ("a",)
    assert worker_snapshot.workers[0]["worker"] == ("worker-1",)
    assert worker_result.result["tags"] == ("a",)
    assert timeout.evidence[0]["failure"] == ("initial",)
    assert retry.evidence[0]["failure"] == ("initial",)
    assert exhaustion.evidence[0]["failure"] == ("initial",)
    assert replay_snapshot.records[0]["file"] == ("file.bin",)
    assert replay_comparison.mismatches[0]["failure"] == ("initial",)
    assert scheduler_result.results["file.bin"]["tags"] == ("a",)
    assert scheduler_result.evidence[0].context["nested"]["value"] == (1,)

    assert materialize_scheduler_mapping(scheduler_result.as_dict())["evidence"][0]["stage"] == "queue"
    _assert_mapping_is_frozen(merge.merged)
    _assert_mapping_is_frozen(worker_result.result)


def test_phase9_scheduler_result_rejects_untyped_evidence_and_replay_requires_snapshots() -> None:
    with pytest.raises(TypeError):
        SchedulerResult(evidence=({"not": "evidence"},))  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        ReplayComparisonResult(True, expected={}, actual=ReplaySnapshot())  # type: ignore[arg-type]
