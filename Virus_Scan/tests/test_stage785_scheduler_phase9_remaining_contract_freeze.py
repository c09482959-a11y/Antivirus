from __future__ import annotations
from Virus_Scan.scheduler.ownership.inmemory_scheduler_state_index import InMemorySchedulerStateIndex

from typing import Any, cast

import pytest

from Virus_Scan.scheduler.evidence.execution_events import SchedulerExecutionEvent
from Virus_Scan.scheduler.orchestration.inmemory_parent_runtime_contracts import InMemoryParentRuntimeSetupResult
from Virus_Scan.scheduler.queue.inmemory_retry_failure_result import InMemoryRetryFailureResult
from Virus_Scan.scheduler.queue.orphan_recovery_claim_state import ActiveClaimState
from Virus_Scan.scheduler.queue.recovery_contract import InMemoryRetryTransition, RecoveryHistoryTransition


def _any(value: object) -> Any:
    return cast(Any, value)


def test_execution_event_direct_construction_freezes_nested_metadata_and_sequences():
    metadata = {"nested": {"value": 1}}
    tags = [{"tag": "a"}]
    errors = [{"error": "e"}]

    event = cast(Any, SchedulerExecutionEvent)(
        event_type="phase9_boundary",
        tags=tags,
        errors=errors,
        metadata=metadata,
    )

    metadata["nested"]["value"] = 99
    tags[0]["tag"] = "changed"
    errors[0]["error"] = "changed"

    as_dict = _any(event.as_dict())
    assert as_dict["metadata"]["nested"]["value"] == 1
    assert as_dict["tags"][0]["tag"] == "a"
    assert as_dict["errors"][0]["error"] == "e"
    with pytest.raises(TypeError):
        event.metadata["new"] = "forbidden"  # type: ignore[index]


def test_parent_runtime_setup_stage_limits_are_immutable_snapshots():
    stage_limits = {"raw": 2, "nested": {"deep": 1}}
    result = cast(Any, InMemoryParentRuntimeSetupResult)(
        requested=1,
        workers=1,
        ctx=None,
        manager=None,
        worker_threads=1,
        base_worker_threads=1,
        thread_scale_cpu=None,
        logical_slots=1,
        queue_depth=1,
        task_q=None,
        result_q=None,
        live_state=None,
        state_index=InMemorySchedulerStateIndex(),
        ewma_state=None,
        cfg=None,
        heartbeat_flags=None,
        stage_limits=stage_limits,
        heartbeat_table=None,
        routing_evidence_context=None,
        memory_policy=None,
        timeout_config_evidence=(),
        max_job_retries=1,
        base_pf_timeout=1.0,
        queued_start_timeout_sec=1.0,
        assigned_start_timeout_sec=1.0,
        heartbeat_stale_sec=1.0,
        progress_stale_sec=1.0,
        cancel_grace_sec=1.0,
        pending=None,
        job_records=None,
        active=None,
        worker_heartbeats=None,
        worker_metrics=None,
        done=None,
        failed=None,
        terminal=None,
        results=None,
        procs=None,
        lifecycle_epoch="epoch",
        max_inflight=1,
        max_queued_unstarted=1,
        recovery=None,
    )

    stage_limits["raw"] = 99
    stage_limits["nested"]["deep"] = 99
    result_stage_limits = _any(result.stage_limits)
    assert result_stage_limits["raw"] == 2
    assert result_stage_limits["nested"]["deep"] == 1
    with pytest.raises(TypeError):
        result.stage_limits["raw"] = 3  # type: ignore[index]


def test_retry_failure_result_and_recovery_transitions_freeze_direct_construction():
    result_source = {"scan_integrity": {"retry": True}}
    evidence_source = {"category": "retry_exhausted", "nested": {"value": 1}}
    retry_failure = InMemoryRetryFailureResult(result_source, evidence_source)
    result_source["scan_integrity"]["retry"] = False
    evidence_source["nested"]["value"] = 42

    assert _any(retry_failure.result_dict())["scan_integrity"]["retry"] is True
    assert _any(retry_failure.evidence_dict())["nested"]["value"] == 1
    mutable_copy = _any(retry_failure.result_dict())
    mutable_copy["scan_integrity"]["retry"] = False
    assert _any(retry_failure.result_dict())["scan_integrity"]["retry"] is True

    retry_transition_source = {"attempt": 1, "nested": {"value": 2}}
    transition = InMemoryRetryTransition(1, 2, retry_transition_source)
    retry_transition_source["nested"]["value"] = 99
    assert _any(transition.as_record())["nested"]["value"] == 2

    history_source = {"history": []}
    item_source = {"action": "retry", "nested": {"value": 3}}
    history = RecoveryHistoryTransition(history_source, item_source)
    item_source["nested"]["value"] = 99
    assert _any(history.as_item())["nested"]["value"] == 3


def test_active_claim_state_severs_source_dicts_and_exports_immutable_snapshots():
    job = {"file": "sample.bin", "queue_info": {"attempt": 1}}
    queue_info = {"attempt": 1, "nested": {"value": 1}}
    state = ActiveClaimState(
        job=job,
        queue_info=queue_info,
        hb_age=1.0,
        claim_age=2.0,
        progress_age=3.0,
        pid=123,
        pid_alive=False,
        heartbeat_fresh=False,
        timeout_expired=True,
        checkpoint_stalled=True,
    )

    job["file"] = "mutated.bin"
    queue_info["nested"]["value"] = 99
    assert state.job["file"] == "sample.bin"
    assert _any(state.queue_info)["nested"]["value"] == 1
    snapshot = _any(state.as_snapshot())
    assert snapshot["job"]["file"] == "sample.bin"
    with pytest.raises(TypeError):
        snapshot["job"]["file"] = "forbidden"  # type: ignore[index]
