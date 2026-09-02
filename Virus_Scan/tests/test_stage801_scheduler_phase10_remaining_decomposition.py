from __future__ import annotations

import inspect
import math
from types import MappingProxyType

from Virus_Scan.scheduler.evidence import scheduler_json_writer
from Virus_Scan.scheduler.evidence.scheduler_json_partial import write_partial_scheduler_results
from Virus_Scan.scheduler.queue.orphan_recovery import _reclaim_stale_process_queue_jobs
from Virus_Scan.scheduler.queue.orphan_recovery_failure_info import build_reclaim_failure_info
from Virus_Scan.scheduler.queue.orphan_recovery_item import reclaim_active_claim_state
from Virus_Scan.scheduler.queue.orphan_recovery_timeout import classify_reclaim_timeout
from Virus_Scan.scheduler.replay.replay_projection import canonical_replay_sequence, queue_replay_result_file_identity
from Virus_Scan.scheduler.replay.replay_validator import QueueReplayComparisonSnapshot
from Virus_Scan.scheduler.runtime import backpressure_policy
from Virus_Scan.scheduler.runtime.backpressure_memory import memory_pressure_level, memory_pressure_snapshot
from Virus_Scan.scheduler.runtime.backpressure_targets import elastic_target_workers, smooth_worker_target
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_callbacks import safe_record_float
from Virus_Scan.scheduler.timeout.inmemory_timeout_policy_numbers import safe_timeout_budget_number
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_running import evaluate_running_timeout_state
from Virus_Scan.scheduler.timeout.inmemory_timeout_sweep_running_budget import build_running_timeout_budget_state


def test_stage801_runtime_backpressure_facade_is_split_into_target_and_memory_boundaries() -> None:
    source = inspect.getsource(backpressure_policy)

    assert "def elastic_target_workers" not in source
    assert "def memory_pressure_snapshot" not in source
    assert backpressure_policy.elastic_target_workers(None, False, raw_live=0, max_workers=4) == 4
    assert elastic_target_workers(None, False, raw_live=0, max_workers=4) == 4
    assert smooth_worker_target(1, 3) == 3
    assert memory_pressure_level({"pressure": "low"}) == "low"
    assert isinstance(memory_pressure_snapshot(), MappingProxyType)


def test_stage801_running_timeout_budget_is_bounded_and_evidence_backed() -> None:
    failures = []
    state = build_running_timeout_budget_state(
        jid="job-1",
        rec={"pid": 42, "running_at": "1.0", "last_heartbeat": "bad", "last_progress_time": "2.0", "timeout_budget": {"timeout_budget": "5"}},
        now=10.0,
        heartbeat_stale_sec=3.0,
        progress_stale_sec=4.0,
        base_pf_timeout=1.0,
        timeout_retry_evidence=failures,
        record_scheduler_suppressed=lambda *_args, **_kwargs: None,
        recoverable_exceptions=(Exception,),
    )

    assert state.pid == 42
    assert math.isclose(state.hard_budget, 5.0)
    assert state.heartbeat_budget == 3.0
    assert failures
    assert any(item.get("final_json_must_record") for item in failures)
    assert callable(evaluate_running_timeout_state)


def test_stage801_orphan_recovery_is_split_into_item_timeout_and_failure_boundaries() -> None:
    source = inspect.getsource(_reclaim_stale_process_queue_jobs)

    assert "classify_reclaim_timeout(" not in source
    assert "build_reclaim_failure_info(" not in source
    assert "terminate_reclaimed_worker(" not in source
    assert callable(reclaim_active_claim_state)
    assert callable(classify_reclaim_timeout)
    info = build_reclaim_failure_info(
        reason_stage="queue_worker_orphaned",
        timeout_expired=False,
        hard_file_timeout=30.0,
        file_timeout=15.0,
        checkpoint_stalled=False,
        progress_age=1.0,
        hb_age=2.0,
        claim_age=3.0,
        pid=123,
        pid_alive=False,
        heartbeat_fresh=False,
        timeout_evidence={"final_json_must_record": True},
        owner_killed=False,
        termination_evidence=None,
        recovered=True,
        attempt=0,
        now_text="2026-01-01T00:00:00Z",
        progress_marker="m",
    )
    assert info["worker_state"] == "queue_worker_orphaned"
    assert info["timeout_evidence"]["final_json_must_record"] is True


def test_stage801_replay_projection_and_json_partial_are_split_from_facades() -> None:
    assert canonical_replay_sequence(["b", "a", "b", ""]) == ("a", "b")
    assert queue_replay_result_file_identity({"file": "sample.bin"})
    snapshot = QueueReplayComparisonSnapshot.from_results([{"job_id": "1", "file": "sample.bin", "verdict": "clean"}])
    assert snapshot.job_count == 1
    assert callable(write_partial_scheduler_results)
    assert scheduler_json_writer.write_partial_scheduler_results is write_partial_scheduler_results


def test_stage801_timeout_policy_number_callbacks_remain_evidence_owned() -> None:
    failures = []
    value = safe_record_float(
        record={"bad": "nan", "attempt": 1},
        field="bad",
        default=7.0,
        job_id="job-1",
        failures=failures,
        record_scheduler_suppressed=lambda *_args, **_kwargs: None,
        recoverable_exceptions=(Exception,),
    )
    assert value == 7.0
    assert failures[0]["checkpoint_must_record"] is True
    budget = safe_timeout_budget_number(
        record={"attempt": 1},
        budget={"timeout_budget": "6.5"},
        field="timeout_budget",
        default=1.0,
        job_id="job-2",
        failures=[],
        record_scheduler_suppressed=lambda *_args, **_kwargs: None,
        recoverable_exceptions=(Exception,),
    )
    assert budget == 6.5
