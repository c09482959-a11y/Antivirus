from __future__ import annotations

from typing import Any, cast

from Virus_Scan.scheduler.queue.orphan_recovery_policy import load_queue_reclaim_policy
from Virus_Scan.scheduler.queue.process_queue_stale_recovery import (
    ProcessQueueStaleRecoveryDependencies,
    ProcessQueueStaleRecoveryRequest,
    reconcile_process_queue_stale_recovery,
)


class DeadWorker:
    alive = False


def test_stage770_malformed_reclaim_policy_values_emit_immutable_evidence():
    policy = load_queue_reclaim_policy(
        stale_sec=cast(Any, "bad-stale"),
        max_retries=cast(Any, object()),
        progress_stall_sec=cast(Any, "bad-progress"),
        per_file_timeout_sec=cast(Any, "bad-timeout"),
    )

    assert policy.evidence
    reasons = {record["reason"] for record in policy.evidence}
    assert "queue_reclaim_stale_sec_malformed" in reasons
    assert "queue_reclaim_max_retries_malformed" in reasons
    assert "queue_reclaim_progress_stall_sec_malformed" in reasons
    assert "queue_reclaim_per_file_timeout_sec_malformed" in reasons
    for record in policy.evidence:
        assert record["timeout_failure"] is True
        assert record["queue_recovery_failure"] is True
        assert record["final_json_must_record"] is True
        assert record["checkpoint_must_record"] is True
        assert record["replay_must_reproduce"] is True


def test_stage770_stale_recovery_propagates_reclaim_policy_evidence(tmp_path):
    output = reconcile_process_queue_stale_recovery(
        ProcessQueueStaleRecoveryRequest(
            queue_dir=tmp_path,
            progress_stall_sec=cast(Any, "bad-progress"),
            per_file_timeout_sec=cast(Any, "bad-timeout"),
            stale_sec=cast(Any, "bad-stale"),
            raw_stage_progress_state={},
        ),
        ProcessQueueStaleRecoveryDependencies(
            raw_stage_progress_recent=lambda *_args, **_kwargs: False,
            file_has_recent_raw_owner_progress=lambda *_args, **_kwargs: False,
            worker_liveness_checker=lambda *_args, **_kwargs: DeadWorker(),
            worker_terminator=lambda *_args, **_kwargs: None,
            log_error=lambda _message: None,
            recoverable_exceptions=(OSError, RuntimeError, TypeError, ValueError),
        ),
    )

    reasons = {record.get("reason") for record in output.evidence}
    assert "queue_reclaim_stale_sec_malformed" in reasons
    assert "queue_reclaim_progress_stall_sec_malformed" in reasons
    assert "queue_reclaim_per_file_timeout_sec_malformed" in reasons
    for record in output.evidence:
        assert record["final_json_must_record"] is True
        assert record["checkpoint_must_record"] is True
        assert record["replay_must_reproduce"] is True
