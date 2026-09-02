from __future__ import annotations

import inspect

from Virus_Scan.scheduler.queue.orphan_recovery_action_decisions import (
    claim_meta_removed_decision,
    move_result_succeeded_decision,
    reclaim_job_identifier_decision,
)
from Virus_Scan.scheduler.queue import orphan_recovery_actions
from Virus_Scan.scheduler.queue.orphan_recovery_actions import requeue_reclaimed_active_job


class HostileIdentifierInput:
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("called __str__")

    def __repr__(self):
        type(self).touched += 1
        raise AssertionError("called __repr__")

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("called __bool__")


def test_stage2119_claim_and_move_bool_results_are_replayable_decisions() -> None:
    accepted_claim = claim_meta_removed_decision(True)
    rejected_claim = claim_meta_removed_decision(object())
    failed_move = move_result_succeeded_decision(False)
    rejected_move = move_result_succeeded_decision(object())

    assert accepted_claim.removed is True
    assert accepted_claim.accepted is True
    assert rejected_claim.removed is False
    assert rejected_claim.reason == "non_bool_claim_meta_result"
    assert failed_move.succeeded is False
    assert failed_move.accepted is True
    assert rejected_move.succeeded is False
    assert rejected_move.reason == "non_bool_move_result"


def test_stage2119_reclaim_job_identifier_decision_preserves_missing_state_without_hooks() -> None:
    HostileIdentifierInput.touched = 0

    found = reclaim_job_identifier_decision({"job_id": "job-7"})
    missing = reclaim_job_identifier_decision({})
    rejected = reclaim_job_identifier_decision(HostileIdentifierInput())

    assert found.identifier == "job-7"
    assert found.accepted is True
    assert found.source_key == "job_id"
    assert missing.identifier == ""
    assert missing.reason == "job_identifier_missing"
    assert rejected.identifier == ""
    assert rejected.reason == "non_dict_job_record"
    assert HostileIdentifierInput.touched == 0


def test_stage2119_orphan_recovery_action_module_removed_hidden_default_helpers() -> None:
    source = inspect.getsource(orphan_recovery_actions)

    assert "def _claim_meta_removed" not in source
    assert "def _move_result_succeeded" not in source
    assert "def _reclaim_job_identifier" not in source
    assert "return False" not in source
    assert 'return ""' not in source


def test_stage2119_requeue_uses_typed_decision_compatibility_projection(tmp_path) -> None:
    active = tmp_path / "active"
    pending = tmp_path / "pending"
    active.mkdir()
    pending.mkdir()
    src = active / "job.json"
    src.write_text("{}", encoding="utf-8")
    src.unlink()
    evidence = []
    suppressed = []

    result = requeue_reclaimed_active_job(
        queue_dir=tmp_path,
        active_dir=active,
        pending_dir=pending,
        src=src,
        name="job.json",
        job={"file": "sample.bin"},
        queue_info={},
        now=100.0,
        attempt=0,
        info={"time": "2026-01-01T00:00:00Z"},
        evidence_records=evidence,
        safe_remove_claim_meta=lambda _path: object(),
        cleanup_orphan_claim_meta=lambda *_args, **_kwargs: 0,
        process_queue_env_int=lambda *_args, **_kwargs: 0,
        record_suppressed=lambda where, exc, **kwargs: suppressed.append((where, exc, kwargs)),
    )

    assert result is None
    assert suppressed[0][0] == "process_queue_reclaim_pre_move_claim_meta_cleanup_incomplete"
    assert evidence[0]["stage"] == "process_queue_reclaim_active_move_rejected"
    assert evidence[0]["job_id"] == "sample.bin"
