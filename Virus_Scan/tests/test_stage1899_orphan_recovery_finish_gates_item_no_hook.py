from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.scheduler.queue.orphan_recovery_claim_state import ActiveClaimState
from Virus_Scan.scheduler.queue.orphan_recovery_finish import (
    UnretryableReclaimedJobFinishRequest,
    finish_unretryable_reclaimed_job,
)
from Virus_Scan.scheduler.queue.orphan_recovery_gates import apply_raw_owner_reclaim_gate
from Virus_Scan.scheduler.queue.orphan_recovery_item import _append_timeout_decision_evidence


class HostilePath:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("path string hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("path repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("path format hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("path truth hook executed")


class HostileRawOwner:
    touched = 0

    def __str__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("raw owner string hook executed")

    def __repr__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("raw owner repr hook executed")

    def __format__(self, _spec):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("raw owner format hook executed")


class HostileEvidence:
    touched = 0

    def __iter__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("evidence iteration hook executed")

    def __bool__(self):  # pragma: no cover - must not execute
        type(self).touched += 1
        raise AssertionError("evidence truth hook executed")


def test_stage1899_finish_failure_records_evidence_without_default_exception_return() -> None:
    HostilePath.touched = 0
    records = []

    def failing_finish(*_args, **_kwargs):
        raise RuntimeError("finish exploded")

    result = finish_unretryable_reclaimed_job(UnretryableReclaimedJobFinishRequest(
        HostilePath(),
        HostilePath(),
        info={"error": "owned"},
        job={"id": "job-1"},
        evidence_records=records,
        finish_process_queue_job=failing_finish,
    ))

    assert result is False
    assert records
    assert records[0]["stage"] == "process_queue_finish_after_reclaim_failed"
    assert records[0]["final_json_must_record"] is True
    assert HostilePath.touched == 0


def test_stage1899_raw_owner_schema_failure_uses_no_hook_type_reason_and_paths() -> None:
    HostilePath.touched = 0
    HostileRawOwner.touched = 0
    records = []

    outcome = apply_raw_owner_reclaim_gate(
        job={"job_type": "file", "file": HostilePath(), "id": "job-2"},
        queue_dir=HostilePath(),
        claim_age=1000.0,
        progress_age=1000.0,
        file_timeout=30.0,
        progress_stall=30.0,
        file_has_recent_raw_owner_progress=lambda *_args, **_kwargs: HostileRawOwner(),
        timeout_expired=False,
        checkpoint_stalled=False,
        evidence_records=records,
    )

    assert outcome == (True, False, False)
    assert records
    assert records[0]["error_category"] == "TypeError"
    assert "HostileRawOwner" in records[0]["detail"]
    assert HostilePath.touched == 0
    assert HostileRawOwner.touched == 0


def test_stage1899_timeout_decision_evidence_materializes_without_unknown_dict_copy_hooks() -> None:
    HostileEvidence.touched = 0
    records = []

    _append_timeout_decision_evidence(HostileEvidence(), records)
    _append_timeout_decision_evidence(
        MappingProxyType(
            {
                "raw_global_progress_probe_evidence": MappingProxyType({"stage": "raw_probe", "final_json_must_record": True}),
                "reclaim_timeout_policy_evidence": (MappingProxyType({"stage": "policy", "checkpoint_must_record": True}),),
            }
        ),
        records,
    )

    assert HostileEvidence.touched == 0
    assert records[0]["stage"] == "raw_probe"
    assert records[1]["stage"] == "policy"


def test_stage1899_active_claim_state_recovery_evidence_is_exact_type_owned() -> None:
    state = ActiveClaimState(
        job={"id": "job-3"},
        queue_info={},
        hb_age=0.0,
        claim_age=0.0,
        progress_age=0.0,
        pid=None,
        pid_alive=False,
        heartbeat_fresh=False,
        timeout_expired=False,
        checkpoint_stalled=False,
        recovery_evidence=(MappingProxyType({"stage": "owned_recovery", "replay_must_record": True}),),
    )
    records = []

    _append_timeout_decision_evidence({"raw_global_progress_probe_evidence": state.recovery_evidence[0]}, records)

    assert records == [{"replay_must_record": True, "stage": "owned_recovery"}]
