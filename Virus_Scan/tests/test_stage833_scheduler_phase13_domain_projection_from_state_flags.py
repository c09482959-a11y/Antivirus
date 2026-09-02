"""Stage833 Phase 13 domain projection from scheduler state flags.

Phase 13 requires every synthetic scheduler failure to prove the expected queue,
worker, timeout, retry, checkpoint, final JSON, and replay state.  Some injected
cases are owned by one domain but also affect timeout/retry state; those flags
must project into the canonical scheduler final-JSON buckets instead of only
appearing as generic evidence.
"""
from __future__ import annotations

import pytest

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.records import build_scheduler_json_evidence_section


@pytest.mark.parametrize(
    ("record", "expected_field"),
    (
        (
            SchedulerEvidenceRecord(
                stage="worker_lifecycle",
                state="degraded",
                error_category="worker_heartbeat_stall",
                error_source="stage833.phase13.matrix",
                message="worker heartbeat stall affected timeout ownership",
                timeout_state_affected=True,
                final_json_must_record=True,
                checkpoint_must_record=True,
                replay_must_record=True,
            ),
            "timeout_decisions",
        ),
        (
            SchedulerEvidenceRecord(
                stage="worker_lifecycle",
                state="degraded",
                error_category="worker_finalization_killed",
                error_source="stage833.phase13.matrix",
                message="worker finalization kill affected timeout ownership",
                timeout_state_affected=True,
                final_json_must_record=True,
                checkpoint_must_record=True,
                replay_must_record=True,
            ),
            "timeout_decisions",
        ),
        (
            SchedulerEvidenceRecord(
                stage="queue_claim",
                state="degraded",
                error_category="stale_lock_claim_file",
                error_source="stage833.phase13.matrix",
                message="stale queue claim affected retry ownership",
                retry_state_affected=True,
                final_json_must_record=True,
                checkpoint_must_record=True,
                replay_must_record=True,
            ),
            "retry_decisions",
        ),
    ),
)
def test_stage833_phase13_state_flags_project_into_domain_owned_final_json_buckets(
    record: SchedulerEvidenceRecord,
    expected_field: str,
) -> None:
    scheduler_section = build_scheduler_json_evidence_section((record,))

    assert scheduler_section["scheduler_status"] == "degraded"
    assert scheduler_section["evidence"]
    assert scheduler_section[expected_field], expected_field
    assert scheduler_section[expected_field][0]["error_category"] == record.error_category
    assert scheduler_section[expected_field][0]["final_json_must_record"] is True
    assert scheduler_section[expected_field][0]["checkpoint_must_record"] is True
    assert scheduler_section[expected_field][0]["replay_must_record"] is True
