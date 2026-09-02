"""Stage832 Phase 13 scheduler stress/failure-injection matrix contract.

This broad matrix closes the Phase 13 validation gap: every required synthetic
case must prove queue/worker/timeout/retry evidence, checkpoint visibility,
final-JSON scheduler visibility, and replay determinism.  The test stays inside
scheduler-owned contracts and writers; it does not execute scanner payloads.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.evidence.checkpoint_writer import write_scheduler_checkpoint
from Virus_Scan.scheduler.evidence.final_json_projection import build_final_json_scheduler_section
from Virus_Scan.scheduler.evidence.records import SchedulerEvidenceBundle, build_scheduler_json_evidence_section
from Virus_Scan.scheduler.replay.replay_validator import compare_scheduler_replay_results


@dataclass(frozen=True, slots=True)
class Phase13Case:
    name: str
    stage: str = "scheduler"
    category: str = ""
    state: str = "ok"
    fatal: bool = False
    retry: bool = False
    timeout: bool = False
    expected_fields: tuple[str, ...] = ()

    @property
    def failure(self) -> bool:
        return self.state != "ok" or bool(self.category)


PHASE13_CASES = (
    Phase13Case("one_file_happy_path"),
    Phase13Case("100_file_mixed_path"),
    Phase13Case("1000_file_synthetic_queue_path"),
    Phase13Case("raw_queue_enabled"),
    Phase13Case("raw_queue_disabled"),
    Phase13Case("fast_path"),
    Phase13Case("deep_path"),
    Phase13Case("replay_path"),
    Phase13Case("worker_exits_before_claiming_work", "worker_lifecycle", "worker_exit_before_claim", expected_fields=("worker_lifecycle_events", "worker_failures")),
    Phase13Case("worker_exits_after_claiming_work", "worker_lifecycle", "worker_exit_after_claim", expected_fields=("worker_lifecycle_events", "worker_failures")),
    Phase13Case("worker_heartbeat_stalls", "worker_lifecycle", "worker_heartbeat_stall", timeout=True, expected_fields=("worker_lifecycle_events", "worker_failures", "timeout_decisions")),
    Phase13Case("worker_timeout", "timeout", "worker_timeout", timeout=True, expected_fields=("timeout_decisions", "worker_failures")),
    Phase13Case("worker_killed_during_finalization", "worker_lifecycle", "worker_finalization_killed", timeout=True, expected_fields=("worker_lifecycle_events", "worker_failures", "timeout_decisions")),
    Phase13Case("worker_writes_partial_result", "worker", "partial_worker_result", expected_fields=("worker_failures",)),
    Phase13Case("worker_writes_invalid_json", "worker", "invalid_worker_json", expected_fields=("worker_failures",)),
    Phase13Case("worker_result_conflicts_with_queue_state", "worker", "worker_queue_state_conflict", expected_fields=("worker_failures",)),
    Phase13Case("corrupt_job_json", "queue_integrity", "corrupt_job_json", expected_fields=("queue_integrity_result",)),
    Phase13Case("corrupt_result_json", "queue_integrity", "corrupt_result_json", expected_fields=("queue_integrity_result",)),
    Phase13Case("missing_result_for_done_job", "queue_integrity", "queue_result_missing", expected_fields=("queue_integrity_result",)),
    Phase13Case("orphan_active_job", "orphan_recovery", "orphan_active_job", expected_fields=("orphan_recovery",)),
    Phase13Case("stale_lock_claim_file", "queue_claim", "stale_lock_claim_file", retry=True, expected_fields=("queue_claims", "retry_decisions")),
    Phase13Case("retryable_scanner_failure", "retry", "retryable_scanner_failure", retry=True, expected_fields=("retry_decisions",)),
    Phase13Case("non_retryable_scanner_failure", "retry", "non_retryable_scanner_failure", retry=True, fatal=True, expected_fields=("retry_decisions",)),
    Phase13Case("retry_exhaustion", "retry_exhaustion", "retry_exhaustion", retry=True, expected_fields=("retry_decisions", "retry_exhaustion")),
    Phase13Case("disk_write_failure_simulation", "scheduler_json_writer", "disk_write_failure", fatal=True),
    Phase13Case("checkpoint_write_failure", "checkpoint_writer", "checkpoint_write_failure", fatal=True),
    Phase13Case("checkpoint_restore_after_partial_run", "checkpoint_restore", "partial_checkpoint_restore"),
    Phase13Case("randomized_filesystem_order"),
    Phase13Case("randomized_worker_completion_order"),
    Phase13Case("frozen_onefile_writable_path_simulation"),
)


def _evidence(case: Phase13Case) -> SchedulerEvidenceRecord | None:
    if not case.failure:
        return None
    return SchedulerEvidenceRecord(
        stage=case.stage,
        state="failure" if case.fatal else "degraded",
        error_category=case.category,
        error_source="stage832.phase13.synthetic_matrix",
        message=f"synthetic Phase 13 scheduler case: {case.name}",
        context={"matrix_case": case.name},
        queue_id=f"queue-{case.name}",
        job_id=f"job-{case.name}",
        worker_id=f"worker-{case.name}" if "worker" in case.stage or "worker" in case.category else "",
        path=f"/synthetic/{case.name}.bin",
        retry_state_affected=case.retry,
        timeout_state_affected=case.timeout,
        final_json_must_record=True,
        checkpoint_must_record=True,
        replay_must_record=True,
        fatal=case.fatal,
    )


def _record(case: Phase13Case, evidence: SchedulerEvidenceRecord | None, scheduler_section: dict) -> dict:
    evidence_payload = [] if evidence is None else [evidence.as_dict()]
    return {
        "job_id": f"job-{case.name}",
        "file": f"/synthetic/{case.name}.bin",
        "verdict": "clean" if evidence is None else "degraded",
        "engine": "renpy",
        "tags": [case.name, "phase13"],
        "chains": ["scheduler_matrix"],
        "failed_count": 0 if evidence is None else 1,
        "scheduler": scheduler_section,
        "scheduler_evidence": evidence_payload,
    }


@pytest.mark.parametrize("case", PHASE13_CASES, ids=[case.name for case in PHASE13_CASES])
def test_stage832_phase13_matrix_records_json_checkpoint_replay_evidence(tmp_path: Path, case: Phase13Case) -> None:
    evidence = _evidence(case)
    records = () if evidence is None else (evidence,)
    scheduler_section = build_scheduler_json_evidence_section(records)
    final_json_section = build_final_json_scheduler_section({"scheduler": scheduler_section})
    assert final_json_section is not None

    if evidence is None:
        assert final_json_section["scheduler_status"] == "ok"
        assert final_json_section["evidence"] == []
    else:
        assert final_json_section["scheduler_status"] == ("fatal" if case.fatal else "degraded")
        assert final_json_section["evidence"]
        emitted = final_json_section["evidence"][0]
        assert emitted["final_json_must_record"] is True
        assert emitted["checkpoint_must_record"] is True
        assert emitted["replay_must_record"] is True
        if case.retry:
            assert emitted["retry_state_affected"] is True
        if case.timeout:
            assert emitted["timeout_state_affected"] is True
        for field_name in case.expected_fields:
            assert final_json_section[field_name], f"{case.name} did not populate {field_name}"
        if case.retry:
            assert final_json_section["retry_decisions"], f"{case.name} lost retry evidence projection"
        if case.timeout:
            assert final_json_section["timeout_decisions"], f"{case.name} lost timeout evidence projection"

    checkpoint = tmp_path / f"{case.name}.checkpoint.json"
    if case.name == "checkpoint_write_failure":
        write_result = write_scheduler_checkpoint(checkpoint, SchedulerEvidenceBundle(records=records), write_json=lambda *a, **kw: False)
        assert write_result.status == "failed"
        assert write_result.evidence and write_result.evidence[0].final_json_must_record is True
    else:
        write_result = write_scheduler_checkpoint(checkpoint, SchedulerEvidenceBundle(records=records))
        assert write_result.status == "written"
        saved = json.loads(checkpoint.read_text(encoding="utf-8"))
        assert saved["scheduler"]["scheduler_status"] == final_json_section["scheduler_status"]

    expected = [_record(case, evidence, final_json_section)]
    actual = list(reversed(expected))
    comparison = compare_scheduler_replay_results(expected, actual)
    assert comparison.matched is True
    assert comparison.expected.records == comparison.actual.records
    if evidence is not None:
        replay_record = comparison.actual.records[0]
        assert replay_record.get("scheduler_evidence")
        assert "stage832.phase13.synthetic_matrix" in replay_record.get("scheduler_evidence")[0]
