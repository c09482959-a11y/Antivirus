from pathlib import Path

from Virus_Scan.scheduler.contracts.evidence_record import SchedulerEvidenceRecord
from Virus_Scan.scheduler.contracts.scheduler_result import SchedulerResult
from Virus_Scan.scheduler.evidence.checkpoint_writer import build_scheduler_checkpoint_payload, write_scheduler_checkpoint
from Virus_Scan.scheduler.evidence.records import build_scheduler_evidence_bundle, build_scheduler_json_evidence_section
from Virus_Scan.scheduler.evidence.scheduler_json_writer import build_scheduler_json_section
from Virus_Scan.scheduler.evidence.trace_writer import build_scheduler_trace_payload, write_scheduler_trace


def test_phase11_evidence_bundle_projects_required_final_json_sections():
    queue = SchedulerEvidenceRecord(
        stage="queue_integrity",
        state="degraded",
        error_category="queue_integrity_error",
        error_source="queue.integrity",
        message="corrupt queue record",
        queue_id="q1",
    )
    worker = SchedulerEvidenceRecord(
        stage="worker_lifecycle",
        state="failure",
        error_category="worker_exit",
        error_source="workers.lifecycle",
        message="worker exited after claim",
        worker_id="w1",
    )
    retry = SchedulerEvidenceRecord(
        stage="retry_exhaustion",
        state="failure",
        error_category="retry_exhaustion",
        error_source="queue.retry_policy",
        message="retry budget exhausted",
        retry_state_affected=True,
        fatal=True,
    )
    section = build_scheduler_json_evidence_section(
        (queue, worker, retry),
        checkpoint_status={"status": "written"},
        replay_status={"status": "matched"},
    )

    assert section["scheduler_status"] == "fatal"
    assert section["queue_integrity_result"][0]["queue_id"] == "q1"
    assert section["worker_lifecycle_events"][0]["worker_id"] == "w1"
    assert section["retry_exhaustion"][0]["retry_state_affected"] is True
    assert section["checkpoint"]["status"] == "written"
    assert section["replay_comparison_result"]["status"] == "matched"
    assert section["fatal_vs_recoverable"]["fatal"][0]["stage"] == "retry_exhaustion"
    assert build_scheduler_json_section((queue,))["scheduler_status"] == "degraded"


def test_phase11_checkpoint_and_trace_writers_use_canonical_json_dependency(tmp_path):
    evidence = SchedulerEvidenceRecord(stage="timeout", error_category="timeout_decision", message="timeout recorded")
    result = SchedulerResult(status="degraded", evidence=(evidence,))
    checkpoint_payload = build_scheduler_checkpoint_payload(result)
    trace_payload = build_scheduler_trace_payload((evidence,))

    assert checkpoint_payload["scheduler_result"]["evidence"][0]["stage"] == "timeout"
    assert checkpoint_payload["scheduler"]["timeout_decisions"][0]["stage"] == "timeout"
    assert trace_payload["scheduler_trace"][0]["error_category"] == "timeout_decision"

    writes = []

    def fake_writer(tmp, final, payload, *, log_context):
        writes.append((Path(tmp).name, Path(final).name, payload, log_context))
        return True

    checkpoint = write_scheduler_checkpoint(tmp_path / "scheduler.checkpoint.json", result, write_json=fake_writer)
    trace = write_scheduler_trace(tmp_path / "scheduler.trace.json", (evidence,), write_json=fake_writer)

    assert checkpoint.status == "written"
    assert trace.status == "written"
    assert [item[3] for item in writes] == ["scheduler_checkpoint", "scheduler_trace"]


def test_phase11_writer_failures_return_explicit_evidence(tmp_path):
    evidence = SchedulerEvidenceRecord(stage="queue_recovery", message="orphan recovered")
    bundle = build_scheduler_evidence_bundle((evidence,))

    def failing_writer(tmp, final, payload, *, log_context):
        return False

    checkpoint = write_scheduler_checkpoint(tmp_path / "scheduler.checkpoint.json", bundle, write_json=failing_writer)
    trace = write_scheduler_trace(tmp_path / "scheduler.trace.json", (evidence,), write_json=failing_writer)

    assert checkpoint.status == "failed"
    assert checkpoint.fatal is True
    assert checkpoint.evidence[0].final_json_must_record is True
    assert checkpoint.evidence[0].checkpoint_must_record is True
    assert trace.status == "failed"
    assert trace.evidence[0].replay_must_record is True
