import pytest

from Virus_Scan.scheduler.workers.child_result_publication import (
    ChildWorkerOutputPublicationEvidence,
    WorkerOutputFinalizeRequest,
    WorkerOutputUpdateRequest,
    finalize_worker_output,
    update_worker_output,
)


def test_stage752_child_output_update_failure_marks_worker_result_degraded(tmp_path):
    reports = []
    child_results = {"a.bin": {"file": "a.bin", "tags": [], "scan_integrity": {}}}
    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")

    ok = update_worker_output(
        WorkerOutputUpdateRequest(
            worker_output_path=blocked_parent / "worker-output.json",
            file_path="a.bin",
            result=child_results["a.bin"],
            child_results=child_results,
            context="stage752.child_output_update",
            report=lambda label, exc: reports.append((label, str(exc))),
        )
    )

    assert ok is False
    assert reports == [
        (
            "stage752.child_output_update.aggregate_write_rejected",
            "aggregate worker output publication rejected",
        )
    ]
    degraded = child_results["a.bin"]
    integrity = degraded["scan_integrity"]
    assert degraded["queue_failure"] is True
    assert degraded["scheduler_failure_reason"] == "worker_output_publication_failed"
    assert degraded["worker_output_publication_failed"] is True
    assert integrity["worker_output_publication_failed"] is True
    assert integrity["worker_output_publication_stage"] == "aggregate_write_rejected"
    assert integrity["allow_learning"] is False


def test_stage752_child_output_finalize_failure_adds_replay_visible_sentinel(tmp_path):
    reports = []
    child_results = {}
    blocked_parent = tmp_path / "blocked-parent"
    blocked_parent.write_text("not a directory", encoding="utf-8")

    ok = finalize_worker_output(
        WorkerOutputFinalizeRequest(
            worker_output_path=blocked_parent / "worker-output.json",
            child_results=child_results,
            context="stage752.child_output_final",
            report=lambda label, exc: reports.append((label, str(exc))),
        )
    )

    assert ok is False
    assert reports == [
        (
            "stage752.child_output_final.aggregate_finalize_failed",
            "aggregate worker output publication rejected",
        )
    ]
    assert set(child_results) == {"__scheduler_worker_output_publication_failure__"}
    evidence_record = child_results["__scheduler_worker_output_publication_failure__"]
    assert evidence_record["queue_failure"] is True
    assert evidence_record["scheduler_failure_reason"] == "worker_output_publication_failed"
    assert evidence_record["worker_output_publication_stage"] == "aggregate_finalize_failed"
    assert evidence_record["scan_integrity"]["worker_output_publication_failed"] is True


def test_stage752_child_output_publication_evidence_is_immutable():
    evidence = ChildWorkerOutputPublicationEvidence(
        context="ctx",
        failure_stage="stage",
        worker_output_path="out.json",
        file_path="a.bin",
        reason="reason",
        child_result_count=1,
    )

    with pytest.raises(AttributeError):
        evidence.reason = "changed"
