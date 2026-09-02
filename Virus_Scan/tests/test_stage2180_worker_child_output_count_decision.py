from __future__ import annotations

from Virus_Scan.scheduler.workers.child_output_evidence import (
    ChildWorkerOutputPublicationRequest,
    child_worker_result_count_decision,
    record_worker_output_publication_failure,
)


class HostileDict(dict):
    touched = 0

    def items(self):
        type(self).touched += 1
        raise RuntimeError("items hook must not run")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("iter hook must not run")


def _reset() -> None:
    HostileDict.touched = 0


def test_stage2180_child_result_count_decision_reports_unavailable_mapping_without_hooks() -> None:
    _reset()
    hostile = HostileDict({"sample.bin": {"file": "sample.bin"}})

    decision = child_worker_result_count_decision(hostile)

    assert decision.value == 0
    assert decision.mapping_available is False
    assert decision.reason == "worker_output_child_results_mapping_unavailable"
    assert HostileDict.touched == 0


def test_stage2180_worker_output_publication_records_child_count_unavailable_evidence() -> None:
    _reset()
    hostile = HostileDict({"sample.bin": {"file": "sample.bin"}})

    evidence = record_worker_output_publication_failure(
        ChildWorkerOutputPublicationRequest(
            child_results=hostile,
            file_path="sample.bin",
            worker_output_path="worker-output.json",
            context="worker_output",
            failure_stage="aggregate_write_exception",
            reason="write failed",
        )
    )

    assert evidence.child_result_count == 0
    assert evidence.child_result_count_reason == "worker_output_child_results_mapping_unavailable"
    integrity = evidence.as_scan_integrity()
    assert integrity["worker_output_publication_child_result_count"] == 0
    assert integrity["worker_output_publication_child_result_count_unavailable"] is True
    assert (
        integrity["worker_output_publication_child_result_count_unavailable_reason"]
        == "worker_output_child_results_mapping_unavailable"
    )
    record = evidence.as_result_record()
    assert record["worker_output_publication_child_result_count_unavailable"] is True
    assert HostileDict.touched == 0
