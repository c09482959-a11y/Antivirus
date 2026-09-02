from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from Virus_Scan.contracts.result_record import make_worker_error_result
from Virus_Scan.scheduler.internal.worker_result_boundary import (
    build_worker_result_schema_failure,
    scheduler_scan_integrity_snapshot,
)
from Virus_Scan.scheduler.workers.child_failure_metadata import worker_error_result
from Virus_Scan.scheduler.workers.child_output_evidence import (
    ChildWorkerOutputPublicationRequest,
    record_worker_output_publication_failure,
)
from Virus_Scan.scheduler.workers.inmemory_worker_lifecycle_evidence import (
    InMemoryWorkerLifecyclePublicationEvidence,
    annotate_worker_lifecycle_publication_failure,
)
from Virus_Scan.scheduler.workers.result_contracts import normalize_scheduler_worker_result


class HostileIntegrity(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise AssertionError("integrity __iter__ must not be called")

    def __len__(self):
        type(self).touched += 1
        raise AssertionError("integrity __len__ must not be called")

    def __getitem__(self, key):
        type(self).touched += 1
        raise AssertionError("integrity __getitem__ must not be called")

    def items(self):
        type(self).touched += 1
        raise AssertionError("integrity items must not be called")

    def get(self, key, default=None):
        type(self).touched += 1
        raise AssertionError("integrity get must not be called")


def _reset_hostile() -> HostileIntegrity:
    HostileIntegrity.touched = 0
    return HostileIntegrity()


def test_scheduler_scan_integrity_snapshot_rejects_hostile_integrity_with_evidence():
    hostile = _reset_hostile()

    integrity = scheduler_scan_integrity_snapshot(
        hostile,
        unavailable_reason="non_materializable_test_integrity",
        original_type_field="test_integrity_original_type",
        unavailable_flag="test_integrity_unavailable",
    )

    assert HostileIntegrity.touched == 0
    assert integrity["test_integrity_unavailable"] is True
    assert integrity["scan_integrity_unavailable"] is True
    assert integrity["scan_integrity_unavailable_reason"] == "non_materializable_test_integrity"
    assert integrity["test_integrity_original_type"] == "HostileIntegrity"
    assert integrity["allow_learning"] is False


def test_worker_schema_failure_does_not_collapse_invalid_integrity_to_empty_dict():
    hostile = _reset_hostile()

    def worker_error_result_with_hostile_integrity(path, exc):
        return {"file": path, "scan_integrity": hostile}

    normalized = build_worker_result_schema_failure(
        "sample.bin",
        {"bad": "result"},
        worker_error_result=worker_error_result_with_hostile_integrity,
        recoverable_exceptions=(Exception,),
        reason="bad-schema",
    )

    assert HostileIntegrity.touched == 0
    integrity = normalized["scan_integrity"]
    assert integrity["worker_result_integrity_unavailable"] is True
    assert integrity["scan_integrity_unavailable"] is True
    assert integrity["worker_result_integrity_original_type"] == "HostileIntegrity"
    assert integrity["worker_result_schema_invalid"] is True
    assert integrity["allow_learning"] is False


def test_normalize_worker_result_preserves_invalid_integrity_evidence():
    hostile = _reset_hostile()

    normalized = normalize_scheduler_worker_result(
        "sample.bin",
        {"file": "sample.bin", "scan_integrity": hostile},
        worker_error_result=make_worker_error_result,
        recoverable_exceptions=(Exception,),
    )

    assert HostileIntegrity.touched == 0
    integrity = normalized["scan_integrity"]
    assert integrity["worker_result_integrity_unavailable"] is True
    assert integrity["scan_integrity_unavailable_reason"] == "non_materializable_worker_result_integrity"
    assert integrity["worker_result_integrity_original_type"] == "HostileIntegrity"
    assert integrity["allow_learning"] is False


def test_lifecycle_annotation_does_not_collapse_invalid_integrity_to_empty_dict():
    hostile = _reset_hostile()
    evidence = InMemoryWorkerLifecyclePublicationEvidence(
        operation="publish",
        job_id=7,
        path="sample.bin",
        generation=1,
        reason="publish failed",
    )

    annotated = annotate_worker_lifecycle_publication_failure(
        {"file": "sample.bin", "scan_integrity": hostile},
        evidence,
    )

    assert HostileIntegrity.touched == 0
    integrity = annotated["scan_integrity"]
    assert integrity["worker_lifecycle_integrity_unavailable"] is True
    assert integrity["scan_integrity_unavailable"] is True
    assert integrity["worker_lifecycle_integrity_original_type"] == "HostileIntegrity"
    assert integrity["worker_lifecycle_publication_failed"] is True
    assert integrity["allow_learning"] is False


def test_worker_output_publication_does_not_collapse_invalid_integrity_to_empty_dict():
    hostile = _reset_hostile()
    child_results = {"sample.bin": {"file": "sample.bin", "scan_integrity": hostile}}

    record_worker_output_publication_failure(
        ChildWorkerOutputPublicationRequest(
            child_results=child_results,
            file_path="sample.bin",
            worker_output_path="worker-output.json",
            context="worker_output",
            failure_stage="write",
            reason="write failed",
        )
    )

    assert HostileIntegrity.touched == 0
    integrity = child_results["sample.bin"]["scan_integrity"]
    assert integrity["worker_output_integrity_unavailable"] is True
    assert integrity["scan_integrity_unavailable"] is True
    assert integrity["worker_output_integrity_original_type"] == "HostileIntegrity"
    assert integrity["worker_output_publication_failed"] is True
    assert integrity["allow_learning"] is False


def test_child_worker_error_result_does_not_collapse_invalid_integrity_to_empty_dict():
    hostile = _reset_hostile()

    def make_error_result_with_hostile_integrity(path, exc):
        return {"file": path, "scan_integrity": hostile}

    result, failure_info = worker_error_result(
        "sample.bin",
        RuntimeError("boom"),
        stage="raw",
        job={"attempt": 2},
        make_error_result=make_error_result_with_hostile_integrity,
        exception_info_builder=lambda exc, **kwargs: {"stage": kwargs["stage"], "attempt": kwargs["attempt"]},
        report=lambda marker, exc: None,
        recoverable_exceptions=(Exception,),
    )

    assert HostileIntegrity.touched == 0
    integrity = result["scan_integrity"]
    assert failure_info["attempt"] == 2
    assert integrity["worker_failure_integrity_unavailable"] is True
    assert integrity["scan_integrity_unavailable"] is True
    assert integrity["worker_failure_integrity_original_type"] == "HostileIntegrity"
    assert integrity["file_failed"] is True
    assert integrity["allow_learning"] is False


def test_stage1637_scan_integrity_default_collapse_routes_removed_from_owner_files():
    root = Path(__file__).resolve().parents[2]
    checked = {
        "Virus_Scan/scheduler/internal/worker_result_boundary.py": "scheduler_owned_mapping_snapshot(",
        "Virus_Scan/scheduler/workers/result_contracts.py": "scheduler_scan_integrity_snapshot(",
        "Virus_Scan/scheduler/workers/inmemory_worker_lifecycle_evidence.py": "scheduler_scan_integrity_snapshot(",
        "Virus_Scan/scheduler/workers/child_output_evidence.py": "scheduler_scan_integrity_snapshot(",
        "Virus_Scan/scheduler/workers/child_failure_metadata.py": "scheduler_scan_integrity_snapshot(",
    }
    forbidden_fragments = (
        'scheduler_owned_mapping_snapshot(dict.get(annotated, "scan_integrity")) or {}',
        'scheduler_owned_mapping_snapshot(normalized_snapshot.get("scan_integrity")) or {}',
        '_owned_mapping_snapshot(dict.get(updated, "scan_integrity")) or {}',
        '_owned_result_snapshot(dict.get(snapshot, "scan_integrity")) or {}',
        'integrity_snapshot or {}',
    )
    for rel, required in checked.items():
        src = (root / rel).read_text(encoding="utf-8")
        assert required in src
        for fragment in forbidden_fragments:
            assert fragment not in src
