import json
import pytest

from Virus_Scan.contracts.result_record import validate_result_record_invariants
#
#)
from Virus_Scan.core.jsonio import validate_persistent_record_semantics
from Virus_Scan.scheduler.queue.identity import QueueJobIdentitySnapshot, queue_job_identity


def test_high_risk_result_without_evidence_hard_fails_persistence_boundary():
    record = {
        "file": "sample.exe",
        "result": {"file": "sample.exe", "classification": "malicious", "score": 95, "tags": [], "chains": []},
    }
    with pytest.raises(ValueError, match="high-risk result missing forensic evidence"):
        validate_persistent_record_semantics(record, context="stage350_queue_result")


def test_high_risk_result_with_evidence_passes_persistence_boundary():
    record = {
        "file": "sample.exe",
        "result": {"file": "sample.exe", "classification": "malicious", "score": 95, "tags": ["embedded_pe_payload"]},
    }
    assert validate_persistent_record_semantics(record, context="stage350_queue_result") is True


def test_result_invariant_rejects_duplicate_tag_ordering():
    with pytest.raises(ValueError, match="duplicate tags"):
        validate_result_record_invariants({"file": "x", "classification": "low", "score": 10, "tags": ["a", "A"]})


def test_queue_job_identity_uses_immutable_snapshot_for_raw_stage():
    job = {"job_type": "raw_stage", "file_id": "abc", "collector": "strings", "seq": 2, "attempt": 1}
    snapshot = QueueJobIdentitySnapshot.from_job(job, "job.json")
    assert snapshot.file_id == "abc"
    assert queue_job_identity(job, "job.json") == "raw:abc:strings:2:1"
