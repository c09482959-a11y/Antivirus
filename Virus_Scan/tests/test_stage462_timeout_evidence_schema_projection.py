from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget
from Virus_Scan.publication.json_writer import compact_result_record


def test_timeout_budget_evidence_includes_explicit_reason_slots(tmp_path):
    target = tmp_path / "sample.png"
    target.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 64)
    evidence = compute_timeout_budget(target, configured_timeout_seconds=20).as_evidence()
    assert "timeout_reason" in evidence
    assert "stall_reason" in evidence
    assert evidence["timeout_reason"] is None
    assert evidence["stall_reason"] is None


def test_finalizer_preserves_required_timeout_evidence_fields():
    timeout_evidence = {
        "archive_member_count": 7,
        "bytes_processed": 123,
        "compressed_size": 456,
        "compression_ratio": 12.5,
        "current_stage": "archive_member_scan",
        "deep_scan": True,
        "estimated_uncompressed_size": 789,
        "file_size": 456,
        "heartbeat_age": 1.5,
        "heartbeat_stale_budget": 30.0,
        "image_pixels": None,
        "inspection_error": None,
        "largest_member_size": 111,
        "nested_archive_count": 2,
        "progress_age": 0.25,
        "progress_counter": 9,
        "recursion_depth": 3,
        "scan_method": "archive_scan",
        "stall_budget": 600.0,
        "stall_reason": "progress_checkpoint_stale",
        "timeout_budget": 7200.0,
        "timeout_reason": "dynamic_hard_timeout",
        "worker_killed": True,
        "worker_pid": 12345,
        "worker_recovered": False,
        "worker_state": "queue_worker_killed_after_stall",
        "workload_class": "archive",
    }
    record = {
        "file": "archive.zip",
        "path": "archive.zip",
        "score": 0.0,
        "classification": "benign_clean",
        "tags": [],
        "routing_evidence": {"detected_engine": "other"},
        "timeout_evidence": timeout_evidence,
    }
    normalized = compact_result_record(record)
    projected = normalized["timeout_evidence"]
    for key in (
        "worker_state",
        "heartbeat_age",
        "progress_age",
        "timeout_budget",
        "timeout_reason",
        "stall_reason",
        "workload_class",
        "current_stage",
        "file_size",
        "archive_member_count",
        "recursion_depth",
        "compression_ratio",
        "worker_killed",
        "worker_recovered",
    ):
        assert key in projected
    assert projected["worker_state"] == "queue_worker_killed_after_stall"
    assert projected["timeout_reason"] == "dynamic_hard_timeout"
    assert projected["stall_reason"] == "progress_checkpoint_stale"
