from __future__ import annotations

from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget


def test_stage758_timeout_budget_records_file_size_probe_failure():
    budget = compute_timeout_budget(
        "sample.bin",
        configured_timeout_seconds=10,
        method="file_scan",
        file_size_probe=lambda _path: 0,
    )
    evidence = budget.as_evidence()

    assert evidence["file_size"] == 0
    assert evidence["inspection_error"] is not None
    assert "scheduler_file_size_probe_rejected" in evidence["inspection_error"]
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
