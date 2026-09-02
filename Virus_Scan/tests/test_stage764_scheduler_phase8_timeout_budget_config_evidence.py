from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget


def test_stage764_timeout_budget_invalid_configured_timeout_records_evidence(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    budget = compute_timeout_budget(sample, configured_timeout_seconds="not-a-number")
    evidence = budget.as_evidence()

    assert "configured_timeout_seconds" in str(evidence["inspection_error"])
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True


def test_stage764_timeout_budget_negative_configured_timeout_records_evidence(tmp_path: Path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"data")

    budget = compute_timeout_budget(sample, configured_timeout_seconds=-5)
    evidence = budget.as_evidence()

    assert "below minimum" in str(evidence["inspection_error"])
    assert evidence["timeout_budget"] >= 30.0
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
