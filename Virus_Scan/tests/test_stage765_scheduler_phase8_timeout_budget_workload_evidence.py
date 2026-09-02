from __future__ import annotations

from pathlib import Path

from Virus_Scan.scheduler.timeout.timeout_budget import compute_timeout_budget


def test_stage765_unsupported_archive_format_records_timeout_inspection_evidence(tmp_path: Path):
    sample = tmp_path / "payload.7z"
    sample.write_bytes(b"not a parsed seven zip fixture")

    budget = compute_timeout_budget(sample)
    evidence = budget.as_evidence()

    assert budget.workload_class == "archive"
    assert "unsupported_archive_format:.7z" in str(evidence["inspection_error"])
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True


def test_stage765_unrecognized_image_header_records_timeout_inspection_evidence(tmp_path: Path):
    sample = tmp_path / "image.bmp"
    sample.write_bytes(b"BM" + b"\x00" * 62)

    budget = compute_timeout_budget(sample)
    evidence = budget.as_evidence()

    assert budget.workload_class == "image_fast_triage"
    assert "unrecognized_image_header:.bmp" in str(evidence["inspection_error"])
    assert evidence["final_json_must_record"] is True
    assert evidence["checkpoint_must_record"] is True
    assert evidence["replay_must_reproduce"] is True
