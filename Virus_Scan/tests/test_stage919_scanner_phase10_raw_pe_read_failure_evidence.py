"""Stage 919 Phase 10 raw PE read-failure evidence tests."""
from __future__ import annotations

from Virus_Scan.scanners.binary_pe import global_raw_pure_pe_header


def test_global_raw_pure_pe_header_read_failure_is_final_json_evidenced(tmp_path) -> None:
    blocked = tmp_path / "blocked.exe"
    blocked.mkdir()

    result = global_raw_pure_pe_header(blocked)
    tags = set(result["tags"])
    meta = result["meta"]

    assert "pure_pe_scan_error" in tags
    assert "global_raw_pure_pe_header_scan_error" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "binary_final_json_must_record" in tags
    assert meta["scanner_degraded"] is True
    assert meta["binary_final_json_must_record"] is True


def test_global_raw_pure_pe_header_plain_non_pe_preserved(tmp_path) -> None:
    sample = tmp_path / "plain.bin"
    sample.write_bytes(b"not a PE")

    result = global_raw_pure_pe_header(sample)

    assert result["tags"] == []
    assert result["meta"]["is_pe"] is False
