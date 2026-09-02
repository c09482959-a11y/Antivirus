from __future__ import annotations

from Virus_Scan.scanners.binary_pe import global_raw_pure_pe_header


def test_raw_pe_header_truncated_mz_records_failure_evidence(tmp_path):
    sample = tmp_path / "truncated.exe"
    sample.write_bytes(b"MZ")

    result = global_raw_pure_pe_header(sample)
    tags = {str(tag).lower() for tag in result["tags"]}
    meta = result["meta"]

    assert meta["is_pe"] is True
    assert meta["pe_header_degraded"] is True
    assert "pe_header_parse_scan_error" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "binary_final_json_must_record" in tags


def test_raw_pe_header_plain_non_pe_stays_plain_non_pe(tmp_path):
    sample = tmp_path / "plain.bin"
    sample.write_bytes(b"plain binary")

    result = global_raw_pure_pe_header(sample)

    assert result["tags"] == []
    assert result["meta"] == {"is_pe": False, "header_bytes": len(b"plain binary")}
