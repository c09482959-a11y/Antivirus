from __future__ import annotations

from Virus_Scan.scanners.binary_pe import scan_pure_python_pe_file


def test_truncated_mz_input_records_pe_header_failure_evidence(tmp_path):
    sample = tmp_path / "truncated.exe"
    sample.write_bytes(b"MZ")

    tags, meta = scan_pure_python_pe_file(sample, finalize=False, include_strings=False)
    tagset = {str(tag).lower() for tag in tags}

    assert meta["is_pe"] is False
    assert meta["pe_header_degraded"] is True
    assert "pe_header_parse_scan_error" in tagset
    assert "scanner_failure_evidence_recorded" in tagset
    assert "binary_final_json_must_record" in tagset


def test_plain_non_pe_binary_remains_non_evidenced_non_pe(tmp_path):
    sample = tmp_path / "plain.bin"
    sample.write_bytes(b"not a pe file")

    tags, meta = scan_pure_python_pe_file(sample, finalize=False, include_strings=False)

    assert tags == []
    assert meta == {"is_pe": False, "sections": 0, "imports": 0}
