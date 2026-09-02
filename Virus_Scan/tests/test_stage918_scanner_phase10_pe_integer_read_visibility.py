"""Stage 918 Phase 10: PE integer helpers must not hide truncation as zero."""
from __future__ import annotations

import pytest

from Virus_Scan.scanners.binary_pe_bytes import pe_u16, pe_u32, pe_u64
from Virus_Scan.scanners.binary_pe import scan_pure_python_pe_file


def test_pe_integer_helpers_raise_on_truncated_reads():
    with pytest.raises(ValueError):
        pe_u16(b"A", 0)
    with pytest.raises(ValueError):
        pe_u32(b"ABC", 0)
    with pytest.raises(ValueError):
        pe_u64(b"ABCDEFG", 0)


def test_truncated_mz_still_becomes_header_evidence(tmp_path):
    sample = tmp_path / "short.exe"
    sample.write_bytes(b"MZ" + b"\0" * 20)

    tags, meta = scan_pure_python_pe_file(sample, finalize=False, include_strings=False)
    low = {str(tag).lower() for tag in tags}

    assert meta["pe_header_degraded"] is True
    assert "pe_header_parse_scan_error" in low
    assert "binary_final_json_must_record" in low
