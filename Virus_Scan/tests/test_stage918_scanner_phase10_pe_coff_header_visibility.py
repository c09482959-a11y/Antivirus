"""Stage 918 Phase 10: MZ/PE signature with truncated COFF header is evidenced."""
from __future__ import annotations

import struct

from Virus_Scan.scanners.binary_pe import global_raw_pure_pe_header, scan_pure_python_pe_file


def _pe_signature_only_bytes() -> bytes:
    data = bytearray(b"MZ" + b"\0" * 58)
    data += struct.pack("<I", 0x40)
    data += b"PE\0\0"
    return bytes(data)


def _mz_missing_pe_signature_bytes() -> bytes:
    data = bytearray(b"MZ" + b"\0" * 58)
    data += struct.pack("<I", 0x40)
    data += b"PX!!"
    return bytes(data)


def test_surface_pe_signature_without_coff_header_records_failure(tmp_path):
    sample = tmp_path / "truncated_coff.exe"
    sample.write_bytes(_pe_signature_only_bytes())

    tags, meta = scan_pure_python_pe_file(sample, finalize=False, include_strings=False)
    low = {str(tag).lower() for tag in tags}

    assert meta["is_pe"] is False
    assert meta["pe_header_degraded"] is True
    assert "pe_header_parse_scan_error" in low
    assert "binary_final_json_must_record" in low


def test_raw_pe_signature_without_coff_header_records_failure(tmp_path):
    sample = tmp_path / "raw_truncated_coff.exe"
    sample.write_bytes(_pe_signature_only_bytes())

    result = global_raw_pure_pe_header(sample)
    low = {str(tag).lower() for tag in result["tags"]}

    assert result["meta"]["is_pe"] is True
    assert result["meta"]["pe_header_degraded"] is True
    assert "pe_header_parse_scan_error" in low
    assert "binary_final_json_must_record" in low


def test_mz_missing_pe_signature_records_header_failure(tmp_path):
    sample = tmp_path / "bad_signature.exe"
    sample.write_bytes(_mz_missing_pe_signature_bytes())

    tags, meta = scan_pure_python_pe_file(sample, finalize=False, include_strings=False)
    low = {str(tag).lower() for tag in tags}

    assert meta["is_pe"] is False
    assert meta["pe_header_degraded"] is True
    assert "pe_header_parse_scan_error" in low
