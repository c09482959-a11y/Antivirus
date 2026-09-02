"""Stage 918 Phase 10: invalid PE C-string offsets must be visible."""
from __future__ import annotations

import pytest

from Virus_Scan.scanners.binary_pe_bytes import pe_cstr
from Virus_Scan.tests.test_stage918_scanner_phase10_pe_import_name_rva_visibility import _pe_with_import_descriptor_name_rva
from Virus_Scan.scanners.binary_pe_sections import parse_pe_import_names, parse_pe_sections


def test_pe_cstr_invalid_offset_raises_instead_of_empty_string():
    with pytest.raises(ValueError):
        pe_cstr(b"abc", None)
    with pytest.raises(ValueError):
        pe_cstr(b"abc", 3)


def test_import_descriptor_empty_name_becomes_evidence():
    data = bytearray(_pe_with_import_descriptor_name_rva(0x1040))
    sections = parse_pe_sections(bytes(data)).sections

    result = parse_pe_import_names(bytes(data), sections)
    low = {str(tag).lower() for tag in result.error_tags}

    assert "pe_import_parse_scan_error" in low
    assert "binary_final_json_must_record" in low
