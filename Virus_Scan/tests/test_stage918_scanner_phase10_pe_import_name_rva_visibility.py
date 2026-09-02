"""Stage 918 Phase 10: malformed PE import name RVAs must emit evidence."""
from __future__ import annotations

import struct

from Virus_Scan.scanners.binary_pe_sections import parse_pe_import_names, parse_pe_sections


def _pe_with_import_descriptor_name_rva(name_rva: int) -> bytes:
    data = bytearray(0x600)
    data[:2] = b"MZ"
    data[60:64] = struct.pack("<I", 0x80)
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = struct.pack("<H", 0x14C)
    data[0x86:0x88] = struct.pack("<H", 1)
    data[0x94:0x96] = struct.pack("<H", 0xE0)
    opt = 0x98
    data[opt:opt + 2] = struct.pack("<H", 0x10B)
    data[opt + 104:opt + 108] = struct.pack("<I", 0x1000)
    data[opt + 108:opt + 112] = struct.pack("<I", 0x28)
    sec = opt + 0xE0
    data[sec:sec + 8] = b".idata\0\0"
    data[sec + 8:sec + 12] = struct.pack("<I", 0x200)
    data[sec + 12:sec + 16] = struct.pack("<I", 0x1000)
    data[sec + 16:sec + 20] = struct.pack("<I", 0x200)
    data[sec + 20:sec + 24] = struct.pack("<I", 0x200)
    # import descriptor at RVA 0x1000 -> file offset 0x200
    data[0x200 + 12:0x200 + 16] = struct.pack("<I", name_rva)
    return bytes(data)


def test_import_descriptor_unmapped_name_rva_becomes_import_parse_evidence():
    data = _pe_with_import_descriptor_name_rva(0x5000)
    sections = parse_pe_sections(data).sections

    result = parse_pe_import_names(data, sections)
    low = {str(tag).lower() for tag in result.error_tags}

    assert "pe_import_parse_scan_error" in low
    assert "binary_final_json_must_record" in low
    assert result.imports == ()


def test_import_descriptor_mapped_name_rva_still_parses():
    data = bytearray(_pe_with_import_descriptor_name_rva(0x1040))
    data[0x240:0x24c] = b"kernel32.dll\0"
    sections = parse_pe_sections(bytes(data)).sections

    result = parse_pe_import_names(bytes(data), sections)

    assert not result.error_tags
    assert result.imports[0][0] == "kernel32.dll"
