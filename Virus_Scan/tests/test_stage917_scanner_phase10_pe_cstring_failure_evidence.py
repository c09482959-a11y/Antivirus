import struct

import pytest

from Virus_Scan.scanners.binary_pe_bytes import pe_cstr
from Virus_Scan.scanners.binary_pe_sections import parse_pe_import_names


class _FindFailBytes(bytes):
    def find(self, *args, **kwargs):
        raise ValueError("synthetic PE CString lookup failure")


def _minimal_import_pe_bytes() -> bytes:
    data = bytearray(0x300)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    opt_off = 0x80 + 24
    struct.pack_into("<H", data, opt_off, 0x10B)
    # Import data directory RVA. _import_directory_offset reads dd_off + 8.
    dd_off = opt_off + 96
    struct.pack_into("<I", data, dd_off + 8, 0x200)
    # Import descriptor at RVA/file offset 0x200.
    struct.pack_into("<I", data, 0x200 + 12, 0x220)  # DLL name RVA
    struct.pack_into("<I", data, 0x200 + 16, 0x240)  # first thunk RVA, nonzero descriptor
    return bytes(data)


def test_pe_cstr_helper_failure_is_not_hidden_as_string_sentinel():
    with pytest.raises(ValueError):
        pe_cstr(_FindFailBytes(b"abcd\x00"), 0)


def test_pe_import_cstring_failure_becomes_parser_evidence():
    data = _FindFailBytes(_minimal_import_pe_bytes())
    sections = (
        {
            "virtual_address": 0x200,
            "virtual_size": 0x100,
            "raw_size": 0x100,
            "raw_ptr": 0x200,
        },
    )
    result = parse_pe_import_names(data, sections)
    assert result.imports == ()
    assert "pe_import_parse_scan_error" in result.error_tags
    assert "scanner_failure_evidence_recorded" in result.error_tags
    assert "binary_final_json_must_record" in result.error_tags
