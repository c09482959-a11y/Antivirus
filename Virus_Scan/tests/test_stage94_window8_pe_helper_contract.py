import struct

from Virus_Scan.scanners import binary


def _minimal_pe_with_claimed_sections(section_count=1, truncate_section_table=True, import_rva=0):
    data = bytearray(b"MZ" + b"\x00" * 0x3A)
    data += struct.pack("<I", 0x80)
    if len(data) < 0x80:
        data.extend(b"\x00" * (0x80 - len(data)))
    data.extend(b"PE\x00\x00")
    data.extend(struct.pack("<H", 0x14C))
    data.extend(struct.pack("<H", section_count))
    data.extend(b"\x00" * 12)
    data.extend(struct.pack("<H", 0xE0))
    data.extend(struct.pack("<H", 0x010F))
    opt_start = len(data)
    data.extend(struct.pack("<H", 0x10B))
    data.extend(b"\x00" * (0xE0 - 2))
    if import_rva:
        struct.pack_into("<I", data, opt_start + 104, import_rva)
    if not truncate_section_table:
        data.extend(b".text\x00\x00\x00")
        data.extend(struct.pack("<IIIIIIHHI", 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020))
        if len(data) < 0x400:
            data.extend(b"\x00" * (0x400 - len(data)))
    return bytes(data)


def test_truncated_pe_section_table_degrades(tmp_path):
    sample = tmp_path / "broken.exe"
    sample.write_bytes(_minimal_pe_with_claimed_sections(section_count=3, truncate_section_table=True))

    tags, meta = binary.scan_pure_python_pe_file(sample, finalize=False, include_strings=False)
    low = {str(t).lower() for t in tags}
    assert {"scanner_failure", "scanner_degraded", "scan_incomplete", "pe_section_parse_scan_error"}.issubset(low)
    assert meta.get("section_parse_degraded") is True


def test_import_directory_unmapped_degrades_without_private_patch(tmp_path):
    sample = tmp_path / "badimports.exe"
    sample.write_bytes(_minimal_pe_with_claimed_sections(section_count=1, truncate_section_table=False, import_rva=0x5000))

    tags, meta = binary.scan_pure_python_pe_file(sample, finalize=False, include_strings=False)
    low = {str(t).lower() for t in tags}
    assert {"scanner_failure", "scanner_degraded", "scan_incomplete", "pe_import_parse_scan_error"}.issubset(low)
    assert meta.get("import_parse_degraded") is True


def test_malformed_pe_helper_path_is_visible_without_side_channel(tmp_path):
    sample = tmp_path / "bad.exe"
    sample.write_bytes(b"MZ")

    tags, meta = binary.scan_pure_python_pe_file(sample, finalize=False, include_strings=False)
    low = {str(t).lower() for t in tags}
    assert {"scanner_failure", "scanner_degraded", "scan_incomplete", "pe_header_parse_scan_error"}.issubset(low)
    assert meta.get("is_pe") is False
    assert meta.get("pe_header_degraded") is True
    assert not hasattr(binary.scan_pure_python_pe_file, "last_error_tags")
    assert not hasattr(binary.scan_pure_python_pe_file, "last_error")


def test_dotnet_metadata_read_failure_degrades_without_private_patch(tmp_path):
    missing = tmp_path / "missing.dll"

    meta = binary.extract_dotnet_metadata(str(missing))
    low = {str(t).lower() for t in meta.get("tags", [])}
    assert meta.get("scanner_degraded") is True
    assert {"scanner_failure", "scanner_degraded", "scan_incomplete", "dotnet_metadata_scan_error"}.issubset(low)
