"""Stage 903 Phase 10 binary private pipeline boundary tests."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.binary_behavior_predicates import _has_c2_behavior, _xor_blob_signal
from Virus_Scan.scanners.binary_pe_bytes import pe_cstr, pe_rva_to_offset, pe_u16, pe_u32, pe_u64

BINARY_MODULES = (
    Path("Virus_Scan/scanners/binary_behavior_predicates.py"),
    Path("Virus_Scan/scanners/binary_pe_sections.py"),
    Path("Virus_Scan/scanners/binary_pe_surface.py"),
)


def test_binary_phase10_modules_do_not_import_private_pipeline_helpers():
    forbidden = "Virus_Scan.scanners.pipeline"
    for path in BINARY_MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module != forbidden, f"{path} imports private scanner pipeline helpers"
            elif isinstance(node, ast.Import):
                assert all(alias.name != forbidden for alias in node.names), f"{path} imports private scanner pipeline helpers"


def test_binary_behavior_predicates_do_not_import_private_pickle_evidence():
    path = Path("Virus_Scan/scanners/binary_behavior_predicates.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    forbidden = "Virus_Scan.scanners.pickle.evidence"
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert node.module != forbidden


def test_binary_owned_text_signals_preserve_c2_and_xor_behavior():
    assert _has_c2_behavior("https://example.test socket.connect command shell createprocess") is True
    assert _has_c2_behavior("plain benign text") is False
    assert _xor_blob_signal(b"A" * 512) is False


def test_binary_owned_pe_byte_helpers_preserve_little_endian_and_rva_mapping():
    data = b"ABCD" + b"\x78\x56\x34\x12" + b"name\x00tail" + (b"\x00" * 16)
    assert pe_u16(data, 4) == 0x5678
    assert pe_u32(data, 4) == 0x12345678
    assert pe_u64(b"ABCD" + b"\x78\x56\x34\x12\x00\x00\x00\x00", 4) == 0x0000000012345678
    assert pe_cstr(data, 8) == "name"
    sections = ({"virtual_address": 0x1000, "virtual_size": 0x100, "raw_size": 0x80, "raw_ptr": 0x40},)
    assert pe_rva_to_offset(0x1010, sections) == 0x50
    assert pe_rva_to_offset(0x2000, sections) is None
