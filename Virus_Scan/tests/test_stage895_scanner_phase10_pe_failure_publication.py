from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file, read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.binary_pe import scan_pure_python_pe_file
from Virus_Scan.scanners.binary_pe_sections import parse_pe_sections, parse_pe_import_names


def test_missing_pe_file_records_binary_final_json_evidence(tmp_path):
    missing = tmp_path / "missing.exe"
    tags, meta = scan_pure_python_pe_file(str(missing))
    tagset = set(tags)
    assert meta["is_pe"] is False
    assert "scanner_failure" in tagset
    assert "scanner_degraded" in tagset
    assert "scan_incomplete" in tagset
    assert "pure_pe_scan_error" in tagset
    assert "scanner_failure_evidence_recorded" in tagset
    assert "scanner_failure_evidence:binary:scan_pure_python_pe_file" in tagset
    assert "binary_final_json_must_record" in tagset


def test_pe_parse_helper_failures_carry_binary_publication_markers():
    section_result = parse_pe_sections(b"MZ" + b"\x00" * 58 + (0x40).to_bytes(4, "little"))
    import_result = parse_pe_import_names(b"MZ" + b"\x00" * 58 + (0x40).to_bytes(4, "little"), [])
    for result in (section_result, import_result):
        tags = set(result.error_tags)
        assert "scanner_failure" in tags
        assert "scanner_failure_evidence_recorded" in tags
        assert "binary_final_json_must_record" in tags


def test_pe_surface_uses_binary_owned_failure_helper():
    text = read_python_file(Path("Virus_Scan/scanners/binary_pe_surface.py"))
    assert 'mark_pe_helper_error("scan_pure_python_pe_file"' in text
    assert 'scanner_failure_tags("scan_pure_python_pe_file"' not in text
    tree = parse_python_file(Path("Virus_Scan/scanners/binary_pe_surface.py"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            assert not [n for n in ast.walk(node) if isinstance(n, (ast.Import, ast.ImportFrom))], node.name
