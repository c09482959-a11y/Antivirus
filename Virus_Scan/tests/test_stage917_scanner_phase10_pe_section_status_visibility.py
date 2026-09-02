from Virus_Scan.tests.support.static_inventory import read_python_file

import ast
from pathlib import Path

from Virus_Scan.scanners.binary_pe_surface import _declared_section_record_status, scan_pure_python_pe_file



def test_declared_section_helper_error_is_not_encoded_as_missing_section_bool():
    source = read_python_file(Path("Virus_Scan/scanners/binary_pe_surface.py"))
    tree = ast.parse(source)
    helper = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_declared_section_record_status")
    helper_source = ast.get_source_segment(source, helper)
    assert "return True" not in helper_source
    assert "return False" not in helper_source
    assert '"helper_error"' in helper_source
    assert '"missing_records"' in helper_source


class _LengthValueError:
    def __len__(self):
        raise ValueError("synthetic declared-section helper failure")


def test_declared_section_helper_failure_returns_explicit_status_and_evidence():
    status, tags = _declared_section_record_status(_LengthValueError(), [])
    assert status == "helper_error"
    assert "pe_section_parse_scan_error" in tags
    assert "scanner_failure_evidence_recorded" in tags
    assert "binary_final_json_must_record" in tags


def test_section_helper_failure_emits_degraded_pe_evidence(tmp_path):
    sample = tmp_path / "bad_section_probe.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 128)
    # Exercise the public scanner with real bytes for malformed header evidence.
    tags, meta = scan_pure_python_pe_file(sample)
    assert "scanner_failure_evidence_recorded" in tags
    assert "binary_final_json_must_record" in tags
    assert meta.get("pe_header_degraded") is True
