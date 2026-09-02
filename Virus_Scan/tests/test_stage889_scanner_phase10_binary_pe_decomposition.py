from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners import binary
from Virus_Scan.scanners import binary_pe
from Virus_Scan.scanners.api import binary_contracts


def test_binary_pe_contracts_are_owned_by_bounded_module():
    assert binary.scan_pure_python_pe_file is binary_pe.scan_pure_python_pe_file
    assert binary.global_raw_pure_pe_header is binary_pe.global_raw_pure_pe_header
    assert binary.is_dotnet_pe is binary_pe.is_dotnet_pe
    assert binary.extract_dotnet_metadata is binary_pe.extract_dotnet_metadata
    assert binary_contracts.scan_pure_python_pe_file is binary_pe.scan_pure_python_pe_file
    assert binary_contracts.global_raw_pure_pe_header is binary_pe.global_raw_pure_pe_header


def test_binary_module_no_longer_owns_pe_parser_implementation():
    tree = parse_python_file(Path("Virus_Scan/scanners/binary.py"))
    function_names = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
    assert "scan_pure_python_pe_file" not in function_names
    assert "global_raw_pure_pe_header" not in function_names
    assert "_global_raw_pure_pe_header" not in function_names
    assert "_umige_parse_pe_sections" not in function_names
    assert "_umige_parse_pe_import_names" not in function_names
    assert "extract_dotnet_metadata" not in function_names
    assert "is_dotnet_pe" not in function_names


def test_binary_pe_malformed_pe_returns_visible_evidence(tmp_path):
    sample = tmp_path / "truncated.exe"
    sample.write_bytes(b"MZ")
    tags, meta = binary_pe.scan_pure_python_pe_file(str(sample), finalize=False, include_strings=False)
    assert "pure_pe_scan_error" in tags or "scanner_failure" in tags or meta.get("is_pe") is False
    metadata = binary_pe.extract_dotnet_metadata(str(sample))
    assert metadata.get("is_dotnet") is False
    assert metadata.get("scanner_degraded") is True or metadata.get("status") in {"malformed", "unsupported"} or metadata.get("error") is True
