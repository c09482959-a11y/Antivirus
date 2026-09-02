
"""Stage 894 Phase 10 strict-fast failure evidence tests."""

from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.binary_strict_fast import _strict_fast_file_is_boring_text


def test_strict_fast_directory_read_failure_records_binary_evidence(tmp_path: Path) -> None:
    blocked = tmp_path / "blocked.txt"
    blocked.mkdir()

    ok, metadata = _strict_fast_file_is_boring_text(blocked)

    assert ok is False
    assert metadata["extension"] == ".txt"
    assert metadata["binary_strict_fast_failure"] == "read"
    assert metadata["scanner_failure"] is True
    assert metadata["scanner_degraded"] is True
    assert metadata["scan_incomplete"] is True
    assert metadata["scanner_failure_evidence_recorded"] is True
    assert metadata["scanner_failure_evidence"] == "binary:strict_fast_file_read"
    assert metadata["binary_final_json_must_record"] is True


def test_strict_fast_missing_path_records_binary_evidence(tmp_path: Path) -> None:
    missing = tmp_path / "missing.txt"

    ok, metadata = _strict_fast_file_is_boring_text(missing)

    assert ok is False
    assert metadata["binary_strict_fast_failure"] == "stat"
    assert metadata["scanner_failure_evidence_recorded"] is True
    assert metadata["binary_final_json_must_record"] is True


def test_strict_fast_gate_is_decomposed_without_function_imports() -> None:
    tree = parse_python_file(Path("Virus_Scan/scanners/binary_strict_fast.py"))
    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    assert functions
    assert max(node.end_lineno - node.lineno + 1 for node in functions) <= 40
    assert not any(
        isinstance(child, (ast.Import, ast.ImportFrom))
        for node in functions
        for child in ast.walk(node)
    )
