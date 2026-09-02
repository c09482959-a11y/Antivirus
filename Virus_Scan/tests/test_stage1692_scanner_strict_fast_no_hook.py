
"""Stage 1692: strict-fast scanner path boundary no-hook validation."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners.binary_strict_fast import _strict_fast_file_is_boring_text


class HostileStrictFastPath:
    touched = 0

    def __bool__(self):
        HostileStrictFastPath.touched += 1
        raise RuntimeError("do not call bool")

    def __str__(self):
        HostileStrictFastPath.touched += 1
        raise RuntimeError("do not call str")

    def __repr__(self):
        HostileStrictFastPath.touched += 1
        raise RuntimeError("do not call repr")

    def __fspath__(self):
        HostileStrictFastPath.touched += 1
        raise RuntimeError("do not call fspath")


def test_strict_fast_rejects_hostile_path_without_str_repr_bool_or_fspath() -> None:
    HostileStrictFastPath.touched = 0

    ok, metadata = _strict_fast_file_is_boring_text(HostileStrictFastPath())

    assert ok is False
    assert HostileStrictFastPath.touched == 0
    assert metadata["extension"] == ""
    assert metadata["binary_strict_fast_failure"] == "path"
    assert metadata["binary_strict_fast_rejection_reason"] == "unsafe_binary_scan_path_rejected"
    assert metadata["scanner_failure"] is True
    assert metadata["scanner_degraded"] is True
    assert metadata["scan_incomplete"] is True
    assert metadata["scanner_failure_evidence_recorded"] is True
    assert metadata["binary_final_json_must_record"] is True


def test_strict_fast_path_boundary_still_accepts_real_path(tmp_path: Path) -> None:
    sample = tmp_path / "note.txt"
    sample.write_text("simple readable scanner note\n", encoding="utf-8")

    ok, metadata = _strict_fast_file_is_boring_text(sample)

    assert ok is True
    assert metadata["extension"] == ".txt"
    assert "binary_strict_fast_failure" not in metadata
    assert "binary_final_json_must_record" not in metadata


def test_strict_fast_module_does_not_materialize_paths_with_hookable_str_or_fspath() -> None:
    tree = parse_python_file(Path("Virus_Scan/scanners/binary_strict_fast.py"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"str", "repr", "format"}
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr != "__fspath__"
