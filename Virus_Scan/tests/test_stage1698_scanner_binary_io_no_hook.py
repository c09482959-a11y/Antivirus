from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

import pytest

from Virus_Scan.scanners.binary_io import binary_string_evidence_tags, read_binary_file_bytes


class HostilePath:
    touched = 0

    def __fspath__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not fspath")

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileLimit:
    touched = 0

    def __int__(self) -> int:
        type(self).touched += 1
        raise RuntimeError("do not int")

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileStringBlob:
    touched = 0

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("do not bool")

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("do not repr")

    def __format__(self, spec: str) -> str:
        type(self).touched += 1
        raise RuntimeError("do not format")


def test_read_binary_file_bytes_rejects_hostile_path_without_fspath_str_or_repr() -> None:
    HostilePath.touched = 0

    with pytest.raises(TypeError):
        read_binary_file_bytes(HostilePath(), max_size=2)

    assert HostilePath.touched == 0


def test_read_binary_file_bytes_rejects_hostile_limit_without_int_bool_or_repr(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abcdef")
    HostileLimit.touched = 0

    with pytest.raises(TypeError):
        read_binary_file_bytes(sample, max_size=HostileLimit())

    assert HostileLimit.touched == 0


def test_read_binary_file_bytes_preserves_exact_limits_and_negative_read_all(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abcdef")

    assert read_binary_file_bytes(sample, max_size=2) == b"ab"
    assert read_binary_file_bytes(sample, max_size=0) == b""
    assert read_binary_file_bytes(sample, max_size=-1) == b"abcdef"
    assert read_binary_file_bytes(sample, max_size=None) == b"abcdef"


def test_binary_string_evidence_rejects_hostile_blob_without_string_hooks() -> None:
    HostileStringBlob.touched = 0

    tags = binary_string_evidence_tags(HostileStringBlob())

    assert HostileStringBlob.touched == 0
    assert "binary_string_input_rejected" in tags
    assert "binary_final_json_must_record" in tags
    assert "scanner_failure_evidence:binary:binary_string_evidence" in tags


def test_binary_string_evidence_preserves_exact_text_detection() -> None:
    tags = binary_string_evidence_tags("PowerShell -EncodedCommand AAAA DownloadString http://x")

    assert "powershell_exec" in tags
    assert "encoded_powershell" in tags
    assert "network_download" in tags
    assert "download_observable" in tags


def test_binary_io_module_blocks_raw_boundary_conversions() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/binary_io.py"))
    tree = ast.parse(source)
    raw_calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in {"str", "int"}:
            raw_calls.append((node.func.id, node.lineno))
        if isinstance(node.func, ast.Name) and node.func.id == "Path":
            if node.args and not (isinstance(node.args[0], ast.Name) and node.args[0].id == "path_text"):
                raw_calls.append(("Path", node.lineno))
    assert raw_calls == []
    assert "str('' if data is None else data)" not in source
    assert "int(max_size)" not in source
    assert "Path(path)" not in source
