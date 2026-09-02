"""Phase 10: binary helper failures must not silently fail open to suspicious hits."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from Virus_Scan.scanners.binary_behavior_predicates import _xor_blob_signal
from Virus_Scan.scanners.binary_embedded_payloads import validated_embedded_payload_hits
from Virus_Scan.scanners.binary_text_signals import binary_regex_match


class _BadBytesLike:
    def __len__(self):
        return 1024

    def __getitem__(self, _item):
        raise TypeError("synthetic binary slice failure")


def _except_blocks(path: str) -> list[str]:
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    lines = source.splitlines()
    blocks: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            blocks.append("\n".join(lines[node.lineno - 1:getattr(node, "end_lineno", node.lineno)]))
    return blocks


def test_binary_predicate_recoverable_failure_is_visible_not_defaulted():
    with pytest.raises(TypeError):
        _xor_blob_signal(_BadBytesLike())


def test_binary_regex_type_failure_is_visible_not_defaulted():
    with pytest.raises(TypeError):
        binary_regex_match("abc", object())


def test_embedded_payload_validator_has_no_fail_open_exception_return():
    blocks = _except_blocks("Virus_Scan/scanners/binary_embedded_payloads.py")
    assert all("return True" not in block for block in blocks)


def test_embedded_payload_validator_still_detects_valid_embedded_pe():
    sample = bytearray(b"A" * 64)
    sample.extend(b"MZ")
    sample.extend(b"\x00" * 58)
    sample.extend((0x40).to_bytes(4, "little"))
    sample.extend(b"PE\x00\x00")
    assert validated_embedded_payload_hits(bytes(sample), min_offset=32) == [(64, "embedded_pe_signature")]
