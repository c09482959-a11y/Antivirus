
"""Stage 920 Phase 10: binary ASCII visibility helper failures must stay visible."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

import pytest

from Virus_Scan.scanners.binary_text_signals import binary_ascii_visibility_ratio


class _BadBoolBuffer:
    def __bool__(self):
        raise ValueError("visibility bool failed")


def test_ascii_visibility_failure_raises_instead_of_sentinel() -> None:
    with pytest.raises(ValueError, match="visibility bool failed"):
        binary_ascii_visibility_ratio(_BadBoolBuffer())


def test_ascii_visibility_has_no_hidden_negative_sentinel_exception_path() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/binary_text_signals.py"))
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            block = source.splitlines()[node.lineno - 1:getattr(node, "end_lineno", node.lineno)]
            assert "return -1.0" not in "\n".join(block)
