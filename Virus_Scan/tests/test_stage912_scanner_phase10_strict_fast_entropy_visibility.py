
"""Stage 912 Phase 10: strict-fast entropy must not hide helper failures."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

import pytest

from Virus_Scan.scanners import entropy


class _BadEntropyInput:
    def __bool__(self):
        return True

    def __iter__(self):
        raise ValueError("entropy iterator failed")


def test_strict_fast_entropy_still_scores_valid_bytes():
    assert entropy._strict_fast_entropy(b"") == 0.0
    assert entropy._strict_fast_entropy(b"AAAA") == 0.0
    assert entropy._strict_fast_entropy(bytes(range(256))) > 7.0


def test_strict_fast_entropy_does_not_convert_helper_failure_to_high_entropy_default():
    with pytest.raises(TypeError, match="unsupported scanner entropy bytes"):
        entropy._strict_fast_entropy(_BadEntropyInput())


def test_strict_fast_entropy_contains_no_exception_default_return():
    source = read_python_file(Path("Virus_Scan/scanners/entropy.py"))
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_strict_fast_entropy":
            assert not any(isinstance(child, ast.ExceptHandler) for child in ast.walk(node))
            return
    raise AssertionError("_strict_fast_entropy not found")
