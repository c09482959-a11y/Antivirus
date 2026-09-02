
"""Stage 918 Phase 10: binary numeric helper failures must stay visible."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

import pytest

from Virus_Scan.scanners.binary_numeric import safe_clamp


def test_safe_clamp_preserves_numeric_bounds():
    assert safe_clamp(-10.0) == 0.0
    assert safe_clamp(0.42) == 0.42
    assert safe_clamp(10.0) == 1.0


def test_safe_clamp_does_not_hide_malformed_numeric_input():
    with pytest.raises((TypeError, ValueError)):
        safe_clamp(object())


def test_safe_clamp_has_no_exception_default_fallback():
    source = read_python_file(Path("Virus_Scan/scanners/binary_numeric.py"))
    tree = ast.parse(source)
    assert not any(isinstance(node, ast.ExceptHandler) for node in ast.walk(tree))
