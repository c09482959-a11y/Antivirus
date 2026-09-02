"""Phase 10: binary scalar helpers must not hide helper failures as clean output."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.binary_entropy_helpers import entropy_from_counts, shannon_entropy_bytes
from Virus_Scan.scanners.binary_numeric import safe_clamp


def test_binary_entropy_helpers_are_non_negative_and_scanner_owned():
    assert shannon_entropy_bytes(b"AAAA") == 0.0
    assert entropy_from_counts([4], 4) == 0.0
    assert shannon_entropy_bytes(b"ABCD") >= 0.0


def test_binary_safe_clamp_bounds_scores():
    assert safe_clamp(-5) == 0.0
    assert safe_clamp(5) == 1.0
    assert safe_clamp(0.25) == 0.25


def test_binary_helper_modules_have_no_clean_default_exception_blocks():
    for rel in [
        "Virus_Scan/scanners/binary_entropy_helpers.py",
        "Virus_Scan/scanners/binary_numeric.py",
        "Virus_Scan/scanners/binary_pe_evidence.py",
    ]:
        source = Path(rel).read_text(encoding="utf-8")
        tree = ast.parse(source)
        lines = source.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                block = "\n".join(lines[node.lineno - 1:getattr(node, "end_lineno", node.lineno)])
                assert "return 0.0" not in block
                assert "pass" not in block
