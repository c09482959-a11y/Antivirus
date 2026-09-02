
"""Stage 892 Phase 10 strict-fast entropy canonical ownership tests."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners import binary
from Virus_Scan.scanners import binary_resources
from Virus_Scan.scanners import binary_strict_fast
from Virus_Scan.scanners import entropy
from Virus_Scan.scanners.api import entropy_contracts
from Virus_Scan.scanners.api import public_contracts


def test_binary_strict_fast_uses_entropy_owned_strict_fast_entropy() -> None:
    """The strict-fast entropy helper has one scanner-owned implementation."""
    assert binary_strict_fast._strict_fast_entropy is entropy._strict_fast_entropy
    assert binary_resources._strict_fast_entropy is entropy._strict_fast_entropy
    assert not hasattr(binary, "_strict_fast_entropy")
    assert entropy_contracts.strict_fast_entropy is entropy._strict_fast_entropy
    assert public_contracts.strict_fast_entropy is entropy._strict_fast_entropy


def test_binary_strict_fast_does_not_redefine_strict_fast_entropy() -> None:
    tree = parse_python_file(Path("Virus_Scan/scanners/binary_strict_fast.py"))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    assert "_strict_fast_entropy" not in function_names


def test_canonical_strict_fast_entropy_runtime_values_are_preserved() -> None:
    assert entropy._strict_fast_entropy(b"") == 0.0
    assert entropy._strict_fast_entropy(b"AAAA") == 0.0
    assert entropy._strict_fast_entropy(bytes(range(256))) > 7.0
