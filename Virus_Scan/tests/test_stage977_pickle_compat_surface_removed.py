"""Stage 977 Phase 1 pickle compatibility-surface removal tests."""
from __future__ import annotations

import ast
from pathlib import Path


_REMOVED_SURFACES = (
    Path("Virus_Scan/scanners/pickle/evidence.py"),
    Path("Virus_Scan/scanners/pickle/renpy_pickle.py"),
)


def test_stage977_removed_pickle_compatibility_facades_stay_absent():
    for path in _REMOVED_SURFACES:
        assert not path.exists(), f"removed compatibility facade reappeared: {path}"


def test_stage977_pickle_callers_use_concrete_canonical_owners():
    forbidden = {
        "Virus_Scan.scanners.pickle.evidence",
        "Virus_Scan.scanners.pickle.renpy_pickle",
    }
    for path in (
        Path("Virus_Scan/scanners/pickle/scanner.py"),
        Path("Virus_Scan/scanners/renpy.py"),
    ):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden, f"{path} imports removed compatibility facade {node.module}"
            elif isinstance(node, ast.Import):
                assert all(alias.name not in forbidden for alias in node.names), f"{path} imports removed compatibility facade"
