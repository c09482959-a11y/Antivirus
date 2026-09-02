
"""Stage 900 Phase 10 binary filetype policy ownership tests."""
from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.scanners import binary_filetype
from Virus_Scan.scanners.api.filetype_policy_contracts import ENGINE_SPECIFIC_FILETYPE_BUCKETS


def test_binary_filetype_no_longer_imports_model_profile_defaults() -> None:
    source = read_python_file(Path("Virus_Scan/scanners/binary_filetype.py"))
    tree = ast.parse(source)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    assert "Virus_Scan.models.profiles" not in imported_modules
    assert not any(module.startswith("Virus_Scan.detection") for module in imported_modules)


def test_scanner_known_engines_are_scanner_filetype_policy_owned() -> None:
    expected = frozenset(ENGINE_SPECIFIC_FILETYPE_BUCKETS) | {"media", "other"}
    assert binary_filetype.SCANNER_KNOWN_ENGINES == expected
    assert "renpy" in binary_filetype.SCANNER_KNOWN_ENGINES
    assert "rpgm" in binary_filetype.SCANNER_KNOWN_ENGINES
    assert "unity" in binary_filetype.SCANNER_KNOWN_ENGINES


def test_get_engine_filetype_info_normalizes_unknown_engine_without_profile_dependency() -> None:
    known = binary_filetype.get_engine_filetype_info("RenPy", "game/script.rpy")
    assert known["bucket"] != "unknown_engine"
    assert known["extension"] == "rpy"

    media = binary_filetype.get_engine_filetype_info("media", "assets/movie.webm")
    assert media["bucket"] == "unknown_engine"
    assert media["extension"] == "webm"

    unknown = binary_filetype.get_engine_filetype_info("not-an-engine", "payload.exe")
    assert unknown == {
        "bucket": "unknown_engine",
        "extension": "exe",
        "execution_capability": "unknown",
        "normal_buckets": set(),
        "rare_buckets": set(),
        "high_risk_buckets": set(),
    }
