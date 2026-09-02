from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners.config.loader import load_engine_policy_snapshot, load_filetype_policy_snapshot
from Virus_Scan.scanners.engine_context import infer_engine_context
from Virus_Scan.scanners.api.filetype_policy_contracts import (
    ALL_ROUTABLE_EXTENSIONS,
    EXPECTED_MAGIC_TYPES_BY_EXTENSION,
    MAGIC_TYPE_CATEGORY,
    ROUTABLE_EXTENSIONS_BY_CLAIM,
)


def _import_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_scanner_filetype_init_uses_scanner_owned_policy_not_routing_tables() -> None:
    modules = _import_modules(Path("Virus_Scan/scanners/init_parts/scanner_filetype_defaults_init.py"))
    assert "Virus_Scan.routing.filetype_tables" not in modules
    assert "Virus_Scan.scanners.filetype_policy" in modules
    assert EXPECTED_MAGIC_TYPES_BY_EXTENSION[".png"] == frozenset({"png"})
    assert ".dll" in ROUTABLE_EXTENSIONS_BY_CLAIM["binary"]
    assert ".png" in ALL_ROUTABLE_EXTENSIONS
    assert MAGIC_TYPE_CATEGORY["unity_assetbundle"] == "unity_asset"


def test_filetype_policy_snapshot_owns_routing_magic_tables() -> None:
    snapshot = load_filetype_policy_snapshot()
    assert snapshot.expected_magic_types_by_extension[".rpa"] >= frozenset({"renpy_rpa"})
    assert ".rpa" in snapshot.routable_extensions_by_claim["archive"]
    assert snapshot.all_routable_extensions >= frozenset({".rpa", ".dll", ".png"})


def test_ilspy_uses_scanner_owned_engine_context_not_routing_engine_detect() -> None:
    modules = _import_modules(Path("Virus_Scan/scanners/ilspy.py"))
    assert "Virus_Scan.routing.engine_detect" not in modules
    assert "Virus_Scan.scanners.engine_context" in modules
    policy = load_engine_policy_snapshot()
    assert ".bundle" in policy.engine_file_context_cues["unity"]["extensions"]
    ctx = infer_engine_context(["unity"], file_structure="Game_Data/Managed/Assembly-CSharp.dll", strings_blob="UnityPlayer Assembly-CSharp")
    assert ctx["unity"] > ctx["unknown"]
