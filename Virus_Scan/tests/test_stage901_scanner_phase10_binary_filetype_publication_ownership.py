from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.scanners import binary_filetype
from Virus_Scan.scanners.api.filetype_policy_contracts import MAGIC_TYPE_CATEGORY


def _import_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def test_binary_filetype_uses_scanner_owned_policy_not_runtime_model_mutation() -> None:
    modules = _import_modules(Path("Virus_Scan/scanners/binary_filetype.py"))
    assert "Virus_Scan.runtime.model_state" not in modules
    assert "Virus_Scan.core.paths" not in modules
    assert "Virus_Scan.routing.filetype_tables" not in modules


def test_update_filetype_returns_immutable_publication_request() -> None:
    result = binary_filetype.update_filetype("DLL", [" Network ", "", "os_execution"])
    assert result["updated"] is True
    assert result["extension"] == "dll"
    assert result["flow"] == ("network", "os_execution")
    assert result["publication_request"] == {
        "kind": "scanner_filetype_baseline_observation",
        "extension": "dll",
        "flow": ("network", "os_execution"),
    }


def test_empty_update_filetype_does_not_publish_hidden_model_update() -> None:
    result = binary_filetype.update_filetype("dll", [])
    assert result == {"updated": False, "reason": "no_behavior_flow", "publication_request": None}


def test_binary_filetype_magic_categories_come_from_scanner_config() -> None:
    assert MAGIC_TYPE_CATEGORY["pe_mz"] == "binary"
    assert MAGIC_TYPE_CATEGORY["zip"] == "archive"
    assert binary_filetype._actual_filetype_category("pe_mz") == "binary"
    assert binary_filetype._actual_filetype_category("zip") == "archive"
