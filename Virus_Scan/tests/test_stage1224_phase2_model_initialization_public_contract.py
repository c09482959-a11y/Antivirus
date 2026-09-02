from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan import models as model_root
from Virus_Scan.models.api import init_contracts
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES


def _module_imports(path: str) -> list[tuple[str, str]]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imports.append((node.module or "", ",".join(alias.name for alias in node.names)))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imports.append((alias.name, ""))
    return imports


def test_stage1224_runtime_top_level_uses_model_initialization_public_contract() -> None:
    imports = _module_imports("Virus_Scan/init_runtime/top_level.py")

    assert (
        "Virus_Scan.models.api.init_contracts",
        "initialize_models",
    ) in imports
    assert not any(module == "Virus_Scan.models" for module, _names in imports)


def test_stage1224_model_root_no_longer_exports_initialization_owner() -> None:
    tree = parse_python_file(Path("Virus_Scan/models/__init__.py"))

    assert not any(
        isinstance(node, ast.FunctionDef) and node.name == "initialize_models"
        for node in tree.body
    )
    assert model_root.__all__ == ()


def test_stage1224_public_model_initialization_contract_preserves_order_and_manifest() -> None:
    tree = parse_python_file(Path("Virus_Scan/models/api/init_contracts.py"))
    initialize = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "initialize_models"
    )
    calls = [
        call.func.id
        for call in ast.walk(initialize)
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
    ]

    assert calls[:3] == ["init_profiles", "init_model_defaults", "init_state_snapshot"]
    assert init_contracts.__all__ == ("initialize_models",)
    assert "Virus_Scan.models.api.init_contracts" in MODEL_BOOTSTRAP_MODULE_NAMES
