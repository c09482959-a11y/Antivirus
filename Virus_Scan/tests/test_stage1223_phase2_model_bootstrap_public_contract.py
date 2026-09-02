"""Stage 1223 Phase 2 regression tests for model bootstrap boundaries."""
from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES
from Virus_Scan.orchestration import bootstrap_initialization


def _import_modules(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
        elif isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
    return tuple(modules)


def test_stage1223_orchestration_bootstrap_uses_public_model_bootstrap_contract_only() -> None:
    model_imports = tuple(
        module
        for module in _import_modules(Path("Virus_Scan/orchestration/bootstrap_initialization.py"))
        if module.startswith("Virus_Scan.models")
    )
    assert model_imports == ("Virus_Scan.models.api",)


def test_stage1223_model_bootstrap_contract_publishes_immutable_module_names() -> None:
    assert isinstance(MODEL_BOOTSTRAP_MODULE_NAMES, tuple)
    assert MODEL_BOOTSTRAP_MODULE_NAMES == tuple(sorted(MODEL_BOOTSTRAP_MODULE_NAMES))
    assert "Virus_Scan.models.markov.api" in MODEL_BOOTSTRAP_MODULE_NAMES
    assert "Virus_Scan.models.profiles" in MODEL_BOOTSTRAP_MODULE_NAMES
    assert "Virus_Scan.models.temporal" in MODEL_BOOTSTRAP_MODULE_NAMES
    assert all(isinstance(name, str) for name in MODEL_BOOTSTRAP_MODULE_NAMES)


def test_stage1223_bootstrap_manifest_still_contains_model_modules() -> None:
    names = bootstrap_initialization._BOOTSTRAP_REGISTRATION_MODULE_NAMES
    assert "Virus_Scan.models.api.bootstrap_registration" in names
    for model_module_name in MODEL_BOOTSTRAP_MODULE_NAMES:
        assert model_module_name in names
