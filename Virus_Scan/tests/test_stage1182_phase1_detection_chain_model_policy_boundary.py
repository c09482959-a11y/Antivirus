from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

import Virus_Scan.detection.models.chain as chain


def test_detection_chain_does_not_reexport_model_behavior_sequence_policy() -> None:
    assert chain.__all__ == ()
    assert not hasattr(chain, "canonical_behavior_event_name")
    assert not hasattr(chain, "CONTEXT_ONLY_TAGS")
    assert not hasattr(chain, "SEQUENCE_ALLOWED_STRUCTURAL_EXCEPTIONS")


def test_detection_chain_has_no_model_contract_imports_or_policy_exports() -> None:
    tree = parse_python_file(Path("Virus_Scan/detection/models/chain.py"))
    imported_modules = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported_modules.append(node.module or "")
        elif isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)

    assert "Virus_Scan.models.behavior_sequence_contract" not in imported_modules
    assert "Virus_Scan.models" not in imported_modules
    assert all(not module.startswith("Virus_Scan.models.") for module in imported_modules)
