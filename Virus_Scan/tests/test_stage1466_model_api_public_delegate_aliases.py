from __future__ import annotations

import ast
from pathlib import Path

MODEL_API_ROOT = Path("Virus_Scan/models/api")


def _module_tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def test_stage1466_model_api_contracts_do_not_import_owner_functions_under_private_aliases() -> None:
    offenders: list[str] = []
    for path in sorted(MODEL_API_ROOT.glob("*_contracts.py")):
        tree = _module_tree(path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            for alias in node.names:
                if alias.asname and alias.asname.startswith("_") and not alias.asname.startswith("__"):
                    offenders.append(f"{path}:{node.lineno}:{alias.name} as {alias.asname}")
    assert offenders == []


def test_stage1466_model_api_contract_delegate_aliases_are_public_owner_names() -> None:
    expected_owner_aliases = {
        "owner_assign_cluster_with_context_tags",
        "owner_compute_graph_relationship_layer",
        "owner_update_temporal",
        "owner_default_engine_profile",
        "owner_replay_should_retain",
    }
    discovered: set[str] = set()
    for path in sorted(MODEL_API_ROOT.glob("*_contracts.py")):
        tree = _module_tree(path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            for alias in node.names:
                if alias.asname:
                    discovered.add(alias.asname)
    assert expected_owner_aliases <= discovered
