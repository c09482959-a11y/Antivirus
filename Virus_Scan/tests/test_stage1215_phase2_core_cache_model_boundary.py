from __future__ import annotations

import ast
from pathlib import Path

CORE_CACHE = Path("Virus_Scan/core/cache.py")


def _tree() -> ast.Module:
    return ast.parse(CORE_CACHE.read_text(encoding="utf-8"), filename=str(CORE_CACHE))


def test_stage1215_core_cache_no_longer_imports_model_compute_owners() -> None:
    imports = []
    for node in ast.walk(_tree()):
        if isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
        elif isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)

    assert not [module for module in imports if module.startswith("Virus_Scan.models")]
    assert "Virus_Scan.runtime.graph_state" in imports


def test_stage1215_core_cache_deleted_dead_model_cache_wrappers() -> None:
    function_names = {
        node.name
        for node in ast.walk(_tree())
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    assert "compute_markov_features_cached" not in function_names
    assert "get_graph_risk_cached" not in function_names
    assert "snapshot_temporal_cached" not in function_names


def test_stage1215_bulk_scan_maintenance_uses_runtime_graph_state_owner() -> None:
    source = CORE_CACHE.read_text(encoding="utf-8")

    assert "prune_graph_owned(max_nodes=5000, max_edges_per_node=80)" in source
    assert "prune_graph(" not in source
    assert "snapshot_temporal(" not in source
    assert "compute_markov_features(" not in source
