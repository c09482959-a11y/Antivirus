from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import parse_python_file


import ast
from pathlib import Path

from Virus_Scan.detection.api import chains_contracts
from Virus_Scan.runtime.model_state import runtime_model_mapping_snapshot


def test_stage1192_detection_chain_api_does_not_export_markov_transition_counts() -> None:
    assert "TRANSITION_COUNTS" not in chains_contracts.__all__
    assert not hasattr(chains_contracts, "TRANSITION_COUNTS")


def test_stage1192_detection_chain_registry_does_not_own_markov_transition_counts() -> None:
    tree = parse_python_file(Path("Virus_Scan/detection/registries/chain_registry.py"))
    assigned_names = {
        target.id
        for node in tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    assert "TRANSITION_COUNTS" not in assigned_names


def test_stage1192_runtime_model_state_remains_canonical_transition_snapshot_owner() -> None:
    snapshot = runtime_model_mapping_snapshot("TRANSITION_COUNTS")
    assert hasattr(snapshot, "items")
