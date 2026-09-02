from __future__ import annotations
from Virus_Scan.tests.support.static_inventory import read_python_file


import ast
from pathlib import Path

from Virus_Scan.models.temporal import anomaly


def test_stage1453_temporal_anomaly_exports_public_markov_projection_helpers_only():
    assert "temporal_pair_anomaly" in anomaly.__all__
    assert "temporal_stage_sequence_anomaly" in anomaly.__all__
    assert "temporal_known_chain_score" not in anomaly.__all__
    assert not hasattr(anomaly, "_temporal_pair_anomaly")
    assert not hasattr(anomaly, "_temporal_stage_sequence_anomaly")
    assert not hasattr(anomaly, "_temporal_known_chain_score")


def test_stage1453_temporal_state_projection_imports_public_anomaly_owner_names():
    source = read_python_file(Path("Virus_Scan/models/temporal/state_projection.py"))
    tree = ast.parse(source)
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.models.temporal.anomaly" for alias in node.names}
    assert "temporal_pair_anomaly" in imported
    assert "temporal_stage_sequence_anomaly" in imported
    assert "temporal_known_chain_score" not in imported
    chain_imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module == "Virus_Scan.detection.api.chain_evaluation" for alias in node.names}
    assert chain_imports == {"evaluate_chain_evidence"}
    assert not any(name.startswith("_temporal_") for name in imported)
