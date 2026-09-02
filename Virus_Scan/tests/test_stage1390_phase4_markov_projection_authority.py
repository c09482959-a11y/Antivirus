from __future__ import annotations

import ast
from collections import Counter, defaultdict
from pathlib import Path

from Virus_Scan.detection.correlation.multi_signal import model_projections
from Virus_Scan.models.api import markov_contracts
from Virus_Scan.runtime.model_state import configure_runtime_model_state


def _imports_for(path: str) -> set[str]:
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
    return imports


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1390_detection_projection_uses_public_learned_markov_contract_only() -> None:
    path = "Virus_Scan/detection/correlation/multi_signal/model_projections.py"
    source = Path(path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    imports = _imports_for(path)

    assert "_known_suspicious_sequence_score" not in function_names
    assert "Virus_Scan.models.markov" not in imports
    assert "Virus_Scan.models.api.markov_contracts" in imports
    assert "decode->exec" not in source
    assert "download->exec" not in source


def test_stage1390_markov_public_contract_has_no_hard_coded_chain_pattern_api() -> None:
    assert "markov_known_pair_anomaly" not in markov_contracts.__all__
    assert "markov_known_chain_score" not in markov_contracts.__all__
    assert not hasattr(markov_contracts, "markov_known_pair_anomaly")
    assert not hasattr(markov_contracts, "markov_known_chain_score")


def test_stage1390_detection_projection_is_cold_start_neutral_and_learned_only() -> None:
    _reset_markov_state()
    flow = ("download", "exec", "network")
    projected = model_projections.detection_markov_features("asset", flow, "runtime")

    assert projected["flow"] == list(markov_contracts.canonical_behavior_flow(flow))
    assert projected["ready"] is False
    assert projected["pair_anomaly"] == 0.0
    assert projected["sequence_anomaly"] == 0.0
    assert "known_suspicious_sequence" not in projected
    assert projected["reason"] == "insufficient_markov_stage_support"
