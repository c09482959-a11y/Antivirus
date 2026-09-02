from __future__ import annotations

import ast
from pathlib import Path

from Virus_Scan.models import markov
from Virus_Scan.models.temporal.anomaly import temporal_stage_sequence_anomaly

TEMPORAL_MODEL = Path("Virus_Scan/models/temporal/anomaly.py")


def _helper_source(name: str) -> str:
    source = TEMPORAL_MODEL.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(TEMPORAL_MODEL))
    helper = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    return ast.get_source_segment(source, helper) or ""


def test_stage1185_temporal_stage_sequence_helper_has_no_local_zero_stub() -> None:
    helper_source = _helper_source("temporal_stage_sequence_anomaly")

    assert "return 0.0" not in helper_source
    assert "markov_transition_score" in helper_source
    assert "len(combined_flow) < 2" not in helper_source


def test_stage1185_temporal_delegates_insufficient_flow_to_markov_owner() -> None:
    assert temporal_stage_sequence_anomaly("asset", [], "runtime", []) == markov.markov_transition_score("asset", [], "runtime")
    assert temporal_stage_sequence_anomaly("asset", ["download"], "runtime", []) == markov.markov_transition_score("asset", ["download"], "runtime")
