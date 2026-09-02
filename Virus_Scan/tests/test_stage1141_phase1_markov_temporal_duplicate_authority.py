from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

import ast
from collections import Counter, defaultdict
from pathlib import Path

from Virus_Scan.models import markov
from Virus_Scan.models.temporal.anomaly import temporal_pair_anomaly
from Virus_Scan.runtime.model_state import configure_runtime_model_state

MARKOV_FEATURES = Path("Virus_Scan/models/markov/features.py")
TEMPORAL_ANOMALY = Path("Virus_Scan/models/temporal/anomaly.py")


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1141_markov_no_longer_defines_temporal_named_anomaly_authority() -> None:
    tree = ast.parse(MARKOV_FEATURES.read_text(encoding="utf-8"), filename=str(MARKOV_FEATURES))
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    assert "temporal_pair_anomaly" not in function_names
    assert "tag_pair_anomaly" in function_names


def test_stage1141temporal_pair_anomaly_consumes_canonical_markov_public_contract() -> None:
    temporal_source = TEMPORAL_ANOMALY.read_text(encoding="utf-8")
    tree = ast.parse(temporal_source, filename=str(TEMPORAL_ANOMALY))
    helper = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "temporal_pair_anomaly"
    )
    helper_source = ast.get_source_segment(temporal_source, helper) or ""

    assert "tag_pair_anomaly" in helper_source
    assert "runtime_model_mapping_snapshot" not in helper_source
    assert "runtime_transition_counter_snapshot" not in helper_source


def test_stage1141_markov_pair_anomaly_behavior_is_preserved_after_duplicate_removal() -> None:
    _reset_markov_state()
    flow = ["download", "exec"]

    for _ in range(5):
        assert markov.update_markov_model("asset", flow, "runtime", learning_decision=accepted_learning_decision(target_names=("markov",), observation_id=f"stage1141-markov-{_}"))["learned"] is True

    markov_score = markov.tag_pair_anomaly(flow, prev_stage="asset")
    assert 0.0 < markov_score < 1.0
    assert temporal_pair_anomaly("asset", flow) == markov_score
