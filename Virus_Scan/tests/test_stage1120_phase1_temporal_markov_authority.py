from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

import ast
from collections import Counter, defaultdict
from pathlib import Path

from Virus_Scan.models import markov, temporal
from Virus_Scan.runtime.model_state import configure_runtime_model_state

TEMPORAL_MODEL = Path("Virus_Scan/models/temporal/anomaly.py")


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def test_stage1120_temporal_imports_canonical_markov_owner_instead_of_local_zero_stubs() -> None:
    tree = ast.parse(TEMPORAL_MODEL.read_text(encoding="utf-8"), filename=str(TEMPORAL_MODEL))
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    assert "canonical_behavior_flow" not in functions
    assert "compute_markov_features" not in functions
    assert "mark_runtime_models_dirty" not in functions

    helper_sources = {
        name: ast.get_source_segment(TEMPORAL_MODEL.read_text(encoding="utf-8"), functions[name]) or ""
        for name in ("temporal_pair_anomaly", "temporal_stage_sequence_anomaly")
    }
    assert "return 0.0" not in "\n".join(helper_sources.values())
    assert not hasattr(temporal, "canonical_behavior_flow")
    assert not hasattr(temporal, "compute_markov_features")
    assert not hasattr(markov, "mark_runtime_models_dirty")
    assert not hasattr(temporal, "mark_runtime_models_dirty")
    assert not hasattr(temporal, "temporal_known_chain_score")
    assert not hasattr(markov, "markov_known_chain_score")


def test_stage1120_temporal_overlay_records_markov_support_and_cold_start_reason() -> None:
    _reset_markov_state()

    cold = temporal.transition_probability_overlay(
        prev_stage="asset",
        tags=["download", "exec"],
        curr_stage="runtime",
    )
    assert cold["probability_ready"] is False
    assert cold["stage_probability"] is None
    assert cold["stage_probability_ready"] is False
    assert cold["cold_start_reason"]
    assert cold["pair_probabilities"][0]["probability"] is None

    for _ in range(3):
        assert markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",), observation_id=f"stage1120-markov-{_}"))["learned"] is True

    trained = temporal.transition_probability_overlay(
        prev_stage="asset",
        tags=["download", "exec"],
        curr_stage="runtime",
    )
    assert trained["probability_ready"] is True
    assert trained["stage_probability_ready"] is True
    assert trained["stage_probability_support"] >= 3
    assert 0.0 < trained["stage_probability"] < 1.0
    assert 0.0 < trained["sequence_probability"] < 1.0
    assert trained["cold_start_reason"] is None
    assert trained["pair_probabilities"][0]["ready"] is True
