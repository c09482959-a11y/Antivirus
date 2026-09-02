from __future__ import annotations
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

from collections import Counter, defaultdict

from Virus_Scan.models import markov
from Virus_Scan.models.temporal.overlay import temporal_markov_overlay_support
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    runtime_model_snapshot,
    runtime_transition_key_to_json,
)


def _reset_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def _empty_cluster_state() -> dict[str, object]:
    return {}


def test_stage1187_markov_public_probability_records_distinguish_cold_start_from_zero_probability() -> None:
    _reset_state()

    cold_pair = markov.markov_pair_probability("download", "exec", prev_stage="asset")
    cold_stage = markov.markov_stage_probability("asset", ["download", "exec"], "runtime")
    cold_sequence = markov.markov_sequence_probability("asset", ["download", "exec"], "runtime")

    for record in (cold_pair, cold_stage, cold_sequence):
        assert record["ready"] is False
        assert record["probability"] is None
        assert record["support"] == 0
        assert record["reason"]
        assert record["smoothing"] == "jeffreys_dirichlet"

    for _ in range(3):
        assert markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",), observation_id=f"stage1187-probability-{_}"))["learned"] is True

    trained_pair = markov.markov_pair_probability("download", "exec", prev_stage="asset")
    trained_stage = markov.markov_stage_probability("asset", ["download", "exec"], "runtime")
    trained_sequence = markov.markov_sequence_probability("asset", ["download", "exec"], "runtime")

    assert trained_pair["ready"] is True
    assert trained_pair["probability"] == 0.7777777777777778
    assert trained_pair["support"] == 3
    assert trained_pair["count"] == 3
    assert trained_pair["vocab"] == 3
    assert trained_pair["smoothing"] == "jeffreys_dirichlet"
    assert trained_pair["alpha"] == 0.5
    assert trained_pair["unseen_bucket_count"] == 1
    assert trained_pair["model_version"] == "markov_contextual_dirichlet_v2"
    assert trained_stage["ready"] is True
    assert trained_stage["probability"] == 0.875
    assert trained_stage["support"] == 3
    assert trained_stage["count"] == 3
    assert trained_stage["flow"] == ("download", "exec")
    assert trained_sequence["model_version"] == "markov_sequence_contextual_dirichlet_v2"


def test_stage1187_temporal_overlay_consumes_markov_probability_records_without_duplicate_support_math() -> None:
    _reset_state()
    for _ in range(3):
        markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",), observation_id=f"stage1187-overlay-{_}"))

    support = temporal_markov_overlay_support("asset", ["download", "exec"], "runtime")

    assert support["ready"] is True
    assert support["stage_probability_record"]["probability"] == 0.875
    assert "stage_probability" not in support
    assert support["stage_probability_record"]["model_version"] == "markov_contextual_dirichlet_v2"
    assert support["sequence_probability_record"]["model_version"] == "markov_sequence_contextual_dirichlet_v2"
    assert support["pair_probability_records"][0]["probability"] == 0.7777777777777778


def test_stage1187_runtime_model_snapshot_materialization_is_order_stable() -> None:
    _reset_state()
    markov.update_markov_model("asset", ["network", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))
    markov.update_markov_model("asset", ["download", "exec"], "runtime", learning_decision=accepted_learning_decision(target_names=("markov",)))
    markov.update_markov_model("asset", ["download", "exec"], "archive", learning_decision=accepted_learning_decision(target_names=("markov",)))

    first = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=_empty_cluster_state,
    )
    second = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=_empty_cluster_state,
    )

    assert first == second
    assert isinstance(first["updated"], int)
    assert first["updated"] > 0
    assert first["transition_counts"] == sorted(
        first["transition_counts"],
        key=lambda row: (row.get("type", ""), repr(row.get("flow", row.get("event", ""))), row.get("target", "")),
    )
    assert first["global_tag_pair_baseline"] == sorted(
        first["global_tag_pair_baseline"],
        key=lambda row: (row["a"], row["b"]),
    )
