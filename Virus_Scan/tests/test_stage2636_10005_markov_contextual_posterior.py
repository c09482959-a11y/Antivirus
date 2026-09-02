"""Stage2636.01 contextual Markov posterior and persistence acceptance tests."""
from __future__ import annotations
from Virus_Scan.tests.support.runtime_model_state import current_runtime_model_record

import ast
from collections import Counter, defaultdict
import math
import pytest
from pathlib import Path

from Virus_Scan.models import markov
from Virus_Scan.contracts.markov_learning import (
    MARKOV_STATE_SCHEMA_VERSION,
    markov_context_levels,
    markov_context_support_key,
    markov_event_transition_key,
    markov_event_vocabulary_key,
    markov_global_context_key,
    markov_stage_transition_key,
    markov_stage_vocabulary_key,
)
from Virus_Scan.models.contracts.probability_record import materialize_probability_record
from Virus_Scan.runtime.model_state import (
    configure_runtime_model_state,
    load_runtime_model_baselines,
    runtime_model_snapshot,
    runtime_transition_counter_snapshot,
    runtime_transition_key_to_json,
)
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision

_TRAINING_CONTEXT = (("learning_baseline_key", "renpy/.test"),)
_ENGINE_FALLBACK_CONTEXT = (("learning_baseline_key", "renpy/.other"),)
_GLOBAL_FALLBACK_CONTEXT = (("learning_baseline_key", "python/.other"),)


def _reset() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def _learn(
    previous_stage: str,
    flow: tuple[str, ...],
    current_stage: str,
    *,
    count: int,
    prefix: str,
    engine: str = "renpy",
) -> None:
    for ordinal in range(count):
        result = markov.update_markov_model(
            previous_stage,
            flow,
            current_stage,
            learning_decision=accepted_learning_decision(
                engine=engine,
                target_names=("markov",),
                observation_id=f"{prefix}:{ordinal}",
            ),
        )
        assert result["learned"] is True


def test_previous_stage_is_part_of_event_transition_identity() -> None:
    _reset()
    _learn("asset", ("download", "exec"), "runtime", count=3, prefix="asset")
    _learn("archive", ("download", "network"), "runtime", count=3, prefix="archive")

    asset = markov.markov_pair_probability("download", "exec", prev_stage="asset")
    archive = markov.markov_pair_probability("download", "exec", prev_stage="archive")

    assert asset["ready"] is True
    assert archive["ready"] is True
    assert asset["support"] == archive["support"] == 3
    assert asset["count"] == 3
    assert archive["count"] == 0
    assert asset["probability"] > archive["probability"]

    context = markov_global_context_key()
    asset_key = markov_event_transition_key(
        context_key=context, previous_stage="asset", source_event="download",
    )
    archive_key = markov_event_transition_key(
        context_key=context, previous_stage="archive", source_event="download",
    )
    assert runtime_transition_counter_snapshot(asset_key) == {"exec": 3}
    assert runtime_transition_counter_snapshot(archive_key) == {"network": 3}


def test_jeffreys_posterior_seen_and_unseen_targets_are_bounded() -> None:
    _reset()
    _learn("asset", ("download", "exec"), "runtime", count=3, prefix="posterior")

    seen = markov.markov_pair_probability("download", "exec", prev_stage="asset")
    unseen = markov.markov_pair_probability("download", "network", prev_stage="asset")

    assert seen["smoothing"] == "jeffreys_dirichlet"
    assert seen["alpha"] == 0.5
    assert seen["unseen_bucket_count"] == 1
    assert seen["support"] == 3
    assert seen["count"] == 3
    assert seen["vocab"] == 3
    assert math.isclose(seen["probability"], 3.5 / 4.5)
    assert unseen["ready"] is True
    assert unseen["count"] == 0
    assert math.isclose(unseen["probability"], 0.5 / 4.5)
    assert 0.0 < unseen["probability"] < seen["probability"] < 1.0


def test_one_observation_never_publishes_certainty_or_ready_anomaly() -> None:
    _reset()
    _learn("asset", ("download", "exec"), "runtime", count=1, prefix="one-shot")

    pair = markov.markov_pair_probability("download", "exec", prev_stage="asset")
    features = markov.compute_markov_features("asset", ("download", "exec"), "runtime")

    assert pair["ready"] is False
    assert pair["probability"] is None
    assert pair["support"] == pair["count"] == 1
    assert pair["reason"] == "insufficient_markov_pair_support"
    assert features["ready"] is False
    assert features["sequence_anomaly"] == 0.0
    assert features["confidence"] == 0.0


def test_source_conditioned_support_is_not_global_transition_support() -> None:
    _reset()
    _learn("asset", ("download", "exec"), "runtime", count=3, prefix="source-a")
    _learn("asset", ("decode", "exec"), "runtime", count=3, prefix="source-b")

    download = markov.markov_pair_probability("download", "exec", prev_stage="asset")
    decode = markov.markov_pair_probability("decode", "exec", prev_stage="asset")

    assert download["support"] == 3
    assert decode["support"] == 3
    assert download["context_support"] == decode["context_support"] == 6


def test_context_fallback_order_and_confidence_reduction_are_deterministic() -> None:
    _reset()
    _learn("asset", ("download", "exec"), "runtime", count=3, prefix="fallback")

    exact = markov.markov_pair_probability(
        "download", "exec", prev_stage="asset",
        context_identity=_TRAINING_CONTEXT, engine="renpy",
    )
    engine = markov.markov_pair_probability(
        "download", "exec", prev_stage="asset",
        context_identity=_ENGINE_FALLBACK_CONTEXT, engine="renpy",
    )
    global_record = markov.markov_pair_probability(
        "download", "exec", prev_stage="asset",
        context_identity=_GLOBAL_FALLBACK_CONTEXT, engine="python",
    )

    assert exact["fallback_level"] == "exact"
    assert engine["fallback_level"] == "engine"
    assert global_record["fallback_level"] == "global"
    assert exact["support"] == engine["support"] == global_record["support"] == 3
    assert exact["fallback_confidence"] > engine["fallback_confidence"] > global_record["fallback_confidence"] > 0.0
    assert exact == markov.markov_pair_probability(
        "download", "exec", prev_stage="asset",
        context_identity=_TRAINING_CONTEXT, engine="renpy",
    )


def test_corrupted_counter_is_unavailable_not_suspicious() -> None:
    _reset()
    context = markov_global_context_key()
    event_key = markov_event_transition_key(
        context_key=context, previous_stage="asset", source_event="download",
    )
    snapshot = {
        event_key: {"exec": float("nan")},
        markov_event_vocabulary_key(context): {"download": 1, "exec": 1},
        markov_context_support_key(context): {"observations": 3},
    }

    record = markov.markov_pair_probability(
        "download", "exec", prev_stage="asset", snapshot=snapshot,
    )

    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "non_finite_markov_count"


def test_persisted_and_reloaded_probability_evidence_is_identical() -> None:
    _reset()
    _learn("asset", ("download", "exec"), "runtime", count=3, prefix="reload")
    before = materialize_probability_record(
        markov.markov_sequence_probability(
            "asset", ("download", "exec"), "runtime",
            context_identity=_TRAINING_CONTEXT, engine="renpy",
        )
    )
    snapshot = runtime_model_snapshot(
        markov_key_to_json=runtime_transition_key_to_json,
        cluster_state_to_json=lambda: {},
    )

    assert snapshot["markov_state_schema_version"] == MARKOV_STATE_SCHEMA_VERSION
    assert snapshot["markov_state_migration_evidence"] == "canonical_initial_contextual_state"
    _reset()
    loaded = load_runtime_model_baselines(snapshot)
    after = materialize_probability_record(
        markov.markov_sequence_probability(
            "asset", ("download", "exec"), "runtime",
            context_identity=_TRAINING_CONTEXT, engine="renpy",
        )
    )

    assert loaded["loaded"] is True
    assert loaded["reason"] is None
    assert before == after


def test_legacy_transition_row_is_rejected_atomically() -> None:
    _reset()
    _learn("asset", ("download", "exec"), "runtime", count=3, prefix="atomic")
    before = materialize_probability_record(
        markov.markov_pair_probability("download", "exec", prev_stage="asset")
    )

    loaded = load_runtime_model_baselines(current_runtime_model_record({
        "transition_counts": [
            {"type": "behavior_event", "source": "download", "target": "exec", "count": 99},
        ],
    }))
    after = materialize_probability_record(
        markov.markov_pair_probability("download", "exec", prev_stage="asset")
    )

    assert loaded["loaded"] is False
    assert loaded["reason"] == "invalid_runtime_transition_type"
    assert loaded["records_loaded"] == 0
    assert before == after


def test_markov_owner_contains_no_known_chain_policy_or_private_chain_import() -> None:
    imports: set[str] = set()
    source = ""
    for path in Path("Virus_Scan/models/markov").glob("*.py"):
        text = path.read_text(encoding="utf-8")
        source += "\n" + text
        tree = ast.parse(text, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)
            elif isinstance(node, ast.Import):
                imports.update(alias.name for alias in node.names)

    assert not any(module.startswith("Virus_Scan.detection.chains") for module in imports)
    assert "decode->exec" not in source
    assert "download->exec" not in source
    assert "known_suspicious_sequence" not in source


def test_runtime_state_exports_only_decision_bound_markov_commit() -> None:
    from Virus_Scan.runtime import model_state

    assert "commit_markov_update_request" in model_state.__all__
    assert "increment_contextual_markov_request" not in model_state.__all__
    assert "increment_global_behavior_flow" not in model_state.__all__
    assert not hasattr(model_state, "increment_contextual_markov_request")
    assert not hasattr(model_state, "increment_global_behavior_flow")
    with pytest.raises(TypeError, match="markov update request required"):
        model_state.commit_markov_update_request({})



def test_average_surprisal_matches_full_flow_geometric_posterior() -> None:
    _reset()
    _learn("asset", ("download", "exec"), "runtime", count=3, prefix="surprisal")

    sequence = markov.markov_sequence_probability(
        "asset", ("download", "exec"), "runtime",
        context_identity=_TRAINING_CONTEXT, engine="renpy",
    )
    features = markov.compute_markov_features(
        "asset", ("download", "exec"), "runtime",
        context_identity=_TRAINING_CONTEXT, engine="renpy",
    )

    assert sequence["ready"] is True
    assert features["ready"] is True
    assert math.isclose(
        features["average_surprisal"],
        -math.log(float(sequence["probability"])),
        rel_tol=1e-12,
        abs_tol=1e-12,
    )
    assert features["supported_transitions"] == 2
    assert features["unavailable_transitions"] == 0


def test_sequence_fallback_level_and_context_key_share_worst_record() -> None:
    _reset()
    levels = markov_context_levels(
        engine="renpy", context_identity=_TRAINING_CONTEXT,
    )
    exact_context = levels[0][1]
    engine_context = levels[1][1]
    flow = ("download", "exec")
    snapshot = {
        markov_stage_transition_key(
            context_key=exact_context,
            previous_stage="asset",
            behavior_flow=flow,
        ): {"runtime": 3},
        markov_stage_vocabulary_key(exact_context): {"runtime": 1},
        markov_context_support_key(exact_context): {"observations": 3},
        markov_event_transition_key(
            context_key=engine_context,
            previous_stage="asset",
            source_event="download",
        ): {"exec": 3},
        markov_event_vocabulary_key(engine_context): {
            "download": 1,
            "exec": 1,
        },
        markov_context_support_key(engine_context): {"observations": 3},
    }

    stage = markov.markov_stage_probability(
        "asset", flow, "runtime",
        context_identity=_TRAINING_CONTEXT, engine="renpy", snapshot=snapshot,
    )
    pair = markov.markov_pair_probability(
        "download", "exec", prev_stage="asset",
        context_identity=_TRAINING_CONTEXT, engine="renpy", snapshot=snapshot,
    )
    sequence = markov.markov_sequence_probability(
        "asset", flow, "runtime",
        context_identity=_TRAINING_CONTEXT, engine="renpy", snapshot=snapshot,
    )

    assert stage["fallback_level"] == "exact"
    assert stage["context_key"] == exact_context
    assert pair["fallback_level"] == "engine"
    assert pair["context_key"] == engine_context
    assert sequence["ready"] is True
    assert sequence["fallback_level"] == "engine"
    assert sequence["context_key"] == engine_context
