from __future__ import annotations

from collections import Counter, defaultdict

from Virus_Scan.models import temporal
from Virus_Scan.models.api import markov_contracts, temporal_contracts
from Virus_Scan.runtime.model_state import configure_runtime_model_state
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def _events() -> list[dict[str, object]]:
    return [
        {"tag": "download", "timestamp": 10.0, "stage": "asset"},
        {"tag": "exec", "timestamp": 15.0, "stage": "runtime"},
    ]


def test_stage1391_temporal_public_contract_exposes_probability_overlay() -> None:
    assert "transition_probability_overlay" in temporal_contracts.__all__
    assert callable(temporal_contracts.transition_probability_overlay)


def test_stage1391_temporal_public_overlay_preserves_canonical_evidence() -> None:
    _reset_markov_state()
    for index in range(3):
        markov_contracts.update_markov_model(
            "asset", ["download", "exec"], "runtime",
            learning_decision=accepted_learning_decision(
                target_names=("markov",), observation_id=f"stage1391-markov-{index}",
            ),
        )

    direct = temporal.transition_probability_overlay(
        prev_stage="asset", tags=["download", "exec"], curr_stage="runtime",
        ordered_events=_events(),
    )
    public = temporal_contracts.transition_probability_overlay(
        prev_stage="asset", tags=["download", "exec"], curr_stage="runtime",
        ordered_events=_events(),
    )

    assert public == direct
    assert public["schema_version"] == "5.0"
    assert public["probability_ready"] is True
    assert public["stage_probability_ready"] is True
    assert public["unavailable_reason"] is None
    assert public["observed_time_evidence"]["reference_timestamp"] == 15.0
    assert all(event["schema_version"] == "temporal_event_v5" for event in public["events"])


def test_stage1391_temporal_public_overlay_cold_start_and_invalid_time_are_explicit() -> None:
    _reset_markov_state()

    public = temporal_contracts.transition_probability_overlay(
        prev_stage="asset", tags=["download", "exec"], curr_stage="runtime",
        ordered_events=[
            {"tag": "download", "timestamp": float("nan"), "stage": "asset"},
            {"tag": "exec", "timestamp": "bad", "stage": "runtime"},
        ],
    )

    assert public["probability_ready"] is False
    assert public["stage_probability"] is None
    assert public["stage_probability_ready"] is False
    assert public["degraded"] is True
    assert public["unavailable_reason"] in {
        "temporal_timestamp_non_finite", "temporal_timestamp_non_numeric",
    }
    assert public["pair_probabilities"]
    assert public["pair_probabilities"][0]["reason"] == "insufficient_markov_pair_support"
    assert public["observed_time_evidence"]["ready"] is False
