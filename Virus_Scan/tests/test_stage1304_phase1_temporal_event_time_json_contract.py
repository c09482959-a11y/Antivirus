from __future__ import annotations

from collections import Counter, defaultdict
import json

from Virus_Scan.models import markov, temporal
from Virus_Scan.runtime.model_state import configure_runtime_model_state
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision


def _reset_markov_state() -> None:
    configure_runtime_model_state(
        transition_counts=defaultdict(Counter),
        global_tag_baseline=defaultdict(int),
        global_tag_pair_baseline=defaultdict(int),
        filetype_baseline=defaultdict(Counter),
    )


def _learn(flow: list[str], prefix: str) -> None:
    for index in range(4):
        assert markov.update_markov_model(
            "asset", flow, "runtime",
            learning_decision=accepted_learning_decision(
                target_names=("markov",), observation_id=f"{prefix}-{index}",
            ),
        )["learned"] is True


def test_stage1304_temporal_overlay_rejects_non_finite_timestamps_as_explicit_evidence() -> None:
    _reset_markov_state()
    _learn(["download", "exec", "network"], "stage1304-finite")

    overlay = temporal.transition_probability_overlay(
        prev_stage="asset",
        tags=["download", "exec", "network"],
        curr_stage="runtime",
        ordered_events=[
            {"tag": "download", "timestamp": 100.0, "stage": "asset"},
            {"tag": "exec", "timestamp": float("nan"), "stage": "runtime"},
            {"tag": "network", "timestamp": float("inf"), "stage": "runtime"},
        ],
    )

    assert overlay["probability_ready"] is True
    assert overlay["degraded"] is True
    assert overlay["unavailable_reason"] == "temporal_timestamp_non_finite"
    assert overlay["observed_time_evidence"] == {
        "ready": True,
        "observed_event_count": 1,
        "reference_timestamp": 100.0,
        "order_only_event_count": 2,
    }
    assert overlay["hidden_state"]["last_evidence_timestamp"] == 100.0
    assert [row["timestamp_kind"] for row in overlay["events"]] == [
        "observed", "ordinal_only", "ordinal_only",
    ]
    json.dumps(overlay, sort_keys=True, allow_nan=False)


def test_stage1304_temporal_overlay_rejects_non_numeric_timestamp_as_explicit_evidence() -> None:
    _reset_markov_state()
    _learn(["download", "exec"], "stage1304-text")

    overlay = temporal.transition_probability_overlay(
        prev_stage="asset",
        tags=["download", "exec"],
        curr_stage="runtime",
        ordered_events=[
            {"tag": "download", "timestamp": "bad", "stage": "asset"},
            {"tag": "exec", "timestamp": 2.0, "stage": "runtime"},
        ],
    )

    assert overlay["probability_ready"] is True
    assert overlay["degraded"] is True
    assert overlay["unavailable_reason"] == "temporal_timestamp_non_numeric"
    assert overlay["observed_time_evidence"]["observed_event_count"] == 1
    assert overlay["observed_time_evidence"]["reference_timestamp"] == 2.0
    assert overlay["hidden_state"]["last_evidence_timestamp"] == 2.0
    json.dumps(overlay, sort_keys=True, allow_nan=False)
