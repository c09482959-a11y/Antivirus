"""Stage 1511 Phase 1 Markov truthiness-boundary regression tests."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from unittest.mock import patch
from Virus_Scan.models.markov import adaptive as markov_adaptive
from Virus_Scan.models.markov import feature_support as markov_feature_support
from Virus_Scan.models.markov import features as markov_features


class HostileBool:
    def __bool__(self):  # pragma: no cover - failure proves boundary regression
        raise AssertionError("markov boundary truth-tested caller-owned readiness")


class HostileZero(int):
    def __new__(cls) -> "HostileZero":
        return int.__new__(cls, 0)

    def __bool__(self):  # pragma: no cover - failure proves boundary regression
        raise AssertionError("markov boundary truth-tested caller-owned support")


class HostileMapping(dict):
    def __bool__(self):  # pragma: no cover - failure proves boundary regression
        raise AssertionError("markov boundary truth-tested caller-owned mapping")


def test_stage1511_markov_adaptive_signal_does_not_truth_test_ready_or_support() -> None:
    def fake_features(prev_stage: Any, tags: Any, curr_stage: Any) -> Mapping[str, Any]:
        return {
            "ready": HostileBool(),
            "reason": "hostile_ready_boundary",
            "support": HostileZero(),
            "rarity": 0.0,
            "transition": 0.0,
            "pair_anomaly": 0.0,
            "model_version": "stage1511_fake_markov_features",
        }

    with patch.object(markov_adaptive, "compute_markov_features", fake_features):
        signal = markov_adaptive.adaptive_markov_signal("static", "result", ("decode", "exec"))

    assert signal["markov_ready"] is False
    assert signal["markov_support"] == 0
    assert signal["markov_unavailable_reason"] == "hostile_ready_boundary"


def test_stage1511_markov_transition_score_does_not_truth_test_readiness() -> None:
    with patch.object(
        markov_features,
        "markov_stage_probability",
        lambda *args, **kwargs: {
            "ready": HostileBool(),
            "probability": 0.25,
            "reason": "hostile_ready_boundary",
        },
    ):
        assert markov_features.markov_transition_score("static", ("decode", "exec"), "result") == 0.0


def test_stage1511_markov_pair_anomaly_does_not_truth_test_probability_record_ready() -> None:
    with (
        patch.object(
            markov_features,
            "markov_pair_probability",
            lambda *args, **kwargs: {
                "ready": HostileBool(),
                "probability": 0.1,
                "reason": "hostile_ready_boundary",
            },
        ),
    ):
        assert markov_features.tag_pair_anomaly(("decode", "exec")) == 0.0


def test_stage1511_markov_compute_features_does_not_truth_test_probability_mappings() -> None:
    def record(probability: float) -> HostileMapping:
        return HostileMapping({
            "ready": True,
            "probability": probability,
            "reason": None,
            "support": 3,
            "context_support": 3,
            "fallback_level": "global",
            "fallback_confidence": 0.25,
        })

    with (
        patch.object(markov_features, "markov_stage_probability", lambda *args, **kwargs: record(0.8)),
        patch.object(markov_features, "markov_pair_probability", lambda *args, **kwargs: record(0.7)),
        patch.object(markov_features, "markov_sequence_probability", lambda *args, **kwargs: record(0.75)),
        patch.object(markov_feature_support, "runtime_model_mapping_snapshot", lambda _name: {}),
    ):
        bundle = markov_features.compute_markov_features("static", ("decode", "exec"), "result")

    assert bundle["ready"] is False
    assert bundle["reason"] == "insufficient_markov_support"
    assert bundle["support"] == 0
    assert bundle["sequence_anomaly"] == 0.0


from Virus_Scan.publication.model_evidence_projection.safe_mapping import safe_text_present
from Virus_Scan.publication.model_evidence_projection.sources import feature_probability_sources
from Virus_Scan.publication.model_evidence_projection.unavailable_projection import (
    invalid_unavailable_reason_key_reason,
    invalid_unavailable_reason_value_reason,
    sanitize_existing_unavailable_reasons_record,
    unavailable_reasons,
)


class HostileText(str):
    def __str__(self):
        return self

    def strip(self, *args, **kwargs):
        return self

    def __bool__(self):  # pragma: no cover - failure proves boundary regression
        raise AssertionError("publication boundary truth-tested caller-owned text")


def test_stage1511_publication_unavailable_reason_helpers_do_not_truth_test_text() -> None:
    assert invalid_unavailable_reason_key_reason(HostileText("markov")) == ""
    assert invalid_unavailable_reason_value_reason(HostileText("cold_start")) == ""
    assert safe_text_present(HostileText("cold_start")) is True


def test_stage1511_publication_unavailable_reason_projection_does_not_use_or_reason_chain() -> None:
    reasons, unavailable, failures = unavailable_reasons(
        {HostileText("markov_unavailable_reason"): HostileText("cold_start")},
        source_name="feature_probabilities",
    )

    assert reasons["markov"] == "cold_start"
    assert unavailable == {}
    assert failures == ()


def test_stage1511_publication_existing_unavailable_reasons_do_not_truth_test_text() -> None:
    reasons, unavailable, failures = sanitize_existing_unavailable_reasons_record(
        {HostileText("temporal"): HostileText("cold_start")}
    )

    assert reasons["temporal"] == "cold_start"
    assert unavailable == {}
    assert failures == ()


def test_stage1511_publication_feature_sources_do_not_truth_test_mapping_read_reason() -> None:
    sources = feature_probability_sources(
        {"feature_probabilities": HostileMapping({"markov_probability": 0.25})}
    )

    assert sources[0][0] == "feature_probabilities"
    assert sources[0][1]["markov_probability"] == 0.25
