from __future__ import annotations

from Virus_Scan.detection.scoring.adaptive import availability, confidence


class HostileProbabilityKey:
    touched = 0

    def __str__(self):  # pragma: no cover - failure proves caller hook was invoked
        type(self).touched += 1
        raise AssertionError("caller-owned probability key __str__ invoked")

    def __repr__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned probability key __repr__ invoked")


class HostileNumeric:
    touched = 0

    def __int__(self):  # pragma: no cover - failure proves caller hook was invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __int__ invoked")

    def __float__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned __float__ invoked")

    def __bool__(self):  # pragma: no cover
        type(self).touched += 1
        raise AssertionError("caller-owned numeric truthiness invoked")


def test_stage1732_probability_feature_key_rejects_hostile_key_without_stringifying() -> None:
    HostileProbabilityKey.touched = 0

    reason = availability.probability_feature_unavailable_reason(
        {"p_graph_ready": True},
        HostileProbabilityKey(),
    )

    assert reason == "invalid_probability_feature_key"
    assert HostileProbabilityKey.touched == 0


def test_stage1732_adaptive_weight_inputs_reject_hostile_numeric_hooks() -> None:
    HostileNumeric.touched = 0
    hostile = HostileNumeric()

    weights = confidence.adaptive_learned_model_weight_from_confidence(
        0.8,
        concrete_count=hostile,
        profile_files_seen=hostile,
        static_anchor_score=hostile,
    )

    assert HostileNumeric.touched == 0
    assert weights["concrete_scoreable_evidence_count"] == 0
    assert weights["profile_files_seen"] == 0
    assert weights["static_anchor_score"] == 0.0
    assert "no_concrete_static_anchors" in weights["caps_applied"]
