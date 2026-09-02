from __future__ import annotations

import math

from Virus_Scan.detection.scoring.adaptive.model_score import adaptive_learned_model_confidence
from Virus_Scan.utils.probability import safe_clamp


def test_stage1307_model_safe_clamp_does_not_promote_nan_to_max_evidence() -> None:
    assert safe_clamp(math.nan) == 0.0
    assert safe_clamp(math.nan, 0.2, 0.8) == 0.2


def test_stage1307_model_safe_clamp_does_not_promote_infinity_to_max_evidence() -> None:
    assert safe_clamp(math.inf) == 0.0
    assert safe_clamp(-math.inf) == 0.0
    assert safe_clamp(math.inf, 0.15, 0.85) == 0.15


def test_stage1307_adaptive_model_confidence_does_not_inflate_nonfinite_model_inputs() -> None:
    confidence = adaptive_learned_model_confidence(
        profile_signal={"profile_ready": True, "profile_anomaly": math.nan},
        markov_signal={"markov_anomaly": math.inf},
        cluster_signal={"cluster_signal": -math.inf},
        vector_signal=math.nan,
        bucket_signal=math.inf,
    )

    assert confidence == 0.0


def test_stage1601_model_probability_safe_clamp_rejects_hostile_numeric_without_hooks() -> None:
    class HostileNumber:
        touched = 0

        def __float__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned __float__ invoked")

        def __repr__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned __repr__ invoked")

    value = HostileNumber()

    assert safe_clamp(value, 0.2, 0.8) == 0.2
    assert HostileNumber.touched == 0
