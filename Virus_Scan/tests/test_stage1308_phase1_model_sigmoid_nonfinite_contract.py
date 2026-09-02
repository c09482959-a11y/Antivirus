import math

from Virus_Scan.detection.scoring.adaptive import model_score
from Virus_Scan.utils.probability import (
    calibrated_sigmoid_probability,
    centered_sigmoid_probability,
    score_to_probability,
    sigmoid_score_100,
)


def test_stage1308_model_sigmoid_rejects_nonfinite_logits_without_max_confidence() -> None:
    assert calibrated_sigmoid_probability(math.inf) == 0.0
    assert calibrated_sigmoid_probability(-math.inf) == 0.0
    assert calibrated_sigmoid_probability(math.nan) == 0.0


def test_stage1308_model_sigmoid_rejects_nonfinite_temperature_without_max_confidence() -> None:
    assert calibrated_sigmoid_probability(10.0, temperature=math.inf) == 0.0
    assert calibrated_sigmoid_probability(10.0, temperature=math.nan) == 0.0


def test_stage1308_model_probability_callers_do_not_promote_infinite_scores() -> None:
    assert score_to_probability(math.inf) == 0.0
    assert centered_sigmoid_probability(math.inf, midpoint=2.5, scale=1.0) == 0.0
    assert sigmoid_score_100(math.inf) == 0.0


def test_stage1308_adaptive_scoring_uses_nonfinite_safe_shared_sigmoid() -> None:
    assert model_score.calibrated_sigmoid_probability(math.inf) == 0.0
    assert model_score.score_to_probability(math.inf) == 0.0
    assert model_score.sigmoid_score_100(math.inf) == 0.0


def test_stage1601_model_probability_sigmoid_helpers_reject_hostile_numeric_without_hooks() -> None:
    class HostileNumber:
        touched = 0

        def __float__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned __float__ invoked")

        def __str__(self):  # pragma: no cover
            type(self).touched += 1
            raise AssertionError("caller-owned __str__ invoked")

    value = HostileNumber()

    assert calibrated_sigmoid_probability(value) == 0.0
    assert centered_sigmoid_probability(value) == 0.0
    assert score_to_probability(value) == 0.0
    assert sigmoid_score_100(value) == 0.0
    assert HostileNumber.touched == 0
