import math

from Virus_Scan.detection.contracts.probability import safe_clamp, score_to_probability
from Virus_Scan.detection.evidence.behavioral import probabilistic_semantics


def test_stage1321_detection_safe_clamp_does_not_promote_infinity_to_max_confidence() -> None:
    assert safe_clamp(math.inf) == 0.0
    assert safe_clamp(-math.inf) == 0.0
    assert safe_clamp(math.nan) == 0.0
    assert safe_clamp(math.inf, 0.15, 0.85) == 0.15


def test_stage1321_detection_score_to_probability_does_not_promote_nonfinite_scores() -> None:
    assert score_to_probability(math.inf) == 0.0
    assert score_to_probability(-math.inf) == 0.0
    assert score_to_probability(math.nan) == 0.0
    assert score_to_probability("not-a-score") == 0.0
    assert 0.0 < score_to_probability(100.0) <= 1.0


def test_stage1321_behavioral_probabilistic_semantics_inherits_nonfinite_boundary() -> None:
    summary = probabilistic_semantics.probabilistic_evidence_semantics(
        raw_confidence=math.inf,
        likelihood=math.inf,
        prior=math.nan,
        prevalence=math.inf,
    )
    assert summary["posterior"] == 0.0
    assert summary["likelihood"] == 0.0
    assert summary["prior"] == 0.0001
    assert summary["prevalence"] == 0.0001
