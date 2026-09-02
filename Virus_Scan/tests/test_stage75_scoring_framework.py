from Virus_Scan.detection.scoring.stress.scoring_framework import IterationScoreProfile, ScorePenalty, SCORE_FIELDS


def test_score_profile_has_required_fields_and_worst_case_weighting():
    p = IterationScoreProfile()
    assert set(p.scores) == set(SCORE_FIELDS)
    p.penalize(ScorePenalty('JSON_integrity_score', 9.0, 'persistence', 'synthetic corruption', 'json'))
    assert p.scores['JSON_integrity_score'] == 1.0
    assert p.aggregate() <= 2.75
    assert p.confidence['JSON_integrity_score'] < 0.92
