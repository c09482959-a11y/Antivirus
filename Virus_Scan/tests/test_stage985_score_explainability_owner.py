from pathlib import Path

from Virus_Scan.detection.scoring.explainability.score_components import build_reproducible_score_explanation
from Virus_Scan.detection.scoring.explainability.score_component_models import ScoreContribution


def test_score_explainability_components_live_under_detection_scoring():
    assert not Path('Virus_Scan/detection/explainability/score_components.py').exists()
    assert not Path('Virus_Scan/detection/explainability/score_component_builders.py').exists()
    assert not Path('Virus_Scan/detection/explainability/score_component_models.py').exists()
    assert Path('Virus_Scan/detection/scoring/explainability/score_components.py').exists()
    assert Path('Virus_Scan/detection/scoring/explainability/score_component_builders.py').exists()
    assert Path('Virus_Scan/detection/scoring/explainability/score_component_models.py').exists()


def test_score_explainability_reconciles_to_emitted_score():
    explanation = build_reproducible_score_explanation(
        final_score=42.5,
        explanation={
            'layers': {'api': {'score': 20.0, 'hits': ['CreateProcess'], 'name': 'api evidence'}},
            'weights': {'api': 1.5},
            'active_layers': 1,
        },
        path='sample.exe',
        active_profile='unity',
    )
    assert explanation['score_reproducibility']['matches_emitted_score'] is True
    assert explanation['score_reproducibility']['emitted_score'] == 42.5
    assert explanation['score_component_schema']['required_fields']
    assert any(component['score_source'] == 'reconciliation:score_total' for component in explanation['score_components'])


def test_score_contribution_record_is_json_safe():
    contribution = ScoreContribution(
        score_source='unit:test',
        weight=1.0,
        raw_score=2.0,
        weighted_score=2.0,
        evidence_reference=('a', 'b'),
        reason='test',
        engine_context='other',
        filetype_context='.txt',
        confidence_impact=2.0,
        malicious_contribution=0.0,
        suspicious_contribution=0.0,
        benign_contribution=2.0,
    )
    record = contribution.to_record()
    assert record['evidence_reference'] == ['a', 'b']
