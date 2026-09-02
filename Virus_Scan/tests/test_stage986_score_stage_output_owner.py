from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType

import pytest

from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.scoring.full_analysis.stage_outputs import (
    DetectionDecision,
    DetectionDecisionRequest,
    ScoreBreakdown,
)


def test_score_stage_outputs_live_under_detection_scoring():
    assert not Path('Virus_Scan/detection/models/scoring_stage_outputs.py').exists()
    assert Path('Virus_Scan/detection/scoring/full_analysis/stage_outputs.py').exists()


def test_score_breakdown_freezes_mapping_and_tags():
    result = ScoreBreakdown(
        score_val='12.5',
        explanation={'nested': {'value': 1}},
        tags=normalize_tag_evidence(
            ('tag_a', 'tag_b'), source_detector='stage986', source_stage='constructor'
        ),
    )
    assert result.score_val == 12.5
    assert isinstance(result.explanation, MappingProxyType)
    assert isinstance(result.explanation['nested'], MappingProxyType)
    assert type(result.tags) is TagEvidence
    assert result.tags.tags == ('tag_a', 'tag_b')
    with pytest.raises(FrozenInstanceError):
        result.score_val = 0.0


def test_detection_decision_freezes_score_and_calibration_context():
    decision = DetectionDecision.from_request(
        DetectionDecisionRequest(
            score_val=91,
            explanation={'classification': 'malicious'},
            classification='Malicious',
            layer_report={'layer': {'score': 91}},
            analytical_calibration={'ready': True},
        )
    )
    assert decision.score_val == 91.0
    assert decision.classification == 'Malicious'
    assert isinstance(decision.explanation, MappingProxyType)
    assert isinstance(decision.layer_report, MappingProxyType)
    assert isinstance(decision.analytical_calibration, MappingProxyType)
