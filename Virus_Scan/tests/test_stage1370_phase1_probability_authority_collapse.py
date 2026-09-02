"""Stage 1370 Phase 1 probability authority regression coverage."""
from __future__ import annotations

import inspect

from Virus_Scan.detection.contracts import probability as detection_probability
from Virus_Scan.utils import probability as canonical_probability


def test_stage1370_detection_probability_contract_reexports_canonical_helpers() -> None:
    assert detection_probability.safe_clamp is canonical_probability.safe_clamp
    assert detection_probability.score_to_probability is canonical_probability.score_to_probability
    assert detection_probability.RELIABILITY_TO_NUMERIC is canonical_probability.RELIABILITY_TO_NUMERIC
    assert detection_probability.EVIDENCE_STRENGTH_TO_LIKELIHOOD is canonical_probability.EVIDENCE_STRENGTH_TO_LIKELIHOOD


def test_stage1370_detection_probability_contract_has_no_duplicate_probability_implementation() -> None:
    source = inspect.getsource(detection_probability)
    assert "def safe_clamp" not in source
    assert "def score_to_probability" not in source
    assert "math.exp" not in source
    assert "MappingProxyType" not in source
