from Virus_Scan.tests.support.static_inventory import read_python_file

from pathlib import Path

import Virus_Scan.scanners.text as text
from Virus_Scan.scanners import text_context, text_policy
from Virus_Scan.detection.scoring.weighting import context_confidence
from Virus_Scan.detection.scoring.weighting import policy_constants as detection_score_policy
from Virus_Scan.detection.scoring.weighting.contextual_expected import (
    ContextualExpectedScoreRequest,
    apply_contextual_expected_behavior_score_from_request,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence


def test_text_policy_snapshot_is_scanner_owned_and_reexported():
    assert text.BROAD_UNVALIDATED_TAGS is text_policy.BROAD_UNVALIDATED_TAGS
    assert text.VECTOR_CLUSTER_MAX_BONUS == text_policy.VECTOR_CLUSTER_MAX_BONUS
    assert text.COMBINED_CONTEXT_MAX_BONUS == text_policy.COMBINED_CONTEXT_MAX_BONUS


def test_text_context_helpers_are_decomposed_from_text_module_and_scoring_is_detection_owned():
    source = read_python_file(Path("Virus_Scan/scanners/text.py"))
    assert "load_text_policy_snapshot" not in source
    assert "load_payload_policy_snapshot" not in source
    assert "def compute_context_confidence_amplifier" not in source
    assert "def apply_contextual_expected_behavior_score" not in source
    assert "def contextual_expected_behavior_signal" not in source
    assert not hasattr(text, "contextual_expected_behavior_signal")
    assert not hasattr(text_context, "contextual_expected_behavior_signal")
    assert not hasattr(text, "compute_context_confidence_amplifier")
    assert not hasattr(text, "apply_contextual_expected_behavior_score")


def test_detection_owned_text_scoring_preserves_context_evidence_shape():
    score, signal = apply_contextual_expected_behavior_score_from_request(
        ContextualExpectedScoreRequest(
            score=35.0,
            engine="unity",
            file_path="sample.asset",
            tag_evidence=normalize_tag_evidence(("process_exec",)),
        )
    )
    assert isinstance(score, float)
    assert signal["version"] == detection_score_policy.CONTEXTUAL_BASELINE_VERSION
    assert "new_score" in signal

    confidence = context_confidence.compute_context_confidence_amplifier(
        node={},
        tags=["process_exec", "network_download"],
        
        layers={},
        pre_context_score=30.0,
    )
    assert confidence["version"] == text_policy.CONTEXT_AMPLIFIER_VERSION
    assert "scanner_degraded" not in confidence
    assert "hits" in confidence
