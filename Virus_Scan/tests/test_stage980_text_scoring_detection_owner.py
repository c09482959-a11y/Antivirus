from pathlib import Path

from Virus_Scan.detection.scoring.weighting.context_confidence import (
    apply_context_safety_cap,
    cap_context_bonus,
    compute_context_confidence_amplifier,
)
from Virus_Scan.detection.scoring.weighting.contextual_expected import (
    ContextualExpectedScoreRequest,
    apply_contextual_expected_behavior_score_from_request,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.scanners import text


def test_text_context_scoring_has_detection_owner_only():
    assert not Path("Virus_Scan/scanners/text_scoring.py").exists()
    assert not hasattr(text, "compute_context_confidence_amplifier")
    assert not hasattr(text, "apply_contextual_expected_behavior_score")
    assert not hasattr(text, "apply_context_safety_cap")
    assert not hasattr(text, "cap_context_bonus")


def test_detection_context_scoring_preserves_public_shapes():
    score, signal = apply_contextual_expected_behavior_score_from_request(
        ContextualExpectedScoreRequest(
            score=35.0,
            engine="unity",
            file_path="sample.asset",
            tag_evidence=normalize_tag_evidence(("process_exec",)),
        )
    )
    assert isinstance(score, float)
    assert "new_score" in signal

    capped = apply_context_safety_cap(75.0, 30.0, ["process_exec", "network_download"])
    assert isinstance(capped, float)

    bonus = cap_context_bonus(30.0, 2.0, 2.0, ["process_exec", "network_download"])
    assert isinstance(bonus, float)

    confidence = compute_context_confidence_amplifier(
        None,
        ["process_exec", "network_download"],
        
        {},
        pre_context_score=30.0,
    )
    assert confidence["version"] == "context_confidence_amplifier_v1_capped"
    assert "combined_context_max_bonus" in confidence["caps"]
