from __future__ import annotations

import inspect
from pathlib import Path

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.correlation.behavioral.cluster_context import cluster_kind_for_tags
from Virus_Scan.detection.evidence.behavioral.semantics import semantic_evidence_vector_overlay
from Virus_Scan.detection.profiles.renpy.updater import renpy_updater_score_cap
from Virus_Scan.detection.scoring.escalation.high_gate import apply_anchor_chain_high_gate
from Virus_Scan.detection.scoring.full_analysis.cap_inputs import apply_score_caps
from Virus_Scan.detection.scoring.weighting.context_confidence import (
    compute_context_confidence_amplifier,
)
from Virus_Scan.detection.scoring.adaptive.layer_weights import learn_adaptive_layer_weights
from Virus_Scan.detection.scoring.adaptive.model_caps import hybrid_static_model_evidence_fusion
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import log_odds_static_model_probabilities
from Virus_Scan.detection.scoring.calibration.analytical_bundle import AnalyticalCalibrationBundleRequest
from Virus_Scan.detection.scoring.full_analysis.decision_builder import finalize_scored_detection
from Virus_Scan.core.paths import runtime_library_score_cap
from Virus_Scan.routing.engine_detect import infer_engine_context, infer_profile_engine
from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence


_DANGEROUS_NAMES = (
    "MimikatzCredentialDump",
    "RansomLockerBackdoor",
    "CobaltStrikeLoader",
)


def test_phase12_yara_names_cannot_unlock_high_gate() -> None:
    score, metadata = apply_anchor_chain_high_gate(
        88.0,
        evaluate_chain_evidence(),
        tags=(),
        path="payload.bin",
    )
    assert score < 50.0
    assert metadata["allowed_high"] is False
    assert metadata["reason"] == "high_requires_concrete_single_anchor_or_confirmed_chain"
    assert "yara_authority" not in metadata
    assert "yara_hits" not in inspect.signature(apply_anchor_chain_high_gate).parameters
    assert "yara_hits" not in inspect.signature(apply_score_caps).parameters


def test_phase12_yara_names_cannot_bypass_renpy_cap() -> None:
    assert "yara_hits" not in inspect.signature(renpy_updater_score_cap).parameters
    score, reasons = renpy_updater_score_cap(
        80.0,
        tags=("renpy",),
        path="game/renpy/common/00updater.rpy",
        strings_blob="renpy updater update available download update",
    )
    assert score == 22.0
    assert reasons == ["renpy_official_updater_cap_score"]


def test_phase12_semantic_vector_keeps_yara_at_zero_authority() -> None:
    result = semantic_evidence_vector_overlay(
        tags=("network_download",),
        yara_hits=_DANGEROUS_NAMES,
        risk=50.0,
    )
    assert result["vector"]["yara_confidence"] == 0.0
    assert result["yara_context"]["probability_authority"] is False
    assert result["yara_context"]["hit_count"] == len(_DANGEROUS_NAMES)
    assert result["yara_probability_unavailable_reason"] == (
        "yara_production_calibration_unavailable"
    )


def test_phase12_context_and_model_interfaces_do_not_accept_yara() -> None:
    tags = physical_tag_evidence(("network_download",), source_detector="phase12")
    result = compute_context_confidence_amplifier(
        None, tags, {}, pre_context_score=60.0,
    )
    assert result["concrete_scoreable_evidence_count"] == 1
    assert "yara_context_evidence_count" not in result
    for owner in (
        compute_context_confidence_amplifier,
        learn_adaptive_layer_weights,
        runtime_library_score_cap,
        infer_engine_context,
        infer_profile_engine,
        finalize_scored_detection,
    ):
        assert "yara_hits" not in inspect.signature(owner).parameters
    assert "yara_hits" not in inspect.signature(AnalyticalCalibrationBundleRequest).parameters


def test_phase12_forged_p_yara_cannot_change_any_fusion_probability() -> None:
    baseline = {
        "p_attack_intelligence": 0.3,
        "p_chain": 0.2,
        "p_exec": 0.1,
        "p_behavior": 0.15,
        "p_evasion": 0.0,
        "p_entropy": 0.1,
    }
    forged = dict(baseline, p_yara=1.0)
    assert hybrid_static_model_evidence_fusion(forged) == hybrid_static_model_evidence_fusion(baseline)
    layer_probs = {"quick_static_probability": 0.2, "threat_intel_probability": 0.2}
    assert log_odds_static_model_probabilities(0.2, layer_probs, forged) == log_odds_static_model_probabilities(0.2, layer_probs, baseline)


def test_phase12_yara_names_cannot_label_cluster_malicious() -> None:
    assert cluster_kind_for_tags(()) == "benign"
    assert cluster_kind_for_tags(("network_download",)) == "mixed"


def test_phase12_removed_name_authority_surfaces_do_not_exist() -> None:
    sources = "\n".join(
        Path(path).read_text(encoding="utf-8")
        for path in (
            "Virus_Scan/yara/match.py",
            "Virus_Scan/yara/constants.py",
            "Virus_Scan/detection/scoring/escalation/high_gate.py",
            "Virus_Scan/detection/scoring/escalation/anchor_constants.py",
            "Virus_Scan/detection/registries/chain_gate_registry_defaults.py",
            "Virus_Scan/models/init_parts/model_defaults_init.py",
        )
    )
    for forbidden in (
        "_high_gate_yara_authority",
        "HIGH_GATE_YARA_AUTHORITY_KEYWORDS",
        "YARA_RULE_CONFIDENCE_KEYWORDS",
    ):
        assert forbidden not in sources
