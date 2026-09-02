from __future__ import annotations
from Virus_Scan.tests.support.attack_mapping_contract_fixtures import unavailable_attack_mapping_fixture

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from collections.abc import Mapping

import pytest

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.full_analysis.cap_inputs import apply_score_caps
from Virus_Scan.detection.scoring.full_analysis.decision_builder import finalize_scored_detection
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.full_analysis.stage_outputs import DetectionDecision, ScoreBreakdown
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence


class TruthHostileList(list):
    def __bool__(self):  # pragma: no cover - should never be reached
        raise AssertionError("caller-owned list truthiness was probed")


class TruthHostileDict(dict):
    def __bool__(self):  # pragma: no cover - should never be reached
        raise AssertionError("caller-owned mapping truthiness was probed")


class TruthHostileMapping(Mapping):
    def __init__(self, data):
        self._data = dict(data)

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):  # pragma: no cover - bool() must not reach here
        raise AssertionError("caller-owned mapping length/truthiness was probed")

    def items(self):
        return self._data.items()

    def get(self, key, default=None):
        return self._data.get(key, default)



def test_stage1491_apply_score_caps_freezes_public_inputs_without_truthiness():
    captured = {}

    def high_gate(score, chain_evidence, *, tags, path):
        captured["tags"] = tags
        captured["chain_evidence"] = chain_evidence
        return score, {"reason": "unchanged", "weak_or_structural_hits": []}

    tag_evidence = physical_tag_evidence(
        ("renpy_bytecode_noise_suppressed",),
        source_detector="stage1491",
        source_stage="score_caps",
    )
    result = apply_score_caps(
        score_val=25.0,
        explanation=TruthHostileDict({"caps": [], "score_breakdown": {}}),
        path="game/script.rpy",
        tags=tag_evidence,
        chain_evidence=evaluate_chain_evidence(
            tags=tag_evidence,
            api_calls=("CreateFileW",),
            ordered_events=("file_read",),
        ),
        active_profile="renpy",
        engine_confidence=TruthHostileDict({"baseline_suppression_allowed": False}),
        baseline_maturity=TruthHostileDict({"samples": 5}),
        evidence_provenance=TruthHostileDict({"source": "unit"}),
        failure_evidence=TruthHostileList([]),
        high_gate_func=high_gate,
    )

    assert isinstance(result, ScoreBreakdown)
    assert captured["tags"] == ("renpy_bytecode_noise_suppressed",)
    assert captured["chain_evidence"].registry_version == "stage2636_11020_chain_registry_v5"
    assert result.tags is tag_evidence
    assert result.tags.tags == ("renpy_bytecode_noise_suppressed",)



def test_stage1491_finalize_scored_detection_uses_detached_mapping_defaults():
    explanation = TruthHostileDict({
        "layers": TruthHostileDict({
            "layer_3_graph_score": TruthHostileDict({}),
            "graph": TruthHostileDict({"score": 17.5}),
        }),
        "score_breakdown": TruthHostileDict({}),
    })

    result = finalize_scored_detection(
        score_val=33.0,
        explanation=explanation,
        path="game/script.rpy",
        node=None,
        tags=physical_tag_evidence(
            ("tag_a",),
            source_detector="stage1491",
            source_stage="finalize",
        ),
        prev_stage=None,
        curr_stage="scan",
        strings_blob="",
        api_result=TruthHostileDict({}),
        ordered_events=TruthHostileList(["event_a"]),
        behavior_flow=TruthHostileList(["flow_a"]),
        active_profile="renpy",
        graph_features=TruthHostileDict({"nodes": 2}),
        failure_evidence=TruthHostileList([]),
        score_explanation_builder=lambda *, final_score, explanation, path, active_profile: explanation,
    )

    assert isinstance(result, DetectionDecision)
    assert result.analytical_calibration["graph_context"]["graph_score"] == 17.5
    assert result.analytical_calibration["summary"]["tag_count"] == 1
    assert result.layer_report["graph"]["score"] == 17.5



def test_stage1491_stage_outputs_direct_constructors_do_not_truth_test_inputs():
    score = ScoreBreakdown(
        score_val=None,
        explanation=TruthHostileMapping({"caps": []}),
        tags=physical_tag_evidence(
            ("a",),
            source_detector="stage1491",
            source_stage="constructor",
        ),
        failure_evidence=TruthHostileList([]),
    )
    decision = DetectionDecision(
        score_val=None,
        explanation=TruthHostileMapping({"classification": "low"}),
        classification="low",
        layer_report=TruthHostileMapping({"graph": {"score": 1.0}}),
        analytical_calibration=TruthHostileMapping({"ready": True}),
        failure_evidence=TruthHostileList([]),
    )

    assert score.score_val == 0.0
    assert type(score.tags) is TagEvidence
    assert score.tags.tags == ("a",)
    assert decision.score_val == 0.0
    assert decision.layer_report["graph"]["score"] == 1.0

from Virus_Scan.detection.scoring.full_analysis.input_builder import ScoreContextRequest, build_score_context
from Virus_Scan.detection.scoring.full_analysis.layered_score import compute_layered_detection
from Virus_Scan.detection.scoring.full_analysis.failure_attachment import attach_failure_evidence
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence


class TruthHostileText:
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return self.text

    def __bool__(self):  # pragma: no cover - should never be reached
        raise AssertionError("caller-owned text truthiness was probed")



def test_stage1491_score_context_and_layered_score_freeze_public_inputs():
    layered_tags = physical_tag_evidence(
        ("process_exec", "network_download"),
        source_detector="stage1491",
        source_stage="layered_score",
    )
    layered_chains = evaluate_chain_evidence(
        tags=layered_tags,
        api_calls=("CreateProcessW",),
        ordered_events=("process_create",),
    )
    layered = compute_layered_detection(
        node=None,
        tags=layered_tags,
        chain_evidence=layered_chains,
        yara_hits=TruthHostileList(["hit"]),
        prev_stage=None,
        curr_stage=TruthHostileText("stage_b"),
        ordered_events=TruthHostileList(["process_create"]),
    )
    assert layered["score_breakdown"]["immutable_evidence_tags"] == 2
    assert layered["layers"]["stage"]["previous_stage"] == "unknown"

    score_tags = physical_tag_evidence(
        ("process_exec",), source_detector="stage1491", source_stage="score_context",
    )
    score_chains = evaluate_chain_evidence(
        tags=score_tags, api_calls=("CreateFileW",), ordered_events=("file_read",),
    )
    context = build_score_context(
        ScoreContextRequest(
            attack_mapping_result=unavailable_attack_mapping_fixture(),
            path="game/script.rpy",
            node=None,
            tag_evidence=score_tags,
            chain_evidence=score_chains,
            yara_evidence=None,
            prev_stage=None,
            curr_stage=TruthHostileText("scan"),
            ordered_events=TruthHostileList(["file_read"]),
            active_profile="renpy",
            failure_evidence=TruthHostileList([]),
        )
    )
    assert isinstance(context, ScoreBreakdown)
    assert context.tags.tags == ("process_exec",)



def test_stage1491_internal_score_owners_reject_noncanonical_tag_inputs_without_hooks():
    hostile = TruthHostileList(["process_exec"])
    with pytest.raises(TypeError, match="score_cap_tag_evidence_required"):
        apply_score_caps(
            score_val=1.0,
            explanation={},
            path="payload.exe",
            tags=hostile,
            chain_evidence=evaluate_chain_evidence(tags=()),
            active_profile="other",
            engine_confidence={},
            baseline_maturity={},
            evidence_provenance={},
        )



def test_stage1491_failure_attachment_does_not_truth_test_failure_records():
    failure = recoverable_failure_evidence(
        stage_name="unit",
        error_source="truthiness_test",
        error=ValueError("boom"),
        affected_context="unit",
    )
    explanation = attach_failure_evidence(TruthHostileDict({"reasons": []}), TruthHostileList([failure]))
    assert explanation["scanner_degraded"] is True
    assert "recoverable_detection_stage_degraded" in explanation["reasons"]
