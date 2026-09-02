"""Stage2636.11020 Phase 19 canonical materialization-owner regressions."""
from __future__ import annotations

import cProfile
import pstats

from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.models.enriched_stage_outputs import DetectionEvidenceFacts, EnrichedDetectionFacts
from Virus_Scan.detection.models.input_stage_outputs import NormalizedFacts, RawScanFacts
from Virus_Scan.detection.models.result_stage_outputs import DetectionResult
from Virus_Scan.detection.models.stage_value_utils import freeze_detection_value
from Virus_Scan.detection.scoring.full_analysis.stage_outputs import (
    DetectionDecision,
    DetectionDecisionRequest,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.tests.support.model_context_fixtures import model_context_snapshot_fixture


def _profile_calls(function) -> tuple[object, dict[str, int]]:
    profiler = cProfile.Profile()
    profiler.enable()
    result = function()
    profiler.disable()
    stats = pstats.Stats(profiler)
    calls: dict[str, int] = {}
    for (_filename, _line, name), values in stats.stats.items():
        calls[name] = calls.get(name, 0) + values[1]
    return result, calls


def _feature_evidence():
    tags = normalize_tag_evidence(("renpy_script", "process_exec"))
    chains = evaluate_chain_evidence(tags=tags)
    return tags, chains


def test_phase19_detection_result_has_one_canonical_freeze_boundary() -> None:
    source = {
        "z": {"beta": list(range(50)), "alpha": {"two", "one"}},
        "a": {"nested": {"b": 2, "a": 1}},
    }
    result, calls = _profile_calls(lambda: DetectionResult.from_mapping(source))

    assert calls["freeze_mapping_or_empty"] == 1
    assert calls["no_hook_json_sort_key"] == 11
    assert result.as_result_record() == {
        "a": {"nested": {"a": 1, "b": 2}},
        "z": {"alpha": ["one", "two"], "beta": list(range(50))},
    }

    source["z"]["beta"].append(99)
    assert result.payload["z"]["beta"] == tuple(range(50))


def test_phase19_exact_string_mapping_order_does_not_resort_by_values() -> None:
    first, first_calls = _profile_calls(lambda: freeze_detection_value({
        "z": {"beta": list(range(50)), "alpha": {"two", "one"}},
        "a": {"nested": {"b": 2, "a": 1}},
    }))
    second, second_calls = _profile_calls(lambda: freeze_detection_value({
        "a": {"nested": {"a": 1, "b": 2}},
        "z": {"alpha": {"one", "two"}, "beta": list(range(50))},
    }))

    assert first == second
    assert tuple(first) == ("a", "z")
    assert first_calls["no_hook_json_sort_key"] == 11
    assert second_calls["no_hook_json_sort_key"] == 11


def test_phase19_constructor_factories_delegate_freezing_to_post_init() -> None:
    _raw, raw_calls = _profile_calls(lambda: RawScanFacts.from_inputs(
        path="sample.rpy",
        tags=["renpy_script"],
        yara_hits=None,
        curr_stage="strings",
        strings_blob="init python:",
        strings_already_enriched=False,
    ))
    _normalized, normalized_calls = _profile_calls(lambda: NormalizedFacts.from_values(
        path="sample.rpy",
        node="sample.rpy",
        tags=["renpy_script"],
        yara_hits=["rule"],
        curr_stage="strings",
        strings_blob="init python:",
        strings_already_enriched=False,
        yara_evidence=None,
    ))
    tag_evidence, chain_evidence = _feature_evidence()
    evidence = DetectionEvidenceFacts(
        api_result={"calls": ["open"]}, behavior_timeline=[{"event": "start"}], ordered_events=[],
        tag_evidence=tag_evidence, chain_evidence=chain_evidence, attack_info={"state": "candidate"},
        baseline_maturity={"state": "warming"}, evidence_provenance={"source": "test"}, heur={"risk": 1},
    )
    model_context = model_context_snapshot_fixture(profile_context={
        "active_profile": "renpy", "engine_confidence": {"score": 0.5, "failure_evidence": ()},
    })
    _enriched, enriched_calls = _profile_calls(
        lambda: EnrichedDetectionFacts.from_evidence(evidence, model_context)
    )
    _decision, decision_calls = _profile_calls(lambda: DetectionDecision.from_request(
        DetectionDecisionRequest(
            score_val=1.0,
            explanation={"reason": {"items": [1, 2]}},
            classification="clean",
            layer_report={"layer": {"items": [1]}},
            analytical_calibration={"calibration": {"items": [1]}},
            failure_evidence=(),
        )
    ))

    assert raw_calls["canonical_yara_scan_result"] == 1
    assert normalized_calls["canonical_yara_scan_result"] == 1
    assert enriched_calls.get("freeze_mapping_or_empty", 0) == 0
    assert enriched_calls["frozen_failure_records"] == 1
    assert decision_calls["full_analysis_mapping"] == 3
    assert decision_calls["frozen_failure_records"] == 1
