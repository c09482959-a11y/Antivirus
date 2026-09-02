from __future__ import annotations

import math

from Virus_Scan.detection.models.detection_result import (
    build_fast_benign_detection_result,
    build_fast_suspicious_detection_result,
)


class _HostileText:
    def __str__(self):
        raise RuntimeError("hostile text")


class _HostileFloat:
    def __float__(self):
        raise RuntimeError("hostile float")


class _HostileIterable:
    def __iter__(self):
        raise RuntimeError("hostile iterator")


def test_stage1419_fast_benign_result_detaches_hostile_contract_inputs() -> None:
    result = build_fast_benign_detection_result(
        path=_HostileText(),
        score=_HostileFloat(),
        confidence=float("nan"),
        tags=_HostileIterable(),
        prefilter_tags=[_HostileText(), "image_asset"],
        effective_stage="prefilter",
        reason=_HostileText(),
        version="stage1419",
        constraints=_HostileIterable(),
        model_evidence={},
        yaralight_active=False,
    )

    assert result["node"] == ""
    assert result["score"] == 0.0
    assert result["confidence"] == 0.0
    assert result["tags"][0]["unavailable_reason"] == "result_sequence_unavailable"
    assert result["tags"][0]["final_json_must_record"] is True
    assert result["prefilter_tags"][0]["unavailable_reason"] == "result_sequence_text_unavailable"
    assert result["prefilter_tags"][1] == "image_asset"
    assert result["explanation"]["constraints"]["model_result_mapping_unavailable"]["unavailable_reason"] == "result_mapping_unreadable"
    assert result["explanation"]["constraints"]["yaralight_active"] is False


def test_stage1419_fast_suspicious_result_detaches_hostile_hits_and_score() -> None:
    result = build_fast_suspicious_detection_result(
        path="sample.exe",
        score=math.inf,
        tags=["process_injection", _HostileText()],
        active_profile=_HostileText(),
        reason="explicit chain",
        version="stage1419",
        constraints=_HostileIterable(),
        heuristic_hits=_HostileIterable(),
        confidence=_HostileFloat(),
        attack_hit=_HostileText(),
        model_evidence={},
    )

    assert result["classification"] == "high_confidence_suspicious"
    assert result["score"] == 0.0
    assert result["tags"][0] == "process_injection"
    assert result["tags"][1]["unavailable_reason"] == "result_sequence_text_unavailable"
    assert result["heuristics"]["hits"][0]["unavailable_reason"] == "result_sequence_unavailable"
    assert result["profile_selection"]["active_profile"] == "other"
