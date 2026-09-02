from __future__ import annotations

from Virus_Scan.detection.models.detection_result import (
    build_fast_benign_detection_result,
    build_fast_suspicious_detection_result,
)


class HostileResultValue:
    touches = 0

    @property
    def __dict__(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("__dict__ property must not execute")

    @property
    def items(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("items property must not execute")

    @property
    def text(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("text property must not execute")

    def __str__(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("str hook must not execute")

    def __repr__(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("repr hook must not execute")

    def __iter__(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("iter hook must not execute")

    def __float__(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("float hook must not execute")

    def __bool__(self):  # pragma: no cover - regression asserts no execution
        type(self).touches += 1
        raise RuntimeError("bool hook must not execute")


def test_stage1601_fast_benign_detection_result_rejects_hostile_values_without_hooks() -> None:
    HostileResultValue.touches = 0
    hostile = HostileResultValue()

    result = build_fast_benign_detection_result(
        path=hostile,
        score=hostile,
        confidence=hostile,
        tags=hostile,
        prefilter_tags=[hostile],
        effective_stage="prefilter",
        reason=hostile,
        version="stage1601",
        constraints=hostile,
        model_evidence={},
        yaralight_active=hostile,
    )

    assert result["node"] == ""
    assert result["score"] == 0.0
    assert result["confidence"] == 0.0
    assert result["tags"][0]["unavailable_reason"] == "result_sequence_unavailable"
    assert result["prefilter_tags"][0]["unavailable_reason"] == "result_sequence_text_unavailable"
    assert result["explanation"]["reasons"] == [""]
    assert result["explanation"]["constraints"]["model_result_mapping_unavailable"]["unavailable_reason"] == "result_mapping_unreadable"
    assert result["explanation"]["constraints"]["yaralight_active"] is False
    assert HostileResultValue.touches == 0


def test_stage1601_fast_suspicious_detection_result_rejects_hostile_values_without_hooks() -> None:
    HostileResultValue.touches = 0
    hostile = HostileResultValue()

    result = build_fast_suspicious_detection_result(
        path=hostile,
        score=hostile,
        tags=["explicit", hostile],
        active_profile=hostile,
        reason=hostile,
        version="stage1601",
        constraints={"safe": "yes", hostile: hostile},
        heuristic_hits=hostile,
        confidence=hostile,
        attack_hit=hostile,
        model_evidence={},
    )

    assert result["classification"] == "high_confidence_suspicious"
    assert result["node"] == ""
    assert result["tags"][0] == "explicit"
    assert result["tags"][1]["unavailable_reason"] == "result_sequence_text_unavailable"
    assert result["profile_selection"]["active_profile"] == "other"
    assert result["heuristics"]["hits"][0]["unavailable_reason"] == "result_sequence_unavailable"
    assert result["attack_intelligence"]["hits"][0]["unavailable_reason"] == "result_sequence_text_unavailable"
    assert result["explanation"]["constraints"]["safe"] == "yes"
    assert any(key.startswith("unavailable_key") for key in result["explanation"]["constraints"])
    assert HostileResultValue.touches == 0
