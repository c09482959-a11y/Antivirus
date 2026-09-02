"""Stage 1529 Phase 1 detection contract/failure exact-text boundary regressions."""
from __future__ import annotations
from Virus_Scan.detection.models.failure_state import DetectionRecoverableFailureRequest

from pathlib import Path

from Virus_Scan.detection.contracts.string_predicates import (
    ascii_visibility_ratio,
    is_renpy_bytecode_path,
    validate_high_risk_tag,
)
from Virus_Scan.detection.contracts.tag_validation import validate_tags_for_path
from Virus_Scan.detection.models.failure_state import DetectionFailureState, failure_state_records
from Virus_Scan.utils.tagging import TAG_NORMALIZATION_FAILURE_EVIDENCE, canonical_raw_tag_name, ordered_unique_tags
from Virus_Scan.utils.text_validation import tag_validation_text


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.str_calls = 0
        obj.strip_calls = 0
        obj.bool_calls = 0
        return obj

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def strip(self, *args, **kwargs):  # pragma: no cover - failure proves caller strip() was used
        self.strip_calls += 1
        raise AssertionError("caller-owned strip() was invoked")

    def __bool__(self):  # pragma: no cover - failure proves truthiness was probed
        self.bool_calls += 1
        raise AssertionError("caller-owned truthiness was invoked")


class HostilePath:
    def __init__(self, value: str):
        self.value = value
        self.str_calls = 0
        self.fspath_calls = 0
        self.bool_calls = 0

    def __fspath__(self):
        self.fspath_calls += 1
        return self.value

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def __bool__(self):  # pragma: no cover - failure proves truthiness was probed
        self.bool_calls += 1
        raise AssertionError("caller-owned truthiness was invoked")


class HostileObject:
    def __init__(self):
        self.str_calls = 0
        self.bool_calls = 0

    def __str__(self):  # pragma: no cover - failure proves raw str() was used
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")

    def __bool__(self):  # pragma: no cover - failure proves truthiness was probed
        self.bool_calls += 1
        raise AssertionError("caller-owned truthiness was invoked")


def test_stage1529_tag_and_string_contracts_do_not_invoke_hostile_text_hooks() -> None:
    tag = HostileText("process_exec")
    strings_blob = HostileText("subprocess.Popen powershell -enc payload")
    path = Path("game/renpy/script.rpyc")
    hostile_path = HostilePath("game/renpy/script.rpyc")

    assert tag_validation_text(strings_blob) == "subprocess.popen powershell -enc payload"
    assert is_renpy_bytecode_path(path) is True
    assert is_renpy_bytecode_path(hostile_path) is False
    assert validate_high_risk_tag(tag, strings_blob=strings_blob, path=path) is True
    assert validate_tags_for_path((tag,), path=path, strings_blob=strings_blob, source=HostileText("scanner")) == ["process_exec"]
    assert canonical_raw_tag_name(HostileText("stage_hit:PowerShell Exec")) == "stage_hit:powershell_exec"
    assert ordered_unique_tags((HostileText("alpha"), HostileText("alpha"), HostileText("beta"))) == ["alpha", "beta"]
    assert ascii_visibility_ratio(memoryview(b"abc\x00")) == 0.75

    assert tag.str_calls == 0
    assert strings_blob.str_calls == 0
    assert hostile_path.str_calls == 0
    assert hostile_path.fspath_calls == 0
    assert tag.strip_calls == 0
    assert strings_blob.strip_calls == 0
    assert tag.bool_calls == 0
    assert hostile_path.bool_calls == 0


def test_stage1529_unsupported_tag_objects_become_explicit_failure_evidence_without_str() -> None:
    hostile = HostileObject()

    assert canonical_raw_tag_name(hostile) == TAG_NORMALIZATION_FAILURE_EVIDENCE
    assert ordered_unique_tags((hostile,)) == [TAG_NORMALIZATION_FAILURE_EVIDENCE, "detection_stage_degraded"]
    assert validate_tags_for_path((hostile,), path=HostilePath("game/script.rpy"), strings_blob=HostileText("subprocess.Popen")) == [
        TAG_NORMALIZATION_FAILURE_EVIDENCE,
        "tag_validation_failure_evidence",
        "detection_stage_degraded",
    ]
    assert hostile.str_calls == 0
    assert hostile.bool_calls == 0


def test_stage1529_failure_state_materializes_text_and_mappings_without_hostile_str_or_bool() -> None:
    stage = HostileText("model_score")
    error = RuntimeError(HostileText("temporal evidence unavailable"))
    context = Path("game/scripts/start.rpy")
    hostile_context = HostilePath("game/scripts/hostile.rpy")
    bool_like = HostileObject()

    state = DetectionFailureState.from_recoverable_request(DetectionRecoverableFailureRequest(
        stage_name=stage,
        error=error,
        error_source=HostileText("temporal_overlay"),
        affected_context=context,
        confidence_degraded=bool_like,
        json_record_required=HostileText("true"),
        replay_record_required=HostileText("false"),
    ))

    assert state.stage_name == "model_score"
    assert state.error_source == "temporal_overlay"
    assert state.affected_context == "game/scripts/start.rpy"
    assert state.confidence_degraded is True
    assert state.json_record_required is True
    assert state.replay_record_required is False
    assert state.message == "temporal evidence unavailable"

    rejected_context_state = DetectionFailureState.from_recoverable_request(DetectionRecoverableFailureRequest(
        stage_name="model_score",
        error="boom",
        error_source="temporal_overlay",
        affected_context=hostile_context,
    ))
    assert rejected_context_state.affected_context == ""
    assert hostile_context.fspath_calls == 0
    assert hostile_context.str_calls == 0

    hostile_key = HostileText("nested")
    hostile_value = HostileObject()
    records = failure_state_records(({hostile_key: {HostileText("reason"): hostile_value}},))

    assert records == ({"nested": {"reason": "<HostileObject>"}},)
    assert stage.str_calls == 0
    assert bool_like.str_calls == 0
    assert bool_like.bool_calls == 0
    assert hostile_key.str_calls == 0
    assert hostile_value.str_calls == 0
    assert hostile_value.bool_calls == 0
