from __future__ import annotations

from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage


class HostileText:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError("do not truth-test")

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr")


class HostileFailure(Exception):
    touched = 0

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError("do not stringify exception")

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError("do not repr exception")


def test_stage1682_failure_stage_slug_rejects_hostile_stage_without_hooks() -> None:
    HostileText.touched = 0

    tags = failure_tags_for_stage(HostileText(), "Recoverable Failure")  # type: ignore[arg-type]

    assert HostileText.touched == 0
    assert "detection_stage_degraded" in tags
    assert "detection_stage_recoverable_failure" in tags
    assert "unsafe_detection_stage_tag_text_rejected" in tags


def test_stage1682_failure_category_rejects_hostile_non_exception_without_hooks() -> None:
    HostileText.touched = 0

    tags = failure_tags_for_stage("decoded payload", HostileText())  # type: ignore[arg-type]

    assert HostileText.touched == 0
    assert "decoded_payload_degraded" in tags
    assert "decoded_payload_recoverable_detection_failure" in tags
    assert "unsafe_failure_tag_error_rejected" in tags


def test_stage1682_failure_exception_category_uses_type_name_without_stringifying_exception() -> None:
    HostileFailure.touched = 0

    tags = failure_tags_for_stage("pickle trigger", HostileFailure("hidden"))

    assert HostileFailure.touched == 0
    assert "pickle_trigger_hostilefailure" in tags
    assert "unsafe_failure_tag_error_rejected" not in tags


def test_stage1682_failure_tags_preserve_exact_string_slug_semantics() -> None:
    tags = failure_tags_for_stage("JS Execution Model", "Recoverable Detection Failure")

    assert tags == (
        "detection_stage_degraded",
        "detection_failure_evidence",
        "failure_evidence_recorded",
        "js_execution_model_degraded",
        "js_execution_model_recoverable_detection_failure",
    )
