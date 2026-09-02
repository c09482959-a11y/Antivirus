from __future__ import annotations

from Virus_Scan.scheduler.evidence.inmemory_result_timeout_bool_decisions import (
    timeout_bool_decision,
    timeout_tags_decision,
)
from Virus_Scan.scheduler.evidence.inmemory_result_timeout_support import timeout_bool, timeout_tags


class HostileBooleanValue:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise AssertionError("boolean hook must not run")

    def __int__(self):
        type(self).touched += 1
        raise AssertionError("integer hook must not run")

    def __str__(self):
        type(self).touched += 1
        raise AssertionError("string hook must not run")


def test_stage2109_timeout_bool_decision_records_missing_false_projection() -> None:
    decision = timeout_bool_decision(None, field="trusted_benign")

    assert decision.value is False
    assert decision.rejected is False
    assert decision.reason == "scheduler_boolean_missing"
    assert decision.field == "trusted_benign"


def test_stage2109_timeout_bool_decision_records_text_false_projection() -> None:
    decision = timeout_bool_decision("clean", field="error")

    assert decision.value is False
    assert decision.rejected is False
    assert decision.reason == "scheduler_boolean_text_false"


def test_stage2109_timeout_bool_projection_preserves_legacy_rejection_shape_without_hooks() -> None:
    HostileBooleanValue.touched = 0
    rejections: list[dict[str, object]] = []

    result = timeout_bool(HostileBooleanValue(), field="queue_failure", rejections=rejections)

    assert result is False
    assert HostileBooleanValue.touched == 0
    assert rejections == [{"field": "queue_failure", "reason": "unsafe_scheduler_boolean_rejected"}]


def test_stage2109_timeout_bool_projection_preserves_true_and_false_inputs() -> None:
    rejections: list[dict[str, object]] = []

    assert timeout_bool(True, field="error", rejections=rejections) is True
    assert timeout_bool(0, field="timed_out", rejections=rejections) is False
    assert timeout_bool("timeout", field="timed_out", rejections=rejections) is True
    assert timeout_bool("passed", field="error", rejections=rejections) is False
    assert rejections == []


def test_stage2109_timeout_tags_decision_records_missing_empty_projection() -> None:
    decision = timeout_tags_decision(None)

    assert decision.value == ()
    assert decision.rejected is False
    assert decision.reason == "scheduler_tags_missing"


def test_stage2109_timeout_tags_projection_preserves_legacy_rejection_shape_without_hooks() -> None:
    HostileBooleanValue.touched = 0
    rejections: list[dict[str, object]] = []

    result = timeout_tags(HostileBooleanValue(), rejections=rejections)

    assert result == ()
    assert HostileBooleanValue.touched == 0
    assert rejections == [{"field": "tags", "reason": "unsafe_scheduler_tag_sequence_rejected"}]
