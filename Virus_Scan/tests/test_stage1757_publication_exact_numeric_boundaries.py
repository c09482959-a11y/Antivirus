from __future__ import annotations

from Virus_Scan.publication.json_finalization.record_fields import (
    record_duration_seconds,
    record_json_status,
)


def test_stage1757_nonintegral_exit_code_is_not_truncated_to_success() -> None:
    assert record_json_status({}, exit_code=0.5) == "completed_unknown_exit"
    assert record_json_status({}, exit_code="0.5") == "completed_unknown_exit"


def test_stage1757_integral_float_and_text_exit_codes_remain_exact() -> None:
    assert record_json_status({}, exit_code=0.0) == "completed"
    assert record_json_status({}, exit_code="0.0") == "completed"
    assert record_json_status({}, exit_code=4.0) == "completed_nonzero_exit"


def test_stage1757_negative_duration_is_explicit_failure_evidence() -> None:
    for value in (-1, -0.25, "-2.5"):
        duration = record_duration_seconds({"duration": value})
        assert duration["model_signal_projection_failed"] is True
        assert duration["reason"] == "unsafe_numeric_value_rejected"


def test_stage1757_zero_and_positive_durations_remain_valid() -> None:
    assert record_duration_seconds({"duration": 0}) == 0.0
    assert record_duration_seconds({"duration": 1.25}) == 1.25
