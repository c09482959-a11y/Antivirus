from __future__ import annotations

import json

from Virus_Scan.models.contracts.model_failure import (
    make_cold_start_record,
    materialize_model_failure_record,
)


def test_stage1303_cold_start_support_metrics_reject_malformed_without_crash() -> None:
    malformed_cases = (
        ("bad", "non_numeric_required_support_metric"),
        (True, "non_numeric_required_support_metric"),
        (-1, "negative_required_support_metric"),
        (1.5, "non_integer_required_support_metric"),
        (float("inf"), "non_finite_required_support_metric"),
    )

    for value, reason in malformed_cases:
        record = make_cold_start_record(
            model_name="markov",
            reason="insufficient_transition_support",
            required_support=value,
            observed_support=value,
            affected_fields=("probability",),
            model_version="stage1303_cold_start_contract_v1",
        )
        materialized = materialize_model_failure_record(record)

        assert materialized["failure_type"] == "cold_start"
        assert materialized["degraded"] is True
        assert materialized["output_affecting"] is True
        assert materialized["required_support"] == 0
        assert materialized["observed_support"] == 0
        assert materialized["required_support_unavailable_reason"] == reason
        assert materialized["observed_support_unavailable_reason"] == reason.replace("required", "observed")
        json.dumps(materialized, sort_keys=True)


def test_stage1303_cold_start_support_metrics_preserve_valid_integer_values() -> None:
    record = make_cold_start_record(
        model_name="temporal",
        reason="insufficient_probability_support",
        required_support="3",
        observed_support=1.0,
        affected_fields={"sequence_probability", "stage_probability"},
        model_version="stage1303_cold_start_contract_v1",
    )
    materialized = materialize_model_failure_record(record)

    assert materialized["required_support"] == 3
    assert materialized["observed_support"] == 1
    assert "required_support_unavailable_reason" not in materialized
    assert "observed_support_unavailable_reason" not in materialized
    assert materialized["affected_fields"] == ("sequence_probability", "stage_probability")
