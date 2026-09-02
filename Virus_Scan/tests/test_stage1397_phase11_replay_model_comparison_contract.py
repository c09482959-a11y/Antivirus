"""Stage 1397: replay model-evidence comparisons use one immutable public path."""

from __future__ import annotations

import pytest

import Virus_Scan.models.api as model_api
from Virus_Scan.models.api.bootstrap_registration import MODEL_BOOTSTRAP_MODULE_NAMES
from Virus_Scan.models.api.replay_comparison_contracts import (
    compare_model_evidence,
    materialize_model_evidence_comparison,
)


def test_stage1397_replay_model_comparison_is_deterministic_and_detached():
    expected = {"z": [3, 2], "a": {"probability": 0.25, "ready": True}}
    actual = {"a": {"ready": True, "probability": 0.5}, "z": [3, 2]}

    comparison = compare_model_evidence(
        model_name="markov",
        expected=expected,
        actual=actual,
    )
    expected["a"]["probability"] = 0.99
    actual["a"]["probability"] = 0.99

    materialized = materialize_model_evidence_comparison(comparison)
    assert materialized["matched"] is False
    assert materialized["mismatch_fields"] == ("a",)
    assert materialized["reason"] == "replay_model_evidence_mismatch"
    assert materialized["expected"]["a"]["probability"] == 0.25
    assert materialized["actual"]["a"]["probability"] == 0.5

    with pytest.raises(TypeError):
        comparison["matched"] = True


def test_stage1397_replay_model_comparison_records_non_mapping_inputs_as_mismatch_evidence():
    comparison = compare_model_evidence(
        model_name="temporal",
        expected=None,
        actual={"ready": False, "reason": "cold_start"},
    )
    materialized = materialize_model_evidence_comparison(comparison)

    assert materialized["matched"] is False
    assert materialized["mismatch_fields"] == ("expected",)
    assert materialized["reason"] == "replay_model_evidence_mismatch"
    assert materialized["expected"] == {}
    assert materialized["expected_unavailable_reason"] == "non_mapping_replay_expected"
    assert materialized["actual"] == {"ready": False, "reason": "cold_start"}


def test_stage1397_replay_comparison_contract_is_public_model_api():
    assert "replay_comparison_contracts" in model_api.__all__
    assert "Virus_Scan.models.api.replay_comparison_contracts" in MODEL_BOOTSTRAP_MODULE_NAMES


def test_stage1397_replay_model_comparison_distinguishes_missing_from_null():
    comparison = compare_model_evidence(
        model_name="profile",
        expected={},
        actual={"probability": None},
    )

    materialized = materialize_model_evidence_comparison(comparison)
    assert materialized["matched"] is False
    assert materialized["mismatch_fields"] == ("probability",)
