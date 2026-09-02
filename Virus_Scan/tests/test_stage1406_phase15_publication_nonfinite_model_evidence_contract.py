"""Stage 1406: publication model evidence absorbs non-finite upstream values."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping

from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def _evidence_for(record: Mapping[str, object]) -> Mapping[str, object]:
    projected = build_model_evidence_final_json_fields(record)
    assert "model_evidence" in projected
    evidence = projected["model_evidence"]
    assert isinstance(evidence, Mapping)
    assert evidence["final_json_must_record"] is True
    assert evidence["replay_record_required"] is True
    json.dumps(evidence, sort_keys=True, allow_nan=False)
    return evidence


def test_stage1406_direct_model_evidence_nonfinite_scalar_is_degraded_not_raised() -> None:
    evidence = _evidence_for({"model_evidence": {"unexpected_metric": math.nan}})

    assert evidence["unavailable_reasons"]["model_evidence"] == "non_finite_model_evidence_value"
    assert evidence["unexpected_metric"] == {
        "unavailable_reason": "non_finite_model_evidence_value",
        "value_type": "float",
        "value_repr": "nan",
    }
    assert any(
        failure["failure_type"] == "invalid_model_evidence_record"
        and failure["reason"] == "non_finite_model_evidence_value"
        for failure in evidence["model_failures"]
    )


def test_stage1406_direct_model_evidence_nested_nonfinite_is_json_safe() -> None:
    evidence = _evidence_for({"model_evidence": {"nested": {"score": math.inf}}})

    assert evidence["unavailable_reasons"]["model_evidence"] == "non_finite_model_evidence_value"
    assert evidence["nested"]["score"] == {
        "unavailable_reason": "non_finite_model_evidence_value",
        "value_type": "float",
        "value_repr": "inf",
    }


def test_stage1406_model_failure_details_nonfinite_are_preserved_as_degraded_evidence() -> None:
    evidence = _evidence_for(
        {
            "model_evidence": {
                "model_failure": {
                    "model_name": "profile",
                    "failure_type": "profile_failure",
                    "reason": "profile_metric_non_finite",
                    "details": {"bad_metric": math.nan},
                }
            }
        }
    )

    failures = evidence["model_failures"]
    assert any(
        failure["model_name"] == "profile"
        and failure["details"]["bad_metric"]["unavailable_reason"] == "non_finite_model_evidence_value"
        for failure in failures
    )
    assert evidence["unavailable_reasons"]["model_evidence"] == "non_finite_model_evidence_value"
