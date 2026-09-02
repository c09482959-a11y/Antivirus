"""Stage2079 publication static-contract regression coverage."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.publication.json_finalization.projection_text import final_json_mapping_items
from Virus_Scan.publication.json_finalization.record_numeric import (
    exact_int_value,
    exact_nonnegative_float,
)
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


def _text_value(value: object) -> str:
    return str(value)


def test_stage2079_numeric_helpers_reject_nonfinite_without_self_comparison() -> None:
    assert exact_int_value(float("nan"), _text_value) is None
    assert exact_int_value("7", _text_value) == 7
    assert exact_nonnegative_float(float("inf"), _text_value) is None
    assert exact_nonnegative_float("3.5", _text_value) == 3.5


def test_stage2079_mapping_proxy_items_are_typed_and_no_hook_safe() -> None:
    backing = {"alpha": 1, "beta": 2}
    assert final_json_mapping_items(MappingProxyType(backing)) == (("alpha", 1), ("beta", 2))


def test_stage2079_model_evidence_projection_preserves_secondary_probability_records() -> None:
    fields = build_model_evidence_final_json_fields(
        {
            "feature_probabilities": {"markov": 0.7},
            "adaptive_learning": {
                "profile_coordinated": {"feature_probabilities": {"profile": 0.4}},
            },
        }
    )
    evidence = fields["model_evidence"]
    assert evidence["feature_probabilities"] == {"markov": 0.7, "profile": 0.4}
    assert evidence["final_json_must_record"] is False
