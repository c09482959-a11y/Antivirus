"""Stage 1735: publication model-evidence numeric validation rejects numeric subclasses without hooks."""

from __future__ import annotations

from Virus_Scan.publication.model_evidence_projection.probability_validation import (
    valid_nonnegative_integer_metric,
    valid_probability,
)
from Virus_Scan.publication.model_evidence_projection import build_model_evidence_final_json_fields


class HostileFloat(float):
    touched = 0

    def __float__(self) -> float:  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned __float__ must not execute")


class HostileInt(int):
    touched = 0

    def __float__(self) -> float:  # pragma: no cover - failure if invoked
        type(self).touched += 1
        raise AssertionError("caller-owned int-subclass __float__ must not execute")


def reset_hooks() -> None:
    HostileFloat.touched = 0
    HostileInt.touched = 0


def test_stage1735_valid_probability_rejects_numeric_subclasses_without_float_hook() -> None:
    reset_hooks()

    assert valid_probability(HostileFloat(0.4)) == (False, None, "non_numeric_probability")
    assert valid_probability(HostileInt(1)) == (False, None, "non_numeric_probability")

    assert HostileFloat.touched == 0
    assert HostileInt.touched == 0


def test_stage1735_count_metric_rejects_numeric_subclasses_without_float_hook() -> None:
    reset_hooks()

    assert valid_nonnegative_integer_metric(HostileFloat(2.0)) == (False, None, "non_numeric_count_support_metric")
    assert valid_nonnegative_integer_metric(HostileInt(2)) == (False, None, "non_numeric_count_support_metric")

    assert HostileFloat.touched == 0
    assert HostileInt.touched == 0


def test_stage1735_model_evidence_probability_projection_rejects_numeric_subclass_without_hooks() -> None:
    reset_hooks()

    fields = build_model_evidence_final_json_fields({"feature_probabilities": {"markov": HostileFloat(0.4)}})

    evidence = fields["model_evidence"]
    assert evidence["unavailable_reasons"]["markov"] == "non_numeric_probability"
    assert evidence["model_failures"][0]["reason"] == "non_numeric_probability"
    assert HostileFloat.touched == 0


def test_stage1735_model_signal_nonfinite_scan_rejects_numeric_subclass_without_hooks() -> None:
    reset_hooks()

    fields = build_model_evidence_final_json_fields({"model_context": {"score": HostileFloat(0.4)}})

    assert fields == {}
    assert HostileFloat.touched == 0
