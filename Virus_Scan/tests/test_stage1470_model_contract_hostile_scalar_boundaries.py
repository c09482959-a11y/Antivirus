"""Stage 1470: public model contracts must convert hostile scalar values into evidence."""

from __future__ import annotations

import json

from Virus_Scan.models.contracts.model_evidence import (
    make_model_evidence_record,
    materialize_model_evidence_record,
)
from Virus_Scan.models.contracts.model_failure import (
    make_cold_start_record,
    materialize_model_failure_record,
)
from Virus_Scan.models.contracts.model_feature_bundle import (
    make_model_feature_bundle,
    materialize_model_feature_bundle,
)
from Virus_Scan.models.contracts.probability_record import (
    make_probability_record,
    materialize_probability_record,
)
from Virus_Scan.contracts.temporal_accumulator import initial_temporal_accumulator_state
from Virus_Scan.models.temporal.accumulator import temporal_evidence_accumulator_update


class _HostileFloat:
    touched = 0

    def __float__(self):  # pragma: no cover - exercised by boundary conversion
        type(self).touched += 1
        raise RuntimeError("hostile float conversion")


class _HostileText:
    def __str__(self):  # pragma: no cover - exercised by materialization boundary
        raise RuntimeError("hostile text conversion")


def test_stage1470_probability_record_hostile_numeric_fields_are_unavailable_not_exceptions() -> None:
    record = make_probability_record(
        ready=True,
        probability=_HostileFloat(),
        support=1,
        count=1,
        vocab=1,
        smoothing="none",
        reason=None,
        model_version="stage1470_probability_v1",
    )
    assert record["ready"] is False
    assert record["probability"] is None
    assert record["reason"] == "non_numeric_probability"
    assert record["probability_unavailable_reason"] == "non_numeric_probability"

    materialized = materialize_probability_record(
        {
            "ready": True,
            "probability": 0.5,
            "support": _HostileFloat(),
            "count": 1,
            "vocab": 1,
            "smoothing": "none",
            "reason": None,
            "model_version": "stage1470_probability_v1",
        }
    )
    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["support"] is None
    assert materialized["support_unavailable_reason"] == "non_numeric_support_metric"
    assert materialized["probability_unavailable_reason"] == "non_numeric_support_metric"


def test_stage1470_feature_and_evidence_materializers_emit_json_safe_unsupported_scalar_evidence() -> None:
    feature_materialized = materialize_model_feature_bundle(
        make_model_feature_bundle({"hostile": _HostileText()}, model_version="stage1470_feature_v1")
    )
    evidence_materialized = materialize_model_evidence_record(
        make_model_evidence_record(
            {"hostile": _HostileText()},
            model_name="stage1470",
            evidence_type="contract_boundary",
            model_version="stage1470_evidence_v1",
        )
    )

    assert feature_materialized["hostile"] == {
        "value": None,
        "unavailable_reason": "unsupported_model_feature_value",
        "value_type": "_HostileText",
    }
    assert evidence_materialized["hostile"] == {
        "value": None,
        "unavailable_reason": "unsupported_model_evidence_value",
        "value_type": "_HostileText",
    }
    json.dumps(feature_materialized, sort_keys=True)
    json.dumps(evidence_materialized, sort_keys=True)


def test_stage1470_cold_start_support_metrics_are_hostile_float_safe() -> None:
    record = materialize_model_failure_record(
        make_cold_start_record(
            model_name="markov",
            reason="cold_start",
            required_support=_HostileFloat(),
            observed_support=_HostileFloat(),
        )
    )

    assert record["required_support"] == 0
    assert record["observed_support"] == 0
    assert record["required_support_unavailable_reason"] == "non_numeric_required_support_metric"
    assert record["observed_support_unavailable_reason"] == "non_numeric_observed_support_metric"


def test_stage1470_temporal_accumulator_hostile_scalars_are_replay_safe() -> None:
    _HostileFloat.touched = 0
    state = temporal_evidence_accumulator_update(
        previous=initial_temporal_accumulator_state(),
        observation=_HostileFloat(),
        observation_confidence=_HostileFloat(),
        evidence_timestamp=_HostileFloat(),
        support=0,
    )

    assert state.posterior_belief == 0.0
    assert state.last_evidence_timestamp is None
    assert state.unavailable_reason == "temporal_accumulator_probability_invalid"
    assert _HostileFloat.touched == 0
