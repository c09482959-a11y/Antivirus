from __future__ import annotations

import math

import pytest

from Virus_Scan.models.contracts import (
    make_cluster_evidence_record,
    make_graph_evidence_record,
    make_markov_probability_record,
    make_model_snapshot,
    make_profile_evidence_record,
    make_replay_model_comparison_record,
    make_temporal_overlay_record,
    materialize_model_evidence_record,
    materialize_model_snapshot,
    materialize_probability_record,
    materialize_replay_model_comparison_record,
)


def test_stage1389_model_snapshot_freezes_nested_state_and_materializes_deterministically() -> None:
    source = {
        "zeta": {"set_values": {"b", "a"}},
        "alpha": ["first", {"inner": 1.0}],
    }

    snapshot = make_model_snapshot(
        source,
        model_name="markov",
        snapshot_type="runtime_counts",
        model_version="stage1389_snapshot_v1",
    )
    source["alpha"].append("mutated")
    source["zeta"]["set_values"].add("c")

    with pytest.raises(TypeError):
        snapshot["ready"] = False  # type: ignore[index]
    with pytest.raises(TypeError):
        snapshot["values"]["alpha"] = ()  # type: ignore[index]

    materialized_first = materialize_model_snapshot(snapshot)
    materialized_second = materialize_model_snapshot(snapshot)

    assert materialized_first == materialized_second
    assert materialized_first["ready"] is True
    assert materialized_first["values"]["alpha"] == ("first", {"inner": 1.0})
    assert materialized_first["values"]["zeta"]["set_values"] == ("a", "b")


def test_stage1389_model_snapshot_records_bad_values_and_nonfinite_failures() -> None:
    snapshot = make_model_snapshot(
        {"score": math.inf, "nested": {"value": math.nan}},
        model_name="graph",
        snapshot_type="feature_snapshot",
        model_version="stage1389_snapshot_v1",
        failures=({"failure_score": math.inf},),
    )

    materialized = materialize_model_snapshot(snapshot)

    assert materialized["values"]["score"] is None
    assert materialized["values"]["score_unavailable_reason"] == "non_finite_model_snapshot_value"
    assert materialized["values"]["nested"]["value"] is None
    assert materialized["values"]["nested"]["value_unavailable_reason"] == "non_finite_model_snapshot_value"
    assert materialized["failures"][0]["failure_score"] is None


def test_stage1389_markov_probability_wrapper_is_immutable_and_rejects_invalid_probability() -> None:
    record = make_markov_probability_record(
        ready=True,
        probability=1.5,
        support=4,
        count=4,
        vocab=2,
        smoothing="laplace",
        reason="trained",
        source="a",
        target="b",
    )

    with pytest.raises(TypeError):
        record["probability"] = 0.5  # type: ignore[index]

    materialized = materialize_probability_record(record)

    assert materialized["ready"] is False
    assert materialized["probability"] is None
    assert materialized["probability_unavailable_reason"] == "out_of_bounds_probability"
    assert materialized["model_version"] == "markov_probability_v1"


def test_stage1389_specialized_model_evidence_records_are_canonical_and_immutable() -> None:
    records = (
        make_temporal_overlay_record({"ready": False, "reason": "cold_start"}),
        make_profile_evidence_record({"profile_valid": False, "reason": "invalid_profile"}),
        make_cluster_evidence_record({"assigned": False, "reason": "cold_start"}),
        make_graph_evidence_record({"edges": {"b", "a"}}),
    )

    expected_versions = (
        "temporal_overlay_record_v5",
        "profile_evidence_record_v1",
        "cluster_evidence_record_v1",
        "graph_evidence_record_v1",
    )
    for record, expected_version in zip(records, expected_versions, strict=True):
        with pytest.raises(TypeError):
            record["model_version"] = "mutated"  # type: ignore[index]
        materialized = materialize_model_evidence_record(record)
        assert materialized["model_name"]
        assert materialized["evidence_type"]
        assert materialized["model_version"] == expected_version

    assert materialize_model_evidence_record(records[-1])["edges"] == ("a", "b")


def test_stage1389_replay_model_comparison_record_freezes_expected_actual_and_mismatch() -> None:
    expected = {"probability": 0.2, "tags": {"alpha", "beta"}}
    actual = {"probability": 0.9, "tags": {"beta", "alpha"}}

    comparison = make_replay_model_comparison_record(
        model_name="markov",
        expected=expected,
        actual=actual,
        matched=False,
        mismatch_fields={"probability"},
    )
    expected["probability"] = 0.8
    actual["tags"].add("gamma")

    with pytest.raises(TypeError):
        comparison["matched"] = True  # type: ignore[index]

    materialized = materialize_replay_model_comparison_record(comparison)

    assert materialized["matched"] is False
    assert materialized["reason"] == "replay_model_evidence_mismatch"
    assert materialized["mismatch_fields"] == ("probability",)
    assert materialized["expected"]["probability"] == 0.2
    assert materialized["actual"]["tags"] == ("alpha", "beta")
