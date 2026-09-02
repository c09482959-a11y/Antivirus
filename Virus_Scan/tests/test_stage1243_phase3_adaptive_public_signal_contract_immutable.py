from __future__ import annotations

from collections.abc import Mapping

import pytest

from Virus_Scan.models.api import adaptive_signals
from Virus_Scan.models.contracts.model_evidence import (
    make_model_evidence_record,
    materialize_model_evidence_record,
)
from Virus_Scan.models.contracts.model_feature_bundle import (
    make_model_feature_bundle,
    materialize_model_feature_bundle,
)


def _assert_immutable_mapping(record: Mapping[str, object], *, expected_version: str) -> None:
    assert isinstance(record, Mapping)
    assert not isinstance(record, dict)
    assert record["model_version"] == expected_version
    with pytest.raises(TypeError):
        record["model_version"] = "mutated"  # type: ignore[index]


def test_stage1243_public_adaptive_signal_wrappers_freeze_model_owned_dicts() -> None:
    graph = adaptive_signals.compute_graph_relationship_layer(None, tags=["alpha", "beta"])
    cluster = adaptive_signals.adaptive_cluster_signal(None, ["alpha"])
    context_cluster = adaptive_signals.context_cluster_quality(None, ["alpha"])
    profile = adaptive_signals.adaptive_profile_signal("sample.txt", ["alpha"])
    extension = adaptive_signals.extension_profile_anomaly("other", "sample.txt", ["alpha"], 0.0)
    coordinated = adaptive_signals.coordinated_model_validation_signal("other", "sample.txt", ["alpha", "beta"])

    _assert_immutable_mapping(graph, expected_version="graph_relationship_adaptive_signal_v1")
    _assert_immutable_mapping(cluster, expected_version="cluster_adaptive_signal_v1")
    _assert_immutable_mapping(context_cluster, expected_version="cluster_context_quality_adaptive_signal_v1")
    _assert_immutable_mapping(profile, expected_version="profile_adaptive_signal_v1")
    _assert_immutable_mapping(extension, expected_version="profile_extension_anomaly_adaptive_signal_v1")
    _assert_immutable_mapping(coordinated, expected_version="profile_coordinated_validation_adaptive_signal_v1")

    nested = graph["graph_features"]
    assert isinstance(nested, Mapping)
    assert not isinstance(nested, dict)
    with pytest.raises(TypeError):
        nested["risk"] = 1.0  # type: ignore[index]


def test_stage1243_model_feature_contract_sorts_sets_deterministically() -> None:
    bundle = make_model_feature_bundle(
        {
            "unordered": {"beta", "alpha", "gamma"},
            "nested": {"items": {"zeta", "eta"}},
        },
        model_version="deterministic_set_contract_v1",
    )

    first = materialize_model_feature_bundle(bundle)
    second = materialize_model_feature_bundle(bundle)

    assert first == second
    assert first["unordered"] == ("alpha", "beta", "gamma")
    assert first["nested"]["items"] == ("eta", "zeta")


def test_stage1243_model_evidence_contract_sorts_sets_deterministically() -> None:
    evidence = make_model_evidence_record(
        {
            "unordered": {"delta", "alpha", "charlie"},
            "nested": {"items": {"two", "one"}},
        },
        model_name="contract_test",
        evidence_type="immutability",
        model_version="deterministic_evidence_set_contract_v1",
    )

    materialized = materialize_model_evidence_record(evidence)

    assert materialized["unordered"] == ("alpha", "charlie", "delta")
    assert materialized["nested"]["items"] == ("one", "two")
    with pytest.raises(TypeError):
        evidence["unordered"] = ()  # type: ignore[index]
