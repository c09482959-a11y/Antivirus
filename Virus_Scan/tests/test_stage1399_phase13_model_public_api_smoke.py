"""Stage 1399: Phase 13 model public API smoke coverage."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from Virus_Scan.models import api as model_api
from Virus_Scan.models.api import (
    clustering_contracts,
    graph_contracts,
    markov_contracts,
    profile_contracts,
    replay_comparison_contracts,
    replay_economics_contracts,
    replay_learning,
    temporal_contracts,
)
from Virus_Scan.models.api.replay_comparison_contracts import materialize_model_evidence_comparison
from Virus_Scan.runtime.cluster_state import ClusterStateNotConfigured


def _assert_public_smoke_result(name: str, value: object) -> None:
    assert value is not None or name.endswith("update_temporal"), name
    if isinstance(value, Mapping):
        assert value, name


def test_stage1399_core_model_public_api_exports_are_registered() -> None:
    required = {
        "markov_contracts",
        "temporal_contracts",
        "profile_contracts",
        "clustering_contracts",
        "graph_contracts",
        "replay_comparison_contracts",
        "replay_economics_contracts",
        "replay_learning",
    }

    assert required <= set(model_api.__all__)


def test_stage1399_model_public_api_smoke_returns_evidence_or_typed_exceptions(tmp_path: Path) -> None:
    cs_file = tmp_path / "sample.cs"
    cs_file.write_text("class A { void B() { eval(\"x\"); } }", encoding="utf-8")
    smoke_cases = {
        "markov_pair_probability": lambda: markov_contracts.markov_pair_probability("source", "target"),
        "markov_stage_probability": lambda: markov_contracts.markov_stage_probability("prev", ["tag"], "curr"),
        "markov_sequence_probability": lambda: markov_contracts.markov_sequence_probability("prev", ["tag"], "curr"),
        "compute_markov_features": lambda: markov_contracts.compute_markov_features("prev", ["tag"], "curr"),
        "temporal_validation": lambda: temporal_contracts.compute_temporal_validation("node", tags=["tag"], prev_stage="prev", curr_stage="curr"),
        "temporal_overlay": lambda: temporal_contracts.transition_probability_overlay(prev_stage="prev", tags=["tag"], curr_stage="curr", ordered_events=[{"tag": "tag", "timestamp": "malformed"}]),
        "temporal_snapshot": lambda: temporal_contracts.snapshot_temporal("node"),
        "profile_default": lambda: profile_contracts.default_engine_profile("renpy"),
        "profile_baseline": lambda: profile_contracts.get_extension_baseline("renpy", "sample.rpy"),
        "profile_corruption": lambda: profile_contracts.profile_corruption_events_snapshot(),
        "cluster_record_load": lambda: clustering_contracts.load_cluster_runtime_model_record(None),
        "cluster_vector_update": lambda: clustering_contracts.online_vector_update({}, []),
        "graph_relationship": lambda: graph_contracts.compute_graph_relationship_layer("node", tags=["tag"]),
        "graph_risk": lambda: graph_contracts.get_graph_risk_enhanced("node"),
        "graph_scan_cs": lambda: graph_contracts.scan_cs(cs_file),
        "replay_compare": lambda: replay_comparison_contracts.compare_model_evidence(model_name="markov", expected={"ready": False}, actual={"ready": True}),
        "replay_should_retain": lambda: replay_economics_contracts.replay_should_retain({}),
        "replay_compress": lambda: replay_economics_contracts.replay_compress_metadata({"b": [2], "a": 1}),
        "replay_learning": lambda: replay_learning.persist_parent_learning_from_results([]),
    }

    for name, call in smoke_cases.items():
        try:
            result = call()
        except (profile_contracts.ProfileSchemaInvariantError, ClusterStateNotConfigured) as exc:
            assert str(exc), name
            continue
        except (NameError, AttributeError) as exc:  # pragma: no cover - regression guard
            pytest.fail(f"{name} raised invalid public API failure: {exc}")
        _assert_public_smoke_result(name, result)


def test_stage1399_replay_public_api_malformed_materializes_typed_unavailable_evidence() -> None:
    comparison = replay_comparison_contracts.compare_model_evidence(
        model_name="profile",
        expected=None,
        actual={"ready": False, "reason": "cold_start"},
    )

    materialized = materialize_model_evidence_comparison(comparison)

    assert materialized["matched"] is False
    assert materialized["expected_unavailable_reason"] == "non_mapping_replay_expected"
    assert materialized["mismatch_fields"] == ("expected",)
