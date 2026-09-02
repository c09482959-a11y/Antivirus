"""Stage 1404: hostile mappings/paths remain degraded model evidence."""

from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.models.api import (
    adaptive_signals,
    graph_contracts,
    profile_retention_contracts,
    replay_comparison_contracts,
    replay_economics_contracts,
    replay_learning,
)


class HostileMapping(Mapping):
    def __iter__(self):
        raise RuntimeError("mapping iteration unavailable")

    def __len__(self):
        raise RuntimeError("mapping length unavailable")

    def __getitem__(self, key):
        raise RuntimeError("mapping item unavailable")

    def keys(self):
        raise RuntimeError("mapping keys unavailable")

    def items(self):
        raise RuntimeError("mapping items unavailable")

    def __str__(self):
        raise RuntimeError("mapping string unavailable")

    def __repr__(self):
        return "<HostileMapping>"


class HostilePath:
    def __fspath__(self):
        raise RuntimeError("path conversion unavailable")

    def __str__(self):
        raise RuntimeError("path string unavailable")

    def __repr__(self):
        return "<HostilePath>"


class HostileValue:
    def __iter__(self):
        raise RuntimeError("iteration unavailable")

    def __str__(self):
        raise RuntimeError("string unavailable")

    def __repr__(self):
        return "<HostileValue>"


def test_stage1404_retention_and_graph_public_boundaries_absorb_hostile_objects() -> None:
    hostile_mapping = HostileMapping()
    hostile_path = HostilePath()

    engine_profile = profile_retention_contracts.prune_engine_profile_for_retention(hostile_mapping)
    assert engine_profile["ready"] is False
    assert engine_profile["degraded"] is True
    assert engine_profile["final_json_must_record"] is True
    assert engine_profile["replay_record_required"] is True

    extension_baseline = profile_retention_contracts.prune_extension_baseline_for_retention(hostile_mapping)
    assert extension_baseline["ready"] is False
    assert extension_baseline["unavailable_reason"] == "non_mapping_extension_baseline_retention_input"

    staged = profile_retention_contracts.prune_staged_benign_store(hostile_mapping)
    assert staged["ready"] is False
    assert staged["unavailable_reason"] == "non_mapping_staged_benign_retention_input"

    assert graph_contracts.scan_cs(hostile_path) == ["graph_cs_scan_unavailable"]


def test_stage1404_replay_public_boundaries_absorb_hostile_mappings() -> None:
    hostile_mapping = HostileMapping()

    comparison = replay_comparison_contracts.compare_model_evidence(
        model_name="hostile_mapping",
        expected=hostile_mapping,
        actual=hostile_mapping,
    )
    assert comparison["matched"] is False
    assert comparison["mismatch_fields"] == ("actual", "expected")
    assert comparison["expected_unavailable_reason"] == "model_evidence_mapping_unreadable"
    assert comparison["actual_unavailable_reason"] == "model_evidence_mapping_unreadable"

    materialized = replay_comparison_contracts.materialize_model_evidence_comparison(hostile_mapping)
    assert materialized["matched"] is False
    assert materialized["record_unavailable_reason"] == "unreadable_replay_model_comparison_record"
    assert materialized["mismatch_fields"] == ("record",)

    assert replay_economics_contracts.replay_should_retain(hostile_mapping) is True

    replay_result = replay_learning.persist_parent_learning_from_results(hostile_mapping)
    assert replay_result["errors"] == 1
    assert replay_result["degraded"] is True
    assert replay_result["final_json_must_record"] is True
    assert replay_result["replay_record_required"] is True


def test_stage1404_adaptive_profile_public_signals_absorb_hostile_values() -> None:
    hostile = HostileValue()

    assert adaptive_signals.get_graph_risk_enhanced(hostile) == 0.0

    profile = adaptive_signals.adaptive_profile_signal(hostile, hostile)
    assert profile["ready"] is False
    assert profile["degraded"] is True
    assert profile["evidence_type"] == "profile_adaptive_signal"
    assert profile["final_json_must_record"] is True
    assert profile["replay_record_required"] is True

    anomaly = adaptive_signals.extension_profile_anomaly(
        hostile,
        hostile,
        hostile,
        hostile,
        api_calls=hostile,
        ordered_events=hostile,
    )
    assert anomaly["ready"] is False
    assert anomaly["degraded"] is True
    assert anomaly["evidence_type"] == "profile_extension_anomaly"

    coordinated = adaptive_signals.coordinated_model_validation_signal(
        hostile,
        hostile,
        hostile,
        api_calls=hostile,
        ordered_events=hostile,
    )
    assert coordinated["ready"] is False
    assert coordinated["degraded"] is True
    assert coordinated["evidence_type"] == "profile_coordinated_validation"
