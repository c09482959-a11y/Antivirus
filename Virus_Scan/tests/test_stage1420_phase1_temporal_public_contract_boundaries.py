from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.models.api import adaptive_signals, temporal_contracts
from Virus_Scan.models.contracts.model_feature_bundle import materialize_model_feature_bundle
from Virus_Scan.tests.support.profile_learning import accepted_learning_decision


class HostileBoolText:
    def __bool__(self):
        raise RuntimeError("hostile truthiness")

    def __str__(self):
        raise RuntimeError("hostile text")


class HostileMapping(Mapping):
    def __iter__(self):
        return iter(("ready", "score"))

    def __len__(self):
        return 2

    def __getitem__(self, key):
        if key == "ready":
            return False
        if key == "score":
            return 0.0
        raise KeyError(key)

    def __bool__(self):
        raise RuntimeError("hostile mapping truthiness")


def test_stage1420_temporal_overlay_records_hostile_stage_as_degraded_v5_evidence() -> None:
    result = temporal_contracts.transition_probability_overlay(
        prev_stage=HostileBoolText(), tags=("download", "execute"),
        curr_stage="runtime",
        ordered_events=(
            {"tag": "download", "timestamp": 1.0},
            {"tag": "execute", "timestamp": 2.0},
        ),
    )

    assert result["schema_version"] == "5.0"
    assert result["ready"] is False
    assert result["probability_ready"] is False
    assert result["degraded"] is True
    assert result["final_json_must_record"] is True
    assert result["replay_record_required"] is True
    assert result["stage_probability"] is None
    assert result["sequence_probability"] is None


def test_stage1420_temporal_validation_records_hostile_stage_as_degraded_evidence() -> None:
    result = temporal_contracts.compute_temporal_validation(
        "node:stage1420", tags=("download",), curr_stage=HostileBoolText(),
    )

    assert result["ready"] is False
    assert result["degraded"] is True
    assert result["unavailable_reason"] == "temporal_validation_public_call_failed"
    assert result["final_json_must_record"] is True
    assert result["replay_record_required"] is True


def test_stage1420_temporal_update_records_hostile_stage_as_degraded_evidence() -> None:
    result = temporal_contracts.update_temporal(
        "node:stage1420", HostileBoolText(), ("execute",),
        learning_decision=accepted_learning_decision(
            target_names=("temporal",), observation_id="stage1420-hostile-update",
        ),
    )

    assert result["updated"] is False
    assert result["ready"] is False
    assert result["degraded"] is True
    assert result["unavailable_reason"] == "invalid_temporal_update_output"
    assert result["final_json_must_record"] is True
    assert result["replay_record_required"] is True


def test_stage1420_adaptive_signal_freezer_does_not_probe_mapping_truthiness() -> None:
    frozen = adaptive_signals.immutable_adaptive_signal(
        HostileMapping(), model_version="stage1420_adaptive_signal_v1",
    )
    materialized = materialize_model_feature_bundle(frozen)

    assert materialized["model_version"] == "stage1420_adaptive_signal_v1"
    assert materialized["ready"] is False
    assert materialized["score"] == 0.0
