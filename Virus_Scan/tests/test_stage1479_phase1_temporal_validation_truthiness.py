from __future__ import annotations

from Virus_Scan.tests.support.canonical_chain_fixtures import physical_tag_evidence
from collections.abc import Mapping

from Virus_Scan.models.temporal.validation import compute_temporal_validation


class HostileTruthyText:
    touched = 0

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("caller-owned truthiness executed")

    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("caller-owned stringification executed")


class HostileIterable:
    touched = 0

    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("caller-owned sequence truthiness executed")

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned sequence iteration executed")


class HostileMarkov(Mapping):
    def __getitem__(self, key: object) -> object:
        raise RuntimeError("caller-owned markov mapping item failed")

    def __iter__(self):
        return iter(("transition", "rarity"))

    def __len__(self) -> int:
        raise RuntimeError("caller-owned markov mapping truthiness executed")


def test_compute_temporal_validation_rejects_hostile_tag_iterable_without_hooks() -> None:
    HostileIterable.touched = 0
    HostileTruthyText.touched = 0
    result = compute_temporal_validation(
        "node-stage1479", tags=HostileIterable(),
        prev_stage=HostileTruthyText(), curr_stage=HostileTruthyText(),
    )

    assert HostileIterable.touched == 0
    assert HostileTruthyText.touched == 0
    assert result["evidence_type"] == "temporal_validation"
    assert result["events"] == ()
    assert result["ready"] is False
    assert result["unavailable_reason"] == "cold_start_no_temporal_validation_support"


def test_compute_temporal_validation_preserves_exact_primitive_tags() -> None:
    result = compute_temporal_validation(
        "node-stage1479", tags=physical_tag_evidence(("api_loadurl", "api_exec"), source_detector="stage1479"),
        prev_stage="extract", curr_stage="scan",
    )

    assert result["evidence_type"] == "temporal_validation"
    assert result["events"]
    assert {event["behavior_id"] for event in result["events"]} == {"loadurl", "exec"}
    assert all(event["schema_version"] == "temporal_event_v5" for event in result["events"])
    assert result["markov_transition_evidence"]["ready"] is False
    assert result["markov_transition_evidence"]["unavailable_reason"] == "insufficient_markov_stage_support"


def test_compute_temporal_validation_records_unavailable_markov_mapping_without_crash() -> None:
    result = compute_temporal_validation(
        "node-stage1479-markov", tags=physical_tag_evidence(("api_loadurl",), source_detector="stage1479"),
        prev_stage="extract", curr_stage="scan", markov=HostileMarkov(),
    )

    assert result["degraded"] is True
    assert result["unavailable_reason"] == "markov_features_invalid"
    assert "temporal_markov_feature_failure_evidence" in result["hits"]
