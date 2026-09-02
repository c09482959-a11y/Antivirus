from __future__ import annotations

from collections.abc import Mapping

import pytest

from Virus_Scan.contracts.detection_observation import DetectionObservation, ObservationSourceLocation
from Virus_Scan.models.markov import canonical_behavior_flow


class HostileBoolEvidence(Mapping):
    def __iter__(self):
        return iter(("url",))

    def __len__(self):
        return 1

    def __getitem__(self, key):
        if key == "url":
            return "https://example.invalid/payload"
        raise KeyError(key)

    def __bool__(self):
        raise RuntimeError("caller-owned evidence truthiness must not run")


class UnreadableEvidenceValue(Mapping):
    def keys(self):
        return ("bad",)

    def __iter__(self):
        return iter(("bad",))

    def __len__(self):
        return 1

    def __getitem__(self, key):
        raise RuntimeError("unreadable evidence value")

    def get(self, key, default=None):
        raise RuntimeError("unreadable evidence value")


class HostileEvidenceObservation(Mapping):
    def __iter__(self):
        return iter(("tag", "evidence"))

    def __len__(self):
        return 2

    def __getitem__(self, key):
        if key == "tag":
            return "api_network_download"
        if key == "evidence":
            return HostileBoolEvidence()
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default



def test_stage1478_direct_observation_rejects_hostile_bool_evidence_without_hooks() -> None:
    with pytest.raises(TypeError):
        DetectionObservation.create(
            tag="api_loadurl",
            producer_id="unit",
            stage_id="unit",
            modality="static_structure",
            artifact_identity="sha256:stage1478",
            source_location=ObservationSourceLocation("event", event_id="api_loadurl"),
            evidence=HostileBoolEvidence(),
        )


def test_stage1478_unreadable_evidence_value_is_rejected_without_hooks() -> None:
    with pytest.raises(TypeError):
        DetectionObservation.create(
            tag="api_loadurl",
            producer_id="unit",
            stage_id="unit",
            modality="static_structure",
            artifact_identity="sha256:stage1478",
            source_location=ObservationSourceLocation("event", event_id="api_loadurl"),
            evidence=UnreadableEvidenceValue(),
        )


def test_stage1478_hostile_mapping_evidence_does_not_erase_markov_behavior_flow() -> None:
    flow = canonical_behavior_flow([HostileEvidenceObservation(), "process_exec"])

    assert flow == ("process_exec",)

from Virus_Scan.models.temporal.api import (
    compute_temporal_validation,
    transition_probability_overlay,
)


class HostileBoolObservation(Mapping):
    def __init__(self, tag: str = "api_network_download") -> None:
        self._tag = tag

    def __iter__(self):
        return iter(("tag",))

    def __len__(self):
        return 1

    def __getitem__(self, key):
        if key == "tag":
            return self._tag
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __bool__(self):
        raise RuntimeError("temporal owner must not truth-test caller mapping observations")


class HostileBoolTimes:
    touched = 0

    def __iter__(self):
        HostileBoolTimes.touched += 1
        raise RuntimeError("temporal owner must not iterate caller event times")

    def __bool__(self):
        HostileBoolTimes.touched += 1
        raise RuntimeError("temporal owner must not truth-test caller event times")



def test_stage1478_temporal_overlay_rejects_single_hostile_mapping_observation() -> None:
    overlay = transition_probability_overlay(tags=HostileBoolObservation())

    assert overlay["flow"] == ()
    assert overlay["degraded"] in {False, True}
    assert overlay["temporal_model_version"]



def test_stage1478_temporal_validation_rejects_single_hostile_mapping_observation() -> None:
    validation = compute_temporal_validation(
        "stage1478-node",
        tags=HostileBoolObservation("process_injection"),
        prev_stage="extract",
        curr_stage="analysis",
    )

    assert validation["events"] == ()
    assert validation["evidence_type"] == "temporal_validation"



def test_stage1478_temporal_overlay_rejects_hostile_ordered_events_without_hooks() -> None:
    HostileBoolTimes.touched = 0
    overlay = transition_probability_overlay(
        tags=("process_injection", "memory_write"),
        ordered_events=HostileBoolTimes(),
    )

    assert HostileBoolTimes.touched == 0
    assert overlay["degraded"] is True
    assert overlay["unavailable_reason"] == "temporal_ordered_events_unavailable"
    assert overlay["probability_ready"] is False
    assert len(overlay["pair_probabilities"]) == 1
    assert overlay["pair_probabilities"][0]["probability"] is None
    assert overlay["pair_probabilities"][0]["elapsed_time_used"] is False
    assert overlay["events"] == ()

from Virus_Scan.models.temporal.anomaly import (
    temporal_flat_events,
    temporal_pair_anomaly,
    temporal_stage_sequence_anomaly,
)


class HostileSequence:
    def __bool__(self):
        raise RuntimeError("temporal anomaly helpers must not truth-test caller sequences")

    def __iter__(self):
        raise RuntimeError("temporal anomaly helpers must bound unreadable caller sequences")


class HostileEvent(Mapping):
    def __iter__(self):
        return iter(("tag", "time", "tags"))

    def __len__(self):
        return 3

    def __getitem__(self, key):
        if key == "tag":
            return "api_network_download"
        if key == "time":
            return 1.0
        if key == "tags":
            return HostileBoolObservation("process_injection")
        raise KeyError(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __bool__(self):
        raise RuntimeError("temporal event mappings must not be truth-tested")



def test_stage1478_temporal_anomaly_markov_delegates_bound_hostile_sequences() -> None:
    assert temporal_pair_anomaly("asset", HostileSequence()) == 0.0
    assert temporal_stage_sequence_anomaly("extract", HostileSequence(), "analysis", HostileSequence()) == 0.0



def test_stage1478_temporal_anomaly_event_helpers_do_not_truthiness_probe_event_mappings() -> None:
    flattened = temporal_flat_events((HostileEvent(),))
    assert flattened == ()
