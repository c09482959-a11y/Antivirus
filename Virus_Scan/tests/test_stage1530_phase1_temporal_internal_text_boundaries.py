"""Stage 1530 temporal exact-text boundary regressions for v5 owners."""
from __future__ import annotations

from Virus_Scan.models.temporal.anomaly import temporal_flat_events
from Virus_Scan.models.temporal.evidence import cache_key
from Virus_Scan.models.temporal.policy import temporal_phase_progression_evidence
from Virus_Scan.models.temporal.text_boundary import (
    TEMPORAL_TEXT_UNAVAILABLE,
    temporal_boundary_text,
)
from Virus_Scan.models.temporal.validation import compute_temporal_validation


class HostileText(str):
    def __new__(cls, value: str):
        obj = str.__new__(cls, value)
        obj.str_calls = obj.strip_calls = obj.bool_calls = 0
        return obj
    def __str__(self):
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")
    def strip(self, *args, **kwargs):
        self.strip_calls += 1
        raise AssertionError("caller-owned strip() was invoked")
    def __bool__(self):
        self.bool_calls += 1
        raise AssertionError("caller-owned truthiness was invoked")


class HostileObject:
    def __init__(self):
        self.str_calls = self.bool_calls = 0
    def __str__(self):
        self.str_calls += 1
        raise AssertionError("caller-owned __str__ was invoked")
    def __bool__(self):
        self.bool_calls += 1
        raise AssertionError("caller-owned truthiness was invoked")


def test_stage1530_temporal_evidence_text_boundaries_do_not_invoke_hostile_hooks() -> None:
    namespace = HostileText("temporal")
    hostile_part = HostileObject()
    reason = HostileObject()
    assert cache_key(namespace, hostile_part) == f"temporal:{TEMPORAL_TEXT_UNAVAILABLE}"
    assert temporal_boundary_text(reason) == TEMPORAL_TEXT_UNAVAILABLE
    assert (namespace.str_calls, namespace.strip_calls, namespace.bool_calls) == (0, 0, 0)
    assert (hostile_part.str_calls, hostile_part.bool_calls) == (0, 0)
    assert (reason.str_calls, reason.bool_calls) == (0, 0)


def test_stage1530_temporal_event_and_policy_boundaries_use_exact_text() -> None:
    stage = HostileText("asset")
    tag = HostileText("download")
    hostile_phase = HostileObject()

    events = temporal_flat_events(({
        "time": 1.0, "stage": stage, "tags": (tag,),
    },))
    phase = temporal_phase_progression_evidence((hostile_phase,))

    assert len(events) == 1
    assert events[0].timestamp_value == 1.0
    assert events[0].stage == "asset"
    assert events[0].behavior_id == "download"
    assert phase["ready"] is False
    assert phase["strength"] == 0.0
    assert (stage.str_calls, stage.strip_calls, stage.bool_calls) == (0, 0, 0)
    assert (tag.str_calls, tag.strip_calls, tag.bool_calls) == (0, 0, 0)
    assert (hostile_phase.str_calls, hostile_phase.bool_calls) == (0, 0)


def test_stage1530_temporal_validation_materializes_v5_events_without_hostile_str() -> None:
    prev_stage = HostileText("asset")
    curr_stage = HostileText("runtime")
    tag = HostileText("credential_access")

    result = compute_temporal_validation(
        "stage1530-node", tags=(tag,), prev_stage=prev_stage,
        curr_stage=curr_stage,
        markov={"transition": 0.0, "rarity": 0.0,
                "pair_anomaly": 0.0, "sequence_anomaly": 0.0},
    )

    assert result["events"] == ()
    assert result["evidence_type"] == "temporal_validation"
    assert result["ready"] is False
    assert result["unavailable_reason"] == "cold_start_no_temporal_validation_support"
    assert prev_stage.str_calls == curr_stage.str_calls == tag.str_calls == 0
