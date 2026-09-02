from __future__ import annotations

from Virus_Scan.models.temporal.anomaly import (
    temporal_flat_events,
    temporal_pair_anomaly,
    temporal_stage_sequence_anomaly,
)
from Virus_Scan.models.temporal.policy import (
    temporal_burst_policy_evidence,
    temporal_phase_progression_evidence,
)


class HostileTruthyText:
    touched = 0
    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("caller-owned text truthiness executed")
    def __str__(self) -> str:
        type(self).touched += 1
        raise RuntimeError("caller-owned text stringification executed")


class HostileFloat:
    touched = 0
    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("caller-owned numeric truthiness executed")
    def __float__(self) -> float:
        type(self).touched += 1
        raise RuntimeError("caller-owned numeric conversion executed")


class HostileIterable:
    touched = 0
    def __bool__(self) -> bool:
        type(self).touched += 1
        raise RuntimeError("caller-owned sequence truthiness executed")
    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError("caller-owned sequence iteration executed")


def test_temporal_policy_owners_reject_hostile_iterables_without_hooks() -> None:
    HostileIterable.touched = HostileTruthyText.touched = 0
    events = HostileIterable()

    phase = temporal_phase_progression_evidence(events)
    burst = temporal_burst_policy_evidence(events)

    assert HostileIterable.touched == 0
    assert HostileTruthyText.touched == 0
    assert phase["ready"] is False
    assert phase["strength"] == 0.0
    assert burst["ready"] is False
    assert burst["strength"] == 0.0


def test_temporal_event_and_markov_consumers_reject_hostile_values_without_hooks() -> None:
    HostileIterable.touched = HostileTruthyText.touched = HostileFloat.touched = 0
    events = temporal_flat_events(HostileIterable())

    assert events == ()
    assert temporal_pair_anomaly("asset", HostileIterable()) == 0.0
    assert temporal_stage_sequence_anomaly(
        HostileTruthyText(), HostileIterable(), HostileTruthyText(),
        HostileIterable(),
    ) == 0.0
    assert HostileIterable.touched == 0
    assert HostileTruthyText.touched == 0
    assert HostileFloat.touched == 0


def test_temporal_flat_events_preserves_primitives_with_explicit_time_provenance() -> None:
    events = temporal_flat_events(({
        "time": 2.0, "stage": "extract",
        "tags": ("api_loadurl", "api_exec"),
    },))

    assert tuple(event.behavior_id for event in events) == ("loadurl", "exec")
    assert events[0].timestamp_kind == "observed"
    assert events[0].timestamp_value == 2.0
    assert events[1].timestamp_kind == "synthetic_order"
    assert events[1].timestamp_value is None
    assert events[0].source_evidence_id == events[1].source_evidence_id
