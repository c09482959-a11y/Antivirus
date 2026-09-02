"""Markov-owned anomaly consumption and canonical event materialization."""
from __future__ import annotations

from Virus_Scan.contracts.temporal_event import TemporalEvent
from Virus_Scan.models.api.markov_contracts import (
    canonical_behavior_flow,
    markov_transition_score,
    tag_pair_anomaly,
)
from Virus_Scan.models.temporal.event_materialization import (
    materialize_temporal_events,
)
from Virus_Scan.models.temporal.text_boundary import temporal_boundary_stage
from Virus_Scan.utils.probability import safe_probability_score


def temporal_pair_anomaly(previous_stage: object, flow: object) -> float:
    sequence = canonical_behavior_flow(flow)
    stage = temporal_boundary_stage(previous_stage, default="unknown")
    return safe_probability_score(
        tag_pair_anomaly(sequence, prev_stage=stage)
    )


def temporal_stage_sequence_anomaly(
    s1: object, flow1: object, s2: object, flow2: object,
) -> float:
    combined = canonical_behavior_flow(
        tuple(canonical_behavior_flow(flow1))
        + tuple(canonical_behavior_flow(flow2))
    )
    return safe_probability_score(markov_transition_score(
        temporal_boundary_stage(s1, default="unknown"),
        combined,
        temporal_boundary_stage(s2, default="unknown"),
    ))


def temporal_flat_events(timeline: object) -> tuple[TemporalEvent, ...]:
    """Materialize canonical events without synthetic numeric timestamps."""
    events, _validations = materialize_temporal_events(
        ordered_events=timeline,
        behavior_flow=(),
        observation_id="temporal_flat_events",
        previous_stage="unknown",
        current_stage="unknown",
    )
    return events


__all__ = (
    "temporal_flat_events",
    "temporal_pair_anomaly",
    "temporal_stage_sequence_anomaly",
)
