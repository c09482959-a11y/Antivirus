"""Canonical v5 temporal test-record builders."""
from __future__ import annotations

import hashlib

from Virus_Scan.contracts.temporal_accumulator import (
    TemporalAccumulatorState,
    initial_temporal_accumulator_state,
)
from Virus_Scan.contracts.temporal_event import (
    TemporalEvent,
    temporal_source_record_digest,
)
from Virus_Scan.contracts.temporal_learning import (
    TEMPORAL_LEARNING_DISPOSITION,
    TemporalLearningRequest,
)


def temporal_v5_event(
    *, event_id: str, source_evidence_id: str, behavior_id: str,
    stage: str, source_ordinal: int, timestamp_value: float | None = None,
    timestamp_kind: str = "ordinal_only", clock_domain: str = "ordinal",
    ordering_confidence: float = 0.5,
) -> TemporalEvent:
    event = TemporalEvent(
        event_id=event_id,
        source_evidence_id=source_evidence_id,
        behavior_id=behavior_id,
        stage=stage,
        timestamp_value=timestamp_value,
        timestamp_kind=timestamp_kind,
        clock_domain=clock_domain,
        ordering_confidence=ordering_confidence,
        source_ordinal=source_ordinal,
        provenance=(("builder", "tests_temporal_v5"),),
    )
    event.validate()
    return event


def temporal_v5_request(
    *, node_id: str, events: tuple[TemporalEvent, ...],
    accumulator_state: TemporalAccumulatorState | None = None,
    decision_ordinal: int = 1, engine: str = "other",
) -> TemporalLearningRequest:
    observation_id = "test-observation:" + node_id
    observation_digest = hashlib.sha256(observation_id.encode("utf-8")).hexdigest()
    source_record_digest = temporal_source_record_digest(events)
    replay_key = hashlib.sha256(
        (observation_id + ":" + str(decision_ordinal)).encode("utf-8")
    ).hexdigest()
    request = TemporalLearningRequest(
        observation_id=observation_id,
        observation_digest=observation_digest,
        source_record_digest=source_record_digest,
        node_id=node_id,
        previous_stage=events[0].stage,
        current_stage=events[-1].stage,
        engine=engine,
        context_identity=(("engine", engine),),
        events=events,
        accumulator_state=(
            accumulator_state or initial_temporal_accumulator_state()
        ),
        learning_disposition=TEMPORAL_LEARNING_DISPOSITION,
        disposition_provenance="test_profiles_authority",
        gate_version="test_learning_gate_v5",
        decision_ordinal=decision_ordinal,
        replay_key=replay_key,
    )
    request.validate()
    return request
