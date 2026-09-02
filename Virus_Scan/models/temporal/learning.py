"""Profiles-authorized construction of the single temporal v5 request."""
from __future__ import annotations

from Virus_Scan.contracts.temporal_accumulator import TemporalAccumulatorState
from Virus_Scan.contracts.temporal_event import (
    TemporalEvent,
    temporal_elapsed_seconds,
    temporal_source_record_digest,
)
from Virus_Scan.contracts.temporal_learning import (
    TEMPORAL_LEARNING_DISPOSITION,
    TEMPORAL_MODEL_VERSION,
    TemporalLearningRequest,
)
from Virus_Scan.models.contracts.learning_authority import (
    LearningDecision,
    learning_authorization_failure,
)
from Virus_Scan.models.temporal.accumulator import (
    temporal_evidence_accumulator_update,
)
from Virus_Scan.models.temporal.event_materialization import (
    materialize_temporal_events,
)
from Virus_Scan.runtime import model_state as runtime_model_state
from Virus_Scan.runtime.temporal_state import (
    commit_temporal_learning_request,
    invalidate_temporal_cache,
    temporal_node_state_snapshot,
    temporal_state_node_key,
)


def _observed_pair_facts(
    events: tuple[TemporalEvent, ...],
) -> tuple[int, float, float | None]:
    confidences: list[float] = []
    timestamps: list[float] = []
    for previous, current in zip(events, events[1:], strict=False):
        delay, reason = temporal_elapsed_seconds(previous, current)
        if delay is None or reason is not None:
            continue
        if previous.stage == "unknown" or current.stage == "unknown":
            continue
        confidences.append(min(
            previous.ordering_confidence, current.ordering_confidence,
        ))
        assert current.timestamp_value is not None
        timestamps.append(float(current.timestamp_value))
    count = len(confidences)
    confidence = (
        sum(confidences) / count * min(1.0, count / 4.0)
        if count else 0.0
    )
    return count, confidence, max(timestamps) if timestamps else None


def _next_accumulator_state(
    node_id: str, events: tuple[TemporalEvent, ...],
) -> TemporalAccumulatorState:
    snapshot = temporal_node_state_snapshot(temporal_state_node_key(node_id))
    prior_record = snapshot.get("hidden_state")
    prior = TemporalAccumulatorState.from_record(dict(prior_record))
    observed_pairs, confidence, timestamp = _observed_pair_facts(events)
    return temporal_evidence_accumulator_update(
        previous=prior,
        observation=0.0,
        observation_confidence=confidence,
        evidence_timestamp=timestamp,
        support=prior.support + observed_pairs,
    )


def build_temporal_learning_request(
    *,
    learning_decision: object,
    node: object,
    previous_stage: object,
    current_stage: object,
    ordered_events: object,
    behavior_flow: object,
) -> tuple[TemporalLearningRequest, tuple[dict[str, object], ...]]:
    """Convert one exact profiles decision into the neutral v5 request."""
    if type(learning_decision) is not LearningDecision:
        raise ValueError("temporal learning decision required")
    learning_decision.validate()
    if not learning_decision.authorizes("temporal"):
        raise ValueError("temporal learning decision unauthorized")
    events, validations = materialize_temporal_events(
        ordered_events=ordered_events,
        behavior_flow=behavior_flow,
        observation_id=learning_decision.observation_id,
        previous_stage=previous_stage,
        current_stage=current_stage,
    )
    if not events:
        raise ValueError("temporal events unavailable")
    node_id = node if type(node) is str and node != "" else "<unknown>"
    previous = (
        str.__str__(previous_stage)
        if type(previous_stage) is str and previous_stage != "" else "unknown"
    )
    current = (
        str.__str__(current_stage)
        if type(current_stage) is str and current_stage != "" else "unknown"
    )
    request = TemporalLearningRequest(
        observation_id=learning_decision.observation_id,
        observation_digest=learning_decision.observation_digest,
        source_record_digest=temporal_source_record_digest(events),
        node_id=node_id,
        previous_stage=previous,
        current_stage=current,
        engine=learning_decision.engine,
        context_identity=learning_decision.context_identity,
        events=events,
        accumulator_state=_next_accumulator_state(node_id, events),
        learning_disposition=TEMPORAL_LEARNING_DISPOSITION,
        disposition_provenance=(
            learning_decision.schema_version + ":"
            + learning_decision.gate_version + ":"
            + learning_decision.reason
        ),
        gate_version=learning_decision.gate_version,
        decision_ordinal=learning_decision.decision_ordinal,
        replay_key=learning_decision.replay_key,
    )
    request.validate()
    return request, tuple(validation.to_record() for validation in validations)


def commit_temporal_runtime_learning(
    *,
    learning_decision: object,
    node: object,
    previous_stage: object,
    current_stage: object,
    ordered_events: object,
    behavior_flow: object,
) -> dict[str, object]:
    """Commit one canonical request to runtime state at most once."""
    reason = learning_authorization_failure(learning_decision, "temporal")
    if reason is not None:
        return {
            "updated": False,
            "reason": reason,
            "ready": False,
            "degraded": True,
            "unavailable_reason": reason,
        }
    try:
        request, validations = build_temporal_learning_request(
            learning_decision=learning_decision,
            node=node,
            previous_stage=previous_stage,
            current_stage=current_stage,
            ordered_events=ordered_events,
            behavior_flow=behavior_flow,
        )
        applied = commit_temporal_learning_request(request)
    except (TypeError, ValueError) as error:
        reason = (
            "no_behavior_flow"
            if error.args == ("temporal events unavailable",)
            else "temporal_learning_request_invalid"
        )
        return {
            "updated": False,
            "reason": reason,
            "node": temporal_state_node_key(node),
            "previous_stage": (
                str.__str__(previous_stage)
                if type(previous_stage) is str and previous_stage else "unknown"
            ),
            "stage": (
                str.__str__(current_stage)
                if type(current_stage) is str and current_stage else "unknown"
            ),
            "flow": (),
            "events": (),
            "event_validations": (),
            "ready": False,
            "degraded": True,
            "unavailable_reason": reason,
            "temporal_model_version": TEMPORAL_MODEL_VERSION,
        }
    if applied:
        invalidate_temporal_cache(request.node_id, node)
        runtime_model_state.mark_runtime_models_dirty()
    return {
        "updated": True,
        "reason": None,
        "node": request.node_id,
        "previous_stage": request.previous_stage,
        "stage": request.current_stage,
        "flow": tuple(event.behavior_id for event in request.events),
        "events": tuple(event.to_record() for event in request.events),
        "event_validations": validations,
        "hidden_state": request.accumulator_state.to_record(),
        "source_record_digest": request.source_record_digest,
        "learning_disposition": request.learning_disposition,
        "idempotent_replay": not applied,
        "ready": True,
        "degraded": any(row["status"] != "valid" for row in validations),
        "unavailable_reason": None,
        "temporal_model_version": TEMPORAL_MODEL_VERSION,
    }


__all__ = (
    "build_temporal_learning_request",
    "commit_temporal_runtime_learning",
)
