"""Canonical projection of immutable temporal runtime evidence."""
from __future__ import annotations

from Virus_Scan.contracts.temporal_accumulator import TemporalAccumulatorState
from Virus_Scan.contracts.temporal_event import TemporalEvent
from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.models.temporal.accumulator import (
    TEMPORAL_ACCUMULATOR_VERSION,
    temporal_evidence_accumulator_update,
)
from Virus_Scan.models.temporal.anomaly import (
    temporal_pair_anomaly,
    temporal_stage_sequence_anomaly,
)
from Virus_Scan.models.temporal.learning import commit_temporal_runtime_learning
from Virus_Scan.runtime.temporal_state import (
    temporal_history_snapshot,
    temporal_node_state_snapshot,
    temporal_state_node_key,
)
from Virus_Scan.utils.probability import safe_probability_score


def build_temporal_history_timeline(node: object) -> list[dict[str, object]]:
    """Publish canonical event records; order-only values remain nonnumeric."""
    return [
        event.to_record()
        for event in temporal_history_snapshot(temporal_state_node_key(node))
    ]


def _chain_event(event: TemporalEvent) -> dict[str, object]:
    row: dict[str, object] = {
        "term": event.behavior_id,
        "evidence_id": event.event_id,
        "root_evidence_id": event.source_evidence_id,
        "stage": event.stage,
    }
    if event.supports_elapsed_time:
        row["timestamp"] = event.timestamp_value
    return row


def detect_sequence_patterns(node: object) -> tuple[float, list[str]]:
    """Publish chain identities from the external chain owner without scoring."""
    history = temporal_history_snapshot(temporal_state_node_key(node))
    if not history:
        return 0.0, []
    evidence = evaluate_chain_evidence(
        ordered_events=tuple(_chain_event(event) for event in history),
        match_modes=("ordered",),
    )
    return 0.0, [
        decision.candidate.chain_id for decision in evidence.decisions
        if decision.status in {"confirmed", "candidate"}
    ][:10]


def explain_temporal_drift(node: object) -> list[str]:
    history = temporal_history_snapshot(temporal_state_node_key(node))
    rows: list[str] = []
    for previous, current in zip(history, history[1:], strict=False):
        if previous.stage != current.stage:
            rows.append(previous.stage + " -> " + current.stage)
    return rows[:10]


def _observed_reference(history: tuple[TemporalEvent, ...]) -> float | None:
    values = [
        float(event.timestamp_value) for event in history
        if event.supports_elapsed_time and event.timestamp_value is not None
    ]
    return max(values) if values else None


def snapshot_temporal(node: object) -> dict[str, object]:
    """Return separate ordered, Markov, time, and accumulator evidence families."""
    key = temporal_state_node_key(node)
    state = temporal_node_state_snapshot(key)
    history = temporal_history_snapshot(key)
    if len(history) < 2:
        return {
            "belief": 0.0,
            "ordered_sequence_evidence": {
                "ready": bool(history), "event_count": len(history),
                "order_confidence": (
                    history[0].ordering_confidence if history else 0.0
                ),
            },
            "observed_time_evidence": {
                "ready": False, "observed_event_count": sum(
                    event.supports_elapsed_time for event in history
                ),
                "unavailable_reason": "insufficient_observed_temporal_history",
            },
            "markov_transition_evidence": {
                "ready": False, "anomaly": 0.0,
                "unavailable_reason": "insufficient_temporal_history",
            },
            "hidden_state": dict(state["hidden_state"]),
            "ready": False,
            "degraded": False,
            "reason": "insufficient_temporal_history",
            "unavailable_reason": "insufficient_temporal_history",
            "evidence_type": "temporal_snapshot",
            "temporal_model_version": TEMPORAL_ACCUMULATOR_VERSION,
        }

    pair_rows: list[dict[str, object]] = []
    markov_values: list[float] = []
    observed_pairs = 0
    for previous, current in zip(history, history[1:], strict=False):
        pair_anomaly = safe_probability_score(
            temporal_pair_anomaly(previous.stage, (
                previous.behavior_id, current.behavior_id,
            ))
        )
        stage_anomaly = safe_probability_score(
            temporal_stage_sequence_anomaly(
                previous.stage, (previous.behavior_id,),
                current.stage, (current.behavior_id,),
            )
        )
        anomaly = safe_probability_score((pair_anomaly + stage_anomaly) / 2.0)
        markov_values.append(anomaly)
        observed = previous.supports_elapsed_time and current.supports_elapsed_time
        observed_pairs += int(observed)
        pair_rows.append({
            "source_event_id": previous.event_id,
            "target_event_id": current.event_id,
            "pair_anomaly": pair_anomaly,
            "stage_anomaly": stage_anomaly,
            "combined_anomaly": anomaly,
            "elapsed_time_supported": observed,
        })
    observation = sum(markov_values) / len(markov_values) if markov_values else 0.0
    order_confidence = sum(event.ordering_confidence for event in history) / len(history)
    observation_confidence = safe_probability_score(
        order_confidence * min(1.0, len(pair_rows) / 4.0)
    )
    reference = _observed_reference(history)
    prior_hidden = TemporalAccumulatorState.from_record(
        dict(state["hidden_state"])
    )
    hidden_state = temporal_evidence_accumulator_update(
        previous=prior_hidden,
        observation=observation,
        observation_confidence=observation_confidence,
        evidence_timestamp=reference,
        support=prior_hidden.support + len(pair_rows),
    )
    hidden = hidden_state.to_record()
    belief = safe_probability_score(
        hidden_state.posterior_belief * hidden_state.maturity
    )
    return {
        "belief": belief,
        "ordered_sequence_evidence": {
            "ready": True,
            "event_count": len(history),
            "distinct_source_evidence_count": len({
                event.source_evidence_id for event in history
            }),
            "order_confidence": order_confidence,
            "synthetic_event_count": sum(
                event.timestamp_kind == "synthetic_order" for event in history
            ),
        },
        "observed_time_evidence": {
            "ready": observed_pairs > 0,
            "observed_pair_count": observed_pairs,
            "reference_timestamp": reference,
            "unavailable_reason": (
                None if observed_pairs else "temporal_order_only_history"
            ),
        },
        "markov_transition_evidence": {
            "ready": bool(markov_values),
            "anomaly": safe_probability_score(observation),
            "pair_count": len(pair_rows),
            "pairs": tuple(pair_rows[-10:]),
            "ownership": "markov",
        },
        "hidden_state": hidden,
        "chain_policy_evidence": {
            "ownership": "chains", "score_contribution": 0.0,
        },
        "ready": True,
        "degraded": observed_pairs == 0,
        "reason": None,
        "unavailable_reason": (
            "temporal_order_only_history" if observed_pairs == 0 else None
        ),
        "evidence_type": "temporal_snapshot",
        "temporal_model_version": TEMPORAL_ACCUMULATOR_VERSION,
    }


def update_temporal(
    node: object,
    stage: object,
    tags: object,
    *,
    previous_stage: object = "unknown",
    ordered_events: object = (),
    learning_decision: object = None,
) -> dict[str, object]:
    """Apply one profiles-authorized canonical temporal request."""
    return commit_temporal_runtime_learning(
        learning_decision=learning_decision,
        node=node,
        previous_stage=previous_stage,
        current_stage=stage,
        ordered_events=ordered_events,
        behavior_flow=tags,
    )


__all__ = (
    "build_temporal_history_timeline",
    "detect_sequence_patterns",
    "explain_temporal_drift",
    "snapshot_temporal",
    "update_temporal",
)
