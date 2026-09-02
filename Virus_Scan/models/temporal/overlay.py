"""Temporal projection over Markov-owned probabilities and canonical event time."""
from __future__ import annotations

import math
from itertools import pairwise

from Virus_Scan.models.api.markov_contracts import (
    canonical_behavior_flow,
    compute_markov_features,
    markov_pair_probability,
    markov_sequence_probability,
    markov_stage_probability,
)
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.temporal_accumulator import initial_temporal_accumulator_state
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.temporal.accumulator import temporal_evidence_accumulator_update
from Virus_Scan.models.temporal.event_materialization import materialize_temporal_events
from Virus_Scan.utils.probability import safe_probability_score

TEMPORAL_OVERLAY_VERSION = "temporal_markov_overlay_v5"


def _mapping(value: object) -> dict[object, object]:
    items = no_hook_mapping_items(value)
    return {} if items is None else dict(items)


def _probability(record: object) -> float | None:
    row = _mapping(record)
    value = row.get("probability")
    if row.get("ready") is not True or type(value) not in (int, float) or isinstance(value, bool):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    return max(1e-12, safe_probability_score(number))


def temporal_markov_overlay_support(
    prev_stage: object, flow: object, curr_stage: object,
) -> dict[str, object]:
    canonical_flow = tuple(canonical_behavior_flow(flow))
    features = compute_markov_features(prev_stage, canonical_flow, curr_stage)
    stage_record = markov_stage_probability(prev_stage, canonical_flow, curr_stage)
    sequence_record = markov_sequence_probability(prev_stage, canonical_flow, curr_stage)
    pairs = tuple(
        markov_pair_probability(source, target, prev_stage=prev_stage)
        for source, target in pairwise(canonical_flow)
    )
    supports = [
        int(_mapping(features).get("supported_transitions", 0) or 0),
        int(_mapping(stage_record).get("support", 0) or 0),
        *(int(_mapping(record).get("support", 0) or 0) for record in pairs),
    ]
    ready = _mapping(sequence_record).get("ready") is True
    reason = None
    if not ready:
        reason = (
            _mapping(features).get("reason")
            if not canonical_flow else
            _mapping(sequence_record).get("reason")
            or _mapping(stage_record).get("reason")
            or _mapping(features).get("reason")
        ) or "insufficient_markov_support"
    return {
        "features": features,
        "support": max(supports, default=0),
        "ready": ready,
        "reason": reason,
        "stage_probability_record": stage_record,
        "sequence_probability_record": sequence_record,
        "pair_probability_records": pairs,
    }


def _overlay_failure(
    *, flow: tuple[str, ...], events: tuple[object, ...],
    validations: tuple[object, ...], reason: str,
) -> dict[str, object]:
    observed_times = [
        float(event.timestamp_value) for event in events
        if event.supports_elapsed_time and event.timestamp_value is not None
    ]
    return {
        "schema_version": "5.0",
        "version": TEMPORAL_OVERLAY_VERSION,
        "evidence_type": "sequence_probability",
        "ready": False,
        "probability_ready": False,
        "flow": flow,
        "events": tuple(event.to_record() for event in events),
        "event_validations": tuple(item.to_record() for item in validations),
        "pair_probabilities": (),
        "average_surprise": 0.0,
        "markov_anomaly": 0.0,
        "sequence_probability": None,
        "stage_probability": None,
        "stage_probability_ready": False,
        "stage_probability_support": 0,
        "hidden_state": initial_temporal_accumulator_state().to_record(),
        "observed_time_evidence": {
            "ready": bool(observed_times),
            "observed_event_count": len(observed_times),
            "reference_timestamp": max(observed_times) if observed_times else None,
            "order_only_event_count": len(events) - len(observed_times),
        },
        "degraded": True,
        "unavailable_reason": reason,
        "cold_start_reason": reason,
        "temporal_model_version": TEMPORAL_OVERLAY_VERSION,
        "prev_stage": "unknown",
        "curr_stage": "unknown",
    }


def transition_probability_overlay(
    prev_stage: object = "unknown",
    tags: object = None,
    curr_stage: object = "unknown",
    *,
    ordered_events: object = (),
) -> dict[str, object]:
    """Publish Markov probability with explicit observed/order-only time facts."""
    flow = tuple(canonical_behavior_flow(() if tags is None else tags))
    events, validations = materialize_temporal_events(
        ordered_events=ordered_events,
        behavior_flow=flow,
        observation_id="temporal_overlay",
        previous_stage=prev_stage,
        current_stage=curr_stage,
    )
    try:
        support = temporal_markov_overlay_support(prev_stage, flow, curr_stage)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _overlay_failure(
            flow=flow, events=events, validations=validations,
            reason="temporal_probability_overlay_error",
        )
    pair_records = tuple(support["pair_probability_records"])
    pair_details: list[dict[str, object]] = []
    surprises: list[float] = []
    for index, (source, target) in enumerate(pairwise(flow)):
        record = pair_records[index] if index < len(pair_records) else {}
        probability = _probability(record)
        surprise = None if probability is None else -math.log(probability)
        if surprise is not None:
            surprises.append(surprise)
        event = events[index + 1] if index + 1 < len(events) else None
        row = _mapping(record)
        pair_details.append({
            "from": source,
            "to": target,
            "probability": probability,
            "surprise": surprise,
            "support": int(row.get("support", 0) or 0),
            "count": int(row.get("count", 0) or 0),
            "vocab": int(row.get("vocab", 0) or 0),
            "smoothing": row.get("smoothing"),
            "alpha": row.get("alpha"),
            "fallback_level": row.get("fallback_level"),
            "context_key": row.get("context_key"),
            "model_version": row.get("model_version"),
            "ready": probability is not None,
            "reason": row.get("reason"),
            "timestamp_kind": (
                event.timestamp_kind if event is not None else "ordinal_only"
            ),
            "clock_domain": event.clock_domain if event is not None else "ordinal",
            "elapsed_time_used": False,
        })
    average_surprise = sum(surprises) / len(surprises) if surprises else 0.0
    anomaly = safe_probability_score(
        1.0 - math.exp(-average_surprise) if surprises else 0.0
    )
    observed_times = [
        float(event.timestamp_value) for event in events
        if event.supports_elapsed_time and event.timestamp_value is not None
    ]
    reference = max(observed_times) if observed_times else None
    confidence = safe_probability_score(
        min(1.0, len(surprises) / max(1.0, len(flow) - 1.0))
    )
    hidden = temporal_evidence_accumulator_update(
        previous=None,
        observation=anomaly,
        observation_confidence=confidence,
        evidence_timestamp=reference,
        support=len(surprises),
    ).to_record()
    sequence_record = _mapping(support["sequence_probability_record"])
    stage_record = _mapping(support["stage_probability_record"])
    invalid_reasons = tuple(sorted({
        reason for validation in validations for reason in validation.reasons
    }))
    return {
        "schema_version": "5.0",
        "version": TEMPORAL_OVERLAY_VERSION,
        "evidence_type": "sequence_probability",
        "ready": bool(pair_details),
        "probability_ready": bool(surprises) and support["ready"] is True,
        "flow": flow,
        "events": tuple(event.to_record() for event in events),
        "event_validations": tuple(item.to_record() for item in validations),
        "pair_probabilities": tuple(pair_details),
        "average_surprise": average_surprise,
        "markov_anomaly": anomaly,
        "sequence_probability": _probability(sequence_record),
        "stage_probability": _probability(stage_record),
        "stage_probability_ready": _probability(stage_record) is not None,
        "stage_probability_support": int(stage_record.get("support", 0) or 0),
        "hidden_state": hidden,
        "observed_time_evidence": {
            "ready": bool(observed_times),
            "observed_event_count": len(observed_times),
            "reference_timestamp": reference,
            "order_only_event_count": len(events) - len(observed_times),
        },
        "degraded": bool(invalid_reasons),
        "unavailable_reason": (
            invalid_reasons[0] if invalid_reasons
            else None if support["ready"] else support["reason"]
        ),
        "cold_start_reason": support["reason"],
        "temporal_model_version": TEMPORAL_OVERLAY_VERSION,
        "prev_stage": prev_stage if type(prev_stage) is str else "unknown",
        "curr_stage": curr_stage if type(curr_stage) is str else "unknown",
    }


__all__ = ("temporal_markov_overlay_support", "transition_probability_overlay")
