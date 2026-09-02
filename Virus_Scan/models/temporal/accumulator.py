"""Canonical deterministic temporal evidence-accumulator mathematics."""
from __future__ import annotations

import math

from Virus_Scan.contracts.temporal_accumulator import (
    TEMPORAL_ACCUMULATOR_DECAY_VERSION,
    TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC,
    TEMPORAL_ACCUMULATOR_MIN_SUPPORT,
    TEMPORAL_ACCUMULATOR_VERSION,
    TemporalAccumulatorState,
    initial_temporal_accumulator_state,
)


def _probability(value: object) -> tuple[float, str | None]:
    if type(value) not in (int, float) or isinstance(value, bool):
        return 0.0, "temporal_accumulator_probability_invalid"
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        return 0.0, "temporal_accumulator_probability_invalid"
    return number, None


def _timestamp(value: object) -> tuple[float | None, str | None]:
    if value is None:
        return None, "temporal_elapsed_evidence_unavailable"
    if type(value) not in (int, float) or isinstance(value, bool):
        return None, "temporal_evidence_timestamp_invalid"
    number = float(value)
    if not math.isfinite(number):
        return None, "temporal_evidence_timestamp_invalid"
    return number, None


def temporal_evidence_accumulator_update(
    *,
    previous: TemporalAccumulatorState | None,
    observation: object,
    observation_confidence: object,
    evidence_timestamp: object,
    support: int,
) -> TemporalAccumulatorState:
    """Update from recorded evidence time; never consult the current clock."""
    prior = (
        initial_temporal_accumulator_state()
        if previous is None else previous
    )
    if type(prior) is not TemporalAccumulatorState:
        raise TypeError("temporal accumulator state required")
    prior.validate()
    if type(support) is not int or isinstance(support, bool) or support < 0:
        raise ValueError("temporal accumulator support invalid")

    observation_value, observation_reason = _probability(observation)
    confidence, confidence_reason = _probability(observation_confidence)
    current_time, timestamp_reason = _timestamp(evidence_timestamp)
    reason = observation_reason or confidence_reason or timestamp_reason
    elapsed = 0.0
    decay = 1.0
    last_time = prior.last_evidence_timestamp
    if current_time is not None and last_time is not None:
        if current_time < last_time:
            reason = reason or "temporal_evidence_timestamp_reversed"
            current_time = last_time
        else:
            elapsed = current_time - last_time
            decay = math.exp(
                -math.log(2.0) * elapsed / TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC
            )
    elif current_time is None:
        current_time = last_time

    effective_confidence = 0.0 if observation_reason or confidence_reason else confidence
    decayed_prior = prior.posterior_belief * decay
    prior_weight = prior.maturity * decay
    denominator = prior_weight + effective_confidence
    posterior = (
        (decayed_prior * prior_weight + observation_value * effective_confidence)
        / denominator if denominator > 1e-12 else decayed_prior
    )
    maturity = min(
        1.0, support / float(TEMPORAL_ACCUMULATOR_MIN_SUPPORT * 2)
    )
    if support < TEMPORAL_ACCUMULATOR_MIN_SUPPORT:
        reason = reason or "insufficient_temporal_accumulator_support"

    state = TemporalAccumulatorState(
        prior_belief=round(prior.posterior_belief, 6),
        current_observation=round(observation_value, 6),
        observation_confidence=round(effective_confidence, 6),
        elapsed_evidence_time=round(elapsed, 6),
        posterior_belief=round(max(0.0, min(1.0, posterior)), 6),
        support=support,
        maturity=round(maturity, 6),
        last_evidence_timestamp=current_time,
        unavailable_reason=reason,
    )
    state.validate()
    return state


__all__ = (
    "TEMPORAL_ACCUMULATOR_DECAY_VERSION",
    "TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC",
    "TEMPORAL_ACCUMULATOR_MIN_SUPPORT",
    "TEMPORAL_ACCUMULATOR_VERSION",
    "TemporalAccumulatorState",
    "initial_temporal_accumulator_state",
    "temporal_evidence_accumulator_update",
)
