"""Immutable data-only contract for canonical temporal accumulator state."""
from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Final

TEMPORAL_ACCUMULATOR_SCHEMA: Final[str] = "temporal_accumulator_state_v5"
TEMPORAL_ACCUMULATOR_VERSION: Final[str] = "temporal_evidence_accumulator_v5"
TEMPORAL_ACCUMULATOR_DECAY_VERSION: Final[str] = "temporal_half_life_decay_v5"
TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC: Final[float] = 604800.0
TEMPORAL_ACCUMULATOR_MIN_SUPPORT: Final[int] = 2


def _probability(value: object, name: str) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise ValueError(name + " invalid")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(name + " invalid")
    return number


def _nonnegative_number(value: object, name: str) -> float:
    if type(value) not in (int, float) or isinstance(value, bool):
        raise ValueError(name + " invalid")
    number = float(value)
    if not math.isfinite(number) or number < 0.0:
        raise ValueError(name + " invalid")
    return number


def _optional_finite(value: object, name: str) -> float | None:
    if value is None:
        return None
    if type(value) not in (int, float) or isinstance(value, bool):
        raise ValueError(name + " invalid")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(name + " invalid")
    return number


@dataclass(frozen=True, slots=True)
class TemporalAccumulatorState:
    prior_belief: float
    current_observation: float
    observation_confidence: float
    elapsed_evidence_time: float
    posterior_belief: float
    support: int
    maturity: float
    last_evidence_timestamp: float | None
    unavailable_reason: str | None
    schema_version: str = TEMPORAL_ACCUMULATOR_SCHEMA
    model_version: str = TEMPORAL_ACCUMULATOR_VERSION
    decay_half_life: float = TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC
    decay_version: str = TEMPORAL_ACCUMULATOR_DECAY_VERSION

    def validate(self) -> bool:
        if self.schema_version != TEMPORAL_ACCUMULATOR_SCHEMA:
            raise ValueError("temporal accumulator schema invalid")
        if self.model_version != TEMPORAL_ACCUMULATOR_VERSION:
            raise ValueError("temporal accumulator model invalid")
        if self.decay_version != TEMPORAL_ACCUMULATOR_DECAY_VERSION:
            raise ValueError("temporal accumulator decay invalid")
        for value, name in (
            (self.prior_belief, "temporal prior belief"),
            (self.current_observation, "temporal current observation"),
            (self.observation_confidence, "temporal observation confidence"),
            (self.posterior_belief, "temporal posterior belief"),
            (self.maturity, "temporal maturity"),
        ):
            _probability(value, name)
        _nonnegative_number(
            self.elapsed_evidence_time, "temporal elapsed evidence time"
        )
        half_life = _nonnegative_number(
            self.decay_half_life, "temporal decay half life"
        )
        if half_life == 0.0:
            raise ValueError("temporal decay half life invalid")
        if type(self.support) is not int or isinstance(
            self.support, bool
        ) or self.support < 0:
            raise ValueError("temporal accumulator support invalid")
        _optional_finite(
            self.last_evidence_timestamp, "temporal last evidence timestamp"
        )
        if self.unavailable_reason is not None and (
            type(self.unavailable_reason) is not str
            or self.unavailable_reason == ""
        ):
            raise ValueError("temporal accumulator reason invalid")
        return True

    def to_record(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "model_version": self.model_version,
            "prior_belief": float(self.prior_belief),
            "current_observation": float(self.current_observation),
            "observation_confidence": float(self.observation_confidence),
            "elapsed_evidence_time": float(self.elapsed_evidence_time),
            "decay_half_life": float(self.decay_half_life),
            "decay_version": self.decay_version,
            "posterior_belief": float(self.posterior_belief),
            "support": self.support,
            "maturity": float(self.maturity),
            "last_evidence_timestamp": self.last_evidence_timestamp,
            "unavailable_reason": self.unavailable_reason,
        }

    @classmethod
    def from_record(cls, value: object) -> "TemporalAccumulatorState":
        if type(value) is not dict:
            raise ValueError("temporal accumulator record invalid")
        if frozenset(value) != frozenset({
            "schema_version", "model_version", "prior_belief",
            "current_observation", "observation_confidence",
            "elapsed_evidence_time", "decay_half_life", "decay_version",
            "posterior_belief", "support", "maturity",
            "last_evidence_timestamp", "unavailable_reason",
        }):
            raise ValueError("temporal accumulator fields invalid")
        state = cls(
            schema_version=dict.get(value, "schema_version"),
            model_version=dict.get(value, "model_version"),
            prior_belief=dict.get(value, "prior_belief"),
            current_observation=dict.get(value, "current_observation"),
            observation_confidence=dict.get(value, "observation_confidence"),
            elapsed_evidence_time=dict.get(value, "elapsed_evidence_time"),
            decay_half_life=dict.get(value, "decay_half_life"),
            decay_version=dict.get(value, "decay_version"),
            posterior_belief=dict.get(value, "posterior_belief"),
            support=dict.get(value, "support"),
            maturity=dict.get(value, "maturity"),
            last_evidence_timestamp=dict.get(value, "last_evidence_timestamp"),
            unavailable_reason=dict.get(value, "unavailable_reason"),
        )
        state.validate()
        return state


def initial_temporal_accumulator_state() -> TemporalAccumulatorState:
    return TemporalAccumulatorState(
        prior_belief=0.0,
        current_observation=0.0,
        observation_confidence=0.0,
        elapsed_evidence_time=0.0,
        posterior_belief=0.0,
        support=0,
        maturity=0.0,
        last_evidence_timestamp=None,
        unavailable_reason="insufficient_temporal_history",
    )


__all__ = (
    "TEMPORAL_ACCUMULATOR_DECAY_VERSION",
    "TEMPORAL_ACCUMULATOR_HALF_LIFE_SEC",
    "TEMPORAL_ACCUMULATOR_MIN_SUPPORT",
    "TEMPORAL_ACCUMULATOR_SCHEMA",
    "TEMPORAL_ACCUMULATOR_VERSION",
    "TemporalAccumulatorState",
    "initial_temporal_accumulator_state",
)
