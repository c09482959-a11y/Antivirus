"""Immutable data-only contract for profiles-authorized temporal learning."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from Virus_Scan.contracts.temporal_accumulator import TemporalAccumulatorState
from Virus_Scan.contracts.temporal_event import (
    TemporalEvent,
    canonical_temporal_pairs,
    required_temporal_text,
    temporal_record_digest,
)

TEMPORAL_LEARNING_REQUEST_SCHEMA: Final[str] = "temporal_learning_request_v5"
TEMPORAL_RUNTIME_STATE_SCHEMA: Final[str] = "temporal_runtime_state_v5"
TEMPORAL_PROFILE_BASELINE_SCHEMA: Final[str] = "profile_temporal_baselines_v5"
TEMPORAL_MODEL_VERSION: Final[str] = "temporal_hybrid_dwell_v5"
TEMPORAL_BASELINE_MODEL_VERSION: Final[str] = "temporal_bounded_histogram_v5"
TEMPORAL_LEARNING_DISPOSITION: Final[str] = "trusted_benign"
_HEX: Final[frozenset[str]] = frozenset("0123456789abcdef")


def _digest_text(value: object, name: str) -> str:
    text = required_temporal_text(value, name)
    if len(text) != 64 or any(char not in _HEX for char in text):
        raise ValueError(name + " invalid")
    return text


@dataclass(frozen=True, slots=True)
class TemporalLearningRequest:
    """One immutable request carrying all state needed for atomic commit."""

    observation_id: str
    observation_digest: str
    source_record_digest: str
    node_id: str
    previous_stage: str
    current_stage: str
    engine: str
    context_identity: tuple[tuple[str, str], ...]
    events: tuple[TemporalEvent, ...]
    accumulator_state: TemporalAccumulatorState
    learning_disposition: str
    disposition_provenance: str
    gate_version: str
    decision_ordinal: int
    replay_key: str
    schema_version: str = TEMPORAL_LEARNING_REQUEST_SCHEMA

    def validate(self) -> bool:
        if self.schema_version != TEMPORAL_LEARNING_REQUEST_SCHEMA:
            raise ValueError("unsupported temporal learning request schema")
        for value, name in (
            (self.observation_id, "temporal observation id"),
            (self.node_id, "temporal node id"),
            (self.previous_stage, "temporal previous stage"),
            (self.current_stage, "temporal current stage"),
            (self.engine, "temporal engine"),
            (self.learning_disposition, "temporal learning disposition"),
            (self.disposition_provenance, "temporal disposition provenance"),
            (self.gate_version, "temporal gate version"),
        ):
            required_temporal_text(value, name)
        _digest_text(self.observation_digest, "temporal observation digest")
        _digest_text(self.source_record_digest, "temporal source record digest")
        _digest_text(self.replay_key, "temporal replay key")
        if self.learning_disposition != TEMPORAL_LEARNING_DISPOSITION:
            raise ValueError("temporal learning disposition not trusted benign")
        canonical_temporal_pairs(
            self.context_identity, "temporal context identity"
        )
        if type(self.events) is not tuple or not self.events or len(self.events) > 128:
            raise ValueError("temporal events invalid")
        event_ids: set[str] = set()
        last_ordinal = -1
        for event in self.events:
            if type(event) is not TemporalEvent:
                raise ValueError("temporal event contract required")
            event.validate()
            if event.event_id in event_ids or event.source_ordinal <= last_ordinal:
                raise ValueError("temporal event order noncanonical")
            event_ids.add(event.event_id)
            last_ordinal = event.source_ordinal
        expected_source_digest = temporal_record_digest(
            [event.to_record() for event in self.events]
        )
        if self.source_record_digest != expected_source_digest:
            raise ValueError("temporal source record digest mismatch")
        if type(self.accumulator_state) is not TemporalAccumulatorState:
            raise ValueError("temporal accumulator contract required")
        self.accumulator_state.validate()
        if type(self.decision_ordinal) is not int or isinstance(
            self.decision_ordinal, bool
        ) or self.decision_ordinal < 0:
            raise ValueError("temporal decision ordinal invalid")
        return True

    def event_digest(self) -> str:
        self.validate()
        return temporal_record_digest(
            [event.to_record() for event in self.events]
        )

    def to_record(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "observation_digest": self.observation_digest,
            "source_record_digest": self.source_record_digest,
            "node_id": self.node_id,
            "previous_stage": self.previous_stage,
            "current_stage": self.current_stage,
            "engine": self.engine,
            "context_identity": [list(row) for row in self.context_identity],
            "events": [event.to_record() for event in self.events],
            "accumulator_state": self.accumulator_state.to_record(),
            "learning_disposition": self.learning_disposition,
            "disposition_provenance": self.disposition_provenance,
            "gate_version": self.gate_version,
            "decision_ordinal": self.decision_ordinal,
            "replay_key": self.replay_key,
        }


__all__ = (
    "TEMPORAL_BASELINE_MODEL_VERSION",
    "TEMPORAL_LEARNING_DISPOSITION",
    "TEMPORAL_LEARNING_REQUEST_SCHEMA",
    "TEMPORAL_MODEL_VERSION",
    "TEMPORAL_PROFILE_BASELINE_SCHEMA",
    "TEMPORAL_RUNTIME_STATE_SCHEMA",
    "TemporalLearningRequest",
)
