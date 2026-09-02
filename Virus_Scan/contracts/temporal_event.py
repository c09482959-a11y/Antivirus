"""Immutable data-only contract for canonical temporal events."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Final

TEMPORAL_EVENT_SCHEMA: Final[str] = "temporal_event_v5"
TEMPORAL_EVENT_VALIDATION_SCHEMA: Final[str] = "temporal_event_validation_v5"
TEMPORAL_TIMESTAMP_KINDS: Final[tuple[str, ...]] = (
    "observed", "derived", "synthetic_order", "ordinal_only",
)
TEMPORAL_ELAPSED_TIMESTAMP_KINDS: Final[frozenset[str]] = frozenset(
    {"observed", "derived"}
)
TEMPORAL_VALIDATION_STATUSES: Final[frozenset[str]] = frozenset(
    {"valid", "degraded", "unavailable"}
)


def required_temporal_text(value: object, name: str) -> str:
    if type(value) is not str:
        raise ValueError(name + " invalid")
    text = str.strip(str.__str__(value))
    if text == "":
        raise ValueError(name + " invalid")
    return text


def canonical_temporal_pairs(
    value: object, name: str,
) -> tuple[tuple[str, str], ...]:
    if type(value) is not tuple:
        raise ValueError(name + " invalid")
    rows: list[tuple[str, str]] = []
    for row in value:
        if type(row) is not tuple or len(row) != 2:
            raise ValueError(name + " invalid")
        rows.append((
            required_temporal_text(row[0], name),
            required_temporal_text(row[1], name),
        ))
    canonical = tuple(sorted(set(rows)))
    if canonical != value:
        raise ValueError(name + " noncanonical")
    return canonical


def temporal_record_digest(value: object) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class TemporalEvent:
    """One event whose time provenance is never inferred from order alone."""

    event_id: str
    source_evidence_id: str
    behavior_id: str
    stage: str
    timestamp_value: float | None
    timestamp_kind: str
    clock_domain: str
    ordering_confidence: float
    source_ordinal: int
    provenance: tuple[tuple[str, str], ...]
    schema_version: str = TEMPORAL_EVENT_SCHEMA

    def validate(self) -> bool:
        if self.schema_version != TEMPORAL_EVENT_SCHEMA:
            raise ValueError("unsupported temporal event schema")
        for value, name in (
            (self.event_id, "temporal event id"),
            (self.source_evidence_id, "temporal source evidence id"),
            (self.behavior_id, "temporal behavior id"),
            (self.stage, "temporal stage"),
            (self.timestamp_kind, "temporal timestamp kind"),
            (self.clock_domain, "temporal clock domain"),
        ):
            required_temporal_text(value, name)
        if self.timestamp_kind not in TEMPORAL_TIMESTAMP_KINDS:
            raise ValueError("temporal timestamp kind invalid")
        if self.timestamp_kind in TEMPORAL_ELAPSED_TIMESTAMP_KINDS:
            if type(self.timestamp_value) not in (int, float) or isinstance(
                self.timestamp_value, bool
            ):
                raise ValueError("temporal timestamp unavailable")
            if not math.isfinite(float(self.timestamp_value)):
                raise ValueError("temporal timestamp nonfinite")
        elif self.timestamp_value is not None:
            raise ValueError("order-only timestamp must be nonnumeric")
        if type(self.ordering_confidence) not in (int, float) or isinstance(
            self.ordering_confidence, bool
        ):
            raise ValueError("temporal ordering confidence invalid")
        confidence = float(self.ordering_confidence)
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError("temporal ordering confidence invalid")
        if type(self.source_ordinal) is not int or isinstance(
            self.source_ordinal, bool
        ) or self.source_ordinal < 0:
            raise ValueError("temporal source ordinal invalid")
        canonical_temporal_pairs(self.provenance, "temporal provenance")
        return True

    @property
    def supports_elapsed_time(self) -> bool:
        return self.timestamp_kind in TEMPORAL_ELAPSED_TIMESTAMP_KINDS

    def to_record(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "source_evidence_id": self.source_evidence_id,
            "behavior_id": self.behavior_id,
            "stage": self.stage,
            "timestamp_value": (
                float(self.timestamp_value)
                if self.timestamp_value is not None else None
            ),
            "timestamp_kind": self.timestamp_kind,
            "clock_domain": self.clock_domain,
            "ordering_confidence": float(self.ordering_confidence),
            "source_ordinal": self.source_ordinal,
            "provenance": [list(row) for row in self.provenance],
        }

    @classmethod
    def from_record(cls, value: object) -> "TemporalEvent":
        if type(value) is not dict:
            raise ValueError("temporal event record invalid")
        if frozenset(value) != frozenset({
            "schema_version", "event_id", "source_evidence_id", "behavior_id",
            "stage", "timestamp_value", "timestamp_kind", "clock_domain",
            "ordering_confidence", "source_ordinal", "provenance",
        }):
            raise ValueError("temporal event fields invalid")
        raw_provenance = dict.get(value, "provenance")
        if type(raw_provenance) is not list:
            raise ValueError("temporal provenance invalid")
        provenance: list[tuple[str, str]] = []
        for row in raw_provenance:
            if type(row) is not list or len(row) != 2:
                raise ValueError("temporal provenance invalid")
            provenance.append((row[0], row[1]))
        timestamp = dict.get(value, "timestamp_value")
        event = cls(
            event_id=dict.get(value, "event_id"),
            source_evidence_id=dict.get(value, "source_evidence_id"),
            behavior_id=dict.get(value, "behavior_id"),
            stage=dict.get(value, "stage"),
            timestamp_value=(
                float(timestamp)
                if type(timestamp) in (int, float)
                and not isinstance(timestamp, bool) else timestamp
            ),
            timestamp_kind=dict.get(value, "timestamp_kind"),
            clock_domain=dict.get(value, "clock_domain"),
            ordering_confidence=dict.get(value, "ordering_confidence"),
            source_ordinal=dict.get(value, "source_ordinal"),
            provenance=tuple(provenance),
            schema_version=dict.get(value, "schema_version"),
        )
        event.validate()
        return event


@dataclass(frozen=True, slots=True)
class TemporalEventValidation:
    event_id: str
    status: str
    reasons: tuple[str, ...]
    schema_version: str = TEMPORAL_EVENT_VALIDATION_SCHEMA

    def validate(self) -> bool:
        if self.schema_version != TEMPORAL_EVENT_VALIDATION_SCHEMA:
            raise ValueError("unsupported temporal validation schema")
        required_temporal_text(self.event_id, "temporal validation event id")
        if self.status not in TEMPORAL_VALIDATION_STATUSES:
            raise ValueError("temporal validation status invalid")
        if type(self.reasons) is not tuple or any(
            type(reason) is not str or reason == "" for reason in self.reasons
        ):
            raise ValueError("temporal validation reasons invalid")
        if self.reasons != tuple(sorted(set(self.reasons))):
            raise ValueError("temporal validation reasons noncanonical")
        return True

    def to_record(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "status": self.status,
            "reasons": list(self.reasons),
        }


def temporal_elapsed_seconds(
    previous: TemporalEvent, current: TemporalEvent,
) -> tuple[float | None, str | None]:
    """Return elapsed time only for compatible observed/derived clocks."""
    previous.validate()
    current.validate()
    if not previous.supports_elapsed_time or not current.supports_elapsed_time:
        return None, "temporal_order_only"
    if previous.clock_domain != current.clock_domain:
        return None, "temporal_clock_domain_mismatch"
    assert previous.timestamp_value is not None
    assert current.timestamp_value is not None
    elapsed = float(current.timestamp_value) - float(previous.timestamp_value)
    if elapsed < 0.0:
        return None, "temporal_timestamp_reversed"
    if elapsed == 0.0:
        return 0.0, "temporal_timestamp_duplicate"
    return elapsed, None


def temporal_source_record_digest(events: tuple[TemporalEvent, ...]) -> str:
    if type(events) is not tuple or not events:
        raise ValueError("temporal events required")
    for event in events:
        if type(event) is not TemporalEvent:
            raise ValueError("temporal event contract required")
        event.validate()
    return temporal_record_digest([event.to_record() for event in events])


__all__ = (
    "TEMPORAL_ELAPSED_TIMESTAMP_KINDS",
    "TEMPORAL_EVENT_SCHEMA",
    "TEMPORAL_EVENT_VALIDATION_SCHEMA",
    "TEMPORAL_TIMESTAMP_KINDS",
    "TemporalEvent",
    "TemporalEventValidation",
    "canonical_temporal_pairs",
    "required_temporal_text",
    "temporal_elapsed_seconds",
    "temporal_record_digest",
    "temporal_source_record_digest",
)
