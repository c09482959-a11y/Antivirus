"""Deterministic no-hook materialization of canonical temporal events."""
from __future__ import annotations

import math
from typing import Final

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.contracts.temporal_event import (
    TemporalEvent,
    TemporalEventValidation,
    temporal_elapsed_seconds,
)
from Virus_Scan.models.api.markov_contracts import canonical_behavior_flow
from Virus_Scan.models.temporal.text_boundary import (
    TEMPORAL_TEXT_UNAVAILABLE,
    temporal_boundary_stage,
    temporal_boundary_text,
)

_EVENT_FIELDS: Final[tuple[str, ...]] = (
    "tag", "term", "behavior_id", "behavior", "event", "name",
)
_TIMESTAMP_FIELDS: Final[tuple[str, ...]] = (
    "timestamp", "time", "observed_at", "event_time",
)
_EVENT_ID_FIELDS: Final[tuple[str, ...]] = (
    "event_id", "evidence_id", "id",
)
_SOURCE_ID_FIELDS: Final[tuple[str, ...]] = (
    "source_evidence_id", "root_evidence_id", "evidence_id", "event_id", "id",
)
_CLOCK_FIELDS: Final[tuple[str, ...]] = (
    "clock_domain", "source_domain", "clock", "timestamp_source",
)


def _mapping_get(value: object, names: tuple[str, ...]) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    for name in names:
        for key, child in items:
            if type(key) is str and str.__eq__(key, name):
                return child
    return None


def _text(value: object, default: str = "") -> str:
    if type(value) is str:
        return str.strip(str.__str__(value)) or default
    text, reason = no_hook_text(
        value, missing_reason="temporal_text_missing",
        unsupported_reason="temporal_text_rejected",
    )
    return default if reason else str.strip(text) or default


def _timestamp(value: object) -> tuple[float | None, str | None]:
    if value is None:
        return None, None
    numeric, reason = no_hook_finite_float(
        value, default=0.0, reason="temporal_timestamp_non_numeric",
        non_finite_reason="temporal_timestamp_non_finite", allow_exact_text=True,
    )
    if reason:
        return None, reason
    if not math.isfinite(float(numeric)):
        return None, "temporal_timestamp_non_finite"
    return float(numeric), None


def _sequence_status(
    value: object, *, unavailable_reason: str,
) -> tuple[tuple[object, ...], str | None]:
    if value is None:
        return (), None
    if type(value) in (str, bytes, bytearray, int, float, bool):
        return (value,), None
    if no_hook_mapping_items(value) is not None:
        return (value,), None
    if type(value) in (tuple, list, set, frozenset):
        return tuple(value), None
    return (), unavailable_reason


def _sequence(value: object) -> tuple[object, ...]:
    items, _reason = _sequence_status(
        value, unavailable_reason="temporal_sequence_unavailable",
    )
    return items


def _row_behaviors(value: object) -> tuple[tuple[str, ...], str | None]:
    tags = _mapping_get(value, ("tags", "behaviors", "events"))
    if tags is not None:
        tag_items, tag_reason = _sequence_status(
            tags, unavailable_reason="temporal_behavior_sequence_unavailable",
        )
        if tag_reason is not None:
            return (), tag_reason
        admitted: list[str] = []
        for item in tag_items:
            text = temporal_boundary_text(item, default="")
            if text in ("", TEMPORAL_TEXT_UNAVAILABLE):
                continue
            admitted.append(text)
        behaviors = canonical_behavior_flow(tuple(admitted))
        return (behaviors, None) if behaviors else ((), "temporal_behavior_unavailable")
    behavior = _mapping_get(value, _EVENT_FIELDS)
    if behavior is None and no_hook_mapping_items(value) is None:
        behavior = value
    text = temporal_boundary_text(behavior, default="")
    if text in ("", TEMPORAL_TEXT_UNAVAILABLE):
        return (), "temporal_behavior_unavailable"
    behaviors = canonical_behavior_flow((text,))
    return (behaviors, None) if behaviors else ((), "temporal_behavior_unavailable")


def _validation(
    event_id: str, reasons: set[str], *, unavailable: bool = False,
) -> TemporalEventValidation:
    status = "unavailable" if unavailable else "degraded" if reasons else "valid"
    record = TemporalEventValidation(
        event_id=event_id, status=status, reasons=tuple(sorted(reasons)),
    )
    record.validate()
    return record


def materialize_temporal_events(
    *,
    ordered_events: object,
    behavior_flow: object,
    observation_id: str,
    previous_stage: object,
    current_stage: object,
) -> tuple[tuple[TemporalEvent, ...], tuple[TemporalEventValidation, ...]]:
    """Return canonical events and explicit validation records.

    Multiple aliases from one raw row share a source evidence identity. Only the
    first event can carry that row's observed/derived time; following aliases are
    `synthetic_order` with no numeric timestamp.
    """
    observation = _text(observation_id, "temporal_observation")
    previous = temporal_boundary_stage(previous_stage, default="unknown")
    current = temporal_boundary_stage(current_stage, default="unknown")
    rows, ordered_events_reason = _sequence_status(
        ordered_events, unavailable_reason="temporal_ordered_events_unavailable",
    )
    using_behavior_flow = False
    if not rows and ordered_events_reason is None:
        flow_items, flow_reason = _sequence_status(
            behavior_flow, unavailable_reason="temporal_behavior_flow_unavailable",
        )
        if flow_reason is None:
            rows = flow_items
            using_behavior_flow = True
        else:
            ordered_events_reason = flow_reason

    events: list[TemporalEvent] = []
    validations: list[TemporalEventValidation] = []
    if ordered_events_reason is not None:
        validations.append(_validation(
            observation + ":event:0", {ordered_events_reason}, unavailable=True,
        ))
        return (), tuple(validations)
    ordinal = 0
    last_flow_behavior: str | None = None
    for row_index, row in enumerate(rows):
        row_is_mapping = no_hook_mapping_items(row) is not None
        behaviors, behavior_reason = _row_behaviors(row)
        if not behaviors:
            event_id = observation + ":event:" + str(ordinal)
            validations.append(_validation(
                event_id,
                {behavior_reason or "temporal_behavior_unavailable"},
                unavailable=True,
            ))
            continue
        raw_time = _mapping_get(row, _TIMESTAMP_FIELDS) if row_is_mapping else None
        timestamp, timestamp_reason = _timestamp(raw_time)
        explicit_kind = _text(
            _mapping_get(row, ("timestamp_kind",)), "",
        ) if row_is_mapping else ""
        if explicit_kind in {"observed", "derived"} and timestamp is not None:
            base_kind = explicit_kind
        elif timestamp is not None:
            base_kind = "observed"
        else:
            base_kind = "ordinal_only"
        stage = temporal_boundary_stage(
            _mapping_get(row, ("stage",)) if row_is_mapping else current,
            default=current,
        )
        raw_event_id = _text(
            _mapping_get(row, _EVENT_ID_FIELDS) if row_is_mapping else None, "",
        )
        raw_source_id = _text(
            _mapping_get(row, _SOURCE_ID_FIELDS) if row_is_mapping else None, "",
        )
        source_id = raw_source_id or raw_event_id or (
            observation + ":source:" + str(row_index)
        )
        clock = _text(
            _mapping_get(row, _CLOCK_FIELDS) if row_is_mapping else None,
            "scan_evidence" if timestamp is not None else "ordinal",
        )
        confidence_raw = (
            _mapping_get(row, ("ordering_confidence",)) if row_is_mapping else None
        )
        confidence, confidence_reason = no_hook_finite_float(
            confidence_raw, default=(1.0 if timestamp is not None else 0.5),
            minimum=0.0, maximum=1.0,
            reason="temporal_ordering_confidence_invalid",
            non_finite_reason="temporal_ordering_confidence_invalid",
        )
        for alias_index, behavior in enumerate(behaviors):
            if using_behavior_flow and behavior == last_flow_behavior:
                continue
            event_id = raw_event_id if len(behaviors) == 1 and raw_event_id else (
                observation + ":event:" + str(ordinal)
            )
            reasons: set[str] = set()
            if timestamp_reason:
                reasons.add(timestamp_reason)
            if confidence_reason:
                reasons.add(confidence_reason)
            if stage == "unknown":
                reasons.add("temporal_stage_unavailable")
            if alias_index == 0:
                kind = base_kind
                event_time = timestamp if kind in {"observed", "derived"} else None
                event_clock = clock if event_time is not None else "ordinal"
            else:
                kind = "synthetic_order"
                event_time = None
                event_clock = "synthetic:" + source_id
                reasons.add("temporal_alias_synthetic_order")
            provenance = tuple(sorted({
                ("materializer", "canonical_temporal_event_v5"),
                ("previous_stage", previous),
                ("row_index", str(row_index)),
                ("timestamp_origin", kind),
            }))
            event = TemporalEvent(
                event_id=event_id,
                source_evidence_id=source_id,
                behavior_id=behavior,
                stage=stage,
                timestamp_value=event_time,
                timestamp_kind=kind,
                clock_domain=event_clock,
                ordering_confidence=float(confidence),
                source_ordinal=ordinal,
                provenance=provenance,
            )
            event.validate()
            events.append(event)
            validations.append(_validation(event_id, reasons))
            if using_behavior_flow:
                last_flow_behavior = behavior
            ordinal += 1

    for index in range(1, len(events)):
        previous_event = events[index - 1]
        current_event = events[index]
        _elapsed, reason = temporal_elapsed_seconds(previous_event, current_event)
        if reason in {
            "temporal_clock_domain_mismatch",
            "temporal_timestamp_reversed",
            "temporal_timestamp_duplicate",
        }:
            existing = validations[index]
            reasons = set(existing.reasons)
            reasons.add(reason)
            validations[index] = _validation(current_event.event_id, reasons)
    return tuple(events), tuple(validations)


__all__ = ("materialize_temporal_events",)
