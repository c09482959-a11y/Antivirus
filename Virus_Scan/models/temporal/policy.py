"""Versioned temporal policy evidence, separate from learned dwell evidence."""
from __future__ import annotations

from typing import Final

from Virus_Scan.contracts.temporal_event import TemporalEvent, temporal_elapsed_seconds
from Virus_Scan.models.temporal.evidence import (
    TEMPORAL_HIGH_RISK_TAGS,
    TEMPORAL_PHASE_ORDER,
    TEMPORAL_TAG_PHASES,
)

TEMPORAL_POLICY_VERSION: Final[str] = "temporal_policy_v5"
TEMPORAL_DELAY_POLICY: Final[tuple[tuple[float, float, str], ...]] = (
    (5.0, 0.2, "delayed_execution_5s"),
    (30.0, 0.5, "delayed_execution_30s"),
    (300.0, 0.8, "delayed_execution_300s"),
)
TEMPORAL_BURST_EVENT_WINDOW: Final[int] = 5
TEMPORAL_BURST_OBSERVED_WINDOW_SEC: Final[float] = 30.0
TEMPORAL_BURST_DISTINCT_BEHAVIORS: Final[int] = 3


def _events(value: object) -> tuple[TemporalEvent, ...]:
    if type(value) is not tuple:
        return ()
    return tuple(event for event in value if type(event) is TemporalEvent)


def temporal_phase_progression_evidence(events: object) -> dict[str, object]:
    phases: list[str] = []
    for event in _events(events):
        phase = TEMPORAL_TAG_PHASES.get(event.behavior_id)
        if type(phase) is str and phase and (not phases or phases[-1] != phase):
            phases.append(phase)
    indices = [TEMPORAL_PHASE_ORDER.index(phase) for phase in phases if phase in TEMPORAL_PHASE_ORDER]
    ordered = bool(indices) and indices == sorted(indices)
    distinct = len(set(phases))
    strength = 0.65 if distinct >= 3 and ordered else 0.3 if distinct >= 2 else 0.0
    return {
        "policy_version": TEMPORAL_POLICY_VERSION,
        "evidence_family": "phase_progression_policy",
        "strength": strength,
        "phases": tuple(phases),
        "ordered": ordered,
        "ready": bool(phases),
        "unavailable_reason": None if phases else "temporal_phase_evidence_unavailable",
    }


def temporal_delay_policy_evidence(events: object) -> tuple[dict[str, object], ...]:
    rows: list[dict[str, object]] = []
    values = _events(events)
    for previous, current in zip(values, values[1:], strict=False):
        delay, reason = temporal_elapsed_seconds(previous, current)
        if delay is None or reason is not None:
            rows.append({
                "policy_version": TEMPORAL_POLICY_VERSION,
                "evidence_family": "dangerous_delay_policy",
                "source_event_id": previous.event_id,
                "target_event_id": current.event_id,
                "delay_seconds": delay,
                "strength": 0.0,
                "matched_rule": None,
                "ready": False,
                "unavailable_reason": reason,
            })
            continue
        strength = 0.0
        matched = None
        for threshold, candidate_strength, rule in TEMPORAL_DELAY_POLICY:
            if delay >= threshold:
                strength = candidate_strength
                matched = rule
        rows.append({
            "policy_version": TEMPORAL_POLICY_VERSION,
            "evidence_family": "dangerous_delay_policy",
            "source_event_id": previous.event_id,
            "target_event_id": current.event_id,
            "delay_seconds": delay,
            "strength": strength,
            "matched_rule": matched,
            "ready": True,
            "unavailable_reason": None,
        })
    return tuple(rows)


def _deduplicated_source_events(events: tuple[TemporalEvent, ...]) -> tuple[TemporalEvent, ...]:
    seen: set[str] = set()
    rows: list[TemporalEvent] = []
    for event in events:
        if event.source_evidence_id in seen:
            continue
        seen.add(event.source_evidence_id)
        rows.append(event)
    return tuple(rows)


def temporal_burst_policy_evidence(events: object) -> dict[str, object]:
    values = _deduplicated_source_events(_events(events))
    best_behaviors: tuple[str, ...] = ()
    observed_window: float | None = None
    for start in range(len(values)):
        segment = values[start:start + TEMPORAL_BURST_EVENT_WINDOW]
        behaviors = tuple(sorted({
            event.behavior_id for event in segment
            if event.behavior_id in TEMPORAL_HIGH_RISK_TAGS
        }))
        if len(behaviors) < TEMPORAL_BURST_DISTINCT_BEHAVIORS:
            continue
        first = segment[0]
        last = segment[-1]
        elapsed, reason = temporal_elapsed_seconds(first, last)
        if elapsed is not None and elapsed <= TEMPORAL_BURST_OBSERVED_WINDOW_SEC:
            best_behaviors = behaviors
            observed_window = elapsed
            break
        if reason is not None and not best_behaviors:
            best_behaviors = behaviors
    observed_ready = observed_window is not None
    order_only = bool(best_behaviors) and not observed_ready
    strength = 0.75 if observed_ready else 0.25 if order_only else 0.0
    return {
        "policy_version": TEMPORAL_POLICY_VERSION,
        "evidence_family": "high_risk_burst_policy",
        "strength": strength,
        "event_count_window": TEMPORAL_BURST_EVENT_WINDOW,
        "observed_time_window_sec": TEMPORAL_BURST_OBSERVED_WINDOW_SEC,
        "distinct_behavior_requirement": TEMPORAL_BURST_DISTINCT_BEHAVIORS,
        "distinct_behaviors": best_behaviors,
        "deduplicated_source_events": len(values),
        "observed_window_seconds": observed_window,
        "observed_time_confirmed": observed_ready,
        "order_only": order_only,
        "ready": bool(best_behaviors),
        "unavailable_reason": None if best_behaviors else "temporal_burst_support_unavailable",
    }


__all__ = (
    "TEMPORAL_BURST_DISTINCT_BEHAVIORS",
    "TEMPORAL_BURST_EVENT_WINDOW",
    "TEMPORAL_BURST_OBSERVED_WINDOW_SEC",
    "TEMPORAL_DELAY_POLICY",
    "TEMPORAL_POLICY_VERSION",
    "temporal_burst_policy_evidence",
    "temporal_delay_policy_evidence",
    "temporal_phase_progression_evidence",
)
