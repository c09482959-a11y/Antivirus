"""Support projections for the canonical temporal v5 validation owner."""
from __future__ import annotations

import math
from typing import Final

from Virus_Scan.contracts.temporal_event import (
    TemporalEvent,
    temporal_elapsed_seconds,
)
from Virus_Scan.detection.api.chain_evaluation import evaluate_chain_evidence
from Virus_Scan.models.api.markov_contracts import compute_markov_features
from Virus_Scan.models.contracts.no_hook_materialization import (
    materialize_json_no_hook,
    no_hook_mapping_items,
)
from Virus_Scan.models.temporal.dwell_baseline import temporal_dwell_evidence
from Virus_Scan.utils.probability import safe_probability_score

TEMPORAL_FUSION_VERSION: Final[str] = "temporal_evidence_fusion_v5"
TEMPORAL_FUSION_WEIGHTS: Final[tuple[tuple[str, float], ...]] = (
    ("learned_dwell", 0.35),
    ("phase_policy", 0.15),
    ("burst_policy", 0.15),
    ("delay_policy", 0.10),
    ("markov", 0.25),
)


def _mapping_get(value: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__eq__(item_key, key):
            return item_value
    return default


def temporal_markov_projection(
    markov: object, previous_stage: str,
    flow: tuple[str, ...], current_stage: str,
) -> dict[str, object]:
    record = markov
    source_invalid = False
    if record is None:
        try:
            record = compute_markov_features(
                previous_stage, flow, current_stage
            )
        except (TypeError, ValueError, RuntimeError):
            record = {"ready": False, "reason": "markov_features_unavailable"}
    elif no_hook_mapping_items(record) is None:
        record = {"ready": False, "reason": "markov_features_invalid"}
        source_invalid = True
    values: list[float] = []
    invalid = source_invalid
    for field in ("transition", "rarity", "pair_anomaly", "sequence_anomaly"):
        value = _mapping_get(record, field)
        if type(value) in (int, float) and not isinstance(value, bool):
            number = float(value)
            if math.isfinite(number):
                values.append(safe_probability_score(number))
            else:
                invalid = True
        elif value is not None:
            invalid = True
    readiness_missing = object()
    declared_ready = _mapping_get(record, "ready", readiness_missing)
    supported = (
        declared_ready is True
        or (declared_ready is readiness_missing and bool(values))
    )
    reason = _mapping_get(record, "reason", "markov_features_unavailable")
    published_record = materialize_json_no_hook(
        record, context="temporal_markov_record",
    )
    return {
        "ownership": "markov",
        "ready": supported and not invalid,
        "anomaly": max(values, default=0.0) if not invalid else 0.0,
        "degraded": invalid,
        "unavailable_reason": (
            "markov_features_invalid" if invalid
            else None if supported else reason
        ),
        "record": published_record,
    }


def temporal_chain_projection(
    events: tuple[TemporalEvent, ...],
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    for event in events:
        row: dict[str, object] = {
            "term": event.behavior_id,
            "evidence_id": event.event_id,
            "root_evidence_id": event.source_evidence_id,
            "stage": event.stage,
        }
        if event.supports_elapsed_time:
            row["timestamp"] = event.timestamp_value
        rows.append(row)
    evidence = evaluate_chain_evidence(
        ordered_events=tuple(rows), match_modes=("ordered",),
    )
    records = tuple(decision.to_record() for decision in evidence.decisions)
    identities = tuple(
        decision.candidate.chain_id for decision in evidence.decisions
        if decision.status in {"confirmed", "candidate", "partial", "blocked"}
    )
    return {
        "ownership": "chains",
        "records": records,
        "identities": identities,
        "score_contribution": 0.0,
    }


def temporal_observed_delay_projection(
    events: tuple[TemporalEvent, ...],
) -> dict[str, object]:
    records: list[dict[str, object]] = []
    for previous, current in zip(events, events[1:], strict=False):
        delay, reason = temporal_elapsed_seconds(previous, current)
        records.append({
            "source_event_id": previous.event_id,
            "target_event_id": current.event_id,
            "delay_seconds": delay,
            "ready": delay is not None and reason is None,
            "unavailable_reason": reason,
            "source_timestamp_kind": previous.timestamp_kind,
            "target_timestamp_kind": current.timestamp_kind,
            "clock_domain": (
                previous.clock_domain
                if previous.clock_domain == current.clock_domain else None
            ),
        })
    ready = tuple(row for row in records if row["ready"] is True)
    return {
        "ready": bool(ready),
        "compatible_pair_count": len(ready),
        "order_only_pair_count": len(records) - len(ready),
        "records": tuple(records),
        "unavailable_reason": (
            None if ready else "compatible_observed_temporal_pair_unavailable"
        ),
    }


def temporal_dwell_projection(
    store: object, *, engine: str, node: str,
    events: tuple[TemporalEvent, ...],
) -> dict[str, object]:
    if store is None:
        return {
            "ready": False,
            "records": (),
            "maximum_anomaly": 0.0,
            "confidence": 0.0,
            "unavailable_reason": "temporal_dwell_baseline_not_supplied",
        }
    try:
        records = temporal_dwell_evidence(
            store, engine=engine, node_id=node, events=events,
        )
    except (TypeError, ValueError):
        return {
            "ready": False,
            "records": (),
            "maximum_anomaly": 0.0,
            "confidence": 0.0,
            "unavailable_reason": "temporal_dwell_baseline_invalid",
        }
    ready_rows = tuple(row for row in records if row.get("ready") is True)
    return {
        "ready": bool(ready_rows),
        "records": records,
        "maximum_anomaly": max(
            (float(row["anomaly"]) for row in ready_rows), default=0.0,
        ),
        "confidence": max(
            (float(row["confidence"]) for row in ready_rows), default=0.0,
        ),
        "unavailable_reason": (
            None if ready_rows else "insufficient_temporal_dwell_support"
        ),
    }


def temporal_fusion_strength(
    *, dwell: dict[str, object], phase: dict[str, object],
    burst: dict[str, object], delay: tuple[dict[str, object], ...],
    markov: dict[str, object],
) -> float:
    values = {
        "learned_dwell": (
            float(dwell["maximum_anomaly"]) * float(dwell["confidence"])
        ),
        "phase_policy": float(phase["strength"]),
        "burst_policy": float(burst["strength"]),
        "delay_policy": max(
            (float(row["strength"]) for row in delay if row["ready"]),
            default=0.0,
        ),
        "markov": float(markov["anomaly"]),
    }
    return safe_probability_score(sum(
        weight * values[name] for name, weight in TEMPORAL_FUSION_WEIGHTS
    ))


__all__ = (
    "TEMPORAL_FUSION_VERSION",
    "TEMPORAL_FUSION_WEIGHTS",
    "temporal_chain_projection",
    "temporal_dwell_projection",
    "temporal_fusion_strength",
    "temporal_markov_projection",
    "temporal_observed_delay_projection",
)
