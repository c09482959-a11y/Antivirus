"""Learned dwell statistics over the profile-owned canonical v5 schema."""
from __future__ import annotations

from typing import Final

from Virus_Scan.contracts.temporal_event import (
    TemporalEvent,
    temporal_elapsed_seconds,
)
from Virus_Scan.contracts.temporal_learning import (
    TEMPORAL_BASELINE_MODEL_VERSION,
    TemporalLearningRequest,
)
from Virus_Scan.contracts.temporal_baseline import (
    TEMPORAL_CONTEXT_LEVELS,
    TEMPORAL_DWELL_BINS_SEC,
    TEMPORAL_DWELL_MAX_APPLIED_KEYS,
    TEMPORAL_DWELL_MAX_RECORDS,
    empty_temporal_baselines,
    new_temporal_baseline_record,
    temporal_baseline_record_key,
    temporal_context_extension,
    validate_temporal_baselines,
)

TEMPORAL_DWELL_MINIMUM_SUPPORT: Final[int] = 5
TEMPORAL_DWELL_ALPHA: Final[float] = 0.5
TEMPORAL_FALLBACK_CONFIDENCE: Final[tuple[tuple[str, float], ...]] = (
    ("exact", 1.0), ("engine", 0.72), ("global", 0.45),
)


def _fallback_confidence(level: str) -> float:
    for candidate, confidence in TEMPORAL_FALLBACK_CONFIDENCE:
        if candidate == level:
            return confidence
    raise ValueError("temporal fallback level invalid")


def _bin_index(value: float) -> int:
    for index, boundary in enumerate(TEMPORAL_DWELL_BINS_SEC):
        if value <= boundary:
            return index
    return len(TEMPORAL_DWELL_BINS_SEC)


def _elapsed_pairs(
    events: tuple[TemporalEvent, ...],
) -> tuple[tuple[TemporalEvent, TemporalEvent, float], ...]:
    rows: list[tuple[TemporalEvent, TemporalEvent, float]] = []
    for previous, current in zip(events, events[1:], strict=False):
        if previous.stage == "unknown" or current.stage == "unknown":
            continue
        delay, reason = temporal_elapsed_seconds(previous, current)
        if reason is None and delay is not None:
            rows.append((previous, current, delay))
    return tuple(rows)


def _update_record(
    record: dict[str, object], delay: float, ordinal: int,
) -> None:
    count = int(record["count"])
    mean = float(record["mean"])
    next_count = count + 1
    delta = delay - mean
    next_mean = mean + delta / next_count
    next_m2 = float(record["m2"]) + delta * (delay - next_mean)
    counts = list(record["histogram_counts"])
    counts[_bin_index(delay)] += 1
    minimum = record["minimum"]
    maximum = record["maximum"]
    record.update({
        "count": next_count,
        "mean": next_mean,
        "m2": next_m2,
        "minimum": delay if minimum is None else min(float(minimum), delay),
        "maximum": delay if maximum is None else max(float(maximum), delay),
        "histogram_counts": counts,
        "last_update_ordinal": ordinal,
    })


def _context_key(
    level: str, request: TemporalLearningRequest,
    previous: TemporalEvent, current: TemporalEvent, extension: str,
) -> str:
    return temporal_baseline_record_key(
        level=level,
        engine=request.engine,
        extension=extension,
        previous_stage=previous.stage,
        current_stage=current.stage,
        source_behavior=previous.behavior_id,
        target_behavior=current.behavior_id,
    )


def apply_temporal_baseline_learning(
    store: object, request: TemporalLearningRequest,
) -> tuple[dict[str, object], dict[str, object]]:
    """Atomically apply one trusted request to a copied profile store."""
    request.validate()
    prepared = validate_temporal_baselines(store)
    applied = prepared["applied_learning_keys"]
    records = prepared["records"]
    assert type(applied) is dict and type(records) is dict
    if request.replay_key in applied:
        return prepared, {
            "updated": True,
            "idempotent_replay": True,
            "transitions": 0,
            "reason": "temporal_learning_already_applied",
        }

    extension = temporal_context_extension(request.node_id)
    transitions = 0
    for previous, current, delay in _elapsed_pairs(request.events):
        for level in TEMPORAL_CONTEXT_LEVELS:
            key = _context_key(level, request, previous, current, extension)
            record = records.get(key)
            if record is None:
                if len(records) >= TEMPORAL_DWELL_MAX_RECORDS:
                    continue
                record = new_temporal_baseline_record(
                    level=level,
                    engine=request.engine,
                    extension=extension,
                    previous_stage=previous.stage,
                    current_stage=current.stage,
                    source_behavior=previous.behavior_id,
                    target_behavior=current.behavior_id,
                )
                records[key] = record
            _update_record(record, delay, request.decision_ordinal)
        transitions += 1

    applied[request.replay_key] = request.decision_ordinal
    if len(applied) > TEMPORAL_DWELL_MAX_APPLIED_KEYS:
        retained = {
            key for _ordinal, key in sorted(
                (ordinal, key) for key, ordinal in applied.items()
            )[-TEMPORAL_DWELL_MAX_APPLIED_KEYS:]
        }
        for key in tuple(applied):
            if key not in retained:
                applied.pop(key, None)
    return validate_temporal_baselines(prepared), {
        "updated": True,
        "idempotent_replay": False,
        "transitions": transitions,
        "reason": (
            "temporal_dwell_baseline_updated"
            if transitions else "temporal_order_only_no_dwell_update"
        ),
    }


def _tail_probability(record: dict[str, object], delay: float) -> float:
    counts = record["histogram_counts"]
    assert type(counts) is list
    index = _bin_index(delay)
    support = int(record["count"])
    bucket_count = len(counts)
    lower = sum(counts[:index + 1])
    upper = sum(counts[index:])
    denominator = support + TEMPORAL_DWELL_ALPHA * bucket_count
    lower_probability = (lower + TEMPORAL_DWELL_ALPHA) / denominator
    upper_probability = (upper + TEMPORAL_DWELL_ALPHA) / denominator
    return max(0.0, min(1.0, 2.0 * min(
        lower_probability, upper_probability,
    )))


def _selected_record(
    records: dict[str, object], *, engine: str, extension: str,
    previous: TemporalEvent, current: TemporalEvent,
) -> tuple[str | None, dict[str, object] | None, str | None]:
    available: list[tuple[str, dict[str, object], str]] = []
    for level in TEMPORAL_CONTEXT_LEVELS:
        key = temporal_baseline_record_key(
            level=level,
            engine=engine,
            extension=extension,
            previous_stage=previous.stage,
            current_stage=current.stage,
            source_behavior=previous.behavior_id,
            target_behavior=current.behavior_id,
        )
        candidate = records.get(key)
        if type(candidate) is dict and int(candidate.get("count", 0)) > 0:
            available.append((level, candidate, key))
            if int(candidate["count"]) >= TEMPORAL_DWELL_MINIMUM_SUPPORT:
                return level, candidate, key
    return available[0] if available else (None, None, None)


def temporal_dwell_evidence(
    store: object, *, engine: str, node_id: str,
    events: tuple[TemporalEvent, ...],
) -> tuple[dict[str, object], ...]:
    """Query deterministic exact→engine→global benign dwell evidence."""
    if type(engine) is not str or engine == "" or type(node_id) is not str:
        raise ValueError("temporal dwell query context invalid")
    if type(events) is not tuple or any(
        type(event) is not TemporalEvent for event in events
    ):
        raise ValueError("temporal dwell query events invalid")
    for event in events:
        event.validate()
    prepared = validate_temporal_baselines(store)
    records = prepared["records"]
    assert type(records) is dict
    extension = temporal_context_extension(node_id)
    outputs: list[dict[str, object]] = []
    for previous, current, delay in _elapsed_pairs(events):
        level, record, context_key = _selected_record(
            records, engine=engine, extension=extension,
            previous=previous, current=current,
        )
        if record is None or level is None:
            outputs.append({
                "ready": False,
                "delay_seconds": delay,
                "support": 0,
                "tail_probability": None,
                "anomaly": 0.0,
                "fallback_level": None,
                "context_key": None,
                "confidence": 0.0,
                "unavailable_reason": "temporal_dwell_baseline_unavailable",
                "source_event_id": previous.event_id,
                "target_event_id": current.event_id,
                "model_version": TEMPORAL_BASELINE_MODEL_VERSION,
            })
            continue
        support = int(record["count"])
        ready = support >= TEMPORAL_DWELL_MINIMUM_SUPPORT
        tail = _tail_probability(record, delay) if ready else None
        maturity = min(
            1.0, support / float(TEMPORAL_DWELL_MINIMUM_SUPPORT * 2)
        )
        outputs.append({
            "ready": ready,
            "delay_seconds": delay,
            "support": support,
            "mean": float(record["mean"]),
            "variance": (
                float(record["m2"]) / (support - 1) if support > 1 else 0.0
            ),
            "minimum": record["minimum"],
            "maximum": record["maximum"],
            "tail_probability": tail,
            "anomaly": 0.0 if tail is None else 1.0 - tail,
            "fallback_level": level,
            "context_key": context_key,
            "confidence": maturity * _fallback_confidence(level),
            "minimum_support": TEMPORAL_DWELL_MINIMUM_SUPPORT,
            "smoothing": "jeffreys_histogram_tail",
            "alpha": TEMPORAL_DWELL_ALPHA,
            "model_version": TEMPORAL_BASELINE_MODEL_VERSION,
            "unavailable_reason": (
                None if ready else "insufficient_temporal_dwell_support"
            ),
            "source_event_id": previous.event_id,
            "target_event_id": current.event_id,
        })
    return tuple(outputs)


__all__ = (
    "TEMPORAL_CONTEXT_LEVELS",
    "TEMPORAL_DWELL_ALPHA",
    "TEMPORAL_DWELL_BINS_SEC",
    "TEMPORAL_DWELL_MINIMUM_SUPPORT",
    "apply_temporal_baseline_learning",
    "empty_temporal_baselines",
    "temporal_dwell_evidence",
    "validate_temporal_baselines",
)
