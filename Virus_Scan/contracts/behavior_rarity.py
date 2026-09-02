"""Neutral behavior-rarity calculation contract.

This module owns only the deterministic rarity math.  Callers still own their
canonical behavior flow and their baseline snapshot source so the model layer
can use runtime-owned learned state while detection scoring can remain pure and
explicit-input driven.
"""

from __future__ import annotations

from typing import Iterable, Mapping

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_optional_sequence_items,
    no_hook_text,
)
from Virus_Scan.utils.probability import safe_probability_score

MIN_BEHAVIOR_RARITY_SUPPORT = 10
RARE_HIGH_RISK_PROBABILITY_GATE = 0.05
HIGH_RISK_RARITY_MIN_SCORE = 7.5
HIGH_RISK_RARITY_MULTIPLIER = 1.25


def _finite_nonnegative_count(value: object) -> int | None:
    count, reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason="unsafe_behavior_baseline_count_rejected",
        non_finite_reason="nonfinite_behavior_baseline_count",
        allow_exact_text=False,
    )
    if reason:
        return None
    return count


def _safe_baseline_mapping(baseline: Mapping[str, int] | None) -> tuple[tuple[object, object], ...]:
    if baseline is None:
        return ()
    items = no_hook_mapping_items(baseline, allow_dict_subclass=True)
    return items if items is not None else ()


def _safe_event_text(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_behavior_event_text",
        unsupported_reason="unsafe_behavior_event_text_rejected",
    )
    return text if reason == "" else ""


def _safe_risk_names(value: object) -> frozenset[str]:
    return frozenset(
        name
        for item in no_hook_optional_sequence_items(value)
        if (name := str.lower(str.strip(_safe_event_text(item))))
    )


def rarity_multiplier_from_probability(
    prob: object,
    *,
    risk: object = 0.0,
    bucket: object = "other_behavior",
    high_risk_names: object = (),
) -> float:
    """Return the canonical behavior rarity multiplier from learned probability."""

    probability, probability_reason = no_hook_finite_float(
        prob,
        default=1.0,
        minimum=0.0,
        maximum=1.0,
        reason="behavior_rarity_probability_rejected",
        non_finite_reason="behavior_rarity_probability_rejected",
    )
    if probability_reason:
        return 1.0

    risk_value, _risk_reason = no_hook_finite_float(
        risk,
        default=0.0,
        minimum=0.0,
        maximum=100.0,
        reason="behavior_rarity_risk_rejected",
        non_finite_reason="behavior_rarity_risk_rejected",
    )
    bucket_text, bucket_reason = no_hook_text(
        bucket,
        missing_reason="behavior_rarity_bucket_missing",
        unsupported_reason="behavior_rarity_bucket_rejected",
    )
    bucket_name = (
        "other_behavior" if bucket_reason else str.lower(str.strip(bucket_text))
    )
    high_risk_signal = (
        risk_value >= HIGH_RISK_RARITY_MIN_SCORE
        or bucket_name in _safe_risk_names(high_risk_names)
    )
    if probability < RARE_HIGH_RISK_PROBABILITY_GATE and high_risk_signal:
        return HIGH_RISK_RARITY_MULTIPLIER
    return 1.0


def behavior_rarity_from_flow(
    flow: Iterable[object] | None,
    baseline: Mapping[str, int] | None,
    *,
    min_support: int = MIN_BEHAVIOR_RARITY_SUPPORT,
) -> float:
    """Return bounded rarity for an already-canonicalized behavior flow."""

    events = tuple(text for item in no_hook_optional_sequence_items(flow) if (text := _safe_event_text(item)))
    baseline_items = tuple(
        (key_text, count)
        for key, value in _safe_baseline_mapping(baseline)
        if (key_text := _safe_event_text(key))
        if (count := _finite_nonnegative_count(value)) is not None
    )
    baseline_snapshot = dict(baseline_items)
    total = sum(count for _key, count in baseline_items)
    minimum, reason = no_hook_exact_nonnegative_int(
        min_support,
        default=MIN_BEHAVIOR_RARITY_SUPPORT,
        reason="unsafe_min_support_rejected",
        non_finite_reason="nonfinite_min_support",
        allow_exact_text=False,
    )
    if reason:
        minimum = MIN_BEHAVIOR_RARITY_SUPPORT
    if not events or total < minimum:
        return 0.0
    denominator = total + max(1, len(baseline_snapshot))
    values = []
    for event in events:
        count = dict.get(baseline_snapshot, event, 0)
        probability = (count + 1.0) / denominator
        bounded_probability = safe_probability_score(probability)
        values.append(1.0 - bounded_probability)
    mean_rarity = sum(values) / max(1, len(values))
    return safe_probability_score(mean_rarity)


__all__ = (
    "HIGH_RISK_RARITY_MIN_SCORE",
    "HIGH_RISK_RARITY_MULTIPLIER",
    "MIN_BEHAVIOR_RARITY_SUPPORT",
    "RARE_HIGH_RISK_PROBABILITY_GATE",
    "behavior_rarity_from_flow",
    "rarity_multiplier_from_probability",
)
