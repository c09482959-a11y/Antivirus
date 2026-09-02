"""In-memory scheduler telemetry smoothing.

EWMA state is owned by the caller's run context.  This module only computes the
next immutable scalar and updates the explicitly supplied state mapping.
"""

from __future__ import annotations

import math


from Virus_Scan.scheduler.internal.immutable_outputs import unsupported_scheduler_value_evidence


def _exact_finite_float(value: object, *, field_name: str) -> tuple[float | None, dict[str, object] | None]:
    if type(value) is int:
        return float(value), None
    if type(value) is float and math.isfinite(value):
        return value, None
    return None, unsupported_scheduler_value_evidence(value, field_name=field_name)


def update_ewma(name: object, value: object, *, state: dict[str, float], alpha: float = 0.25) -> object:
    if type(name) is str and name:
        key, key_evidence = str.__str__(name), None
    else:
        key, key_evidence = None, unsupported_scheduler_value_evidence(name, field_name="ewma_name")
    value_f, value_evidence = _exact_finite_float(value, field_name="ewma_value")
    alpha_f, alpha_evidence = _exact_finite_float(alpha, field_name="ewma_alpha")
    if type(state) is not dict:
        return unsupported_scheduler_value_evidence(state, field_name="ewma_state")
    evidence = key_evidence or value_evidence or alpha_evidence
    if key is None or value_f is None or alpha_f is None:
        return evidence
    bounded_alpha = max(0.01, min(1.0, alpha_f))
    prev = dict.get(state, key)
    prev_f: float | None
    if prev is None:
        prev_f = None
    else:
        prev_f, prev_evidence = _exact_finite_float(prev, field_name="ewma_previous")
        if prev_f is None:
            return prev_evidence
    cur = value_f if prev_f is None else bounded_alpha * value_f + (1.0 - bounded_alpha) * prev_f
    state[key] = cur
    return cur


__all__ = ("update_ewma",)
