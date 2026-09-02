"""Detection-owned numeric coercion helpers for scoring weights."""
from __future__ import annotations


from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float


def adaptive_weight_float(value: object, default: float = 0.0) -> float:
    """Coerce adaptive scoring weights without caller-owned numeric hooks."""
    default_metric, _default_reason = no_hook_finite_float(
        default,
        default=0.0,
        reason="adaptive_weight_default_rejected",
        non_finite_reason="adaptive_weight_default_non_finite",
        allow_exact_text=True,
    )
    metric, reason = no_hook_finite_float(
        value,
        default=default_metric,
        reason="adaptive_weight_numeric_rejected",
        non_finite_reason="adaptive_weight_non_finite",
        allow_exact_text=True,
    )
    if reason:
        return default_metric
    return metric


__all__ = ("adaptive_weight_float",)
