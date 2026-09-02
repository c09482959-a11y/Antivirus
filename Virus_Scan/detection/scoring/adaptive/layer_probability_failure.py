"""Explicit probability projection for rejected adaptive layer mappings."""
from __future__ import annotations

from typing import Mapping


def rejected_layer_probability_summary(
    failure: Mapping[str, object],
    reason: str,
) -> dict[str, object]:
    return {
        "quick_static_probability": 0.0,
        "stage_probability": 0.0,
        "graph_probability": 0.0,
        "threat_intel_probability": 0.0,
        "quick_static_unavailable_reason": reason,
        "stage_unavailable_reason": reason,
        "graph_unavailable_reason": reason,
        "threat_intel_unavailable_reason": reason,
        "adaptive_input_failure": dict(failure),
    }


__all__ = ("rejected_layer_probability_summary",)
