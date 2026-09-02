"""Reporting-owned risk label rendering.

This module converts an already-computed numeric detection score into a
human-facing reporting label. It does not compute detection risk.
"""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float


PLR2004N25_0 = 25.0
PLR2004N50_0 = 50.0
PLR2004N75_0 = 75.0


def risk_label_from_score(score: object) -> str:
    """Return a display label for an emitted numeric score."""
    score_value, _reason = no_hook_finite_float(score, default=0.0, minimum=0.0, allow_exact_text=True)
    if score_value >= PLR2004N75_0:
        return "MALICIOUS"
    if score_value >= PLR2004N50_0:
        return "HIGH"
    if score_value >= PLR2004N25_0:
        return "MEDIUM"
    return "LOW"


__all__ = ("risk_label_from_score",)
