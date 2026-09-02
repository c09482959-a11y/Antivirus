"""Pure detection-owned score classification helpers."""

from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float


PLR2004N25_0 = 25.0
PLR2004N50_0 = 50.0
PLR2004N75_0 = 75.0


def _score_value(score: object) -> tuple[float, bool]:
    if score is None:
        return 0.0, True
    value, reason = no_hook_finite_float(
        score,
        default=0.0,
        allow_exact_text=True,
        reason="detection_score_rejected",
        non_finite_reason="detection_score_non_finite",
    )
    return value, reason == ""


def classify_detection_score(score: object) -> tuple[str, float]:
    """Return the canonical detection verdict/confidence for a numeric score."""
    score_value, valid = _score_value(score)
    if not valid:
        return ("score_unavailable", 0.0)
    if score_value >= PLR2004N75_0:
        return ("malicious", 0.95)
    if score_value >= PLR2004N50_0:
        return ("high_confidence", 0.8)
    if score_value >= PLR2004N25_0:
        return ("low_confidence", 0.55)
    return ("benign_clean", 0.2)


def detection_exit_code_for_score(score: object, *, had_error: bool = False) -> int:
    """Detection-owned process-exit mapping without importing CLI/runtime state."""
    if had_error:
        return 4
    score_value, valid = _score_value(score)
    if not valid:
        return 4
    if score_value >= PLR2004N75_0:
        return 3
    if score_value >= PLR2004N50_0:
        return 2
    if score_value >= PLR2004N25_0:
        return 1
    return 0


__all__ = ("classify_detection_score", "detection_exit_code_for_score")
