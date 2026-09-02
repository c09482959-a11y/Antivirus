# Stage 4 real split module for cli/exit_codes.py.
from __future__ import annotations

# Exact v27c function bodies are copied here; no exec-string module body is used.
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items
from Virus_Scan.runtime.api import record_suppressed_failure

PLR2004N25_0 = 25.0
PLR2004N50_0 = 50.0


def exit_code_for_score(score: object, *, had_error: bool = False) -> int:
    """Requested process exit-code mapping: 4 error, 3 malicious, 2 high, 1 low, 0 clean."""
    if had_error is True:
        return 4
    if type(had_error) is not bool:
        return 4
    if score is None:
        return 4
    score, score_reason = no_hook_finite_float(
        score,
        default=0.0,
        reason="unsafe_exit_score_rejected",
        non_finite_reason="non_finite_exit_score",
        allow_exact_text=True,
    )
    if score_reason:
        return 4
    if score >= 75.0:
        return 3
    if score >= PLR2004N50_0:
        return 2
    if score >= PLR2004N25_0:
        return 1
    return 0


def completed_scan_final_status(exit_code: object) -> str | None:
    """Return the terminal record status for completed classification exits."""
    if type(exit_code) is not int or type(exit_code) is bool or not 0 <= exit_code <= 3:
        return None
    return "completed" if exit_code == 0 else "completed_nonzero_exit"

def score_from_result(result: object) -> float:
    """Robust final score extraction across staged result key names."""
    if type(result) is not dict:
        exc = ValueError("scan result is not an exact result record")
        record_suppressed_failure("score_from_result_record", exc, domain="scoring", fatal=True)
        raise exc
    for key in ("score", "final_score", "risk", "risk_score", "layered_score"):
        if key in result:
            score, score_reason = no_hook_finite_float(
                dict.get(result, key),
                default=0.0,
                reason="unsafe_result_score_rejected",
                non_finite_reason="non_finite_result_score",
                allow_exact_text=True,
            )
            if score_reason:
                exc = ValueError("malformed score field " + str.__repr__(key) + ": " + score_reason)
                record_suppressed_failure("score_from_result", exc, domain="scoring", fatal=True)
                raise exc
            return score
    layers = dict.get(result, "layers")
    if type(layers) is dict:
        vals = []
        invalid_layers = 0
        for _layer_name, raw_value in no_hook_mapping_items(layers) or ():
            value = raw_value
            if type(value) is dict:
                value = dict.get(value, "score")
            score, score_reason = no_hook_finite_float(
                value,
                default=0.0,
                reason="unsafe_layer_score_rejected",
                non_finite_reason="non_finite_layer_score",
                allow_exact_text=True,
            )
            if score_reason:
                invalid_layers += 1
                record_suppressed_failure(
                    "score_from_result_layer",
                    ValueError(score_reason),
                    domain="scoring",
                    fatal=True,
                )
                continue
            vals.append(score)
        if vals:
            return max(vals)
        if invalid_layers:
            exception_message = "all declared layer scores are malformed"
            raise ValueError(exception_message)
    exc = ValueError("scan result does not contain a score")
    record_suppressed_failure("score_from_result_missing", exc, domain="scoring", fatal=True)
    raise exc

__all__ = ('completed_scan_final_status', 'exit_code_for_score', 'score_from_result')
