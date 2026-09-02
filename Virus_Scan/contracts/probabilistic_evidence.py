"""Canonical probabilistic evidence summary contract.

This module owns the cross-domain summary projection used by detection and
reporting. It is pure, immutable-input friendly, and rejects caller-owned hooks
at probabilistic evidence boundaries.
"""
from __future__ import annotations


from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text, no_hook_type_name

ANALYTICAL_EVIDENCE_SCHEMA_VERSION = 1
PROBABILISTIC_SEMANTICS_VERSION = 1


def _owned_mapping(value: object) -> bool:
    return type(value) is dict


def _owned_sequence(value: object) -> bool:
    return type(value) in (tuple, list, set, frozenset)


def _safe_probability_value(value: object, minimum: float = 0.0, maximum: float = 1.0) -> tuple[float, str]:
    lower, lower_reason = no_hook_finite_float(minimum, default=0.0, allow_exact_text=True)
    upper, upper_reason = no_hook_finite_float(maximum, default=1.0, allow_exact_text=True)
    if lower_reason:
        lower = 0.0
    if upper_reason:
        upper = 1.0
    if upper < lower:
        lower, upper = upper, lower
    numeric, reason = no_hook_finite_float(
        value,
        default=lower,
        minimum=lower,
        maximum=upper,
        reason="non_numeric_probability_evidence",
        non_finite_reason="non_finite_probability_evidence",
        allow_exact_text=True,
    )
    return numeric, reason


def _safe_clamp(value: object, minimum: float = 0.0, maximum: float = 1.0) -> float:
    numeric, _reason = _safe_probability_value(value, minimum, maximum)
    return numeric


def _detail_get(detail: dict[str, object], key: str, default: object = None) -> object:
    try:
        return dict.get(detail, key, default)
    except IO_CONFIGURATION_ERRORS:
        return default


def _probability_group_name(detail: dict[str, object], semantic_group: object) -> str:
    for candidate in (_detail_get(detail, "correlation_group"), semantic_group, "generic_behavior"):
        group_text, group_reason = no_hook_text(
            candidate,
            missing_reason="missing_probability_correlation_group",
            unsupported_reason="unsupported_probability_correlation_group",
        )
        if group_reason == "" and str.strip(group_text) != "":
            return str.strip(group_text)
    return "generic_behavior"


def _detail_int(detail: dict[str, object], key: str) -> int:
    value = _detail_get(detail, key, 0)
    if type(value) is int and type(value) is not bool:
        return int.__int__(value)
    return 0


def correlation_group_summary(evidence_details: object) -> dict[str, dict[str, object]]:
    """Fuse correlated evidence by group without importing domain internals."""
    grouped: dict[str, list[tuple[float, str]]] = {}
    if evidence_details is None:
        iterable: tuple[object, ...] = ()
    elif type(evidence_details) is tuple:
        iterable = evidence_details
    elif type(evidence_details) is list:
        iterable = tuple(list.__iter__(evidence_details))
    elif type(evidence_details) is set:
        iterable = tuple(set.__iter__(evidence_details))
    elif type(evidence_details) is frozenset:
        iterable = tuple(frozenset.__iter__(evidence_details))
    else:
        return {
            "unsupported_probability_evidence": {
                "count": 0,
                "valid_count": 0,
                "strongest": 0.0,
                "correlated_fused": 0.0,
                "overcount_limited": False,
                "degraded": True,
                "failure_evidence_recorded": True,
                "invalid_numeric_inputs": 0,
                "invalid_numeric_reason": "unsupported_probability_evidence_iterable",
                "evidence_value_type": no_hook_type_name(evidence_details),
            }
        }
    for detail in iterable:
        if not _owned_mapping(detail):
            continue
        semantic = _detail_get(detail, "probabilistic_semantics")
        semantic_group = _detail_get(semantic, "correlation_group") if _owned_mapping(semantic) else None
        group = _probability_group_name(detail, semantic_group)
        confidence, reason = _safe_probability_value(
            _detail_get(detail, "posterior", _detail_get(detail, "confidence", 0.0))
        )
        grouped.setdefault(group, []).append((confidence, reason))

    output: dict[str, dict[str, object]] = {}
    for group, values in dict.items(grouped):
        clamped = [value for value, _reason in values]
        invalid_reasons = tuple(reason for _value, reason in values if reason)
        strongest = max(clamped) if clamped else 0.0
        residual = sum(sorted(clamped, reverse=True)[1:]) * 0.15
        group_record: dict[str, object] = {
            "count": len(clamped),
            "valid_count": len(clamped) - len(invalid_reasons),
            "strongest": round(strongest, 6),
            "correlated_fused": round(_safe_clamp(strongest + residual), 6),
            "overcount_limited": len(clamped) > 1,
        }
        if invalid_reasons:
            group_record.update(
                {
                    "degraded": True,
                    "failure_evidence_recorded": True,
                    "invalid_numeric_inputs": len(invalid_reasons),
                    "invalid_numeric_reason": sorted(set(invalid_reasons))[0],
                }
            )
        output[group] = group_record
    return output


def probabilistic_evidence_summary(evidence_details: object, prior: float = 0.03) -> dict[str, object]:
    """Build an uncertainty-aware, correlation-limited evidence summary."""
    try:
        groups = correlation_group_summary(evidence_details)
        if not groups:
            return {
                "schema_version": ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
                "version": PROBABILISTIC_SEMANTICS_VERSION,
                "ready": False,
                "reason": "no_evidence",
                "posterior": 0.0,
                "correlation_groups": {},
            }
        prod_not = 1.0
        group_values = tuple(dict.values(groups))
        for group in group_values:
            prod_not *= 1.0 - _safe_clamp(_detail_get(group, "correlated_fused", 0.0))
        fused = _safe_clamp(1.0 - prod_not)
        max_group = max(
            (_safe_clamp(_detail_get(group, "correlated_fused", 0.0)) for group in group_values),
            default=0.0,
        )
        posterior = _safe_clamp(max_group + (fused - max_group) * 0.55)
        invalid_inputs = sum(_detail_int(group, "invalid_numeric_inputs") for group in group_values)
        valid_inputs = sum(_detail_int(group, "valid_count") for group in group_values)
        degraded_groups = any(_detail_get(group, "degraded", False) is True for group in group_values)
        prior_value, prior_reason = _safe_probability_value(prior)
        ready = valid_inputs > 0
        result: dict[str, object] = {
            "schema_version": ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
            "version": PROBABILISTIC_SEMANTICS_VERSION,
            "ready": ready,
            "posterior": round(posterior if ready else 0.0, 6),
            "raw_noisy_or": round(fused if ready else 0.0, 6),
            "prior": round(prior_value, 6),
            "correlation_groups": groups,
            "conditional_independence_assumed": False,
            "uncertainty_propagated": True,
        }
        if invalid_inputs or prior_reason or degraded_groups:
            result.update(
                {
                    "degraded": True,
                    "failure_evidence_recorded": True,
                    "invalid_numeric_inputs": invalid_inputs,
                }
            )
        if not ready:
            result["reason"] = "no_valid_probability_evidence"
        if prior_reason:
            result["prior_unavailable_reason"] = prior_reason
        return result
    except IO_CONFIGURATION_ERRORS as exc:
        return {
            "schema_version": ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
            "version": PROBABILISTIC_SEMANTICS_VERSION,
            "ready": False,
            "reason": "summary_failed",
            "error_type": type(exc).__name__,
            "degraded": True,
            "failure_evidence_recorded": True,
            "json_record_required": True,
            "replay_record_required": True,
        }


__all__ = (
    "ANALYTICAL_EVIDENCE_SCHEMA_VERSION",
    "PROBABILISTIC_SEMANTICS_VERSION",
    "correlation_group_summary",
    "probabilistic_evidence_summary",
)
