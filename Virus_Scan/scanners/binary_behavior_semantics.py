"""Scanner-owned binary behavior semantic scoring helpers.

This module keeps Phase 10 binary scoring independent from detection-owned
private scoring internals.  It is intentionally read-only and deterministic.
All behavior policy lists are read from the schema-validated binary policy
snapshot instead of mutable Python policy tables.
"""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.no_hook_materialization import no_hook_text
from Virus_Scan.scanners.config.loader import load_binary_policy_snapshot
from Virus_Scan.scanners.binary_numeric import scanner_clamped_probability, scanner_clamped_ratio

_BINARY_POLICY = load_binary_policy_snapshot()
_OS_EXECUTION_TAGS = _BINARY_POLICY.binary_os_execution_tags
_BUCKET_TERMS = _BINARY_POLICY.binary_behavior_bucket_terms
_HIGH_CONFIDENCE_TAGS = _BINARY_POLICY.binary_high_confidence_tags


@dataclass(frozen=True, slots=True)
class EffectiveEvidenceScoreRequest:
    file_path: object
    tag: object
    strings_blob: object = ""
    api_calls: object = None
    ordered_events: object = None


def _scanner_behavior_text(value: object, *, missing_reason: str, unsupported_reason: str) -> tuple[str, str]:
    """Return scanner-owned text without invoking caller-owned hooks."""
    text, reason = no_hook_text(
        value,
        missing_reason=missing_reason,
        unsupported_reason=unsupported_reason,
    )
    if reason:
        return "", reason
    return str.strip(text).lower(), ""


def _scanner_behavior_text_values(values: object, *, unsupported_reason: str) -> tuple[str, ...]:
    """Materialize exact scanner text sequences without truthiness or iteration hooks."""
    if values is None:
        return ()
    if type(values) in (str, bytes, bytearray, bool, int, float):
        text, reason = _scanner_behavior_text(
            values,
            missing_reason="missing_binary_behavior_text",
            unsupported_reason=unsupported_reason,
        )
        return (text,) if not reason and text else ()
    if type(values) not in (tuple, list, set, frozenset):
        return ()
    out: list[str] = []
    for value in tuple(values):
        text, reason = _scanner_behavior_text(
            value,
            missing_reason="missing_binary_behavior_text",
            unsupported_reason=unsupported_reason,
        )
        if not reason and text:
            out.append(text)
    return tuple(out)


def tag_behavior_bucket(tag: str) -> str:
    low, reason = _scanner_behavior_text(
        tag,
        missing_reason="empty_behavior_tag",
        unsupported_reason="unsafe_behavior_tag_rejected",
    )
    if reason or not low:
        return "other_behavior"
    if low in _OS_EXECUTION_TAGS or "exec" in low:
        return "os_execution"
    for bucket in ("network", "credential", "persistence", "injection", "evasion"):
        if any(part in low for part in _BUCKET_TERMS[bucket]):
            return bucket
    return "other_behavior"


def evidence_level_for_tag(tag: str, *, strings_blob: str = "", path: object = None, api_calls: object = None, ordered_events: object = None) -> tuple[str, float]:
    del path  # Explicitly unused contract parameters.
    low, tag_reason = _scanner_behavior_text(
        tag,
        missing_reason="empty_behavior_tag",
        unsupported_reason="unsafe_behavior_tag_rejected",
    )
    blob, _blob_reason = _scanner_behavior_text(
        strings_blob,
        missing_reason="missing_binary_behavior_blob",
        unsupported_reason="unsafe_binary_behavior_blob_rejected",
    )
    api_values = _scanner_behavior_text_values(api_calls, unsupported_reason="unsafe_binary_api_call_rejected")
    event_values = _scanner_behavior_text_values(ordered_events, unsupported_reason="unsafe_binary_event_rejected")
    api_text = " ".join(api_values)
    event_text = " ".join(event_values)
    if tag_reason == "unsafe_behavior_tag_rejected":
        return ("unsafe_behavior_tag_rejected", 0.0)
    if not low:
        return ("empty_tag", 0.0)
    if low in event_text:
        return ("confirmed_timeline", 0.85)
    if low in api_text:
        return ("confirmed_api", 0.75)
    if low in _HIGH_CONFIDENCE_TAGS:
        return ("high_authority_scanner_tag", 0.78)
    if low.replace("_", " ") in blob or low in blob:
        return ("string_or_pattern", 0.55)
    bucket = tag_behavior_bucket(low)
    if bucket in {"os_execution", "credential", "persistence", "injection", "evasion"}:
        return ("behavior_tag", 0.6)
    if bucket == "network":
        return ("network_behavior_tag", 0.5)
    return ("supporting_scanner_tag", 0.35)


def tag_effective_evidence_score(request: EffectiveEvidenceScoreRequest) -> object:
    low, tag_reason = _scanner_behavior_text(
        request.tag,
        missing_reason="empty_behavior_tag",
        unsupported_reason="unsafe_behavior_tag_rejected",
    )
    bucket = tag_behavior_bucket(low)
    evidence, confidence = evidence_level_for_tag(
        request.tag,
        strings_blob=request.strings_blob,
        path=request.file_path,
        api_calls=request.api_calls,
        ordered_events=request.ordered_events,
    )
    if tag_reason == "unsafe_behavior_tag_rejected":
        return {
            "tag": "",
            "bucket": "other_behavior",
            "risk": 0.0,
            "risk_raw": 0.0,
            "evidence": evidence,
            "confidence": 0.0,
            "probability": 0.0,
            "rarity_multiplier": 1.0,
            "effective_score": 0.0,
            "score_cap": 0.0,
            "ready": False,
            "reason": tag_reason,
            "failure_evidence_recorded": True,
        }
    risk_raw = 2.0 if bucket == "other_behavior" else 4.0
    if low in _HIGH_CONFIDENCE_TAGS:
        risk_raw = 7.5
    probability = 0.0
    rarity_multiplier = 1.5 if confidence >= 0.6 else 1.0
    raw = risk_raw * confidence * rarity_multiplier
    cap = 2.5 if confidence < 0.3 else 5.0 if confidence < 0.6 else 10.0
    return {
        "tag": low,
        "bucket": bucket,
        "risk": scanner_clamped_ratio(risk_raw, 10.0, field="risk"),
        "risk_raw": risk_raw,
        "evidence": evidence,
        "confidence": scanner_clamped_probability(confidence, field="confidence"),
        "probability": probability,
        "rarity_multiplier": rarity_multiplier,
        "effective_score": min(raw, cap),
        "score_cap": cap,
        "ready": bool(low),
        "reason": "ok" if low else "empty_behavior_tag",
        "failure_evidence_recorded": False,
    }




__all__ = (
    'EffectiveEvidenceScoreRequest',
    'evidence_level_for_tag',
    'tag_behavior_bucket',
    'tag_effective_evidence_score',
)
