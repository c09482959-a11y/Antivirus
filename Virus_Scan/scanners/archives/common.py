"""Archive scanner common policy helpers."""

from __future__ import annotations

import re

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text
from Virus_Scan.scanners.config.loader import load_archive_policy_snapshot
from Virus_Scan.scanners.filetype_policy import HIGH_RISK_BUCKETS

_ARCHIVE_POLICY = load_archive_policy_snapshot()


def extract_methods(cs_text: object) -> dict[str, str]:
    """Extract C#-like method bodies from text for archive/member evidence."""
    text, text_reason = no_hook_text(
        cs_text,
        missing_reason="archive_methods_text_missing",
        unsupported_reason="archive_methods_text_unsafe",
    )
    if text_reason == "archive_methods_text_missing":
        return {}
    if text_reason:
        return {text_reason: text_reason}
    methods: dict[str, str] = {}
    current: str | None = None
    brace_depth = 0
    buf: list[str] = []
    method_header = re.compile(r"(?:public|private|protected|internal)?\s*(?:static\s+)?[\w<>,\[\]]+\s+\w+\s*\([^)]*\)")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            continue
        if current is None and method_header.search(stripped) and "{" in stripped:
            current = stripped
            brace_depth = stripped.count("{") - stripped.count("}")
            buf = [stripped]
            continue
        if current is not None:
            brace_depth += stripped.count("{") - stripped.count("}")
            buf.append(stripped)
            if brace_depth <= 0:
                methods[current] = "\n".join(buf)
                current = None
                buf = []
    return methods


def rarity_multiplier_for_probability(prob: float, risk: float = 0.0, bucket: str = "other_behavior") -> float:
    """Return archive ecosystem rarity multiplier from immutable archive policy."""
    safe_prob, prob_reason = no_hook_finite_float(
        prob,
        default=0.0,
        minimum=0.0,
        maximum=1.0,
        reason="archive_rarity_probability_unsafe",
        non_finite_reason="archive_rarity_probability_unsafe",
    )
    risk_value, risk_reason = no_hook_finite_float(
        risk,
        default=0.0,
        minimum=0.0,
        reason="archive_rarity_risk_unsafe",
        non_finite_reason="archive_rarity_risk_unsafe",
    )
    bucket_text, bucket_reason = no_hook_text(
        bucket,
        missing_reason="archive_rarity_bucket_missing",
        unsupported_reason="archive_rarity_bucket_unsafe",
    )
    if prob_reason or risk_reason:
        risk_value = _ARCHIVE_POLICY.rarity_high_risk_min_score
    if bucket_reason:
        bucket_text = "os_execution"
    bucket_name = str.lower(str.strip(bucket_text))
    if safe_prob <= _ARCHIVE_POLICY.rarity_high_risk_probability and (
        risk_value >= _ARCHIVE_POLICY.rarity_high_risk_min_score or bucket_name in HIGH_RISK_BUCKETS
    ):
        return _ARCHIVE_POLICY.rarity_high_risk_multiplier
    if safe_prob < _ARCHIVE_POLICY.rarity_rare_probability:
        return _ARCHIVE_POLICY.rarity_rare_multiplier
    if safe_prob < _ARCHIVE_POLICY.rarity_uncommon_probability:
        return _ARCHIVE_POLICY.rarity_uncommon_multiplier
    if safe_prob < _ARCHIVE_POLICY.rarity_common_probability:
        return _ARCHIVE_POLICY.rarity_common_multiplier
    return _ARCHIVE_POLICY.rarity_default_multiplier


__all__ = ("extract_methods", "rarity_multiplier_for_probability")
