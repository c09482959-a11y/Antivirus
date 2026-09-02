"""Canonical admission policy for staged benign profile observations."""
from __future__ import annotations

from Virus_Scan.contracts.tag_evidence import (
    contextual_dangerous_anchor_hits,
    dangerous_anchor_learning_block_enabled,
)
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.models.profiles.chain_records import profile_scoreable_chain_decisions
from Virus_Scan.models.profiles.common import (
    profile_finite_float,
    profile_public_ordered_events,
    profile_public_tags,
    profile_public_yara_hits,
    profile_safe_text,
)
from Virus_Scan.models.profiles.learning_gate import triage_learning_block_hits
from Virus_Scan.models.profiles.transaction_contracts import LearningCommitRequest
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.runtime.structured_failures import record_suppressed_failure

CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS = dangerous_anchor_learning_block_enabled()
MAX_RISK_FOR_STAGING = float(get_init_value("MAX_RISK_FOR_STAGING") or 25.0)


def promotion_inputs(
    request: LearningCommitRequest,
) -> tuple[set[str], tuple[object, ...], tuple[object, ...], float, str | None]:
    """Return canonical staging inputs or one explicit rejection reason."""
    risk = profile_finite_float(request.risk, 0.0)
    normalized_tags, reason = profile_public_tags(
        request.tag_evidence, "malformed_profile_staging_tags",
    )
    if reason is not None:
        return set(), (), (), risk, reason
    yara_hits, reason = profile_public_yara_hits(
        request.yara_hits, "malformed_profile_staging_yara_hits",
    )
    if reason is not None:
        return set(), (), (), risk, reason
    ordered_events, reason = profile_public_ordered_events(
        request.ordered_events, "malformed_profile_staging_ordered_events",
    )
    if reason is not None:
        return set(), (), (), risk, reason
    tags_l = {
        profile_safe_text(tag, replacement="").lower() for tag in normalized_tags
    }
    if request.verdict.lower() not in {"benign", "clean", "benign_clean", "ok"}:
        return tags_l, yara_hits, ordered_events, risk, "verdict_not_clean_for_staging"
    if risk > MAX_RISK_FOR_STAGING:
        return tags_l, yara_hits, ordered_events, risk, "risk_too_high_for_staging"
    if yara_hits:
        return tags_l, yara_hits, ordered_events, risk, "yara_hit_blocks_staging"
    if (
        contextual_dangerous_anchor_hits(tags_l)
        and CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS
    ):
        return tags_l, yara_hits, ordered_events, risk, "dangerous_anchor_blocks_staging"
    if triage_learning_block_hits(tags_l):
        return tags_l, yara_hits, ordered_events, risk, "triage_red_flag_blocks_staging"
    if "renpy_bytecode_noise_suppressed" in tags_l:
        return tags_l, yara_hits, ordered_events, risk, "validation_suppressed_noise_blocks_staging"
    try:
        chain_evidence = evaluate_chain_evidence(
            tags=request.tag_evidence, ordered_events=ordered_events,
        )
        if profile_scoreable_chain_decisions(chain_evidence):
            return tags_l, yara_hits, ordered_events, risk, "suspicious_chain_blocks_staging"
    except IO_CONFIGURATION_ERRORS as exc:
        record_suppressed_failure("suppressed_exception", exc, domain="runtime")
    if request.validation.get("rare_high_conf_single_indicator") is True:
        return (
            tags_l, yara_hits, ordered_events, risk,
            "rare_high_confidence_indicator_blocks_staging",
        )
    return tags_l, yara_hits, ordered_events, risk, None


__all__ = ("promotion_inputs",)
