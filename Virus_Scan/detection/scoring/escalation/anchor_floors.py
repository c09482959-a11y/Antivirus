"""Post-model score floors derived from canonical chain decisions."""

from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.contracts.probability import safe_clamp
from Virus_Scan.utils.tagging import norm_lower_set, normalize_tags

_ASSET_STAGES = frozenset({"asset", "image", "audio", "font", "archive"})
_ENTROPY_TAGS = frozenset({
    "high_entropy_packed",
    "very_high_entropy",
    "high_entropy_sections",
    "possible_packed_or_encrypted_blob",
    "possible_xor_encoded_blob",
})
_CONCRETE_ATTACK_TAGS = frozenset({
    "certutil_exec",
    "powershell_exec",
    "encoded_powershell",
    "wmi_exec",
    "admin_share_access",
    "smb_activity",
    "shadowcopy_delete",
    "defender_disable",
    "memory_write",
    "thread_execution",
    "credential_dump_attempt",
    "lsass_access",
    "dns_tunneling",
    "encoded_payload_candidate",
})


def _score(value: object) -> float:
    numeric, _reason = no_hook_finite_float(
        value,
        default=0.0,
        minimum=0.0,
        maximum=100.0,
        reason="anchor_score_rejected",
        non_finite_reason="anchor_score_non_finite",
        allow_exact_text=True,
    )
    return safe_clamp(numeric, 0.0, 100.0)


def _stage(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="anchor_stage_missing",
        unsupported_reason="anchor_stage_rejected",
    )
    if reason:
        return str()
    return text.strip().lower()


def _asset_entropy_cap(score: float, tags: object, stage: object) -> tuple[float, list[str]] | None:
    projected_tags = tags.tags if type(tags) is TagEvidence else normalize_tags(tags)
    normalized = frozenset(norm_lower_set(projected_tags))
    archive_inner = frozenset(
        tag.split(":", 1)[1]
        for tag in normalized
        if tag.startswith("archive_inner:") and ":" in tag
    )
    concrete = normalized | archive_inner
    entropy_only = bool(normalized & _ENTROPY_TAGS) and not bool(concrete & _CONCRETE_ATTACK_TAGS)
    if _stage(stage) in _ASSET_STAGES and entropy_only:
        return min(score, 18.0), ["asset_entropy_cap"]
    return None


def apply_anchor_score_floors(
    score: object,
    chain_evidence: ChainEvidence,
    *,
    tags: object = None,
    stage: object = None,
) -> tuple[float, list[str]]:
    """Apply the highest confirmed floor from one exact canonical bundle."""
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("canonical_chain_evidence_required")
    current = _score(score)
    capped = _asset_entropy_cap(current, tags, stage)
    if capped is not None:
        return capped
    evidence = chain_evidence
    floor = evidence.maximum_anchor_floor
    if floor <= current:
        return current, []
    applied = tuple(
        decision
        for decision in evidence.decisions
        if decision.scoreable
        and decision.status == "confirmed"
        and decision.anchor_floor == floor
    )
    hits = [
        decision.candidate.chain_id + "@" + decision.candidate.rule_version
        for decision in applied
    ]
    return _score(floor), hits


__all__ = ("apply_anchor_score_floors",)
