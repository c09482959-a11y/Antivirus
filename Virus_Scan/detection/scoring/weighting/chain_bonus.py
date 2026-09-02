"""Single canonical score projection for immutable behavior-chain evidence."""

from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.scoring.weighting.scoreable_tags import (
    concrete_score_count,
    scoreable_tag_evidence,
    scoreable_tag_set,
)
from Virus_Scan.detection.scoring.weighting.noise_gate import cap_noise_only_score as apply_noise_only_score_cap
from Virus_Scan.detection.tags.heuristics.tag_phase import norm_lower_set


def calibrated_chain_bonus(evidence: ChainEvidence) -> tuple[float, list[str]]:
    """Return the family-deduplicated score projection from one exact bundle."""
    if type(evidence) is not ChainEvidence:
        raise TypeError("canonical_chain_evidence_required")
    hits = [
        "chain_bonus:" + decision.candidate.chain_id + "@" + decision.candidate.rule_version + ":" + decision.status
        for decision in evidence.decisions
        if decision.scoreable
    ]
    if evidence.failures:
        hits.append("chain_bonus_degraded")
    return evidence.total_score_points, hits[:64]


def cap_noise_only_score(score: object, tags: object, stage: object = None) -> object:
    evidence = scoreable_tag_evidence(
        tags, allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    norm = norm_lower_set(evidence.tags)
    scoreable = scoreable_tag_set(evidence)
    try:
        concrete_count = concrete_score_count(evidence)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
        concrete_count = 0
    return apply_noise_only_score_cap(score, norm, scoreable, stage=stage, concrete_count=concrete_count)


__all__ = ("calibrated_chain_bonus", "cap_noise_only_score")
