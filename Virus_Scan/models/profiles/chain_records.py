"""Profile projections over the canonical immutable chain-evidence contract."""

from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainDecision, ChainEvidence


def profile_scoreable_chain_decisions(
    evidence: ChainEvidence,
) -> tuple[ChainDecision, ...]:
    """Return bounded suspicious decisions without reconstructing chain identity."""
    if type(evidence) is not ChainEvidence:
        raise TypeError("profile_chain_evidence_required")
    return tuple(
        decision
        for decision in evidence.decisions
        if decision.scoreable and decision.status in {"confirmed", "candidate"}
    )


def profile_chain_frequency_key(decision: ChainDecision) -> str:
    """Return one versioned persisted frequency key for a canonical decision."""
    if type(decision) is not ChainDecision:
        raise TypeError("profile_chain_decision_required")
    candidate = decision.candidate
    return "|".join((
        candidate.chain_id,
        candidate.rule_version,
        decision.status,
        candidate.order_class,
    ))


def profile_chain_family_count(evidence: ChainEvidence) -> int:
    """Count distinct scoreable families rather than expanded chain strings."""
    return len({
        decision.candidate.family
        for decision in profile_scoreable_chain_decisions(evidence)
    })


__all__ = (
    "profile_chain_family_count",
    "profile_chain_frequency_key",
    "profile_scoreable_chain_decisions",
)
