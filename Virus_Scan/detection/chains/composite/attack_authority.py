"""Concrete attack authority projected from one canonical chain bundle."""

from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainDecision, ChainEvidence


def _authoritative(decision: ChainDecision) -> bool:
    return (
        decision.status == "confirmed"
        and decision.scoreable
        and decision.candidate.order_class in {"observed_order", "causal_link"}
    )


def has_concrete_attack_chain(chain_evidence: ChainEvidence) -> bool:
    """Return true only for confirmed causal or observed-order evidence."""
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("canonical_chain_evidence_required")
    return any(_authoritative(decision) for decision in chain_evidence.decisions)


def high_gate_attack_chain_details(
    chain_evidence: ChainEvidence,
) -> tuple[bool, list[str]]:
    """Publish confirmed high-authority chain IDs from the exact bundle."""
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("canonical_chain_evidence_required")
    names = [
        decision.candidate.chain_id
        for decision in chain_evidence.decisions
        if _authoritative(decision)
    ]
    return bool(names), names


__all__ = ("has_concrete_attack_chain", "high_gate_attack_chain_details")
