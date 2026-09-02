"""Canonical clustering projections for immutable chain evidence."""
from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.models.clustering.common import cluster_text_set


def cluster_chain_signature(chain_evidence: ChainEvidence) -> set[str]:
    """Project canonical scoreable chain identities without tag inference."""
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("cluster_chain_evidence_required")
    return {
        ":".join((
            decision.status,
            decision.candidate.family,
            decision.candidate.chain_id,
            decision.candidate.rule_version,
        ))
        for decision in chain_evidence.decisions
        if decision.scoreable and decision.status in {"confirmed", "candidate"}
    }


def cluster_behavior_signature(tags: object) -> set[str]:
    """Project bounded behavior labels from already-materialized tag text."""
    values = cluster_text_set(tags, reason="cluster_behavior_input_unavailable")
    return {
        value.split(":", 1)[-1].strip().lower()
        for value in values
        if value.strip()
    }


__all__ = ("cluster_behavior_signature", "cluster_chain_signature")
