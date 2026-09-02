"""Canonical ChainEvidence fixtures for direct adaptive-scoring contract tests."""
from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.chains.execution.anchors import evaluate_chain_evidence
from Virus_Scan.detection.scoring.adaptive.log_odds_fusion import log_odds_tag_evidence


def adaptive_chain_evidence_fixture(
    *,
    tags: object = None,
    api_calls: object = None,
    ordered_events: object = None,
) -> ChainEvidence:
    """Reproduce the scorer's former canonical ChainEvidence input explicitly."""
    tag_evidence, _tags, _roots = log_odds_tag_evidence(tags)
    return evaluate_chain_evidence(
        tags=tag_evidence,
        api_calls=api_calls,
        ordered_events=ordered_events,
    )


__all__ = ("adaptive_chain_evidence_fixture",)
