"""Expected-behavior publication from canonical chain-rule records."""

from __future__ import annotations

from Virus_Scan.contracts.chain_evidence import ChainRule
from Virus_Scan.detection.registries.chain_registry import CHAIN_ROLE_EXPECTED_BEHAVIOR


def chain_expected_behavior_mapping(rule: ChainRule) -> dict[str, object]:
    """Publish explainability directly from one immutable canonical rule."""
    if type(rule) is not ChainRule:
        raise TypeError("canonical_chain_rule_required")
    pattern = tuple(tuple(step.alternatives) for step in rule.steps)
    return {
        "chain": rule.chain_id,
        "version": rule.version,
        "role": rule.family,
        "expected_behavior": CHAIN_ROLE_EXPECTED_BEHAVIOR.get(
            rule.family,
            CHAIN_ROLE_EXPECTED_BEHAVIOR["generic"],
        ),
        "pattern": pattern,
        "match_mode": rule.match_mode,
        "minimum_distinct_roots": rule.minimum_distinct_roots,
        "correlation_group": rule.correlation_group,
        "requires_concrete_behavior": True,
        "scoreable_without_linked_evidence": False,
    }


__all__ = ("chain_expected_behavior_mapping",)
