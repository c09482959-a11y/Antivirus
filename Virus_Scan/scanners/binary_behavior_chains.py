"""Scanner-owned binary behavior chain detectors."""

from __future__ import annotations

from Virus_Scan.scanners.config import load_binary_policy_snapshot
from Virus_Scan.utils.tagging import norm_lower_set, ordered_unique_tags

_BINARY_POLICY = load_binary_policy_snapshot()


def binary_lolbin_chain(tags: object) -> object:
    """Order-tolerant scanner-owned LOLBIN chain detector."""
    tagset = norm_lower_set(ordered_unique_tags(tags))
    score = 0.0
    hits: list[str] = []
    for chain in _BINARY_POLICY.binary_lolbin_chain_definitions:
        required = frozenset(chain["required"])
        optional = frozenset(chain["optional"])
        if required.issubset(tagset):
            optional_hits = len(optional & tagset)
            score += float(chain["score"]) + min(4.0, optional_hits * 1.5)
            hits.append(str(chain["name"]))
    return score, sorted(set(hits))


def binary_scheduled_task_persistence(tags: object) -> object:
    """Scanner-owned scheduled-task persistence detector."""
    tagset = norm_lower_set(tags)
    score = 0.0
    hits: list[str] = []
    for rule in _BINARY_POLICY.binary_scheduled_task_persistence_rules:
        tags_for_rule = set(rule["tags"])
        mode = str(rule["mode"])
        matched = bool(tags_for_rule & tagset) if mode == "any" else tags_for_rule.issubset(tagset)
        if matched:
            score += float(rule["score"])
            hits.append(str(rule["hit"]))
    return score, sorted(set(hits))


__all__ = (
    "binary_lolbin_chain",
    "binary_scheduled_task_persistence",
)
