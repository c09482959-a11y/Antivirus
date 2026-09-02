"""Canonical detection normalization owner for tag phase snapshots."""

from Virus_Scan.detection.tags.heuristics.normalization_runtime import canonical_tag_name, normalize_tags
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.detection.registries.chain_registry import ATTACK_GRAPH
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items


def norm_lower_set(tags: object) -> object:
    """Return a normalized immutable-friendly set of canonical lowercase tags."""
    out = set()
    for tag in ordered_unique_tags(tags):
        try:
            canonical = canonical_tag_name(tag)
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
            canonical = "tag_normalization_failure_evidence"
        if canonical:
            out.add(canonical)
    return out


def phase_hits_from_tags(tags: object) -> object:
    """Return deterministic attack-phase hits from normalized tag inputs."""
    normalized_tags = set(normalize_tags(tags))
    out = {}
    graph_items = no_hook_mapping_items(ATTACK_GRAPH)
    if graph_items is None:
        return out
    for phase, data in graph_items:
        if type(phase) is not str:
            continue
        data_items = no_hook_mapping_items(data)
        if data_items is None:
            continue
        nodes = ()
        for key, value in data_items:
            if type(key) is str and key == "nodes":
                nodes = value if type(value) in (tuple, list, set, frozenset) else ()
                break
        matched = sorted(set(nodes) & normalized_tags)
        if matched:
            out[phase] = matched
    return out
