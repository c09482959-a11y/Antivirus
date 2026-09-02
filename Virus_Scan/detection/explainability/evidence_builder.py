"""Immutable explainability handoff ownership for detection explainability.

This module owns reporting-facing explanation structures produced from immutable
detection outputs. It does not score, mutate tags/chains, write reports, or own
scheduler/runtime lifecycle state.
"""

from Virus_Scan.detection.explainability.evasion_signals import detect_evasion_signals
from Virus_Scan.models.api.graph_contracts import (
    explain_graph_influence as model_graph_influence,
)
from Virus_Scan.models.api.temporal_contracts import (
    explain_temporal_drift as model_temporal_drift,
)


def explain_graph_influence(node: object) -> object:
    """Detection-owned graph influence projection for immutable explanations."""
    return model_graph_influence(node)


def explain_temporal_drift(node: object) -> object:
    """Detection-owned temporal drift projection for immutable explanations."""
    return model_temporal_drift(node)

def explain_behavior_patterns(tags: object) -> object:
    """
    Extract high-risk behavior indicators for explanation layer.
    """
    explanations = []
    if 'process_exec' in tags:
        explanations.append('process execution detected')
    if 'network_download' in tags:
        explanations.append('network retrieval activity')
    if 'registry_mod' in tags:
        explanations.append('registry modification behavior')
    if 'scheduled_task' in tags:
        explanations.append('persistence via scheduled tasks')
    if 'encoded_powershell' in tags:
        explanations.append('obfuscated command execution')
    if 'memory_read' in tags or 'process_injection' in tags:
        explanations.append('memory-level access (possible credential theft)')
    return explanations[:10]


def build_explanation_bundle(node: object, tags: object) -> object:
    """Build the immutable reporting-facing explanation bundle."""
    return {
        "behavior": tuple(explain_behavior_patterns(tags)),
        "graph_influence": tuple(explain_graph_influence(node) if node else ()),
        "temporal_drift": tuple(explain_temporal_drift(node) if node else ()),
        "evasion_signals": detect_evasion_signals(tags, node),
    }
