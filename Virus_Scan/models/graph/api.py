"""Canonical public graph model API.

The graph package owns graph state access, relationships, influence, feature
projection, and replay/publication-ready graph evidence. Production callers
should prefer this module or the bounded wrappers under ``Virus_Scan.models.api``
instead of importing graph implementation modules directly.
"""
from __future__ import annotations

from Virus_Scan.models.graph.attention import (
    compute_attention_weights,
    graph_attention_evidence,
    propagate_graph_attention,
    propagate_graph_attention_refined,
    safe_attention_lookup,
)
from Virus_Scan.models.graph.cache import cache_get, cache_key, cache_set
from Virus_Scan.models.graph.chains import (
    propagate_behavior_chains_from_node,
    reconstruct_attack_chain,
    score_attack_chain_presence,
    score_attack_chain_presence_from_edges,
)
from Virus_Scan.models.graph.cluster_projection import (
    propagate_cluster_influence,
    reinforce_cluster_with_graph,
    reinforce_graph_with_cluster,
)
from Virus_Scan.models.graph.evidence import (
    causal_entity_lineage_overlay,
    infer_behavioral_entities,
    infer_causal_transition_edges,
)
from Virus_Scan.models.graph.features import get_graph_features
from Virus_Scan.models.graph.influence import (
    explain_graph_influence,
    integrate_graph_intelligence,
)
from Virus_Scan.models.graph.links import (
    incremental_graph_update,
    link_archive_members_to_graph,
    link_tags_to_graph,
    link_temporal_to_graph,
)
from Virus_Scan.models.graph.method_graph import (
    add_method_node,
    build_method_graph,
    extract_calls,
    extract_methods,
)
from Virus_Scan.models.graph.relationships import (
    compute_graph_relationship_layer,
    phase_hits_from_tags,
    phase_matches_from_tags,
)
from Virus_Scan.models.graph.risk import (
    compute_graph_signal,
    get_graph_risk,
    get_graph_risk_enhanced,
    get_graph_risk_enhanced_evidence,
)
from Virus_Scan.models.graph.scan import scan_cs
from Virus_Scan.models.graph.stage import emit_stage_event
from Virus_Scan.models.graph.state import (
    add_graph_edge,
    enforce_graph_decay,
    ensure_graph_node,
    get_graph_node,
    graph_similarity,
    prune_graph,
)

__all__ = (
    "add_graph_edge",
    "add_method_node",
    "build_method_graph",
    "cache_get",
    "cache_key",
    "cache_set",
    "causal_entity_lineage_overlay",
    "compute_attention_weights",
    "compute_graph_relationship_layer",
    "compute_graph_signal",
    "emit_stage_event",
    "enforce_graph_decay",
    "ensure_graph_node",
    "explain_graph_influence",
    "extract_calls",
    "extract_methods",
    "get_graph_features",
    "graph_attention_evidence",
    "get_graph_node",
    "get_graph_risk",
    "get_graph_risk_enhanced",
    "get_graph_risk_enhanced_evidence",
    "graph_similarity",
    "incremental_graph_update",
    "infer_behavioral_entities",
    "infer_causal_transition_edges",
    "integrate_graph_intelligence",
    "link_archive_members_to_graph",
    "link_tags_to_graph",
    "link_temporal_to_graph",
    "phase_hits_from_tags",
    "phase_matches_from_tags",
    "propagate_behavior_chains_from_node",
    "propagate_cluster_influence",
    "propagate_graph_attention",
    "propagate_graph_attention_refined",
    "prune_graph",
    "reconstruct_attack_chain",
    "reinforce_cluster_with_graph",
    "reinforce_graph_with_cluster",
    "safe_attention_lookup",
    "scan_cs",
    "score_attack_chain_presence",
    "score_attack_chain_presence_from_edges",
)
