"""Canonical execution/chain and temporal graph-risk components."""
from __future__ import annotations

from Virus_Scan.models.contracts.no_hook_materialization import no_hook_finite_float
from Virus_Scan.models.graph.chains import (
    propagate_behavior_chains_from_node,
    score_attack_chain_presence_from_edges,
)
from Virus_Scan.models.graph.contracts import (
    GRAPH_EXECUTION_CONTRACT_VERSION,
    GRAPH_TEMPORAL_CONTRACT_VERSION,
    GraphComponentEvidence,
    unavailable_component,
)
from Virus_Scan.models.graph.snapshot import admitted_edge_records

_EXECUTION_EDGE_TYPES = frozenset({
    "attack_phase", "behavior", "call", "phase_tag", "temporal",
})


def _text(record: object, key: str, default: str = "") -> str:
    if type(record) is not dict:
        return default
    value = record.get(key, default)
    return str.__str__(value) if isinstance(value, str) else default


def execution_graph_component(node: object, snapshot: object) -> GraphComponentEvidence:
    if type(snapshot) is not dict:
        return unavailable_component(
            "execution", "graph_snapshot_unavailable",
            GRAPH_EXECUTION_CONTRACT_VERSION,
        )
    records = admitted_edge_records(snapshot)
    execution_records = tuple(
        record for record in records
        if _text(record, "edge_type", "generic") in _EXECUTION_EDGE_TYPES
    )
    try:
        propagated = propagate_behavior_chains_from_node(node, max_depth=2)
    except (KeyError, TypeError, ValueError, RuntimeError, OSError):
        return unavailable_component(
            "execution", "graph_execution_chain_unavailable",
            GRAPH_EXECUTION_CONTRACT_VERSION,
        )
    if type(propagated) is not tuple or len(propagated) != 2:
        return unavailable_component(
            "execution", "graph_execution_chain_unavailable",
            GRAPH_EXECUTION_CONTRACT_VERSION,
        )
    raw_score, discovered = propagated
    chain_score, chain_reason = no_hook_finite_float(
        raw_score, default=0.0, minimum=0.0, maximum=40.0,
        reason="graph_execution_chain_score_unavailable",
    )
    if chain_reason:
        return unavailable_component(
            "execution", chain_reason, GRAPH_EXECUTION_CONTRACT_VERSION,
        )
    chain_value = min(1.0, chain_score / 40.0)
    relation_strength = 0.0
    if execution_records:
        weighted: list[float] = []
        for record in execution_records:
            weight, weight_reason = no_hook_finite_float(
                record.get("weight"), default=0.0, minimum=0.0,
                reason="graph_execution_weight_unavailable",
            )
            confidence, confidence_reason = no_hook_finite_float(
                record.get("confidence"), default=0.0, minimum=0.0, maximum=1.0,
                reason="graph_execution_confidence_unavailable",
            )
            if weight_reason or confidence_reason:
                continue
            weighted.append(min(1.0, weight / 3.0) * confidence)
        relation_strength = min(1.0, sum(weighted) / 4.0)
    edge_destinations = tuple(_text(record, "destination") for record in records)
    phase_coverage = score_attack_chain_presence_from_edges(edge_destinations)
    value = max(chain_value, min(1.0, relation_strength * 0.7 + phase_coverage * 0.3))
    chain_rows = discovered if type(discovered) is list else []
    flow_lengths = [len(row.get("flow", ())) for row in chain_rows if type(row) is dict]
    temporal_present = any(_text(record, "edge_type") == "temporal" for record in execution_records)
    if chain_rows and temporal_present:
        evidence_order = "causal"
    elif any(length > 1 for length in flow_lengths):
        evidence_order = "ordered"
    elif chain_rows:
        evidence_order = "unordered"
    elif execution_records:
        evidence_order = "partial"
    else:
        evidence_order = "none"
    chain_ids = sorted({
        chain
        for row in chain_rows if type(row) is dict
        for chain in row.get("chains", ()) if isinstance(chain, str)
    })
    support = len(execution_records) + len(chain_ids)
    return GraphComponentEvidence(
        name="execution", value=value, ready=True, support_count=support,
        maturity=min(1.0, 0.25 + support / 10.0), unavailable_reason=None,
        provenance=(
            "evidence_order:" + evidence_order,
            "chain_ids:" + ",".join(chain_ids),
            "execution_edge_evidence:" + str(len(execution_records)),
        ),
        version=GRAPH_EXECUTION_CONTRACT_VERSION,
    )


def temporal_graph_component(snapshot: object) -> GraphComponentEvidence:
    if type(snapshot) is not dict:
        return unavailable_component(
            "temporal", "graph_snapshot_unavailable",
            GRAPH_TEMPORAL_CONTRACT_VERSION,
        )
    records = tuple(
        record for record in admitted_edge_records(snapshot)
        if _text(record, "edge_type") == "temporal"
    )
    if not records:
        return GraphComponentEvidence(
            name="temporal", value=0.0, ready=True, support_count=0,
            maturity=0.2, unavailable_reason=None,
            provenance=("temporal_edge_evidence:0",),
            version=GRAPH_TEMPORAL_CONTRACT_VERSION,
        )
    strengths: list[float] = []
    for record in records:
        weight, weight_reason = no_hook_finite_float(
            record.get("weight"), default=0.0, minimum=0.0,
            reason="graph_temporal_weight_unavailable",
        )
        confidence, confidence_reason = no_hook_finite_float(
            record.get("confidence"), default=0.0, minimum=0.0, maximum=1.0,
            reason="graph_temporal_confidence_unavailable",
        )
        if weight_reason or confidence_reason:
            return unavailable_component(
                "temporal", weight_reason or confidence_reason,
                GRAPH_TEMPORAL_CONTRACT_VERSION,
            )
        strengths.append(min(1.0, weight / 2.0) * confidence)
    value = min(1.0, sum(strengths) / max(1, len(strengths)))
    return GraphComponentEvidence(
        name="temporal", value=value, ready=True, support_count=len(records),
        maturity=min(1.0, 0.3 + len(records) / 8.0), unavailable_reason=None,
        provenance=("temporal_edge_evidence:" + str(len(records)), "ordering:causal"),
        version=GRAPH_TEMPORAL_CONTRACT_VERSION,
    )


__all__ = ("execution_graph_component", "temporal_graph_component")
