"""Canonical type-aware structural graph risk component."""
from __future__ import annotations

import math

from Virus_Scan.models.contracts.no_hook_materialization import no_hook_finite_float
from Virus_Scan.models.graph.contracts import (
    GRAPH_RISK_POLICY,
    GRAPH_RISK_POLICY_VERSION,
    GraphComponentEvidence,
    unavailable_component,
)
from Virus_Scan.models.graph.snapshot import admitted_edge_records

_HIGH_RISK_EDGE_TYPES = frozenset({
    "archive_safety", "attack_phase", "behavior", "call", "engine_fingerprint",
    "phase_tag", "temporal",
})


def _text(record: object, key: str, default: str = "") -> str:
    if type(record) is not dict:
        return default
    value = record.get(key, default)
    return str.__str__(value) if isinstance(value, str) else default


def structural_graph_component(snapshot: object) -> GraphComponentEvidence:
    if type(snapshot) is not dict:
        return unavailable_component(
            "structural", "graph_snapshot_unavailable", GRAPH_RISK_POLICY_VERSION,
        )
    records = tuple(
        record for record in admitted_edge_records(snapshot)
        if _text(record, "edge_type", "generic") not in GRAPH_RISK_POLICY.explanation_edge_types
    )
    support = len(records)
    if support == 0:
        return GraphComponentEvidence(
            name="structural", value=0.0, ready=True, support_count=0,
            maturity=0.2, unavailable_reason=None,
            provenance=("distinct_edge_evidence:0", "high_risk_families:0"),
            version=GRAPH_RISK_POLICY_VERSION,
        )
    families = {_text(record, "edge_type", "generic") for record in records}
    high_families = families & _HIGH_RISK_EDGE_TYPES
    destinations = {_text(record, "destination") for record in records}
    destination_families = {
        destination.split(":", 1)[0] if ":" in destination else "node"
        for destination in destinations if destination
    }
    intensity_values: list[float] = []
    directed_high = 0
    for record in records:
        weight, weight_reason = no_hook_finite_float(
            record.get("weight"), default=0.0, minimum=0.0,
            reason="graph_structural_weight_unavailable",
        )
        confidence, confidence_reason = no_hook_finite_float(
            record.get("confidence"), default=0.0, minimum=0.0, maximum=1.0,
            reason="graph_structural_confidence_unavailable",
        )
        if weight_reason or confidence_reason:
            return unavailable_component(
                "structural", weight_reason or confidence_reason,
                GRAPH_RISK_POLICY_VERSION,
            )
        intensity_values.append(min(1.0, weight / 3.0) * confidence)
        if _text(record, "edge_type", "generic") in _HIGH_RISK_EDGE_TYPES:
            if _text(record, "direction", "outbound") in {"outbound", "bidirectional"}:
                directed_high += 1
    degree = min(
        1.0,
        math.log1p(support) / math.log1p(GRAPH_RISK_POLICY.max_structural_edges),
    )
    family_score = min(1.0, len(high_families) / 5.0)
    intensity = sum(intensity_values) / max(1, len(intensity_values))
    diversity = min(1.0, len(destination_families) / 6.0)
    directional = directed_high / max(1, support)
    value = min(1.0, max(0.0,
        family_score * 0.34
        + degree * 0.18
        + intensity * 0.22
        + diversity * 0.14
        + directional * 0.12
    ))
    maturity = min(1.0, 0.25 + support / 20.0)
    return GraphComponentEvidence(
        name="structural", value=value, ready=True, support_count=support,
        maturity=maturity, unavailable_reason=None,
        provenance=(
            "distinct_edge_evidence:" + str(support),
            "high_risk_families:" + ",".join(sorted(high_families)),
            "edge_families:" + ",".join(sorted(families)),
            "destination_families:" + str(len(destination_families)),
        ),
        version=GRAPH_RISK_POLICY_VERSION,
    )


__all__ = ("structural_graph_component",)
