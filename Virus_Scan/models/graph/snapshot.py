"""Admission helpers for the canonical runtime-owned graph snapshot."""
from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
)
from Virus_Scan.models.graph.common import safe_graph_text_with_reason
from Virus_Scan.runtime.graph_state import (
    GRAPH_EDGE_RECORD_VERSION,
    GRAPH_SNAPSHOT_SCHEMA_VERSION,
    graph_snapshot_digest_owned,
)


def _mapping_get(value: object, name: str, default: object = None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for key, item in items:
        if isinstance(key, str) and str.__str__(key) == name:
            return item
    return default


def admitted_graph_snapshot(value: object) -> tuple[Mapping[str, object] | None, str]:
    items = no_hook_mapping_items(value)
    if items is None:
        return None, "graph_node_snapshot_unavailable"
    snapshot = dict(items)
    version = _mapping_get(snapshot, "snapshot_version")
    if not isinstance(version, str) or str.__str__(version) != GRAPH_SNAPSHOT_SCHEMA_VERSION:
        return None, "graph_snapshot_version_unavailable"
    digest, digest_reason = safe_graph_text_with_reason(
        _mapping_get(snapshot, "snapshot_digest"), "graph_snapshot_digest_unavailable",
    )
    if digest_reason or len(digest) != 64:
        return None, "graph_snapshot_digest_unavailable"
    if graph_snapshot_digest_owned(snapshot) != digest:
        return None, "graph_snapshot_digest_mismatch"
    node_id, node_reason = safe_graph_text_with_reason(
        _mapping_get(snapshot, "node_id"), "graph_snapshot_node_id_unavailable",
    )
    if node_reason or node_id == "":
        return None, "graph_snapshot_node_id_unavailable"
    node_type, type_reason = safe_graph_text_with_reason(
        _mapping_get(snapshot, "node_type"), "graph_snapshot_node_type_unavailable",
    )
    if type_reason or node_type == "":
        return None, "graph_snapshot_node_type_unavailable"
    ordinal, ordinal_reason = no_hook_exact_nonnegative_int(
        _mapping_get(snapshot, "update_ordinal"),
        default=0,
        reason="graph_snapshot_ordinal_unavailable",
    )
    if ordinal_reason:
        return None, ordinal_reason
    edge_records = _mapping_get(snapshot, "edge_records", ())
    if type(edge_records) is not tuple:
        return None, "graph_edge_records_unavailable"
    seen_evidence: set[str] = set()
    for record in edge_records:
        record_items = no_hook_mapping_items(record)
        if record_items is None:
            return None, "graph_edge_record_unavailable"
        record_map = dict(record_items)
        if _mapping_get(record_map, "record_version") != GRAPH_EDGE_RECORD_VERSION:
            return None, "graph_edge_record_version_unavailable"
        evidence_id, evidence_reason = safe_graph_text_with_reason(
            _mapping_get(record_map, "source_evidence_id"),
            "graph_edge_evidence_id_unavailable",
        )
        if evidence_reason or evidence_id == "":
            return None, "graph_edge_evidence_id_unavailable"
        if evidence_id in seen_evidence:
            continue
        seen_evidence.add(evidence_id)
        weight, weight_reason = no_hook_finite_float(
            _mapping_get(record_map, "weight"), default=0.0, minimum=0.0,
            reason="graph_edge_weight_unavailable",
        )
        confidence, confidence_reason = no_hook_finite_float(
            _mapping_get(record_map, "confidence"), default=0.0,
            minimum=0.0, maximum=1.0,
            reason="graph_edge_confidence_unavailable",
        )
        if weight_reason or confidence_reason or weight < 0.0 or not 0.0 <= confidence <= 1.0:
            return None, weight_reason or confidence_reason or "graph_edge_metric_unavailable"
    snapshot["update_ordinal"] = ordinal
    return snapshot, ""


def admitted_edge_records(snapshot: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    records = snapshot.get("edge_records", ())
    if type(records) is not tuple:
        return ()
    out: list[Mapping[str, object]] = []
    seen: set[str] = set()
    for record in records:
        items = no_hook_mapping_items(record)
        if items is None:
            continue
        row = dict(items)
        evidence_id = row.get("source_evidence_id")
        if not isinstance(evidence_id, str):
            continue
        evidence_text = str.__str__(evidence_id)
        if evidence_text in seen:
            continue
        seen.add(evidence_text)
        out.append(row)
    return tuple(out)


__all__ = ("admitted_edge_records", "admitted_graph_snapshot")
