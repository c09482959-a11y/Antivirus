"""Event-native analytical calibration snapshots.

Runtime owns event-bus emission and lineage when finalizing runtime evidence.
The shared analytical evidence math is imported from the neutral contract so
format oddity and tag-family correlation do not have duplicate owners.
"""
from __future__ import annotations

import hashlib

from .causal_event_stream import get_global_event_bus
from Virus_Scan.contracts.analytical_evidence import (
    ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
    analytical_mapping_size,
    analytical_optional_text,
    analytical_text_sequence,
    analytical_correlation_ceiling,
    analytical_family_counts,
    analytical_finite_float,
    analytical_numeric_readiness,
    analytical_format_oddity_snapshot as format_oddity_snapshot,
)


def build_analytical_calibration_bundle(path: object=None, tags: object=None, entropy: object=None, prev_stage: object="unknown", curr_stage: object="unknown", graph_score: object=0.0, graph_features: object=None, risk: object=0.0) -> object:
    tag_values = list(analytical_text_sequence(
        tags,
        missing_reason="missing_runtime_analytical_tag_value",
        unsupported_reason="unsafe_runtime_analytical_tag_value_rejected",
    ))
    prev_stage_text = analytical_optional_text(prev_stage, default='unknown') or 'unknown'
    curr_stage_text = analytical_optional_text(curr_stage, default='unknown') or 'unknown'
    path_text = analytical_optional_text(path, default='')
    families = analytical_family_counts(tag_values)
    ceiling = analytical_correlation_ceiling(families)
    oddity = format_oddity_snapshot(path=path, entropy=entropy, tags=tag_values)
    finite_risk = analytical_finite_float(risk, 0.0)
    risk_readiness = analytical_numeric_readiness(risk)
    finite_graph_score = analytical_finite_float(graph_score, 0.0)
    graph_readiness = analytical_numeric_readiness(graph_score)
    graph_feature_count, graph_feature_reason = analytical_mapping_size(graph_features)
    bus = get_global_event_bus()
    ev = bus.emit(
        "calibration",
        "analytical_snapshot",
        {
            "path_hash": int(hashlib.sha256(path_text.encode("utf-8", "replace")).hexdigest()[:8], 16),
            "tag_count": len(tag_values),
            "risk": finite_risk,
            "prev_stage": prev_stage_text,
            "curr_stage": curr_stage_text,
        },
        workload_id=(path_text or "unknown")[:256],
    )
    return {
        "schema_version": ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
        "evidence_type": "analytical_calibration_bundle",
        "event_seq": ev.seq,
        "lineage_id": ev.lineage_id,
        "format_oddity": oddity,
        "oddity": oddity,
        "sequence_probability": {"ready": False, "reason": "event_native_snapshot_only", "prev_stage": prev_stage_text, "curr_stage": curr_stage_text, "confidence": 0.0},
        "temporal_decay": {"ready": False, "reason": "event_native_snapshot_only"},
        "graph_context": {"graph_score": finite_graph_score, "feature_count": graph_feature_count, "confidence": min(1.0, max(0.0, finite_graph_score / 100.0)), "ready": graph_readiness["ready"] and graph_feature_reason is None, "reason": graph_feature_reason or graph_readiness["reason"]},
        "correlation_control": ceiling,
        "families": families,
        "summary": {"tag_count": len(tag_values), "risk": finite_risk, "risk_ready": risk_readiness["ready"], "risk_reason": risk_readiness["reason"]},
    }


__all__ = ("ANALYTICAL_EVIDENCE_SCHEMA_VERSION", "build_analytical_calibration_bundle", "format_oddity_snapshot")
