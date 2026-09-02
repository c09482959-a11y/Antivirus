"""Canonical detection-owned analytical calibration snapshots."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from Virus_Scan.contracts.analytical_evidence import (
    ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
    analytical_correlation_ceiling,
    analytical_finite_float,
    analytical_format_oddity_snapshot as format_oddity_snapshot,
    analytical_mapping_size,
    analytical_numeric_readiness,
    analytical_optional_text,
    analytical_root_family_counts,
)
from Virus_Scan.contracts.tag_evidence import distinct_root_tag_evidence_records
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence


ANALYTICAL_CONSUMED_EVIDENCE_KINDS = frozenset({
    "observed", "normalized", "derived", "composite",
})


@dataclass(frozen=True, slots=True)
class AnalyticalLineageRequest:
    path: object
    root_tags: tuple[str, ...]
    risk: object
    prev_stage: object
    curr_stage: object


def _lineage(request: AnalyticalLineageRequest) -> tuple[int, str]:
    material = json.dumps(
        {
            "path": analytical_optional_text(request.path, default=""),
            "root_tags": request.root_tags,
            "risk": analytical_finite_float(request.risk, 0.0),
            "prev_stage": analytical_optional_text(request.prev_stage, default="unknown") or "unknown",
            "curr_stage": analytical_optional_text(request.curr_stage, default="unknown") or "unknown",
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    digest = hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()
    return int(digest[:8], 16), "detection-calibration-" + digest[:16]


@dataclass(frozen=True, slots=True)
class AnalyticalCalibrationBundleRequest:
    path: object
    tags: TagEvidence
    entropy: object = None
    prev_stage: object = "unknown"
    curr_stage: object = "unknown"
    graph_score: object = 0.0
    graph_features: object = None
    risk: object = 0.0


def build_analytical_calibration_bundle(
    request: AnalyticalCalibrationBundleRequest,
) -> dict[str, object]:
    """Build one immutable-input analytical snapshot from distinct evidence roots."""
    if type(request) is not AnalyticalCalibrationBundleRequest:
        raise TypeError("analytical_calibration_request_required")
    if type(request.tags) is not TagEvidence:
        raise TypeError("analytical_calibration_tag_evidence_required")

    root_records = distinct_root_tag_evidence_records(
        request.tags.records,
        allowed_evidence_kinds=ANALYTICAL_CONSUMED_EVIDENCE_KINDS,
    )
    root_tags = tuple(record.canonical_tag_id for record in root_records)
    prev_stage = analytical_optional_text(request.prev_stage, default="unknown") or "unknown"
    curr_stage = analytical_optional_text(request.curr_stage, default="unknown") or "unknown"
    families = analytical_root_family_counts(root_tags)
    ceiling = analytical_correlation_ceiling(families)
    oddity = format_oddity_snapshot(
        path=request.path, entropy=request.entropy, tags=root_tags
    )
    finite_risk = analytical_finite_float(request.risk, 0.0)
    risk_readiness = analytical_numeric_readiness(request.risk)
    finite_graph_score = analytical_finite_float(request.graph_score, 0.0)
    graph_readiness = analytical_numeric_readiness(request.graph_score)
    graph_feature_count, graph_feature_reason = analytical_mapping_size(
        request.graph_features
    )
    event_seq, lineage_id = _lineage(
        AnalyticalLineageRequest(
            path=request.path,
            root_tags=root_tags,
            risk=request.risk,
            prev_stage=prev_stage,
            curr_stage=curr_stage,
        )
    )
    return {
        "schema_version": ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
        "evidence_type": "analytical_calibration_bundle",
        "event_seq": event_seq,
        "lineage_id": lineage_id,
        "format_oddity": oddity,
        "oddity": oddity,
        "sequence_probability": {
            "ready": False,
            "reason": "pure_detection_snapshot_only",
            "prev_stage": prev_stage,
            "curr_stage": curr_stage,
            "confidence": 0.0,
        },
        "temporal_decay": {
            "ready": False, "reason": "pure_detection_snapshot_only"
        },
        "graph_context": {
            "graph_score": finite_graph_score,
            "feature_count": graph_feature_count,
            "confidence": min(1.0, max(0.0, finite_graph_score / 100.0)),
            "ready": graph_readiness["ready"] and graph_feature_reason is None,
            "reason": graph_feature_reason or graph_readiness["reason"],
        },
        "correlation_control": ceiling,
        "families": families,
        "tag_evidence_contract": {
            "consumed_evidence_kinds": tuple(sorted(ANALYTICAL_CONSUMED_EVIDENCE_KINDS)),
            "distinct_root_count": len(root_records),
            "canonical_tag_count": len(request.tags.tags),
            "distinct_correlation_group_count": request.tags.summary.get(
                "distinct_correlation_group_count", 0
            ),
        },
        "summary": {
            "tag_count": len(root_records),
            "risk": finite_risk,
            "risk_ready": risk_readiness["ready"],
            "risk_reason": risk_readiness["reason"],
        },
    }


__all__ = (
    "ANALYTICAL_EVIDENCE_SCHEMA_VERSION",
    "ANALYTICAL_CONSUMED_EVIDENCE_KINDS",
    "AnalyticalCalibrationBundleRequest",
    "build_analytical_calibration_bundle",
    "format_oddity_snapshot",
)
