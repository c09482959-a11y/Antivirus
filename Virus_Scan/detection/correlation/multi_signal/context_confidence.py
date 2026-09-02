"""Canonical detection correlation owner for immutable analytical context confidence overlays."""
from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items, no_hook_text
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    norm_lower_set,
    ordered_unique_tags,
)
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_set
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags as expand_detection_tags
from Virus_Scan.detection.contracts.calibration_math import sigmoid01 as _sigmoid01
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence
from Virus_Scan.detection.scoring.calibration.analytical_bundle import ANALYTICAL_EVIDENCE_SCHEMA_VERSION

PLR2004N2 = 2
GRAPH_CONTEXT_FEATURE_RISK_KEYS = ("risk", "base_risk", "anomaly")
FORMAT_METADATA_KEYS = frozenset(("format", "file_format", "extension", "ext", "file_type"))

FORMAT_ODDITY_BASELINES = detection_registry_value("FORMAT_ODDITY_BASELINES", {"default": {"entropy_mean": 6.2, "entropy_std": 1.2}})
ODDITY_CALIBRATION_VERSION = detection_registry_value("ODDITY_CALIBRATION_VERSION", "format_zscore_v1")
GRAPH_CONFIDENCE_VERSION = detection_registry_value("GRAPH_CONFIDENCE_VERSION", "graph_context_uncertainty_v1")


def _context_tags(tags: object | None) -> tuple[str, ...]:
    raw = ordered_unique_tags(tags)
    if TAG_NORMALIZATION_FAILURE_EVIDENCE in raw or DETECTION_STAGE_DEGRADED_TAG in raw:
        return raw
    return expand_detection_tags(raw)


def _tag_input_failure_evidence(stage_name: str, affected_context: object) -> object:
    return recoverable_failure_evidence(
        stage_name=stage_name,
        error="context_tag_input_rejected",
        error_source="detection.correlation.multi_signal.context_confidence",
        affected_context=affected_context,
    )


def _finite_metric(value: object, *, default: float=0.0, minimum: float | None=None, maximum: float | None=None, reason: str='unsafe_context_metric_rejected') -> tuple[float, str]:
    metric, failure_reason = no_hook_finite_float(
        value,
        default=default,
        minimum=minimum,
        maximum=maximum,
        reason=reason,
        non_finite_reason="non_finite_context_metric",
    )
    return metric, failure_reason


def _graph_context_confidence(value: object) -> float:
    confidence, _reason = _finite_metric(
        value,
        default=0.0,
        minimum=0.0,
        maximum=1.0,
        reason="unsafe_graph_context_confidence_rejected",
    )
    return confidence


def _graph_feature_mapping(graph_features: object) -> tuple[dict[str, object], str]:
    if graph_features is None:
        return {}, ""
    items = no_hook_mapping_items(graph_features, allow_dict_subclass=True)
    if items is None:
        return {}, "unreadable_graph_features"
    features: dict[str, object] = {}
    for key, value in items:
        if type(key) is str:
            features[str.__str__(key)] = value
    return features, ""


def _graph_feature_score(features: dict[str, object]) -> tuple[float, str]:
    scores = []
    for key in GRAPH_CONTEXT_FEATURE_RISK_KEYS:
        if key not in features:
            continue
        metric, reason = _finite_metric(
            dict.get(features, key),
            default=0.0,
            minimum=0.0,
            maximum=1.0,
            reason="unsafe_graph_feature_metric_rejected",
        )
        if reason:
            return 0.0, reason
        scores.append(metric)
    if not scores:
        return 0.0, ""
    return max(scores) * 100.0, ""


def _format_extension_from_metadata(metadata: object) -> tuple[str, str]:
    if metadata is None:
        return "", ""
    items = no_hook_mapping_items(metadata, allow_dict_subclass=True)
    if items is None:
        return "", "unreadable_format_metadata"
    for key, value in items:
        if type(key) is not str or str.__str__(key) not in FORMAT_METADATA_KEYS:
            continue
        text, reason = no_hook_text(
            value,
            missing_reason="missing_format_metadata_value",
            unsupported_reason="unsafe_format_metadata_value_rejected",
        )
        if reason:
            return "", reason
        return str.lower(str.strip(text)).lstrip("."), ""
    return "", ""

def format_oddity_zscore(path: object | None=None, entropy: object | None=None, tags: object | None=None, metadata: object | None=None) -> dict[str, object]:
    """Return an immutable-ready per-format oddity overlay for entropy anomalies."""
    normalized_tags = _context_tags(tags)
    tagset = norm_lower_set(normalized_tags)
    ext = "default"
    failure_evidence = []
    try:
        ext = get_scan_extension(path).lstrip(".").lower() or "default"
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as exc:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='format_oddity_extension_context',
            error=exc,
            error_source='detection.correlation.multi_signal.context_confidence',
            affected_context=path,
        ))
    metadata_ext, metadata_reason = _format_extension_from_metadata(metadata)
    if metadata_reason:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='format_oddity_metadata_context',
            error=metadata_reason,
            error_source='detection.correlation.multi_signal.context_confidence',
            affected_context=path,
        ))
    if ext == "default" and metadata_ext:
        ext = metadata_ext
    base = FORMAT_ODDITY_BASELINES.get(ext, FORMAT_ODDITY_BASELINES["default"])
    ent = None
    if TAG_NORMALIZATION_FAILURE_EVIDENCE in tagset or DETECTION_STAGE_DEGRADED_TAG in tagset:
        failure_evidence.append(_tag_input_failure_evidence('format_oddity_tag_context', path))
    ent = None
    if entropy is not None:
        ent, entropy_reason = _finite_metric(entropy, reason='unsafe_entropy_metric_rejected')
        if entropy_reason:
            failure_evidence.append(recoverable_failure_evidence(
                stage_name='format_oddity_entropy_context',
                error=entropy_reason,
                error_source='detection.correlation.multi_signal.context_confidence',
                affected_context=path,
            ))
            ent = None
    if ent is None:
        signal_tags = {
            "high_entropy_packed", "very_high_entropy", "high_entropy_sections",
            "possible_packed_or_encrypted_blob", "packed_or_obfuscated",
            "embedded_payload_after_eof", "image_appended_payload", "stego_payload_suspect",
        }
        inferred = bool(tagset & signal_tags)
        return {
            "schema_version": ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
            "version": ODDITY_CALIBRATION_VERSION,
            "evidence_type": "format_oddity",
            "format": ext,
            "entropy": None,
            "zscore": None,
            "confidence": 0.3 if inferred else 0.0,
            "confidence_source": "tag_inferred_oddity" if inferred else "no_oddity_signal",
            "note": "raw entropy unavailable; preserving historical tags and using weak calibrated overlay",
            "degraded": bool(failure_evidence),
            "failure_evidence": [failure.to_record() for failure in failure_evidence],
        }
    mean, mean_reason = _finite_metric(
        base.get("entropy_mean", FORMAT_ODDITY_BASELINES["default"]["entropy_mean"]),
        default=FORMAT_ODDITY_BASELINES["default"]["entropy_mean"],
        reason="unsafe_entropy_mean_rejected",
    )
    std_raw, std_reason = _finite_metric(
        base.get("entropy_std", FORMAT_ODDITY_BASELINES["default"]["entropy_std"]),
        default=FORMAT_ODDITY_BASELINES["default"]["entropy_std"],
        minimum=0.05,
        reason="unsafe_entropy_std_rejected",
    )
    if mean_reason:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='format_oddity_baseline_mean_context',
            error=mean_reason,
            error_source='detection.correlation.multi_signal.context_confidence',
            affected_context=path,
        ))
    if std_reason:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='format_oddity_baseline_std_context',
            error=std_reason,
            error_source='detection.correlation.multi_signal.context_confidence',
            affected_context=path,
        ))
    std = max(0.05, std_raw)
    zscore = (ent - mean) / std
    confidence = _sigmoid01(abs(zscore), midpoint=2.0, scale=0.8)
    return {
        "schema_version": ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
        "version": ODDITY_CALIBRATION_VERSION,
        "evidence_type": "format_oddity",
        "format": ext,
        "entropy": round(ent, 4),
        "mean": mean,
        "std": std,
        "zscore": round(zscore, 4),
        "confidence": round(confidence, 4),
        "confidence_source": "per_format_zscore",
        "degraded": bool(failure_evidence),
        "failure_evidence": [failure.to_record() for failure in failure_evidence],
    }


def graph_context_uncertainty(node: object | None=None, tags: object | None=None, graph_features: object | None=None, graph_score: float=0.0) -> dict[str, object]:
    """Return a context confidence cap for graph/threat-intel signals without local evidence."""
    normalized_tags = _context_tags(tags)
    failure_evidence = []
    if TAG_NORMALIZATION_FAILURE_EVIDENCE in normalized_tags or DETECTION_STAGE_DEGRADED_TAG in normalized_tags:
        failure_evidence.append(_tag_input_failure_evidence('graph_context_tag_context', node))
    feature_map, feature_reason = _graph_feature_mapping(graph_features)
    if feature_reason:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='graph_context_features_context',
            error=feature_reason,
            error_source='detection.correlation.multi_signal.context_confidence',
            affected_context=node,
        ))
    concrete = scoreable_tag_set(normalized_tags)
    concrete_count = len(concrete)
    graph_score, graph_score_reason = _finite_metric(
        graph_score,
        default=0.0,
        minimum=0.0,
        reason="unsafe_graph_score_rejected",
    )
    if graph_score_reason:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='graph_context_score_context',
            error=graph_score_reason,
            error_source='detection.correlation.multi_signal.context_confidence',
            affected_context=node,
        ))
    if graph_score_reason == '' and graph_score == 0.0:
        feature_score, feature_score_reason = _graph_feature_score(feature_map)
        if feature_score_reason:
            failure_evidence.append(recoverable_failure_evidence(
                stage_name='graph_context_features_metric_context',
                error=feature_score_reason,
                error_source='detection.correlation.multi_signal.context_confidence',
                affected_context=node,
            ))
        else:
            graph_score = feature_score
    if concrete_count <= 0:
        cap = 0.2
    elif concrete_count == 1:
        cap = 0.45
    elif concrete_count == PLR2004N2:
        cap = 0.7
    else:
        cap = 1.0
    confidence = _graph_context_confidence(graph_score / 100.0 * cap)
    return {
        "schema_version": ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
        "version": GRAPH_CONFIDENCE_VERSION,
        "evidence_type": "graph_context",
        "raw_graph_score": round(graph_score, 4),
        "graph_feature_count": len(feature_map),
        "graph_features_ready": feature_reason == '',
        "concrete_local_evidence_count": concrete_count,
        "context_cap": cap,
        "confidence": round(confidence, 4),
        "confidence_source": "capped_without_concrete_local_evidence" if cap < 1.0 else "local_evidence_supported",
        "degraded": bool(failure_evidence),
        "failure_evidence": [failure.to_record() for failure in failure_evidence],
    }
