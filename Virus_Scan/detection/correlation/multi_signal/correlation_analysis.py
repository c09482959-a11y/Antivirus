"""Canonical detection correlation explainability ownership."""

from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.detection.scoring.calibration.analytical_bundle import ANALYTICAL_EVIDENCE_SCHEMA_VERSION
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence
from Virus_Scan.detection.correlation.multi_signal.correlation_groups import infer_correlation_group
from Virus_Scan.detection.contracts.probability import safe_clamp
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items, no_hook_sequence_items

COUNTERFACTUAL_SUPPRESSION_VERSION = detection_registry_value("COUNTERFACTUAL_SUPPRESSION_VERSION", "counterfactual_suppression_v1")


def _redundant_correlation_groups(tags: object) -> dict[str, int]:
    normalized = normalize_tags(no_hook_sequence_items(tags))
    groups: dict[str, int] = {}
    for tag in normalized:
        group = infer_correlation_group(tag, tags=[])
        groups[group] = groups.get(group, 0) + 1
    return {group: count for group, count in dict.items(groups) if count > 1 and group != 'generic_behavior'}


def _mapping_float_value(value: object, target_key: str) -> float:
    items = no_hook_mapping_items(value)
    if items is None:
        return 0.0
    for key, item_value in items:
        if type(key) is str and str.__str__(key) == target_key:
            result, _reason = no_hook_finite_float(item_value, default=0.0)
            return result
    return 0.0


def _causal_support(causal_edges: object) -> float:
    confidences = [
        _mapping_float_value(edge, 'confidence')
        for edge in no_hook_sequence_items(causal_edges)
    ]
    return safe_clamp(sum(confidences) / max(1, len(confidences)))


def _counterfactual_record(redundant_groups: dict[str, int], causal_support: float, posterior: float) -> object:
    redundancy_penalty = min(0.25, 0.04 * sum(max(0, count - 1) for count in dict.values(redundant_groups)))
    adjusted = safe_clamp(posterior - redundancy_penalty + causal_support * 0.15)
    return {
        'schema_version': ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
        'version': COUNTERFACTUAL_SUPPRESSION_VERSION,
        'evidence_type': 'counterfactual_suppression',
        'redundant_correlation_groups': redundant_groups,
        'causal_support': round(causal_support, 6),
        'posterior_before': round(posterior, 6),
        'redundancy_penalty': round(redundancy_penalty, 6),
        'adjusted_posterior': round(adjusted, 6),
        'historical_evidence_removed': False,
    }


def _counterfactual_failure(error: object) -> object:
    failure = recoverable_failure_evidence(
        stage_name='counterfactual_suppression_analysis',
        error=error,
        error_source='detection.correlation.multi_signal.correlation_analysis',
        affected_context='counterfactual_suppression',
    )
    return {
        'version': COUNTERFACTUAL_SUPPRESSION_VERSION,
        'ready': False,
        'reason': 'counterfactual_failed',
        'degraded': True,
        'failure_evidence': [failure.to_record()],
        'confidence_degraded': True,
        'json_record_required': True,
        'replay_record_required': True,
    }


def counterfactual_suppression_analysis(tags: object=None, causal_edges: object=None, probabilistic: object=None) -> object:
    """Estimate bounded evidence redundancy without removing historical evidence."""
    try:
        redundant_groups = _redundant_correlation_groups(tags)
        causal_support = _causal_support(causal_edges)
        posterior = safe_clamp(_mapping_float_value(probabilistic, 'posterior'))
        return _counterfactual_record(redundant_groups, causal_support, posterior)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        return _counterfactual_failure(error)
