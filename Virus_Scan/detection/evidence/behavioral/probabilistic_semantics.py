"""Bounded probabilistic evidence semantics ownership."""

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_text
from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.contracts.probability import (
    EVIDENCE_STRENGTH_TO_LIKELIHOOD,
    RELIABILITY_TO_NUMERIC,
    safe_clamp as probability_safe_clamp,
)

ANALYTICAL_EVIDENCE_SCHEMA_VERSION = 1
PROBABILISTIC_SEMANTICS_VERSION = 1


safe_clamp = probability_safe_clamp

from Virus_Scan.contracts.probabilistic_evidence import (
    correlation_group_summary,
    probabilistic_evidence_summary,
)


def _semantic_label(value: object, *, default: str, reason: str) -> tuple[str, str]:
    candidate = default if value is None else value
    text, text_reason = no_hook_text(
        candidate,
        missing_reason=reason,
        unsupported_reason=reason,
    )
    if text_reason:
        return default, text_reason
    text = str.strip(text)
    return (text or default), ""


def _semantic_number(
    value: object,
    *,
    default: float,
    minimum: float,
    maximum: float,
    reason: str,
    non_finite_reason: str,
) -> tuple[float, str]:
    candidate = default if value is None else value
    metric, metric_reason = no_hook_finite_float(
        candidate,
        default=minimum,
        minimum=minimum,
        maximum=maximum,
        reason=reason,
        non_finite_reason=non_finite_reason,
    )
    if metric_reason:
        return probability_safe_clamp(minimum, minimum, maximum), metric_reason
    return probability_safe_clamp(metric, minimum, maximum), ""


def _probabilistic_semantics_payload(
    *,
    evidence_type: object,
    reliability: object,
    strength: object,
    raw_confidence: object,
    correlation_group: object,
    prior: object,
    likelihood: object,
    prevalence: object,
) -> dict[str, object]:
    rel_label, rel_reason = _semantic_label(
        reliability,
        default='contextual',
        reason='unsafe_probabilistic_reliability_label_rejected',
    )
    str_label, str_reason = _semantic_label(
        strength,
        default=rel_label,
        reason='unsafe_probabilistic_strength_label_rejected',
    )
    evidence_label, evidence_reason = _semantic_label(
        evidence_type,
        default='generic',
        reason='unsafe_probabilistic_evidence_type_rejected',
    )
    group_label, group_reason = _semantic_label(
        correlation_group,
        default='generic_behavior',
        reason='unsafe_probabilistic_correlation_group_rejected',
    )
    rel_num = probability_safe_clamp(RELIABILITY_TO_NUMERIC.get(rel_label, RELIABILITY_TO_NUMERIC.get('contextual', 0.2)))
    base_like = EVIDENCE_STRENGTH_TO_LIKELIHOOD.get(str_label, EVIDENCE_STRENGTH_TO_LIKELIHOOD.get(rel_label, 0.25))
    raw, raw_reason = _semantic_number(
        raw_confidence,
        default=0.0,
        minimum=0.0,
        maximum=1.0,
        reason='unsafe_probabilistic_raw_confidence_rejected',
        non_finite_reason='nonfinite_probabilistic_raw_confidence',
    )
    if likelihood is None:
        like = probability_safe_clamp(max(base_like, raw * 0.85))
        like_reason = ""
    else:
        like, like_reason = _semantic_number(
            likelihood,
            default=base_like,
            minimum=0.0,
            maximum=1.0,
            reason='unsafe_probabilistic_likelihood_rejected',
            non_finite_reason='nonfinite_probabilistic_likelihood',
        )
    pr, prior_reason = _semantic_number(
        prior,
        default=0.03,
        minimum=0.0001,
        maximum=0.8,
        reason='unsafe_probabilistic_prior_rejected',
        non_finite_reason='nonfinite_probabilistic_prior',
    )
    prev, prevalence_reason = _semantic_number(
        prevalence,
        default=0.05,
        minimum=0.0001,
        maximum=0.95,
        reason='unsafe_probabilistic_prevalence_rejected',
        non_finite_reason='nonfinite_probabilistic_prevalence',
    )
    odds = like * pr / max(1e-09, prev)
    posterior = probability_safe_clamp(odds / (1.0 + odds))
    posterior = probability_safe_clamp(posterior * rel_num + raw * (1.0 - rel_num) * 0.25)
    out: dict[str, object] = {
        'schema_version': ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
        'version': PROBABILISTIC_SEMANTICS_VERSION,
        'evidence_type': evidence_label,
        'likelihood': round(like, 6),
        'reliability': round(rel_num, 6),
        'reliability_class': rel_label,
        'evidence_strength': str_label,
        'prior': round(pr, 6),
        'prevalence': round(prev, 6),
        'posterior': round(posterior, 6),
        'uncertainty': round(probability_safe_clamp(1.0 - rel_num), 6),
        'correlation_group': group_label,
        'semantics_note': 'posterior_like_calibrated_metadata_not_final_verdict',
    }
    rejections = tuple(
        reason
        for reason in (
            rel_reason, str_reason, evidence_reason, group_reason,
            raw_reason, like_reason, prior_reason, prevalence_reason,
        )
        if reason
    )
    if rejections:
        out['input_rejections'] = rejections
        out['failure_evidence_recorded'] = True
        out['degraded'] = True
    return out


def probabilistic_evidence_semantics(evidence_type: object='generic', reliability: object='contextual', strength: object=None, raw_confidence: object=0.0, correlation_group: object=None, prior: object=0.03, likelihood: object=None, prevalence: object=None) -> object:
    """Separate probability-like semantics from one ambiguous confidence value.

    confidence remains as the stable outward field, while this structure distinguishes:
      - likelihood: how predictive the evidence is when malicious
      - reliability: detector trustworthiness
      - prior: conservative base rate
      - posterior: bounded posterior-like belief after reliability discount
      - correlation_group: dependency class used to cap correlated evidence
    """
    try:
        return _probabilistic_semantics_payload(
            evidence_type=evidence_type,
            reliability=reliability,
            strength=strength,
            raw_confidence=raw_confidence,
            correlation_group=correlation_group,
            prior=prior,
            likelihood=likelihood,
            prevalence=prevalence,
        )
    except RECOVERABLE_RUNTIME_ERRORS as e:
        return {
            'schema_version': ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
            'version': PROBABILISTIC_SEMANTICS_VERSION,
            'ready': False,
            'reason': 'semantics_failed',
            'error_type': type(e).__name__,
            'degraded': True,
            'failure_evidence_recorded': True,
            'json_record_required': True,
            'replay_record_required': True,
        }


__all__ = ('correlation_group_summary', 'probabilistic_evidence_semantics', 'probabilistic_evidence_summary')
