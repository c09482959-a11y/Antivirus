"""Threat-intelligence scoring layer owned by composite chain detection."""

from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import compute_attack_intelligence
from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.evidence.failure_evidence import failure_evidence_payload, recoverable_failure_evidence
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.scoring.weighting.scoreable_tags import (
    concrete_score_count,
    scoreable_tag_evidence,
)
from Virus_Scan.detection.chains.composite.text_boundaries import composite_prefixed, exact_record_value
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float


def compute_threat_intel_layer(tags: object, chain_evidence: ChainEvidence, yara_hits: object=None) -> object:
    """Layer 4: known TTP patterns and family inference."""
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("canonical_chain_evidence_required")
    tag_evidence = scoreable_tag_evidence(
        tags, allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    concrete_count = concrete_score_count(tag_evidence)
    hits = []
    score = 0.0
    failure_evidence = []
    try:
        attack = compute_attack_intelligence(tag_evidence, yara_hits)
        attack_probability, _attack_probability_reason = no_hook_finite_float(exact_record_value(attack, 'aggregate_probability', 0.0), default=0.0, reason='unsafe_threat_intel_attack_probability_rejected')
        attack_points = min(65.0, attack_probability * 65.0)
        if concrete_count < 2:
            attack_points = min(attack_points, 12.0)
        score += attack_points
        if exact_record_value(attack, 'best_family'):
            hits.append(composite_prefixed('family:', exact_record_value(attack, 'best_family')))
    except RECOVERABLE_RUNTIME_ERRORS as error:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='threat_intel_attack_intelligence',
            error=error,
            error_source='detection.chains.composite.threat_intel',
            affected_context='compute_attack_intelligence',
        ))
        attack = {'aggregate_probability': 0.0, 'family_probabilities': {}, 'best_family': None, 'failure_evidence': [failure_evidence[-1].to_record()]}
    chain_hits = [
        decision.candidate.chain_id
        for decision in chain_evidence.decisions
        if decision.status in {"confirmed", "candidate"}
    ]
    if chain_hits:
        score += min(35.0, chain_evidence.total_score_points)
        hits.extend([composite_prefixed('ttp:', item) for item in chain_hits[:12]])
    if chain_evidence.failures:
        failure_evidence.extend(dict(item) for item in chain_evidence.failures)
    failure_payload = failure_evidence_payload(tuple(failure_evidence))
    return {
        'name': 'Layer 4 Threat Intelligence',
        'score': min(100.0, score),
        'attack': attack,
        'chain_hits': chain_hits[:20],
        'hits': sorted(set(hits)),
        'summary': 'known TTP patterns',
        'degraded': failure_payload['degraded'],
        'failure_evidence': failure_payload['failures'],
        'failure_count': failure_payload['failure_count'],
    }
