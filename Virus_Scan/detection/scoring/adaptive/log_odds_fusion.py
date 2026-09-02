from __future__ import annotations
from Virus_Scan.contracts.yara_hits import canonical_yara_scan_result
from dataclasses import dataclass
from collections.abc import Mapping
from Virus_Scan.detection.attack.calibration import ATTACK_FINAL_FUSION_CALIBRATION_STATE
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_type_name
from Virus_Scan.contracts.tag_evidence import distinct_root_tag_evidence_records
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.evidence.normalization import correlation_ceiling
from Virus_Scan.detection.attack.mapping.contracts import AttackMappingResult
from Virus_Scan.detection.scoring.adaptive.availability import (
    availability_aware_layer_probability_summary,
)
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_event_sequence,
    adaptive_public_mapping,
    adaptive_public_mapping_field,
    adaptive_public_sequence,
    adaptive_public_text,
)
from Virus_Scan.detection.scoring.adaptive.evidence_projection import (
    probability_feature_bundle,
    build_probability_features,
)
from Virus_Scan.detection.scoring.adaptive.feature_bundle import (
    model_failure_record,
)
from Virus_Scan.detection.scoring.adaptive.settings import (
    CALIBRATED_SCORE_THRESHOLDS, CALIBRATED_SCORE_VERSION,
)
from Virus_Scan.detection.scoring.escalation.anchor_scores import apply_anchor_score_floors
from Virus_Scan.detection.scoring.weighting.chain_bonus import calibrated_chain_bonus
from Virus_Scan.detection.scoring.adaptive.log_odds_probabilities import (
    LogOddsFeatureProbabilitiesRequest,
    log_odds_feature_probabilities,
    log_odds_static_model_probabilities,
)
from Virus_Scan.detection.scoring.adaptive.log_odds_weights import (
    apply_log_odds_concrete_caps,
    derive_log_odds_weights,
    log_odds_active_layer_bonus,
)
from Virus_Scan.detection.scoring.adaptive.model_caps import concrete_score_count
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.utils.probability import (
    calibrated_sigmoid_probability,
    safe_clamp,
    safe_logit_probability,
    score_to_probability,
)
from Virus_Scan.utils.tagging import normalize_tags
LOG_ODDS_TAG_EVIDENCE_KINDS = frozenset({
    'observed', 'normalized', 'derived', 'composite',
})
@dataclass(frozen=True)
class ConcreteCountUnavailable:
    """Typed evidence that concrete scoreable evidence count could not be derived."""
    count: int
    reason: str
    value_type: str
    def as_evidence(self) -> dict[str, object]:
        return {
            "concrete_scoreable_evidence_count_unavailable": True,
            "count": self.count,
            "reason": self.reason,
            "value_type": self.value_type,
            "detection_contract": "log_odds_concrete_count",
            "replay_must_record": True,
        }
def log_odds_learning_meta(adaptive_learning: object) -> tuple[object, object, object, object, object, object, object]:
    adaptive_learning = adaptive_public_mapping(adaptive_learning)
    profile_meta = adaptive_public_mapping_field(adaptive_learning, 'profile')
    markov_meta = adaptive_public_mapping_field(adaptive_learning, 'markov')
    cluster_meta = adaptive_public_mapping_field(adaptive_learning, 'cluster')
    bucket_vector_meta = adaptive_public_mapping_field(adaptive_learning, 'bucket_vector')
    bv_bucket = adaptive_public_mapping_field(bucket_vector_meta, 'bucket_validation')
    bv_vector = adaptive_public_mapping_field(bucket_vector_meta, 'vector_validation')
    bv_timeline = adaptive_public_mapping_field(bucket_vector_meta, 'timeline_validation')
    rolling_meta = adaptive_public_mapping_field(adaptive_learning, 'rolling_learned_static')
    return profile_meta, markov_meta, cluster_meta, bv_bucket, bv_vector, bv_timeline, rolling_meta

def log_odds_concrete_count_status(tags: object) -> int | ConcreteCountUnavailable:
    try:
        return concrete_score_count(tags)
    except RECOVERABLE_RUNTIME_ERRORS:
        return ConcreteCountUnavailable(
            count=0,
            reason="concrete_score_count_unavailable",
            value_type=no_hook_type_name(tags),
        )

def log_odds_concrete_count(tags: object) -> int:
    count = log_odds_concrete_count_status(tags)
    if type(count) is ConcreteCountUnavailable:
        return count.count
    return count

def log_odds_tag_evidence(tags: object) -> tuple[TagEvidence, tuple[object, ...], tuple[str, ...]]:
    """Materialize one canonical evidence bundle and its bounded projections."""
    if type(tags) is TagEvidence:
        source = tags
    else:
        source = normalize_tag_evidence(
            normalize_tags(adaptive_public_sequence(tags)),
            source_detector='log_odds_fusion',
            source_stage='adaptive_score',
        )
    evidence = scoreable_tag_evidence(
        source, allowed_evidence_kinds=LOG_ODDS_TAG_EVIDENCE_KINDS,
    )
    roots = distinct_root_tag_evidence_records(
        evidence.records, allowed_evidence_kinds=LOG_ODDS_TAG_EVIDENCE_KINDS,
    )
    root_projection = tuple(record.publication_name for record in roots)
    return evidence, tuple(evidence.tags), root_projection

def probability_feature_build_failed_bundle() -> Mapping[str, object]:
    return probability_feature_bundle(
        {
            'p_attack_intelligence': 0.0,
            'p_attack_intelligence_unavailable_reason': 'probability_feature_build_failed',
            'p_attention': 0.0,
            'p_behavior': 0.0,
            'p_bucket': 0.0,
            'p_bucket_unavailable_reason': 'probability_feature_build_failed',
            'p_chain': 0.0,
            'p_cluster': 0.0,
            'p_cluster_unavailable_reason': 'probability_feature_build_failed',
            'p_engine': 0.0,
            'p_engine_unavailable_reason': 'probability_feature_build_failed',
            'p_entropy': 0.0,
            'p_chain_unavailable_reason': 'probability_feature_build_failed',
            'p_evasion': 0.0,
            'p_evasion_unavailable_reason': 'probability_feature_build_failed',
            'p_exec': 0.0,
            'p_graph': 0.0,
            'p_graph_chain': 0.0,
            'p_graph_chain_unavailable_reason': 'probability_feature_build_failed',
            'p_graph_unavailable_reason': 'probability_feature_build_failed',
            'p_markov': 0.0,
            'p_markov_unavailable_reason': 'probability_feature_build_failed',
            'p_mitre': 0.0,
            'p_mitre_unavailable_reason': 'probability_feature_build_failed',
            'p_profile': 0.0,
            'p_profile_unavailable_reason': 'probability_feature_build_failed',
            'p_temporal': 0.0,
            'p_temporal_unavailable_reason': 'probability_feature_build_failed',
            'p_vector': 0.0,
            'p_vector_unavailable_reason': 'probability_feature_build_failed',
            'p_yara': 0.0,
            'model_failure': model_failure_record(
                model_name='adaptive_probability_features',
                failure_type='feature_build_failed',
                reason='probability_feature_build_failed',
                affected_fields=(
                    'p_attack_intelligence',
                    'p_attention',
                    'p_bucket',
                    'p_chain',
                    'p_cluster',
                    'p_engine',
                    'p_evasion',
                    'p_graph',
                    'p_graph_chain',
                    'p_markov',
                    'p_mitre',
                    'p_profile',
                    'p_temporal',
                    'p_vector',
                ),
                details={'unavailable_probability': 0.0},
                model_version='adaptive_probability_feature_failure_v1',
            ),
        }
    )
def calibrated_log_odds_score_100(raw_weighted_score: float, *, attack_mapping_result: AttackMappingResult, chain_evidence: ChainEvidence, tags: object | None=None, yara_hits: object | None=None, node: object | None=None, prev_stage: object | None=None, curr_stage: object | None=None, active_layers: int=0, layers: object | None=None, adaptive_learning: object | None=None, strings_blob: str='', api_calls: object | None=None, ordered_events: object | None=None, artifact_platform: str='') -> tuple[float, dict[str, object]]:
    """
    Final calibrated score using log-odds fusion + calibrated sigmoid.

    Static side = direct extraction, execution anchors, behavior/chain evidence.
    Model side = profile/vector/bucket/temporal/Markov/cluster evidence.
    The rolling learned/static weight decides how much each side contributes.
    """
    tag_evidence, tags, root_tags = log_odds_tag_evidence(tags)
    yara_hits = canonical_yara_scan_result(yara_hits)
    api_calls = adaptive_public_sequence(api_calls)
    ordered_events = adaptive_public_event_sequence(ordered_events)
    strings_blob = adaptive_public_text(strings_blob)
    layers = adaptive_public_mapping(layers)
    raw = safe_clamp(raw_weighted_score, 0.0, 100.0)
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("calibrated_log_odds_chain_evidence_required")
    chain_bonus, chain_hits = calibrated_chain_bonus(chain_evidence)
    explicit_anchor_meta = {'hits': []}
    layer_probs = availability_aware_layer_probability_summary(layers)
    try:
        feature_probs = build_probability_features(tags=tag_evidence, yara_hits=yara_hits, chain_evidence=chain_evidence, attack_mapping_result=attack_mapping_result, node=node, prev_stage=prev_stage, curr_stage=curr_stage, file_structure=node, strings_blob=strings_blob, api_calls=api_calls, ordered_events=ordered_events, platform=artifact_platform)
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('log-odds probability feature build failed')
        feature_probs = probability_feature_build_failed_bundle()
    profile_meta, markov_meta, cluster_meta, bv_bucket, bv_vector, bv_timeline, rolling_meta = log_odds_learning_meta(adaptive_learning)
    probability_request = LogOddsFeatureProbabilitiesRequest(
        feature_probs, profile_meta, markov_meta, cluster_meta,
        bv_bucket, bv_vector, bv_timeline, layer_probs,
    )
    probs = log_odds_feature_probabilities(probability_request)
    raw_prob = score_to_probability(raw, midpoint=50.0, scale=16.0)
    static_prob, model_prob, attack_chain_prob = log_odds_static_model_probabilities(raw_prob, layer_probs, probs)
    if explicit_anchor_meta.get('hits'):
        explicit_floor, _explicit_floor_reason = no_hook_finite_float(
            explicit_anchor_meta.get('floor', 0.0),
            default=0.0,
            reason='explicit_anchor_floor_rejected',
            non_finite_reason='explicit_anchor_floor_rejected',
        )
        static_prob = max(static_prob, score_to_probability(explicit_floor, midpoint=32.0, scale=12.0))
    concrete_count_result = log_odds_concrete_count_status(tag_evidence)
    concrete_count_unavailable = None
    if type(concrete_count_result) is ConcreteCountUnavailable:
        concrete_count = concrete_count_result.count
        concrete_count_unavailable = concrete_count_result.as_evidence()
    else:
        concrete_count = concrete_count_result
    static_weight, model_weight = derive_log_odds_weights(rolling_meta, profile_meta, probs, concrete_count, raw, layer_probs)
    static_weight, model_weight, caps = apply_log_odds_concrete_caps(static_weight, model_weight, concrete_count)
    raw_log_odds = -0.28 + 1.65 * static_weight * safe_logit_probability(static_prob) + 1.45 * model_weight * safe_logit_probability(model_prob)
    fused_prob = calibrated_sigmoid_probability(raw_log_odds, temperature=1.25)
    base_score = safe_clamp(fused_prob * 100.0, 0.0, 100.0)
    layer_bonus = log_odds_active_layer_bonus(active_layers)
    additive_reference, _additive_reference_reason = no_hook_finite_float(
        explicit_anchor_meta.get('additive_reference', 0.0),
        default=0.0,
        reason='explicit_anchor_additive_reference_rejected',
        non_finite_reason='explicit_anchor_additive_reference_rejected',
    )
    pre_anchor_score = safe_clamp(base_score + layer_bonus + additive_reference, 0.0, 100.0)
    final, anchor_floor_hits = apply_anchor_score_floors(pre_anchor_score, chain_evidence, tags=tag_evidence, stage=curr_stage)
    high_gate_score, high_gate_meta = (final, {})
    final = safe_clamp(high_gate_score, 0.0, 100.0)
    runtime_capped_score, runtime_cap_hits = (final, [])
    updater_capped_score, updater_cap_hits = (runtime_capped_score, [])
    reference_capped_score, reference_cap_hits = (updater_capped_score, [])
    final = safe_clamp(reference_capped_score, 0.0, 100.0)
    correlation_meta = correlation_ceiling(root_tags, base_score=final)
    if correlation_meta.get('capped'):
        final = safe_clamp(correlation_meta.get('score', final), 0.0, 100.0)
    return (final, {'version': CALIBRATED_SCORE_VERSION, 'raw_weighted_score': raw, 'raw_probability': raw_prob, 'static_probability': static_prob, 'model_probability': model_prob, 'attack_chain_probability': attack_chain_prob, 'attack_final_fusion_calibration_state': ATTACK_FINAL_FUSION_CALIBRATION_STATE, 'static_weight': static_weight, 'model_weight': model_weight, 'raw_log_odds': raw_log_odds, 'calibrated_probability': fused_prob, 'calibrated_base_score': base_score, 'chain_bonus_reference': chain_bonus, 'chain_hits': chain_hits, 'chain_evidence': chain_evidence.to_record(decision_limit=64), 'layer_bonus': layer_bonus, 'pre_anchor_floor_score': pre_anchor_score, 'anchor_floor_hits': anchor_floor_hits, 'explicit_behavior_anchor': explicit_anchor_meta, 'anchor_chain_high_gate': high_gate_meta, 'runtime_library_score_cap': runtime_cap_hits, 'renpy_updater_score_cap': updater_cap_hits, 'reference_url_score_cap': reference_cap_hits, 'correlation_ceiling': correlation_meta, 'concrete_scoreable_evidence_count': concrete_count, 'concrete_scoreable_evidence_count_unavailable': concrete_count_unavailable, 'tag_evidence': tag_evidence.to_record(record_limit=64), 'caps_applied': caps, 'feature_probabilities': {'model_failure': probs.get('model_failure'), 'yara': probs['p_yara'], 'attack_intelligence': probs['p_attack_intelligence'], 'attack_intelligence_unavailable_reason': probs.get('p_attack_intelligence_unavailable_reason'), 'mitre': probs['p_mitre'], 'mitre_unavailable_reason': probs.get('p_mitre_unavailable_reason'), 'mitre_evidence': probs.get('mitre_evidence'), 'exec': probs['p_exec'], 'behavior': probs['p_behavior'], 'evasion': probs['p_evasion'], 'evasion_unavailable_reason': probs.get('p_evasion_unavailable_reason'), 'entropy': probs['p_entropy'], 'profile': probs['p_profile'], 'profile_unavailable_reason': probs.get('p_profile_unavailable_reason'), 'bucket': probs['p_bucket'], 'bucket_unavailable_reason': probs.get('p_bucket_unavailable_reason'), 'vector': probs['p_vector'], 'vector_unavailable_reason': probs.get('p_vector_unavailable_reason'), 'engine_unavailable_reason': probs.get('p_engine_unavailable_reason'), 'markov': probs['p_markov'], 'temporal': probs['p_temporal'], 'temporal_unavailable_reason': probs.get('p_temporal_unavailable_reason'), 'cluster': probs['p_cluster'], 'cluster_unavailable_reason': probs.get('p_cluster_unavailable_reason'), 'markov_unavailable_reason': probs.get('p_markov_unavailable_reason'), 'graph_unavailable_reason': probs.get('p_graph_unavailable_reason'), 'graph_chain': probs['p_graph_chain'], 'graph_chain_unavailable_reason': probs.get('p_graph_chain_unavailable_reason'), 'chain': probs['p_chain'], 'chain_unavailable_reason': probs.get('p_chain_unavailable_reason'), 'attention': probs['p_attention'], 'graph': probs['p_graph']}, 'layer_probability_unavailable_reasons': {key: reason for key, reason in (('graph', layer_probs.get('graph_unavailable_reason')), ('threat_intel', layer_probs.get('threat_intel_unavailable_reason')), ('stage_timeline', layer_probs.get('stage_unavailable_reason')), ('quick_static', layer_probs.get('quick_static_unavailable_reason'))) if reason}, 'thresholds': dict(CALIBRATED_SCORE_THRESHOLDS)})
__all__ = (
    'calibrated_log_odds_score_100',
    'log_odds_concrete_count',
    'log_odds_learning_meta',
    'probability_feature_build_failed_bundle',
)
