from dataclasses import dataclass
from collections.abc import Mapping

from Virus_Scan.detection.scoring.adaptive.availability import (
    adaptive_unavailable_reason,
    available_feature_probability,
    available_model_signal_probability,
    probability_feature_unavailable_reason,
)
from Virus_Scan.detection.attack.api import materialize_official_attack_probability_evidence
from Virus_Scan.detection.scoring.adaptive.feature_bundle import materialize_model_failure
from Virus_Scan.detection.scoring.adaptive.public_inputs import adaptive_public_mapping
from Virus_Scan.detection.scoring.adaptive.boundary_values import adaptive_mapping_get, first_adaptive_probability_reason
from Virus_Scan.utils.probability import safe_clamp


def adaptive_probability(record: object, key: object) -> object:
    return safe_clamp(adaptive_mapping_get(record, key, 0.0))


def combined_probability(*values: object) -> object:
    combined = 0.0
    for value in values:
        bounded = safe_clamp(value)
        combined = max(combined, bounded)
    return combined


@dataclass(frozen=True, slots=True)
class LogOddsFeatureProbabilitiesRequest:
    feature_probs: object
    profile_meta: object
    markov_meta: object
    cluster_meta: object
    bv_bucket: object
    bv_vector: object
    bv_timeline: object
    layer_probs: object


def log_odds_feature_probabilities(request: LogOddsFeatureProbabilitiesRequest) -> object:
    """Project canonical adaptive probabilities from one immutable request."""
    if type(request) is not LogOddsFeatureProbabilitiesRequest:
        raise TypeError("log_odds_feature_probabilities_request_required")
    feature_probs = request.feature_probs
    profile_meta = request.profile_meta
    markov_meta = request.markov_meta
    cluster_meta = request.cluster_meta
    bv_bucket = request.bv_bucket
    bv_vector = request.bv_vector
    bv_timeline = request.bv_timeline
    layer_probs = request.layer_probs
    feature_probs = adaptive_public_mapping(feature_probs)
    profile_meta = adaptive_public_mapping(profile_meta)
    markov_meta = adaptive_public_mapping(markov_meta)
    cluster_meta = adaptive_public_mapping(cluster_meta)
    bv_bucket = adaptive_public_mapping(bv_bucket)
    bv_vector = adaptive_public_mapping(bv_vector)
    bv_timeline = adaptive_public_mapping(bv_timeline)
    layer_probs = adaptive_public_mapping(layer_probs)
    model_failure = adaptive_mapping_get(feature_probs, 'model_failure')
    if isinstance(model_failure, Mapping):
        model_failure = materialize_model_failure(model_failure)
    p_profile = available_model_signal_probability(profile_meta, 'profile_anomaly')
    p_markov = available_model_signal_probability(markov_meta, 'markov_anomaly')
    p_cluster = available_model_signal_probability(cluster_meta, 'cluster_signal')
    p_bucket = available_model_signal_probability(bv_bucket, 'bucket_anomaly')
    p_vector = available_model_signal_probability(bv_vector, 'anomaly')
    graph_reason = first_adaptive_probability_reason(
        probability_feature_unavailable_reason,
        adaptive_mapping_get(feature_probs, 'p_graph_unavailable_reason'),
        adaptive_mapping_get(layer_probs, 'graph_unavailable_reason'),
    )
    graph_unavailable_reason = probability_feature_unavailable_reason(feature_probs, 'p_graph', graph_reason, 'graph_probability_not_ready')
    profile_unavailable_reason = adaptive_unavailable_reason(profile_meta) or probability_feature_unavailable_reason(feature_probs, 'p_profile', adaptive_mapping_get(feature_probs, 'p_profile_unavailable_reason'), 'profile_probability_not_ready')
    bucket_unavailable_reason = adaptive_unavailable_reason(bv_bucket) or probability_feature_unavailable_reason(feature_probs, 'p_bucket', adaptive_mapping_get(feature_probs, 'p_bucket_unavailable_reason'), 'bucket_probability_not_ready')
    vector_unavailable_reason = adaptive_unavailable_reason(bv_vector) or probability_feature_unavailable_reason(feature_probs, 'p_vector', adaptive_mapping_get(feature_probs, 'p_vector_unavailable_reason'), 'vector_probability_not_ready')
    temporal_unavailable_reason = adaptive_unavailable_reason(bv_timeline) or probability_feature_unavailable_reason(feature_probs, 'p_temporal', adaptive_mapping_get(feature_probs, 'p_temporal_unavailable_reason'), 'temporal_probability_not_ready')
    cluster_unavailable_reason = adaptive_unavailable_reason(cluster_meta) or probability_feature_unavailable_reason(feature_probs, 'p_cluster', adaptive_mapping_get(feature_probs, 'p_cluster_unavailable_reason'), 'cluster_probability_not_ready')
    p_graph_feature = available_feature_probability(feature_probs, 'p_graph', graph_unavailable_reason)
    if graph_unavailable_reason:
        p_graph = 0.0
    else:
        p_graph = combined_probability(p_graph_feature, adaptive_mapping_get(layer_probs, 'graph_probability', 0.0))
    p_profile_feature = available_feature_probability(feature_probs, 'p_profile', profile_unavailable_reason)
    markov_unavailable_reason = adaptive_unavailable_reason(markov_meta) or probability_feature_unavailable_reason(feature_probs, 'p_markov', adaptive_mapping_get(feature_probs, 'p_markov_unavailable_reason'), 'markov_probability_not_ready')
    p_markov_feature = available_feature_probability(feature_probs, 'p_markov', markov_unavailable_reason)
    p_temporal_feature = available_feature_probability(feature_probs, 'p_temporal', temporal_unavailable_reason)
    p_cluster_feature = available_feature_probability(feature_probs, 'p_cluster', cluster_unavailable_reason)
    p_bucket_feature = available_feature_probability(feature_probs, 'p_bucket', bucket_unavailable_reason)
    p_vector_feature = available_feature_probability(feature_probs, 'p_vector', vector_unavailable_reason)
    graph_chain_reason = first_adaptive_probability_reason(
        probability_feature_unavailable_reason,
        adaptive_mapping_get(feature_probs, 'p_graph_chain_unavailable_reason'),
        graph_unavailable_reason,
    )
    p_graph_chain = available_feature_probability(
        feature_probs,
        'p_graph_chain',
        probability_feature_unavailable_reason(
            feature_probs, 'p_graph_chain', graph_chain_reason,
            'graph_chain_probability_not_ready',
        ),
    )
    p_attention = available_feature_probability(feature_probs, 'p_attention', graph_unavailable_reason)
    return {
        'model_failure': model_failure,
        'p_yara': 0.0,
        'p_attack_intelligence': available_feature_probability(feature_probs, 'p_attack_intelligence', probability_feature_unavailable_reason(feature_probs, 'p_attack_intelligence', adaptive_mapping_get(feature_probs, 'p_attack_intelligence_unavailable_reason'), 'attack_intelligence_probability_not_ready')),
        'p_mitre': available_feature_probability(feature_probs, 'p_mitre', probability_feature_unavailable_reason(feature_probs, 'p_mitre', adaptive_mapping_get(feature_probs, 'p_mitre_unavailable_reason'), 'mitre_probability_not_ready')),
        'mitre_evidence': materialize_official_attack_probability_evidence(
            adaptive_mapping_get(feature_probs, 'mitre_evidence_json'),
        ),
        'p_chain': available_feature_probability(feature_probs, 'p_chain', probability_feature_unavailable_reason(feature_probs, 'p_chain', adaptive_mapping_get(feature_probs, 'p_chain_unavailable_reason'), 'chain_probability_not_ready')),
        'p_exec': adaptive_probability(feature_probs, 'p_exec'),
        'p_behavior': adaptive_probability(feature_probs, 'p_behavior'),
        'p_evasion': available_feature_probability(feature_probs, 'p_evasion', probability_feature_unavailable_reason(feature_probs, 'p_evasion', adaptive_mapping_get(feature_probs, 'p_evasion_unavailable_reason'), 'evasion_probability_not_ready')),
        'p_evasion_unavailable_reason': probability_feature_unavailable_reason(feature_probs, 'p_evasion', adaptive_mapping_get(feature_probs, 'p_evasion_unavailable_reason'), 'evasion_probability_not_ready'),
        'p_entropy': adaptive_probability(feature_probs, 'p_entropy'),
        'p_profile': combined_probability(p_profile_feature, p_profile),
        'p_markov': combined_probability(p_markov_feature, p_markov),
        'p_temporal': p_temporal_feature,
        'p_cluster': combined_probability(p_cluster_feature, p_cluster),
        'p_bucket': combined_probability(p_bucket_feature, p_bucket),
        'p_vector': combined_probability(p_vector_feature, p_vector),
        'p_graph_chain': p_graph_chain,
        'p_graph_chain_unavailable_reason': probability_feature_unavailable_reason(
            feature_probs, 'p_graph_chain', graph_chain_reason,
            'graph_chain_probability_not_ready',
        ),
        'p_attention': p_attention,
        'p_graph': p_graph,
        'p_attack_intelligence_unavailable_reason': probability_feature_unavailable_reason(feature_probs, 'p_attack_intelligence', adaptive_mapping_get(feature_probs, 'p_attack_intelligence_unavailable_reason'), 'attack_intelligence_probability_not_ready'),
        'p_chain_unavailable_reason': probability_feature_unavailable_reason(feature_probs, 'p_chain', adaptive_mapping_get(feature_probs, 'p_chain_unavailable_reason'), 'chain_probability_not_ready'),
        'p_cluster_unavailable_reason': cluster_unavailable_reason,
        'p_graph_unavailable_reason': graph_unavailable_reason,
        'p_markov_unavailable_reason': markov_unavailable_reason,
        'p_mitre_unavailable_reason': probability_feature_unavailable_reason(feature_probs, 'p_mitre', adaptive_mapping_get(feature_probs, 'p_mitre_unavailable_reason'), 'mitre_probability_not_ready'),
        'p_profile_unavailable_reason': profile_unavailable_reason,
        'p_bucket_unavailable_reason': bucket_unavailable_reason,
        'p_vector_unavailable_reason': vector_unavailable_reason,
        'p_temporal_unavailable_reason': temporal_unavailable_reason,
        'p_engine_unavailable_reason': probability_feature_unavailable_reason(feature_probs, 'p_engine', adaptive_mapping_get(feature_probs, 'p_engine_unavailable_reason'), 'engine_probability_not_ready'),
    }


def log_odds_static_model_probabilities(raw_prob: object, layer_probs: object, probs: object) -> object:
    layer_probs = adaptive_public_mapping(layer_probs)
    probs = adaptive_public_mapping(probs)
    raw_probability = safe_clamp(raw_prob)
    attack_intelligence_probability = available_feature_probability(
        probs, 'p_attack_intelligence', adaptive_mapping_get(probs, 'p_attack_intelligence_unavailable_reason'),
    )
    chain_probability = available_feature_probability(
        probs, 'p_chain', adaptive_mapping_get(probs, 'p_chain_unavailable_reason'),
    )
    static_probability = safe_clamp(
        0.3 * raw_probability
        + 0.18 * available_feature_probability(layer_probs, 'quick_static_probability', adaptive_mapping_get(layer_probs, 'quick_static_unavailable_reason'))
        + 0.18 * available_feature_probability(layer_probs, 'threat_intel_probability', adaptive_mapping_get(layer_probs, 'threat_intel_unavailable_reason'))
        + 0.1 * adaptive_probability(probs, 'p_exec')
        + 0.08 * adaptive_probability(probs, 'p_behavior')
        + 0.08 * available_feature_probability(probs, 'p_evasion', adaptive_mapping_get(probs, 'p_evasion_unavailable_reason'))
        + 0.04 * adaptive_probability(probs, 'p_entropy')
        + 0.04 * attack_intelligence_probability
        + 0.02 * chain_probability
    )
    model_probability = safe_clamp(
        0.22 * available_feature_probability(probs, 'p_vector', adaptive_mapping_get(probs, 'p_vector_unavailable_reason'))
        + 0.2 * available_feature_probability(probs, 'p_bucket', adaptive_mapping_get(probs, 'p_bucket_unavailable_reason'))
        + 0.16 * available_feature_probability(probs, 'p_profile', adaptive_mapping_get(probs, 'p_profile_unavailable_reason'))
        + 0.14 * available_feature_probability(probs, 'p_markov', adaptive_mapping_get(probs, 'p_markov_unavailable_reason'))
        + 0.1 * available_feature_probability(probs, 'p_temporal', adaptive_mapping_get(probs, 'p_temporal_unavailable_reason'))
        + 0.08 * available_feature_probability(probs, 'p_cluster', adaptive_mapping_get(probs, 'p_cluster_unavailable_reason'))
        + 0.06 * available_feature_probability(probs, 'p_attention', adaptive_mapping_get(probs, 'p_graph_unavailable_reason'))
        + 0.04 * available_feature_probability(probs, 'p_graph', adaptive_mapping_get(probs, 'p_graph_unavailable_reason'))
    )
    attack_chain_probability = safe_clamp(
        0.45 * attack_intelligence_probability
        + 0.20 * chain_probability
        + 0.05 * adaptive_probability(probs, 'p_behavior')
    )
    return static_probability, model_probability, attack_chain_probability

__all__ = (
    "LogOddsFeatureProbabilitiesRequest",
    "log_odds_feature_probabilities",
    "log_odds_static_model_probabilities",
)
