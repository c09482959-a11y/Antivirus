from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.yara_hits import canonical_yara_scan_result
from Virus_Scan.detection.attack.api import serialize_official_attack_probability_evidence
from Virus_Scan.detection.attack.mapping.contracts import AttackMappingResult
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.correlation.multi_signal.attack_intelligence import (
    compute_attack_intelligence,
)
from Virus_Scan.detection.explainability.evasion_signals import detect_evasion_signals
from Virus_Scan.detection.scoring.adaptive.evidence_projection_assembly import (
    intrinsic_probability_scores,
    probability_feature_values,
    zero_unavailable_scores,
)
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import (
    attack_intelligence_probability_component,
    chain_probability_component,
    cluster_probability_component,
    evasion_probability_component,
    graph_probability_components,
    mitre_probability_component,
    markov_probability_component,
    temporal_probability_component,
)
from Virus_Scan.detection.scoring.adaptive.evidence_projection_profile_components import (
    engine_profile_probability_components,
)
from Virus_Scan.detection.scoring.adaptive.model_inputs import cluster_probability_feature
from Virus_Scan.detection.scoring.adaptive.feature_bundle import (
    model_behavior_flow,
    model_coordinated_validation_signal,
    model_extension_profile_anomaly,
    model_feature_bundle,
    model_graph_relationship_layer,
    model_graph_risk_enhanced,
    model_graph_risk_enhanced_evidence,
    model_markov_features,
    model_temporal_snapshot,
)
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_event_sequence,
    adaptive_public_node_reference,
    adaptive_public_sequence,
    adaptive_public_text,
    adaptive_public_text_with_reason,
)
from Virus_Scan.detection.scoring.adaptive.settings import (
    ADAPTIVE_PROBABILITY_FEATURE_BUNDLE_VERSION,
)
from Virus_Scan.detection.scoring.weighting.tag_entropy import tag_entropy
from Virus_Scan.detection.scoring.yara.context_evidence import (
    generic_yara_evidence_context,
    serialize_generic_yara_evidence_context,
)
from Virus_Scan.routing.engine_detect import infer_engine_context

__all__ = (
    'build_probability_features',
    'probability_feature_bundle',
)

_ORIGINAL_MODEL_GRAPH_RISK_ENHANCED = model_graph_risk_enhanced


def probability_feature_bundle(values: object) -> object:
    return model_feature_bundle(
        values,
        model_version=ADAPTIVE_PROBABILITY_FEATURE_BUNDLE_VERSION,
    )



def build_probability_features(
    tags: object,
    yara_hits: object,
    chain_evidence: ChainEvidence,
    attack_mapping_result: AttackMappingResult,
    node: object = None,
    prev_stage: object = None,
    curr_stage: object = None,
    file_structure: object = None,
    strings_blob: object = '',
    api_calls: object = None,
    ordered_events: object = None,
    platform: str = "",
) -> object:
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("canonical_chain_evidence_required")
    if type(attack_mapping_result) is not AttackMappingResult:
        raise TypeError("canonical_attack_mapping_result_required")
    stable_tags = tags if type(tags) is TagEvidence else adaptive_public_sequence(tags)
    tag_evidence = scoreable_tag_evidence(
        stable_tags, allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    tag_names = list(tag_evidence.tags)
    raw_yara_hits = canonical_yara_scan_result(yara_hits)
    yara_context = generic_yara_evidence_context(raw_yara_hits)
    nonprobabilistic_yara_names: tuple[str, ...] = ()
    api_calls = adaptive_public_sequence(api_calls)
    ordered_events = adaptive_public_event_sequence(ordered_events)
    strings_blob = adaptive_public_text(strings_blob)
    node_for_model, node_unavailable_reason = adaptive_public_node_reference(node)
    file_context_reason = None
    if file_structure is not None:
        file_context_text, file_context_reason = adaptive_public_text_with_reason(file_structure)
        file_context = file_context_text or node_for_model
    else:
        file_context = node_for_model
    scores = intrinsic_probability_scores(
        tag_evidence,
        tag_entropy_fn=tag_entropy,
    )
    scores['p_graph'], scores['p_graph_chain'], p_graph_unavailable_reason = graph_probability_components(
        node_for_model,
        node_unavailable_reason,
        tag_evidence,
        model_graph_risk_enhanced_fn=model_graph_risk_enhanced,
        original_model_graph_risk_enhanced=_ORIGINAL_MODEL_GRAPH_RISK_ENHANCED,
        model_graph_risk_enhanced_evidence_fn=model_graph_risk_enhanced_evidence,
        model_graph_relationship_layer_fn=model_graph_relationship_layer,
    )
    scores['p_temporal'], p_temporal_reason = temporal_probability_component(
        node_for_model,
        node_unavailable_reason,
        model_temporal_snapshot_fn=model_temporal_snapshot,
    )
    scores['p_markov'], p_markov_reason = markov_probability_component(
        tag_names,
        ordered_events,
        prev_stage,
        curr_stage,
        model_behavior_flow_fn=model_behavior_flow,
        model_markov_features_fn=model_markov_features,
    )
    scores['p_attack_intelligence'], p_attack_intelligence_reason = attack_intelligence_probability_component(
        tag_evidence,
        raw_yara_hits,
        compute_attack_intelligence_fn=compute_attack_intelligence,
    )
    scores['p_chain'], p_chain_reason = chain_probability_component(chain_evidence)
    scores['p_mitre'], p_mitre_reason, mitre_evidence = mitre_probability_component(
        attack_mapping_result,
    )
    scores['p_evasion'], p_evasion_reason = evasion_probability_component(
        tag_names,
        node_for_model,
        node_unavailable_reason,
        detect_evasion_signals_fn=detect_evasion_signals,
    )
    (
        scores['p_engine'],
        scores['p_profile'],
        scores['p_bucket'],
        scores['p_vector'],
        p_engine_reason,
        p_profile_reason,
        p_bucket_reason,
        p_vector_reason,
    ) = engine_profile_probability_components(
        tag_names,
        file_context,
        file_context_reason,
        strings_blob,
        api_calls,
        ordered_events,
        infer_engine_context_fn=infer_engine_context,
        model_extension_profile_anomaly_fn=model_extension_profile_anomaly,
        model_coordinated_validation_signal_fn=model_coordinated_validation_signal,
    )
    scores['p_cluster'], p_cluster_reason = cluster_probability_component(
        node_for_model,
        cluster_probability_feature_fn=cluster_probability_feature,
    )
    reasons = {
        'p_attack_intelligence': p_attack_intelligence_reason,
        'p_bucket': p_bucket_reason,
        'p_chain': p_chain_reason,
        'p_cluster': p_cluster_reason,
        'p_engine': p_engine_reason,
        'p_evasion': p_evasion_reason,
        'p_graph': p_graph_unavailable_reason,
        'p_markov': p_markov_reason,
        'p_mitre': p_mitre_reason,
        'p_profile': p_profile_reason,
        'p_temporal': p_temporal_reason,
        'p_vector': p_vector_reason,
        'p_yara': yara_context.probability_unavailable_reason,
    }
    zero_unavailable_scores(scores, reasons)
    scores['p_attention'] = 0.0 if p_graph_unavailable_reason else scores['p_graph_chain']
    values = probability_feature_values(scores, reasons)
    values['mitre_evidence_json'] = serialize_official_attack_probability_evidence(mitre_evidence)
    values['yara_evidence_context_json'] = serialize_generic_yara_evidence_context(yara_context)
    return probability_feature_bundle(values)
