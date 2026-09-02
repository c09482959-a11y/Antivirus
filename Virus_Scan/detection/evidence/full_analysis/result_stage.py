"""DetectionResult assembly and hard failure result ownership."""
from __future__ import annotations


from Virus_Scan.detection.scoring.explainability.score_components import build_reproducible_score_explanation
from Virus_Scan.detection.evidence.failure_evidence import failure_evidence_payload
from Virus_Scan.detection.models.failure_state import DetectionFailureState
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.detection_observation import (
    DetectionObservation,
    ObservationSourceLocation,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.models.result_stage_outputs import DetectionResult
from Virus_Scan.detection.models.stage_value_utils import thaw_detection_value
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.attack.api import (
    official_attack_probability_evidence,
    unavailable_official_attack_probability_evidence,
)
from Virus_Scan.detection.attack.mapping.contracts import AttackMappingResult
from Virus_Scan.detection.attack.explainability import AttackExplainabilitySnapshot
from Virus_Scan.contracts.evidence_discovery_plan import EvidenceDiscoveryPlan
from Virus_Scan.detection.attack.candidate_retrieval import (
    unavailable_attack_candidate_retrieval,
)
from Virus_Scan.detection.scoring.calibration.analytical_bundle import ANALYTICAL_EVIDENCE_SCHEMA_VERSION
from Virus_Scan.contracts.yara_hits import normalize_yara_hits, yara_scan_result_record


def _result_tag_evidence(tags: object) -> TagEvidence:
    """Require and return the exact upstream canonical bundle for publication."""
    if type(tags) is not TagEvidence:
        raise TypeError("result_tag_evidence_required")
    return tags


def build_success_result(
    *,
    node: object,
    path: str,
    score_val: object,
    cluster_id: object,
    classification: str,
    tags: object,
    chain_evidence: ChainEvidence,
    yara_evidence: object,
    strings_blob: object,
    api_result: object,
    behavior_timeline: object,
    ordered_events: object,
    attack_info: object,
    attack_candidate_retrieval: object,
    attack_discovery_plan: EvidenceDiscoveryPlan,
    attack_explainability: AttackExplainabilitySnapshot,
    attack_mapping_result: AttackMappingResult,
    heur: object,
    layer_report: object,
    graph_features: object,
    temporal_features: object,
    markov_features: object,
    engine_context: object,
    engine_confidence: object,
    baseline_maturity: object,
    profile_context: object,
    evidence_provenance: object,
    analytical_calibration: object,
    active_profile: str,
    vector: object,
    explanation: object,
    failure_evidence: object = (),
) -> DetectionResult:
    """Assemble the final immutable detection result snapshot."""
    explanation = thaw_detection_value(explanation or {})
    feature_probabilities = explanation.pop("feature_probabilities", {})
    explanation.pop("mitre_evidence_json", None)
    if type(attack_mapping_result) is not AttackMappingResult:
        raise TypeError("result_attack_mapping_result_required")
    model_evidence: dict[str, object] = {}
    if type(feature_probabilities) is dict and feature_probabilities:
        model_evidence["feature_probabilities"] = feature_probabilities
    model_evidence["mitre_evidence"] = official_attack_probability_evidence(
        attack_mapping_result
    )
    if type(attack_candidate_retrieval) is not dict:
        raise TypeError("attack_candidate_retrieval_record_required")
    if type(attack_discovery_plan) is not EvidenceDiscoveryPlan:
        raise TypeError("attack_discovery_plan_required")
    if type(attack_explainability) is not AttackExplainabilitySnapshot:
        raise TypeError("attack_explainability_snapshot_required")
    model_evidence["attack_candidate_retrieval"] = attack_candidate_retrieval
    model_evidence["evidence_discovery_plan"] = attack_discovery_plan.to_record()
    failure_payload = failure_evidence_payload(failure_evidence)
    if failure_payload.get('degraded'):
        explanation['detection_failures'] = failure_payload['failures']
        explanation['scanner_degraded'] = True
        explanation['confidence_degraded'] = bool(failure_payload.get('confidence_degraded'))
    explanation = build_reproducible_score_explanation(
        final_score=score_val,
        explanation=explanation,
        path=path,
        active_profile=active_profile,
    )

    tag_evidence = _result_tag_evidence(tags)
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("result_chain_evidence_required")
    payload = {
        'node': node,
        'file': path,
        'score': score_val,
        'cluster': cluster_id,
        'class': classification,
        'classification': classification,
        'tags': sorted(set(tag_evidence.tags)),
        'tag_evidence': tag_evidence.to_record(record_limit=200),
        'canonical_chain_evidence': chain_evidence.to_record(),
        'yara_hits': normalize_yara_hits(yara_evidence),
        'yara_evidence': yara_scan_result_record(yara_evidence),
        'api': api_result,
        'behavior_timeline': behavior_timeline,
        'ordered_events': ordered_events,
        'attack_intelligence': attack_info,
        'attack_explainability': attack_explainability.to_record(),
        'heuristics': heur,
        'layered_detection': layer_report,
        'active_layers': explanation.get('active_layers', 0),
        'layer_weights': explanation.get('weights', {}),
        'graph_features': graph_features,
        'temporal_features': temporal_features,
        'markov_features': markov_features,
        'engine_context': engine_context,
        'engine_confidence': engine_confidence,
        'baseline_maturity': baseline_maturity,
        'evidence_provenance': evidence_provenance,
        'evidence_schema_version': ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
        'analytical_calibration': analytical_calibration,
        'profile_selection': {'active_profile': active_profile},
        'detection_profile_context': profile_context,
        'feature_vector': vector,
        'explanation': explanation,
        'model_evidence': model_evidence,
        'score_components': explanation.get('score_components', []),
        'score_reproducibility': explanation.get('score_reproducibility', {}),
        'score_component_schema': explanation.get('score_component_schema', {}),
        'detection_failures': failure_payload.get('failures', []),
        'scan_integrity': {
            'ok': not bool(failure_payload.get('degraded')),
            'degraded': bool(failure_payload.get('degraded')),
            'failure_count': failure_payload.get('failure_count', 0),
            'json_record_required': bool(failure_payload.get('json_record_required')),
            'replay_record_required': bool(failure_payload.get('replay_record_required')),
        },
    }
    return DetectionResult.from_mapping(payload)


def build_failure_result(*, path: str, node: object, tags: object, yara_hits: object, error: BaseException) -> DetectionResult:
    """Build explicit error DetectionResult when full analysis fails."""
    failure_tag = 'failure_scanner_analyze_file_full_observe_only'

    upstream_evidence = (
        tags
        if type(tags) is TagEvidence
        else normalize_tag_evidence(
            tags,
            source_detector='result_failure_input',
            source_stage='full_analysis_failure_input',
            derive=True,
        )
    )
    failure_observations = tuple(
        DetectionObservation.create(
            tag=tag,
            producer_id='result_failure',
            stage_id='full_analysis_failure',
            modality='metadata',
            artifact_identity=path if type(path) is str else '',
            source_location=ObservationSourceLocation(
                'analysis_failure',
                locator=path if type(path) is str else '',
                event_id='full-analysis-failure',
            ),
            integrity_status='unavailable',
            directness='direct',
            confidence=0.0,
            unavailable_reason='full_analysis_failed',
        )
        for tag in (
            failure_tag,
            'scanner_failure',
            'scanner_degraded',
            'scan_incomplete',
            'scan_integrity_failed',
        )
    )
    failure_evidence = normalize_tag_evidence(
        failure_observations,
        source_detector='result_failure',
        source_stage='full_analysis_failure',
        derive=True,
    )
    tag_evidence = TagEvidence.from_records(
        (*upstream_evidence.records, *failure_evidence.records),
        reasons={
            'upstream_record_count': len(upstream_evidence.records),
            'failure_record_count': len(failure_evidence.records),
        },
    )
    result_tags = list(tag_evidence.tags)

    fatal_failure = DetectionFailureState.fatal_failure(
        stage_name='full_analysis',
        error=error,
        error_source='analyze_file_full_observe_only',
        affected_context=path,
    )
    model_evidence = {
        "feature_probabilities": {"mitre": 0.0},
        "unavailable_reasons": {"mitre": "full_analysis_failed"},
        "mitre_evidence": unavailable_official_attack_probability_evidence(
            "full_analysis_failed"
        ),
        "attack_candidate_retrieval": unavailable_attack_candidate_retrieval(
            "full_analysis_failed"
        ).to_record(),
    }
    explanation = build_reproducible_score_explanation(
        final_score=0.0,
        explanation={
            'classification': 'error',
            'exit_code': 4,
            'file_failed': True,
            'scan_incomplete': True,
            'scanner_degraded': True,
            'failure_tags': result_tags,
            'reasons': ['analysis_exception', str(error)],
            'detection_failures': [fatal_failure.to_record()],
        },
        path=path,
        active_profile='other',
    )

    payload = {
        'node': node,
        'file': path,
        'score': 0.0,
        'class': 'error',
        'classification': 'error',
        'tags': result_tags,
        'tag_evidence': tag_evidence.to_record(record_limit=200),
        'yara_hits': yara_hits,
        'error': str(error),
        'exit_code': 4,
        'file_failed': True,
        'scan_incomplete': True,
        'scanner_degraded': True,
        'explanation': explanation,
        'model_evidence': model_evidence,
        'score_components': explanation.get('score_components', []),
        'score_reproducibility': explanation.get('score_reproducibility', {}),
        'score_component_schema': explanation.get('score_component_schema', {}),
        'detection_failures': [fatal_failure.to_record()],
        'scan_integrity': {
            'ok': False,
            'reason': 'analysis_exception',
            'failure_tag': failure_tag,
            'failure_count': 1,
            'json_record_required': True,
            'replay_record_required': True,
        },
    }
    return DetectionResult.from_mapping(payload)
