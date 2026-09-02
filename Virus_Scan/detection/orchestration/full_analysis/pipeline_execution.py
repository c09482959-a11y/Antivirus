"""Bounded execution helpers for the full observe-only detection pipeline."""

from Virus_Scan.detection.models.stage_value_utils import thaw_detection_value
from Virus_Scan.detection.scoring.full_analysis.boundaries import (
    full_analysis_mapping,
    full_analysis_mapping_get,
    full_analysis_sequence,
)
from Virus_Scan.detection.publication.full_analysis_effects import (
    ScoredDetectionPublicationRequest,
)
from Virus_Scan.detection.scoring.full_analysis.input_builder import ScoreContextRequest
from Virus_Scan.detection.attack.explainability import build_attack_explainability


def prepare_full_analysis_inputs(
    deps: object,
    path: object,
    tags: object,
    yara_hits: object,
    curr_stage: object,
    strings_blob: object,
    strings_already_enriched: object,
    artifact_read_snapshot: object,
    scan_session_snapshot: object,
    router_identity: object = None,
) -> object:
    """Prepare full-analysis inputs while preserving optional string scan injection."""
    return deps.prepare_analysis_inputs(
        path,
        tags=tags,
        yara_hits=yara_hits,
        curr_stage=curr_stage,
        strings_blob=strings_blob,
        strings_already_enriched=strings_already_enriched,
        router_identity=router_identity,
        artifact_read_snapshot=artifact_read_snapshot,
        attack_repository_digest=scan_session_snapshot.cache_execution_identity.attack_repository_digest,
        **({'scan_strings_func': deps.scan_strings_func} if deps.scan_strings_func is not None else {}),
    )


def build_full_analysis_context(
    deps: object,
    path: object,
    node: object,
    normalized_tags: object,
    yara_evidence: object,
    scan_session_snapshot: object,
    static_program_analyses: object,
    inputs: object,
    prev_stage: object,
) -> object:
    """Build the API/model/family context with explicit optional dependencies."""
    del node, scan_session_snapshot, prev_stage
    return deps.build_detection_api_context(
        path=path,
        tags=normalized_tags,
        yara_evidence=yara_evidence,
        strings_blob=inputs.strings_blob,
        static_program_analyses=static_program_analyses,
        strings_already_enriched=inputs.strings_already_enriched,
        failure_evidence=inputs.failure_evidence,
        **({'api_graph_enricher': deps.api_graph_enricher} if deps.api_graph_enricher is not None else {}),
        **({'family_heuristics_builder': deps.family_heuristics_builder} if deps.family_heuristics_builder is not None else {}),
    )


def score_full_analysis_context(
    deps: object,
    path: object,
    node: object,
    prev_stage: object,
    inputs: object,
    context: object,
    attack_mapping_result: object,
    routing_evidence_context: object | None = None,
    router_identity: object | None = None,
) -> dict[str, object]:
    """Build score context, apply caps, and finalize one canonical score."""
    api_result = full_analysis_mapping(context.api_result)
    ordered_events = full_analysis_sequence(context.ordered_events)
    chain_evidence = context.chain_evidence
    score_breakdown = deps.build_score_context(
        ScoreContextRequest(
            path=path,
            node=node,
            tag_evidence=context.tag_evidence,
            chain_evidence=chain_evidence,
            yara_evidence=inputs.yara_evidence,
            attack_mapping_result=attack_mapping_result,
            prev_stage=prev_stage,
            curr_stage=inputs.curr_stage,
            ordered_events=ordered_events,
            active_profile=context.active_profile,
            failure_evidence=context.failure_evidence,
            artifact_platform=inputs.artifact_platform,
        )
    )
    capped_score = deps.apply_score_caps(
        score_val=score_breakdown.score_val,
        explanation=score_breakdown.explanation,
        path=path,
        tags=context.tag_evidence,
        chain_evidence=chain_evidence,
        active_profile=context.active_profile,
        engine_confidence=context.engine_confidence,
        baseline_maturity=context.baseline_maturity,
        evidence_provenance=context.evidence_provenance,
        failure_evidence=context.failure_evidence,
        routing_evidence_context=routing_evidence_context,
        router_identity=router_identity,
        **({'high_gate_func': deps.high_gate_func} if deps.high_gate_func is not None else {}),
    )
    scored = deps.finalize_scored_detection(
        score_val=capped_score.score_val,
        explanation=capped_score.explanation,
        path=path,
        node=node,
        tags=capped_score.tags,
        prev_stage=prev_stage,
        curr_stage=inputs.curr_stage,
        strings_blob=inputs.strings_blob,
        api_result=context.api_result,
        ordered_events=context.ordered_events,
        behavior_flow=context.behavior_flow,
        active_profile=context.active_profile,
        graph_features=context.graph_features,
        failure_evidence=capped_score.failure_evidence,
        **({'score_explanation_builder': deps.score_explanation_builder} if deps.score_explanation_builder is not None else {}),
    )
    return {
        'score_breakdown': score_breakdown,
        'capped_score': capped_score,
        'scored': scored,
        'chain_evidence': chain_evidence,
    }


def build_full_analysis_publication(
    deps: object,
    path: object,
    node: object,
    prev_stage: object,
    inputs: object,
    context: object,
    capped_score: object,
    scored: object,
) -> object:
    """Publish detection state for final explanation enrichment."""
    return deps.publish_scored_detection_state(
        ScoredDetectionPublicationRequest(
            path=path,
            node=node,
            tags=capped_score.tags,
            score_val=scored.score_val,
            classification=scored.classification,
            active_profile=context.active_profile,
            strings_blob=inputs.strings_blob,
            api_result=context.api_result,
            ordered_events=context.ordered_events,
            behavior_flow=context.behavior_flow,
            prev_stage=prev_stage,
            curr_stage=inputs.curr_stage,
        )
    )


def merge_publication_explanation(scored: object, publication: object) -> object:
    """Merge publication metadata into the final public explanation mapping."""
    final_explanation = thaw_detection_value(scored.explanation)
    if isinstance(final_explanation, dict):
        if publication.get('learning') is not None:
            final_explanation['learning'] = publication.get('learning')
        final_explanation['publication'] = publication
        if publication.get('failures'):
            final_explanation.setdefault('detection_failures', []).extend(publication.get('failures') or [])
            final_explanation['scanner_degraded'] = True
            final_explanation['confidence_degraded'] = True
    return final_explanation


def build_full_analysis_success_record(
    deps: object,
    path: object,
    node: object,
    inputs: object,
    context: object,
    capped_score: object,
    scored: object,
    final_explanation: object,
    evidence_lifecycle: object,
    attack_mapping_result: object,
) -> object:
    """Build the final successful full-analysis result record."""
    attack_explainability = build_attack_explainability(
        evidence_lifecycle.final_evidence,
        attack_mapping_result,
        evidence_lifecycle.candidate_retrieval,
        evidence_lifecycle.discovery_plan,
    )
    detection_result = deps.build_success_result(
        node=node,
        path=path,
        score_val=scored.score_val,
        cluster_id=context.cluster_id,
        classification=scored.classification,
        tags=capped_score.tags,
        chain_evidence=context.chain_evidence,
        yara_evidence=inputs.yara_evidence,
        strings_blob=inputs.strings_blob,
        api_result=context.api_result,
        behavior_timeline=context.behavior_timeline,
        ordered_events=context.ordered_events,
        attack_info=context.attack_info,
        attack_candidate_retrieval=evidence_lifecycle.candidate_retrieval.to_record(),
        attack_discovery_plan=evidence_lifecycle.discovery_plan,
        attack_explainability=attack_explainability,
        attack_mapping_result=attack_mapping_result,
        heur=context.heur,
        layer_report=scored.layer_report,
        graph_features=context.graph_features,
        temporal_features=context.temporal_features,
        markov_features=context.markov_features,
        engine_context=context.engine_context,
        engine_confidence=context.engine_confidence,
        baseline_maturity=context.baseline_maturity,
        profile_context=context.profile_context,
        evidence_provenance=context.evidence_provenance,
        analytical_calibration=scored.analytical_calibration,
        active_profile=context.active_profile,
        vector=context.vector,
        explanation=final_explanation,
        failure_evidence=scored.failure_evidence,
    )
    return detection_result.as_result_record()
