"""Thin full observe-only detection analysis pipeline."""

from dataclasses import dataclass
from typing import Callable

from Virus_Scan.contracts.artifact_read_snapshot import (
    attach_artifact_read_record,
    require_artifact_read_snapshot,
)
from Virus_Scan.contracts.scan_session_snapshot import (
    ScanSessionSnapshot,
    attach_scan_session_record,
)
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.models.enriched_stage_outputs import EnrichedDetectionFacts
from Virus_Scan.contracts.yara_hits import normalize_yara_hits
from Virus_Scan.detection.enrichment.full_analysis.api_context import build_detection_api_context
from Virus_Scan.detection.enrichment.full_analysis.input_stage import prepare_analysis_inputs
from Virus_Scan.detection.evidence.full_analysis.result_stage import build_failure_result, build_success_result
from Virus_Scan.detection.evidence.artifact_session import build_artifact_evidence_lifecycle
from Virus_Scan.detection.attack.evaluation_stage import evaluate_final_attack_mapping
from Virus_Scan.detection.orchestration.full_analysis.pipeline_execution import (
    build_full_analysis_context,
    build_full_analysis_publication,
    build_full_analysis_success_record,
    merge_publication_explanation,
    prepare_full_analysis_inputs,
    score_full_analysis_context,
)
from Virus_Scan.detection.publication.full_analysis_effects import publish_scored_detection_state
from Virus_Scan.routing.extension_outcome import route_identity_record
from Virus_Scan.routing.magic import sniff_file_identity_from_snapshot
from Virus_Scan.detection.scoring.full_analysis.cap_inputs import apply_score_caps
from Virus_Scan.detection.scoring.full_analysis.decision_builder import finalize_scored_detection
from Virus_Scan.detection.scoring.full_analysis.input_builder import build_score_context


@dataclass(frozen=True)
class FullAnalysisPipelineDependencies:
    """Direct dependencies for full detection analysis failure-injection tests."""

    prepare_analysis_inputs: Callable[..., object]
    build_detection_api_context: Callable[..., object]
    build_score_context: Callable[..., object]
    evaluate_final_attack_mapping: Callable[..., object]
    apply_score_caps: Callable[..., object]
    finalize_scored_detection: Callable[..., object]
    publish_scored_detection_state: Callable[..., object]
    build_success_result: Callable[..., object]
    build_failure_result: Callable[..., object]
    scan_strings_func: Callable[..., object] | None = None
    api_graph_enricher: Callable[..., object] | None = None
    model_context_builder: Callable[..., object] | None = None
    profile_context_builder: Callable[..., object] | None = None
    family_heuristics_builder: Callable[..., object] | None = None
    high_gate_func: Callable[..., object] | None = None
    score_explanation_builder: Callable[..., object] | None = None


def default_full_analysis_pipeline_dependencies() -> FullAnalysisPipelineDependencies:
    """Return production full-analysis dependencies without mutable module patching."""

    return FullAnalysisPipelineDependencies(
        prepare_analysis_inputs=prepare_analysis_inputs,
        build_detection_api_context=build_detection_api_context,
        build_score_context=build_score_context,
        evaluate_final_attack_mapping=evaluate_final_attack_mapping,
        apply_score_caps=apply_score_caps,
        finalize_scored_detection=finalize_scored_detection,
        publish_scored_detection_state=publish_scored_detection_state,
        build_success_result=build_success_result,
        build_failure_result=build_failure_result,
    )


def analyze_file_full_observe_only(
    path: object,
    tags: object = None,
    yara_hits: object = None,
    prev_stage: object = None,
    curr_stage: object = None,
    strings_blob: object = '',
    *, scan_session_snapshot: object, artifact_read_snapshot: object,
    static_program_analyses: object = (),
    strings_already_enriched: object = False,
    routing_evidence_context: object | None = None,
    router_identity: object = None,
    dependencies: object = None,
) -> object:
    """Primary analyzer. Receives router tags and coordinates explicit owned stages."""
    if type(scan_session_snapshot) is not ScanSessionSnapshot:
        raise TypeError("scan_session_snapshot_required")
    artifact_snapshot = require_artifact_read_snapshot(artifact_read_snapshot, path)
    effective_router_identity = router_identity
    if route_identity_record(effective_router_identity) is None:
        effective_router_identity = sniff_file_identity_from_snapshot(path, artifact_snapshot)
    deps = dependencies or default_full_analysis_pipeline_dependencies()
    node = path
    normalized_tags = tags if type(tags) is TagEvidence else list(tags or [])
    normalized_yara_hits = normalize_yara_hits(yara_hits)
    try:
        inputs = prepare_full_analysis_inputs(
            deps,
            path,
            tags,
            yara_hits,
            curr_stage,
            strings_blob,
            strings_already_enriched,
            artifact_snapshot,
            scan_session_snapshot,
            effective_router_identity,
        )
        node = inputs.node
        normalized_tags = inputs.tag_evidence
        context = build_full_analysis_context(
            deps,
            path,
            node,
            normalized_tags,
            inputs.yara_evidence,
            scan_session_snapshot,
            static_program_analyses,
            inputs,
            prev_stage,
        )
        evidence_context = context
        evidence_lifecycle = build_artifact_evidence_lifecycle(
            artifact_read_snapshot=artifact_snapshot,
            scan_session_snapshot=scan_session_snapshot,
            static_program_analyses=static_program_analyses,
            yara_scan_result=inputs.yara_evidence,
            tag_evidence=evidence_context.tag_evidence,
            chain_evidence=evidence_context.chain_evidence,
            node=node,
            path=path,
            strings_blob=inputs.strings_blob,
            api_result=evidence_context.api_result,
            ordered_events=evidence_context.ordered_events,
            behavior_timeline=evidence_context.behavior_timeline,
            prev_stage=prev_stage,
            curr_stage=inputs.curr_stage,
            **({'model_context_builder': deps.model_context_builder} if deps.model_context_builder is not None else {}),
            **({'profile_context_builder': deps.profile_context_builder} if deps.profile_context_builder is not None else {}),
        )
        context = EnrichedDetectionFacts.from_evidence(
            evidence_context, evidence_lifecycle.model_context,
        )
        attack_mapping_result = deps.evaluate_final_attack_mapping(
            evidence_lifecycle.final_evidence
        )
        score_state = score_full_analysis_context(
            deps,
            path,
            node,
            prev_stage,
            inputs,
            context,
            attack_mapping_result,
            routing_evidence_context,
            effective_router_identity,
        )
        capped_score = score_state['capped_score']
        scored = score_state['scored']
        publication = build_full_analysis_publication(
            deps,
            path,
            node,
            prev_stage,
            inputs,
            context,
            capped_score,
            scored,
        )
        final_explanation = merge_publication_explanation(scored, publication)
        result = build_full_analysis_success_record(
            deps,
            path,
            node,
            inputs,
            context,
            capped_score,
            scored,
            final_explanation,
            evidence_lifecycle,
            attack_mapping_result,
        )
        attach_artifact_read_record(result, artifact_snapshot)
        return attach_scan_session_record(result, scan_session_snapshot)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        failure_result = deps.build_failure_result(
            path=path,
            node=node,
            tags=normalized_tags,
            yara_hits=normalized_yara_hits,
            error=e,
        )
        record = failure_result.as_result_record()
        attach_artifact_read_record(record, artifact_snapshot)
        return attach_scan_session_record(record, scan_session_snapshot)
