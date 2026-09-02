"""Pure final decision builder for full-analysis detection."""
from __future__ import annotations

from Virus_Scan.detection.scoring.full_analysis.classification import classify_detection_score
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence
from Virus_Scan.detection.scoring.explainability.score_components import build_reproducible_score_explanation
from Virus_Scan.detection.scoring.full_analysis.stage_outputs import (
    DetectionDecision,
    DetectionDecisionRequest,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.models.stage_value_utils import thaw_detection_value
from Virus_Scan.detection.scoring.calibration.analytical_bundle import (
    ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
    AnalyticalCalibrationBundleRequest,
    build_analytical_calibration_bundle,
)
from Virus_Scan.detection.scoring.full_analysis.failure_attachment import attach_failure_evidence
from Virus_Scan.detection.scoring.full_analysis.boundaries import (
    full_analysis_first_mapping,
    full_analysis_float,
    full_analysis_mapping,
    full_analysis_sequence,
    full_analysis_text,
)


def _with_stage_failure(failures: object, *, stage_name: str, error_source: str, error: object, path: object) -> object:
    out = list(full_analysis_sequence(failures))
    out.append(recoverable_failure_evidence(
        stage_name=stage_name,
        error_source=error_source,
        error=error,
        affected_context=str(path),
    ))
    return tuple(out)


def finalize_scored_detection(*, score_val: float, explanation: object, path: object, node: object, tags: TagEvidence, prev_stage: str, curr_stage: str, strings_blob: object, api_result: object, ordered_events: object, behavior_flow: object, active_profile: object, graph_features: object, failure_evidence: tuple[object, ...]=(), score_explanation_builder: object=build_reproducible_score_explanation) -> DetectionDecision:
    """Finalize classification and calibration as immutable detection output."""
    del api_result, behavior_flow, node, ordered_events, strings_blob  # Explicitly unused contract parameters.
    if type(tags) is not TagEvidence:
        raise TypeError("final_score_tag_evidence_required")
    explanation = thaw_detection_value(full_analysis_mapping(explanation))
    stage_failures = tuple(full_analysis_sequence(failure_evidence))
    layer_report = full_analysis_first_mapping(explanation, 'layers')
    if isinstance(explanation, dict) and explanation.get('classification') == 'error':
        classification = 'error'
        explanation['exit_code'] = 4
        explanation['file_failed'] = True
        explanation['scan_incomplete'] = True
        explanation['scanner_degraded'] = True
    else:
        classification = classify_detection_score(score_val)[0]
        if isinstance(explanation, dict):
            explanation['classification'] = classification

    if isinstance(explanation, dict):
        explanation['score_breakdown'] = explanation.get('score_breakdown', {})

    try:
        graph_score_for_cal = 0.0
        if isinstance(layer_report, dict):
            graph_layer = full_analysis_first_mapping(layer_report, 'layer_3_graph_score', 'graph')
            if isinstance(graph_layer, dict):
                graph_score_for_cal = full_analysis_float(graph_layer.get('score', 0.0))
        analytical_calibration = build_analytical_calibration_bundle(
            AnalyticalCalibrationBundleRequest(
                path=path,
                tags=tags,
                entropy=None,
                prev_stage=full_analysis_text(prev_stage, default='unknown'),
                curr_stage=full_analysis_text(curr_stage, default='unknown'),
                graph_score=graph_score_for_cal,
                graph_features=full_analysis_mapping(graph_features),
                risk=full_analysis_float(score_val),
            )
        )
        if isinstance(explanation, dict):
            explanation['analytical_calibration'] = analytical_calibration
            explanation['evidence_schema_version'] = ANALYTICAL_EVIDENCE_SCHEMA_VERSION
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        stage_failures = _with_stage_failure(
            stage_failures,
            stage_name='final_score_analytical_calibration',
            error_source='build_analytical_calibration_bundle',
            error=e,
            path=path,
        )
        analytical_calibration = {
            'schema_version': ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
            'evidence_type': 'analytical_calibration_bundle',
            'ready': False,
            'reason': 'calibration_failed',
        }

    explanation = attach_failure_evidence(explanation, stage_failures)
    explanation = score_explanation_builder(
        final_score=score_val,
        explanation=explanation,
        path=path,
        active_profile=active_profile,
    )
    return DetectionDecision.from_request(
        DetectionDecisionRequest(
            score_val=score_val,
            explanation=explanation,
            classification=classification,
            layer_report=layer_report,
            analytical_calibration=analytical_calibration,
            failure_evidence=stage_failures,
        )
    )


__all__ = ('finalize_scored_detection',)
