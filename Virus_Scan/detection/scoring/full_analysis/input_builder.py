"""Pure score-input builder owner for full-analysis detection."""

from dataclasses import dataclass

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.attack.mapping.contracts import AttackMappingResult
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.full_analysis.score_explained import ScoreExplainedRequest, score_explained
from Virus_Scan.detection.scoring.explainability.score_components import build_reproducible_score_explanation
from Virus_Scan.detection.scoring.full_analysis.stage_outputs import ScoreBreakdown
from Virus_Scan.detection.scoring.full_analysis.failure_attachment import attach_failure_evidence
from Virus_Scan.detection.scoring.full_analysis.boundaries import full_analysis_sequence


@dataclass(frozen=True, slots=True)
class ScoreContextRequest:
    """Internal request for scoring from explicit authoritative evidence."""

    path: object
    node: object
    tag_evidence: TagEvidence
    chain_evidence: ChainEvidence
    yara_evidence: object
    attack_mapping_result: AttackMappingResult
    prev_stage: object = None
    curr_stage: object = None
    ordered_events: object = None
    active_profile: object = None
    failure_evidence: object = ()
    artifact_platform: str = ""


def build_score_context(request: ScoreContextRequest) -> object:
    """Compute the pre-cap score context from exact canonical evidence."""
    if type(request.tag_evidence) is not TagEvidence:
        raise TypeError("score_context_tag_evidence_required")
    if type(request.chain_evidence) is not ChainEvidence:
        raise TypeError("score_context_chain_evidence_required")
    stable_ordered_events = full_analysis_sequence(request.ordered_events)
    stable_failure_evidence = full_analysis_sequence(request.failure_evidence)
    score_val, explanation = score_explained(
        ScoreExplainedRequest(
            tags=request.tag_evidence,
            chain_evidence=request.chain_evidence,
            yara_evidence=request.yara_evidence,
            attack_mapping_result=request.attack_mapping_result,
            node=request.node,
            prev_stage=request.prev_stage,
            curr_stage=request.curr_stage,
            ordered_events=stable_ordered_events,
            artifact_platform=request.artifact_platform,
        )
    )
    explanation = attach_failure_evidence(explanation, stable_failure_evidence)
    explanation = build_reproducible_score_explanation(
        final_score=score_val,
        explanation=explanation,
        path=request.path,
        active_profile=request.active_profile,
    )
    return ScoreBreakdown(
        score_val=score_val,
        explanation=explanation,
        tags=request.tag_evidence,
        failure_evidence=stable_failure_evidence,
    )


__all__ = ("ScoreContextRequest", "build_score_context")
