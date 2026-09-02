"""Pure detection-owned score-explanation assembly."""

from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.evidence.failure_tags import failure_tags_for_stage
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.full_analysis.classification import detection_exit_code_for_score
from Virus_Scan.detection.attack.api import (
    serialize_official_attack_probability_evidence,
)
from Virus_Scan.detection.attack.mapping.contracts import AttackMappingResult
from Virus_Scan.detection.scoring.adaptive.evidence_projection_components import (
    mitre_probability_component,
)
from Virus_Scan.detection.scoring.full_analysis.layered_score import compute_layered_detection
from Virus_Scan.detection.scoring.yara.context_evidence import generic_yara_evidence_context


def _score_input_has_unavailable_tag_evidence(tags: TagEvidence) -> bool:
    return bool(tags.summary.get("failure_count", 0)) or any(
        tag in {"tag_normalization_failure_evidence", "detection_stage_degraded"}
        for tag in tags.tags
    )


@dataclass(frozen=True, slots=True)
class ScoreExplainedRequest:
    tags: TagEvidence
    chain_evidence: ChainEvidence
    yara_evidence: object
    attack_mapping_result: AttackMappingResult
    node: object = None
    prev_stage: object = None
    curr_stage: object = None
    ordered_events: object = None
    artifact_platform: str = ""


def score_explained(request: ScoreExplainedRequest) -> object:
    """Return the pre-cap score and explanation from exact canonical evidence."""
    try:
        if type(request.tags) is not TagEvidence:
            raise TypeError("score_explained_tag_evidence_required")
        if type(request.chain_evidence) is not ChainEvidence:
            raise TypeError("score_explained_chain_evidence_required")
        if type(request.attack_mapping_result) is not AttackMappingResult:
            raise TypeError("score_explained_attack_mapping_result_required")
        if _score_input_has_unavailable_tag_evidence(request.tags):
            raise RuntimeError("score_tag_normalization_failed")
        layered = compute_layered_detection(
            node=request.node,
            tags=request.tags,
            chain_evidence=request.chain_evidence,
            yara_hits=request.yara_evidence,
            prev_stage=request.prev_stage,
            curr_stage=request.curr_stage,
            ordered_events=request.ordered_events,
        )
        score = layered.get("score", 0.0)
        yara_context = generic_yara_evidence_context(request.yara_evidence)
        mitre_probability, mitre_reason, mitre_evidence = mitre_probability_component(
            request.attack_mapping_result,
        )
        return (
            score,
            {
                "classification": layered.get("classification"),
                "exit_code": detection_exit_code_for_score(score),
                "reasons": layered.get("reasons", []),
                "attack_family": layered.get("attack_family"),
                "family_probabilities": layered.get("family_probabilities", {}),
                "layers": layered.get("layers", {}),
                "active_layers": layered.get("active_layers", 0),
                "weights": layered.get("weights", {}),
                "anchor_chain_high_gate": layered.get("anchor_chain_high_gate", {}),
                "renpy_failsafe_cap": layered.get("renpy_failsafe_cap"),
                "score_breakdown": layered.get("score_breakdown", {}),
                "feature_probabilities": {
                    "mitre": mitre_probability,
                    "mitre_unavailable_reason": mitre_reason or "",
                },
                "mitre_evidence_json": serialize_official_attack_probability_evidence(
                    mitre_evidence
                ),
                "yara_evidence_context": yara_context.to_record(),
            },
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        failure_tags = failure_tags_for_stage("score_explained", error, context=request.node)
        return (
            0.0,
            {
                "classification": "error",
                "exit_code": 4,
                "file_failed": True,
                "scan_incomplete": True,
                "scanner_degraded": True,
                "failure_tags": [
                    *list(failure_tags),
                    "scanner_failure",
                    "scanner_degraded",
                    "scan_incomplete",
                    "score_integrity_failed",
                ],
                "reasons": ["layered scoring failed", str(error)],
                "attack_family": None,
                "family_probabilities": {},
                "layers": {},
                "active_layers": 0,
            },
        )


__all__ = ("ScoreExplainedRequest", "score_explained")
