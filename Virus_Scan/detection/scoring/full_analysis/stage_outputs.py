"""Immutable scoring and decision outputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.models.stage_value_utils import (
    freeze_detection_value,
    frozen_failure_records,
    thaw_detection_value,
)
from Virus_Scan.detection.scoring.full_analysis.boundaries import (
    full_analysis_float,
    full_analysis_mapping,
    full_analysis_sequence,
    full_analysis_text,
)


@dataclass(frozen=True)
class ScoreBreakdown:
    """Score components and weights only."""

    score_val: float
    explanation: Mapping[str, object]
    tags: TagEvidence
    failure_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        """Deep-freeze direct constructor scoring payloads."""
        object.__setattr__(self, "score_val", full_analysis_float(self.score_val))
        object.__setattr__(self, "explanation", freeze_detection_value(full_analysis_mapping(self.explanation)))
        if type(self.tags) is not TagEvidence:
            raise TypeError("score_breakdown_tag_evidence_required")
        object.__setattr__(self, "failure_evidence", frozen_failure_records(full_analysis_sequence(self.failure_evidence)))


    def mutable_explanation(self) -> dict[str, object]:
        return thaw_detection_value(self.explanation)


@dataclass(frozen=True, slots=True)
class DetectionDecisionRequest:
    """Immutable construction contract for a scored detection decision."""

    score_val: object
    explanation: object
    classification: str
    layer_report: object
    analytical_calibration: object
    failure_evidence: object = ()


@dataclass(frozen=True)
class DetectionDecision:
    """Classification only, with immutable score/report context."""

    score_val: float
    explanation: Mapping[str, object]
    classification: str
    layer_report: Mapping[str, object]
    analytical_calibration: Mapping[str, object]
    failure_evidence: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        """Deep-freeze direct constructor decision payloads."""
        object.__setattr__(self, "score_val", full_analysis_float(self.score_val))
        object.__setattr__(self, "explanation", freeze_detection_value(full_analysis_mapping(self.explanation)))
        object.__setattr__(self, "classification", full_analysis_text(self.classification))
        object.__setattr__(self, "layer_report", freeze_detection_value(full_analysis_mapping(self.layer_report)))
        object.__setattr__(self, "analytical_calibration", freeze_detection_value(full_analysis_mapping(self.analytical_calibration)))
        object.__setattr__(self, "failure_evidence", frozen_failure_records(full_analysis_sequence(self.failure_evidence)))

    @classmethod
    def from_request(cls, request: DetectionDecisionRequest) -> "DetectionDecision":
        """Build a decision from the canonical immutable request contract."""
        return cls(
            score_val=request.score_val,
            explanation=request.explanation,
            classification=request.classification,
            layer_report=request.layer_report,
            analytical_calibration=request.analytical_calibration,
            failure_evidence=request.failure_evidence,
        )



__all__ = ("ScoreBreakdown", "DetectionDecisionRequest", "DetectionDecision")
