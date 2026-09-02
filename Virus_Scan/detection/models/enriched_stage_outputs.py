"""Immutable enrichment outputs for detection stages."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.models.stage_value_utils import (
    freeze_mapping_or_empty,
    frozen_failure_records,
    frozen_tuple_or_empty,
)

DetectionModelValue = object
DetectionModelMapping = Mapping[str, DetectionModelValue]


@dataclass(frozen=True, slots=True)
class DetectionEvidenceFacts:
    """Authoritative enrichment/evidence facts before model context is built."""

    api_result: DetectionModelMapping
    behavior_timeline: tuple[DetectionModelValue, ...]
    ordered_events: tuple[DetectionModelValue, ...]
    tag_evidence: TagEvidence
    chain_evidence: ChainEvidence
    attack_info: DetectionModelMapping
    baseline_maturity: DetectionModelMapping
    evidence_provenance: DetectionModelMapping
    heur: DetectionModelMapping
    failure_evidence: tuple[DetectionModelValue, ...] = ()

    def __post_init__(self) -> None:
        if type(self.tag_evidence) is not TagEvidence:
            raise TypeError("detection_evidence_tag_evidence_required")
        if type(self.chain_evidence) is not ChainEvidence:
            raise TypeError("detection_evidence_chain_evidence_required")
        object.__setattr__(self, "api_result", freeze_mapping_or_empty(self.api_result))
        object.__setattr__(self, "behavior_timeline", frozen_tuple_or_empty(self.behavior_timeline))
        object.__setattr__(self, "ordered_events", frozen_tuple_or_empty(self.ordered_events))
        object.__setattr__(self, "attack_info", freeze_mapping_or_empty(self.attack_info))
        object.__setattr__(self, "baseline_maturity", freeze_mapping_or_empty(self.baseline_maturity))
        object.__setattr__(self, "evidence_provenance", freeze_mapping_or_empty(self.evidence_provenance))
        object.__setattr__(self, "heur", freeze_mapping_or_empty(self.heur))
        object.__setattr__(self, "failure_evidence", frozen_failure_records(self.failure_evidence))

    @property
    def tags(self) -> tuple[DetectionModelValue, ...]:
        return tuple(self.tag_evidence.tags)


@dataclass(frozen=True, slots=True)
class EnrichedDetectionFacts:
    """Final enriched facts with one canonical context-only model snapshot."""

    evidence: DetectionEvidenceFacts
    model_context: ModelContextSnapshot
    failure_evidence: tuple[DetectionModelValue, ...] = ()

    def __post_init__(self) -> None:
        if type(self.evidence) is not DetectionEvidenceFacts:
            raise TypeError("enriched_detection_evidence_required")
        if type(self.model_context) is not ModelContextSnapshot:
            raise TypeError("enriched_model_context_snapshot_required")
        combined = frozen_failure_records(
            (*self.evidence.failure_evidence, *self.model_context.failure_evidence, *self.failure_evidence)
        )
        object.__setattr__(self, "failure_evidence", combined)

    @property
    def api_result(self) -> DetectionModelMapping:
        return self.evidence.api_result

    @property
    def behavior_timeline(self) -> tuple[DetectionModelValue, ...]:
        return self.evidence.behavior_timeline

    @property
    def ordered_events(self) -> tuple[DetectionModelValue, ...]:
        return self.evidence.ordered_events

    @property
    def tag_evidence(self) -> TagEvidence:
        return self.evidence.tag_evidence

    @property
    def chain_evidence(self) -> ChainEvidence:
        return self.evidence.chain_evidence

    @property
    def tags(self) -> tuple[DetectionModelValue, ...]:
        return self.evidence.tags

    @property
    def attack_info(self) -> DetectionModelMapping:
        return self.evidence.attack_info

    @property
    def baseline_maturity(self) -> DetectionModelMapping:
        return self.evidence.baseline_maturity

    @property
    def evidence_provenance(self) -> DetectionModelMapping:
        return self.evidence.evidence_provenance

    @property
    def heur(self) -> DetectionModelMapping:
        return self.evidence.heur

    @property
    def graph_features(self) -> DetectionModelMapping:
        return self.model_context.graph_features

    @property
    def temporal_features(self) -> DetectionModelMapping:
        return self.model_context.temporal_features

    @property
    def markov_features(self) -> DetectionModelMapping:
        return self.model_context.markov_features

    @property
    def engine_context(self) -> DetectionModelMapping:
        return self.model_context.engine_context

    @property
    def behavior_flow(self) -> tuple[DetectionModelValue, ...]:
        return self.model_context.behavior_flow

    @property
    def vector(self) -> tuple[DetectionModelValue, ...]:
        return self.model_context.feature_vector

    @property
    def cluster_id(self) -> DetectionModelValue:
        return self.model_context.cluster_context.get("cluster_id")

    @property
    def profile_context(self) -> DetectionModelMapping:
        return self.model_context.profile_context

    @property
    def engine_confidence(self) -> DetectionModelMapping:
        value = self.model_context.profile_context.get("engine_confidence", {})
        return value if isinstance(value, Mapping) else {}

    @property
    def active_profile(self) -> str:
        value = self.model_context.profile_context.get("active_profile", "other")
        return str.__str__(value) if type(value) is str and value else "other"

    @classmethod
    def from_evidence(
        cls,
        evidence: DetectionEvidenceFacts,
        model_context: ModelContextSnapshot,
    ) -> "EnrichedDetectionFacts":
        return cls(evidence=evidence, model_context=model_context)


__all__ = ("DetectionEvidenceFacts", "EnrichedDetectionFacts")
