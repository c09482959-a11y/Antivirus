"""Scoreable tag set and concrete score-count ownership."""

from __future__ import annotations

from Virus_Scan.detection.registries.chain_registry import CHAIN_CONCLUSION_TAGS
from Virus_Scan.contracts.tag_evidence import (
    active_tag_evidence_records,
    tag_evidence_records,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.weighting.policy_constants import norm_lower_tag_set
from Virus_Scan.detection.tags.heuristics.behavior_derivation import derive_behavior_evidence
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence

ScoreableValue = object
ScoreableSet = set[str]


def _source_tag_evidence(
    tags: ScoreableValue, allowed_evidence_kinds: frozenset[str],
) -> TagEvidence:
    if not allowed_evidence_kinds or not allowed_evidence_kinds <= {
        "observed", "normalized", "derived", "composite",
    }:
        return TagEvidence(reasons={"unavailable_reason": "evidence_kind_declaration_rejected"})
    if type(tags) is TagEvidence:
        source = tags
    else:
        records = tag_evidence_records(tags)
        if records:
            source = TagEvidence.from_records(records)
        else:
            normalized = normalize_tag_evidence(
                tags, source_detector="scoreable_tags", source_stage="scoreability",
            )
            source = TagEvidence.from_records(
                derive_behavior_evidence(normalized.records), reasons=normalized.reasons,
            )
    selected = tuple(
        record for record in source.records
        if record.canonical_tag_id not in CHAIN_CONCLUSION_TAGS
        and (
            record.evidence_kind in allowed_evidence_kinds
            or record.evidence_kind in {"suppression", "failure"}
        )
    )
    return TagEvidence.from_records(selected, reasons=source.reasons)


def scoreable_tag_evidence(
    tags: ScoreableValue, *, allowed_evidence_kinds: frozenset[str],
) -> TagEvidence:
    """Return canonical evidence with scoreability authority preserved, never minted."""
    source = _source_tag_evidence(tags, allowed_evidence_kinds)
    reasons = dict(source.reasons)
    reasons["scoreability_policy_version"] = "tag_scoreability_policy_v2_evidence_owned"
    return TagEvidence.from_records(source.records, reasons=reasons)

def scoreable_tag_set(tags: ScoreableValue) -> ScoreableSet:
    """Return only labels backed by canonical positive scoreability evidence."""
    bundle = scoreable_tag_evidence(
        tags, allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    return {
        record.canonical_tag_id
        for record in active_tag_evidence_records(bundle.records)
        if record.is_positive_scoreable
        and record.canonical_tag_id not in CHAIN_CONCLUSION_TAGS
    }


def distinct_scoreable_root_ids(tags: ScoreableValue) -> frozenset[str]:
    """Return distinct contributing observations, never alias/tag cardinality."""
    bundle = scoreable_tag_evidence(
        tags, allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    labels = scoreable_tag_set(bundle)
    active = active_tag_evidence_records(bundle.records)
    parent_roots = {
        record.root_observation_id for record in active
        if record.canonical_tag_id in labels
        and record.evidence_kind in {"observed", "normalized", "derived"}
    }
    return frozenset(parent_roots)



def required_scoreable_tags_have_distinct_roots(
    tags: ScoreableValue, required: object, *, allowed_evidence_kinds: frozenset[str],
) -> bool:
    """Prove each required tag has an independent contributing root."""
    bundle = scoreable_tag_evidence(
        tags, allowed_evidence_kinds=allowed_evidence_kinds,
    )
    required_tags = frozenset(
        value for value in norm_lower_tag_set(required) if value
    )
    active = active_tag_evidence_records(bundle.records)
    used: set[str] = set()
    for tag in sorted(required_tags):
        candidates = tuple(
            record for record in active
            if record.canonical_tag_id == tag
            and record.is_positive_scoreable
            and record.root_observation_id not in used
        )
        if not candidates:
            return False
        used.add(candidates[0].root_observation_id)
    return True

def concrete_score_count(tags: ScoreableValue) -> int:
    """Count distinct scoreable root observations, never expanded aliases."""
    return len(distinct_scoreable_root_ids(tags))


__all__ = (
    "concrete_score_count", "distinct_scoreable_root_ids",
    "required_scoreable_tags_have_distinct_roots",
    "scoreable_tag_evidence", "scoreable_tag_set",
)
