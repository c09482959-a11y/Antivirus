"""Canonical tag-evidence projections owned by clustering models."""

from Virus_Scan.contracts.tag_evidence import distinct_root_tag_evidence_records
from Virus_Scan.detection.api.tag_evidence_contracts import (
    TagEvidence,
    normalize_tag_evidence,
)
from Virus_Scan.models.clustering.common import cluster_input_sequence

CLUSTER_TAG_EVIDENCE_KINDS = frozenset({
    'observed', 'normalized', 'derived', 'composite',
})


def cluster_tag_evidence(value: object) -> object:
    """Materialize raw public observations once into clustering evidence.

    This is the sole clustering tag-input owner. Internal clustering consumers
    receive the returned exact ``TagEvidence`` bundle and never reconstruct
    score-bearing evidence from string projections.
    """
    if type(value) is TagEvidence:
        bundle = value
    else:
        items, input_reason = cluster_input_sequence(
            value, reason='cluster_tag_input_unavailable',
        )
        if input_reason is not None:
            return TagEvidence(), input_reason
        bundle = normalize_tag_evidence(
            items,
            source_detector='clustering',
            source_stage='cluster_input',
        )
    if int(bundle.summary.get('failure_count', 0)) > 0:
        return bundle, 'cluster_tag_evidence_unavailable'
    return bundle, None


def cluster_root_tag_records(value: object) -> object:
    """Return one positive semantic record per clustering evidence root."""
    bundle, reason = cluster_tag_evidence(value)
    if reason is not None:
        return bundle, (), reason
    records = distinct_root_tag_evidence_records(
        bundle.records, allowed_evidence_kinds=CLUSTER_TAG_EVIDENCE_KINDS,
    )
    return bundle, records, None


def cluster_root_tag_projection(value: object) -> object:
    """Return canonical root tags used by clustering similarity and vectors."""
    bundle, records, reason = cluster_root_tag_records(value)
    if reason is not None:
        return bundle, (), reason
    tags = tuple(sorted({
        record.canonical_tag_id
        for record in records
        if record.polarity == 'positive' and record.canonical_tag_id
    }))
    return bundle, tags, None


def cluster_tag_vector_projection(value: object) -> object:
    """Return canonical root tags plus independent root/group cardinalities."""
    bundle, records, reason = cluster_root_tag_records(value)
    if reason is not None:
        return bundle, (), 0, 0, reason
    root_tags = tuple(sorted({
        record.canonical_tag_id
        for record in records
        if record.polarity == 'positive' and record.canonical_tag_id
    }))
    correlation_groups = frozenset(
        record.correlation_group
        for record in records
        if record.polarity == 'positive' and record.correlation_group
    )
    return bundle, root_tags, len(records), len(correlation_groups), None


__all__ = (
    'CLUSTER_TAG_EVIDENCE_KINDS',
    'cluster_root_tag_projection',
    'cluster_root_tag_records',
    'cluster_tag_evidence',
    'cluster_tag_vector_projection',
)
