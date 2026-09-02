"""Canonical immutable tag-evidence boundary for profile models."""

from __future__ import annotations

from Virus_Scan.contracts.tag_evidence import (
    active_tag_evidence_records,
    distinct_root_tag_evidence_records,
)
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.detection.api.tag_evidence_contracts import scoreable_tag_evidence
from Virus_Scan.models.profiles.common import profile_public_tags

PROFILE_TAG_EVIDENCE_KINDS = frozenset({
    'observed', 'normalized', 'derived', 'composite',
})


def profile_tag_evidence_projection(
    value: object,
    reason: object = 'malformed_profile_tags',
) -> tuple[TagEvidence, tuple[object, ...], tuple[str, ...], int, str | None]:
    """Return roots/tags plus distinct positive correlation-group count."""
    if type(value) is TagEvidence:
        source = scoreable_tag_evidence(
            value, allowed_evidence_kinds=PROFILE_TAG_EVIDENCE_KINDS,
        )
    else:
        tags, unavailable = profile_public_tags(value, reason)
        if unavailable is not None:
            return TagEvidence(), (), (), 0, str(unavailable)
        source = scoreable_tag_evidence(
            tags, allowed_evidence_kinds=PROFILE_TAG_EVIDENCE_KINDS,
        )
    records = distinct_root_tag_evidence_records(
        source.records, allowed_evidence_kinds=PROFILE_TAG_EVIDENCE_KINDS,
    )
    if not records and int(source.summary.get('failure_count', 0)) > 0:
        return source, (), (), 0, 'profile_tag_evidence_unavailable'
    root_tags = tuple(sorted({
        record.canonical_tag_id for record in records
        if record.polarity == 'positive' and record.canonical_tag_id
    }))
    correlation_group_count = len({
        record.correlation_group for record in records
        if record.polarity == 'positive' and record.correlation_group
    })
    return source, records, root_tags, correlation_group_count, None


def profile_scoreable_root_ids(bundle: TagEvidence) -> frozenset[str]:
    """Return profile roots with at least one positive scoreable record."""
    return frozenset(
        record.root_observation_id
        for record in active_tag_evidence_records(bundle.records)
        if record.evidence_kind in PROFILE_TAG_EVIDENCE_KINDS
        and record.is_positive_scoreable
    )



__all__ = (
    'PROFILE_TAG_EVIDENCE_KINDS',
    'profile_scoreable_root_ids',
    'profile_tag_evidence_projection',
)
