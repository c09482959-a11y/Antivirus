"""Canonical public-input normalization for profile learning commits."""
from __future__ import annotations

from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.models.profiles.common import (
    profile_first_reason,
    profile_public_ordered_events,
    profile_public_tags,
    profile_public_yara_hits,
)


def normalized_commit_inputs(
    tags: object, yara_hits: object, api_calls: object,
    ordered_events: object, behavior_flow: object,
) -> tuple[object, ...]:
    if type(tags) is TagEvidence:
        raw_tags, raw_reason, normalized_tags, tag_reason = (
            tuple(tags.tags), None, tags, None,
        )
    else:
        raw_tags, raw_reason = profile_public_ordered_events(
            tags, "malformed_profile_learning_tags",
        )
        normalized_tags, tag_reason = profile_public_tags(
            tags, "malformed_profile_learning_tags",
        )
    yara_values, yara_reason = profile_public_yara_hits(
        yara_hits, "malformed_profile_learning_yara_hits",
    )
    api_values, api_reason = profile_public_ordered_events(
        api_calls, "malformed_profile_learning_api_calls",
    )
    event_values, event_reason = profile_public_ordered_events(
        ordered_events, "malformed_ordered_profile_events",
    )
    flow_values, flow_reason = profile_public_ordered_events(
        behavior_flow, "malformed_profile_learning_flow",
    )
    reason = profile_first_reason(
        raw_reason, tag_reason, yara_reason, api_reason,
        event_reason, flow_reason, replacement="",
    )
    return (
        raw_tags, normalized_tags, yara_values, api_values,
        event_values, flow_values, reason,
    )


__all__ = ("normalized_commit_inputs",)
