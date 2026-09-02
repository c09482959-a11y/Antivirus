"""Canonical tag-to-behavior bucket ownership.

This module owns behavior bucket resolution for detection code.  Callers use the
same immutable tag-to-bucket snapshot instead of duplicating lookup logic across
chains, evidence, and tags.
"""
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.detection.tags.heuristics.normalization_runtime import canonical_tag_name
from Virus_Scan.detection.registries.context import detection_registry_value

TAG_TO_BEHAVIOR = MappingProxyType(dict(detection_registry_value("TAG_TO_BEHAVIOR", {})))
_SCORE_BUCKET_TAGS = MappingProxyType(dict(detection_registry_value("BUCKET_TAGS", {})))


def _mapping_items(value: object) -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(value, allow_dict_subclass=True)
    return items if items is not None else ()


def _clean_bucket(value: object) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="behavior_bucket_missing",
        unsupported_reason="behavior_bucket_rejected",
    )
    bucket = "other_behavior" if reason else text.strip().lower()
    return bucket or "other_behavior"


def tag_behavior_bucket(tag: object) -> object:
    clean_tag = canonical_tag_name(tag)
    return _clean_bucket(TAG_TO_BEHAVIOR.get(clean_tag, "other_behavior"))


def tag_score_bucket(tag: object) -> str:
    """Return the canonical coarse scoring bucket for one canonical tag."""
    clean_tag = canonical_tag_name(tag)
    if not clean_tag:
        return "other_behavior"
    matches = []
    for bucket, values in _mapping_items(_SCORE_BUCKET_TAGS):
        clean_bucket = _clean_bucket(bucket)
        if type(values) in (set, frozenset, tuple, list) and clean_tag in values:
            matches.append(clean_bucket)
    return matches[0] if len(matches) == 1 else "other_behavior"


def build_behavior_bucket_index(tag_to_behavior: object=None) -> object:
    source_items = _mapping_items(TAG_TO_BEHAVIOR if tag_to_behavior is None else tag_to_behavior)
    buckets = {}
    for tag, bucket in source_items:
        clean_tag = canonical_tag_name(tag)
        if not clean_tag:
            continue
        clean_bucket = _clean_bucket(bucket)
        buckets.setdefault(clean_bucket, set()).add(clean_tag)
    bucket_items = _mapping_items(buckets)
    return MappingProxyType({bucket: frozenset(values) for bucket, values in sorted(bucket_items)})


BUCKET_TAGS = build_behavior_bucket_index()


__all__ = ("BUCKET_TAGS", "TAG_TO_BEHAVIOR", "build_behavior_bucket_index", "tag_behavior_bucket", "tag_score_bucket")
