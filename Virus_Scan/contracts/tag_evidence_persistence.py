"""Neutral no-hook projections for versioned persisted tag evidence."""

from __future__ import annotations

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.contracts.tag_evidence import canonical_tag_name

PersistedRecord = dict[str, object]
PersistedRecordGroup = tuple[PersistedRecord, ...]
PersistedCountStatus = tuple[int, str]


def _mapping_value(mapping: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return default
    for item_key, item_value in items:
        if type(item_key) is str and str.__str__(item_key) == key:
            return item_value
    return default


def _positive_count(value: object) -> int:
    if type(value) is int and type(value) is not bool and value > 0:
        return value
    return 0


def _positive_count_status(value: object) -> PersistedCountStatus:
    if type(value) is int and type(value) is not bool and value >= 0:
        return value, ""
    return 0, "persisted_tag_observation_count_rejected"


def _persisted_records_items(state: object) -> tuple[tuple[object, object], ...] | None:
    state_items = no_hook_mapping_items(state)
    if state_items is None:
        return None
    records = _mapping_value(state, "records", None)
    items = no_hook_mapping_items(records)
    if items is None:
        return None
    return items


def persisted_tag_evidence_record_groups(state: object) -> tuple[PersistedRecordGroup, ...]:
    """Return deterministic persisted-record groups by independent root."""
    items = _persisted_records_items(state)
    if items is None:
        return ()
    groups: dict[str, list[PersistedRecord]] = {}
    for _record_key, raw_record in items:
        record_items = no_hook_mapping_items(raw_record)
        if record_items is None:
            continue
        record = {
            str.__str__(key): value
            for key, value in record_items
            if type(key) is str
        }
        root_id = _mapping_value(record, "root_observation_id", "")
        if type(root_id) is not str or not root_id:
            continue
        groups.setdefault(str.__str__(root_id), []).append(record)

    def record_order(record: PersistedRecord) -> str:
        evidence_id = _mapping_value(record, "evidence_id", "")
        return str.__str__(evidence_id) if type(evidence_id) is str else ""

    return tuple(
        tuple(sorted(values, key=record_order))
        for _root_id, values in sorted(groups.items())
    )


def persisted_tag_frequency_projection(state: object) -> dict[str, int]:
    """Return a deterministic non-authoritative tag-frequency projection."""
    totals: dict[str, int] = {}
    for records in persisted_tag_evidence_record_groups(state):
        root_counts: dict[str, int] = {}
        for record in records:
            tag = canonical_tag_name(
                _mapping_value(record, "publication_name", "")
                or _mapping_value(record, "canonical_tag_id", "")
            )
            count = _positive_count(_mapping_value(record, "observation_count", 0))
            if tag and count:
                root_counts[tag] = max(root_counts.get(tag, 0), count)
        for tag, count in root_counts.items():
            totals[tag] = totals.get(tag, 0) + count
    return {tag: totals[tag] for tag in sorted(totals)}


def persisted_tag_observation_count_status(state: object, tag: object) -> PersistedCountStatus:
    """Return learned frequency once per root, with explicit malformed-state status."""
    if type(tag) is not str:
        return 0, "persisted_tag_lookup_rejected"
    target = canonical_tag_name(tag)
    if not target:
        return 0, "persisted_tag_lookup_rejected"
    items = _persisted_records_items(state)
    if items is None:
        return 0, "persisted_tag_evidence_records_rejected"

    groups: dict[str, list[PersistedRecord]] = {}
    for _record_key, raw_record in items:
        record_items = no_hook_mapping_items(raw_record)
        if record_items is None:
            return 0, "persisted_tag_evidence_record_rejected"
        record = {
            str.__str__(key): value
            for key, value in record_items
            if type(key) is str
        }
        root_id = _mapping_value(record, "root_observation_id", "")
        if type(root_id) is not str or not root_id:
            return 0, "persisted_tag_evidence_root_rejected"
        groups.setdefault(str.__str__(root_id), []).append(record)

    total = 0
    for root_id in sorted(groups):
        root_count = 0
        for record in groups[root_id]:
            labels = {
                canonical_tag_name(_mapping_value(record, "canonical_tag_id", "")),
                canonical_tag_name(_mapping_value(record, "publication_name", "")),
            }
            if target not in labels:
                continue
            count, reason = _positive_count_status(
                _mapping_value(record, "observation_count", 0)
            )
            if reason:
                return 0, reason
            root_count = max(root_count, count)
        total += root_count
    return total, ""


def persisted_tag_observation_count(state: object, tag: object) -> int:
    """Return learned frequency once per matching independent evidence root."""
    count, _reason = persisted_tag_observation_count_status(state, tag)
    return count


def persisted_behavior_bucket_observation_count(state: object, bucket: object) -> int:
    """Return bucket observations once per independent evidence root."""
    if type(bucket) is not str or not bucket:
        return 0
    total = 0
    for records in persisted_tag_evidence_record_groups(state):
        root_count = 0
        for record in records:
            if _mapping_value(record, "behavior_bucket", "") == bucket:
                root_count = max(
                    root_count,
                    _positive_count(_mapping_value(record, "observation_count", 0)),
                )
        total += root_count
    return total


__all__ = (
    "persisted_behavior_bucket_observation_count",
    "persisted_tag_evidence_record_groups",
    "persisted_tag_frequency_projection",
    "persisted_tag_observation_count",
    "persisted_tag_observation_count_status",
)
