"""Detection behavior-flow normalization owned by detection/correlation/behavioral.

This module converts raw timeline/tag/event objects into deterministic behavior
flow tokens used by chain, temporal, Markov, and clustering consumers.
It does not score, emit reports, or mutate runtime state.
"""

from collections.abc import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text
from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.tags.heuristics.behavior_buckets import TAG_TO_BEHAVIOR


def _detection_flow_text(value: object, *, default_text: str = '') -> str:
    replacement_text, _replacement_reason = no_hook_text(
        default_text,
        missing_reason='missing_detection_flow_default_text',
        unsupported_reason='unsafe_detection_flow_default_text_rejected',
    )
    text, reason = no_hook_text(
        value,
        missing_reason='missing_detection_flow_text',
        unsupported_reason='unsafe_detection_flow_text_rejected',
    )
    if reason is not None and reason != '':
        return str.strip(replacement_text)
    text = str.strip(text)
    return text or str.strip(replacement_text)


def _detection_mapping_value(item: Mapping[object, object], key: str) -> object:
    items = no_hook_mapping_items(item)
    if items is None:
        return None
    for item_key, item_value in items:
        if type(item_key) is str and str.__eq__(item_key, key):
            return item_value
    return None


def _detection_flow_iterable(events_or_tags: object) -> tuple[object, ...]:
    if events_or_tags is None:
        return ()
    if type(events_or_tags) in (str, bytes, bytearray, int, float, bool):
        return (events_or_tags,)
    if no_hook_mapping_items(events_or_tags) is not None:
        return (events_or_tags,)
    if type(events_or_tags) in (tuple, list, set, frozenset):
        return tuple(events_or_tags)
    return ()

def detection_behavior_event_name(item: object) -> object:
    if no_hook_mapping_items(item) is not None:
        value = None
        for key in ('behavior', 'event', 'tag', 'raw'):
            candidate = _detection_mapping_value(item, key)
            candidate_text = _detection_flow_text(candidate)
            if candidate_text:
                value = candidate_text
                break
    else:
        value = item
    name = _detection_flow_text(value).lower()
    if not name:
        return ''
    mapped = TAG_TO_BEHAVIOR.get(name, name)
    mapped_text = _detection_flow_text(mapped, default_text=name).lower()
    for prefix in ('api_', 'tag_'):
            mapped_text = mapped_text.removeprefix(prefix)
    return mapped_text

def detection_behavior_flow(events_or_tags: object) -> object:
    """
    Detection-local behavior path for correlation/scoring labels.

    Input may be timeline event dicts or tags. Output is an ordered, de-duplicated
    list of behavior event names. Tag-only input is intentionally filtered
    so weak context cannot train or score sequence models.
    """
    out = []
    seen_consecutive = None
    for item in _detection_flow_iterable(events_or_tags):
        try:
            name = detection_behavior_event_name(item)
            if not name:
                continue
            if name == seen_consecutive:
                continue
            out.append(name)
            seen_consecutive = name
        except RECOVERABLE_RUNTIME_ERRORS:
            continue
    return out
