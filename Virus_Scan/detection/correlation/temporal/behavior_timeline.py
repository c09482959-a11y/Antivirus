"""Canonical temporal correlation ownership for behavior timeline construction."""

from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.tags.heuristics.primary_behavior import primary_behavior_for_tag
from Virus_Scan.contracts.api_behavior import api_to_timeline_tag, build_api_regex
from Virus_Scan.detection.correlation.temporal.timeline import real_ordered_event_names
from Virus_Scan.detection.enrichment.strings.raw_stage_strings import iter_ordered_string_events
from Virus_Scan.detection.contracts.string_extraction import build_extraction_view
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text

API_REGEX = build_api_regex()


def _timeline_text(value: object, *, missing_reason: object='missing_timeline_text', unsupported_reason: object='timeline_text_rejected') -> object:
    text, reason = no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)
    if reason:
        return '', reason
    return text, ''


def _timeline_event_text(value: object, *, reason_tag: object='timeline_text_unavailable') -> object:
    text, reason = _timeline_text(value, unsupported_reason=reason_tag)
    if reason:
        return reason_tag, reason
    return text, ''


def _timeline_failure(index: int, raw: object, tag: str, source: str) -> dict[str, object]:
    return {
        'index': index,
        'kind': 'failure_evidence',
        'raw': raw,
        'tag': tag,
        'behavior': 'failure_evidence',
        'source': source,
        'degraded': True,
    }


def _append_raw_api_events(timeline: list[dict[str, object]], raw_blob: str) -> None:
    try:
        for match in API_REGEX.finditer(raw_blob):
            api = match.group(0)
            tag = api_to_timeline_tag(api)
            timeline.append({'index': int(match.start()), 'kind': 'api', 'raw': api, 'tag': tag, 'behavior': primary_behavior_for_tag(tag), 'source': 'strings_blob'})
    except RECOVERABLE_RUNTIME_ERRORS as error:
        timeline.append(_timeline_failure(-30, type.__getattribute__(type(error), '__name__'), 'api_timeline_failure_evidence', 'api_timeline_extraction'))


def _has_api_event(timeline: list[dict[str, object]]) -> bool:
    return any(event.get('kind') == 'api' for event in timeline)


def _append_api_sequence_events(timeline: list[dict[str, object]], api_items: object) -> None:
    if not api_items or _has_api_event(timeline):
        return
    for index, api in enumerate(api_items):
        api_text, api_reason = _timeline_event_text(api, reason_tag='api_sequence_value_rejected')
        if api_reason:
            timeline.append(_timeline_failure(1000000 + index, api_reason, 'api_timeline_failure_evidence', 'api_sequence'))
            continue
        tag = api_to_timeline_tag(api_text)
        timeline.append({'index': 1000000 + index, 'kind': 'api', 'raw': api_text, 'tag': tag, 'behavior': primary_behavior_for_tag(tag), 'source': 'api_sequence'})


def _append_string_events(timeline: list[dict[str, object]], raw_blob: str) -> None:
    try:
        for index, event in iter_ordered_string_events(raw_blob) or []:
            event['index'] = int(index)
            timeline.append(event)
    except RECOVERABLE_RUNTIME_ERRORS as error:
        timeline.append(_timeline_failure(-20, type.__getattribute__(type(error), '__name__'), 'string_timeline_failure_evidence', 'string_timeline_extraction'))


def _append_decoded_events(timeline: list[dict[str, object]], raw_blob: str, decoded_payloads: object) -> None:
    try:
        decoded_view = build_extraction_view(raw_blob, decoded_payloads=decoded_payloads)
        if not decoded_view or decoded_view == raw_blob:
            return
        base_index = 2000000
        for match in API_REGEX.finditer(decoded_view):
            api = match.group(0)
            tag = api_to_timeline_tag(api)
            timeline.append({'index': base_index + int(match.start()), 'kind': 'decoded_api', 'raw': api, 'tag': tag, 'behavior': primary_behavior_for_tag(tag), 'source': 'decoded_extraction_view'})
        for index, raw_event in iter_ordered_string_events(decoded_view) or []:
            event = dict(raw_event)
            event['index'] = base_index + int(index)
            event['kind'] = 'decoded_string'
            event['source'] = 'decoded_extraction_view'
            timeline.append(event)
    except RECOVERABLE_RUNTIME_ERRORS as error:
        timeline.append(_timeline_failure(-10, type.__getattribute__(type(error), '__name__'), 'decoded_timeline_failure_evidence', 'decoded_timeline_extraction'))


def _deduplicated_timeline(timeline: list[dict[str, object]]) -> list[dict[str, object]]:
    timeline.sort(key=lambda event: (int(event.get('index', 0)), event.get('kind', ''), event.get('tag', '')))
    deduplicated: list[dict[str, object]] = []
    seen: set[object] = set()
    for event in timeline:
        raw_text, raw_reason = _timeline_event_text(event.get('raw', ''), reason_tag='timeline_event_raw_rejected')
        key = (event.get('index'), event.get('kind'), raw_text.lower() if raw_reason == '' else raw_reason, event.get('tag'))
        if key not in seen:
            seen.add(key)
            deduplicated.append(event)
    return deduplicated


def build_behavior_timeline(strings_blob: object='', api_calls: object=None, api_sequence: object=None, tags: object=None, decoded_payloads: object=None) -> object:
    """Build the ordered behavior timeline while preserving existing tag authority."""
    timeline: list[dict[str, object]] = []
    tag_items = no_hook_sequence_items(tags)
    api_items = no_hook_sequence_items(api_sequence)
    if api_items == ():
        api_items = no_hook_sequence_items(api_calls)
    raw_blob, raw_blob_reason = _timeline_text(
        strings_blob,
        missing_reason='missing_timeline_string_blob',
        unsupported_reason='timeline_string_blob_rejected',
    )
    if raw_blob_reason:
        timeline.append(_timeline_failure(-30, raw_blob_reason, 'api_timeline_failure_evidence', 'api_timeline_extraction'))
    _append_raw_api_events(timeline, raw_blob)
    _append_api_sequence_events(timeline, api_items)
    _append_string_events(timeline, raw_blob)
    _append_decoded_events(timeline, raw_blob, decoded_payloads)
    if tag_items == () and tags is not None:
        timeline.append(_timeline_failure(-5, 'timeline_tags_rejected', 'tag_timeline_failure_evidence', 'tag_timeline_extraction'))
    ordered_timeline = _deduplicated_timeline(timeline)
    return ordered_timeline, real_ordered_event_names(ordered_timeline)


__all__ = ('build_behavior_timeline',)
