"""Scanner-owned API behavior timeline construction."""

from Virus_Scan.exception_contracts import SCAN_CONTENT_ERRORS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.scanners.contracts import scanner_contract_error_message, scanner_contract_join
from Virus_Scan.scanners.text_api_policy import API_REGEX
from Virus_Scan.scanners.text_api_mapping import api_to_timeline_tag, primary_behavior_for_tag
from Virus_Scan.contracts.api_behavior import canonical_api_text
from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text


def _api_event(index: object, api: object, source: object) -> object:
    raw = canonical_api_text(api)
    if raw == 'api_name_text_unavailable':
        return None
    tag = api_to_timeline_tag(api)
    return {
        'index': int(index),
        'kind': 'api',
        'raw': raw,
        'tag': tag,
        'behavior': primary_behavior_for_tag(tag),
        'source': source,
    }


def _dedupe_timeline(timeline: object) -> object:
    deduped = []
    seen = set()
    for event in timeline:
        raw_text, _raw_reason = no_hook_text(event.get('raw', ''), missing_reason='missing_timeline_raw', unsupported_reason='unsafe_timeline_raw_rejected')
        key = (event.get('index'), event.get('kind'), raw_text.lower(), event.get('tag'))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(event)
    return deduped


def _ordered_event_tags(events: object) -> object:
    ordered_events = []
    last = None
    for event in events:
        tag_text, _tag_reason = no_hook_text(event.get('tag'), missing_reason='missing_timeline_tag', unsupported_reason='unsafe_timeline_tag_rejected')
        tag = tag_text.strip().lower()
        if tag and tag != last:
            ordered_events.append(tag)
            last = tag
    return ordered_events


def build_behavior_timeline(strings_blob: object = '', api_calls: object = None, api_sequence: object = None, tags: object = None) -> object:
    """Build a deterministic scanner-owned API behavior timeline."""
    del tags  # Explicitly unused contract parameters.
    timeline = []
    api_sequence = no_hook_sequence_items(api_sequence) or no_hook_sequence_items(api_calls)
    blob, blob_reason = no_hook_text(strings_blob, missing_reason='missing_timeline_blob', unsupported_reason='unsafe_timeline_blob_rejected')
    if blob_reason:
        blob = ''
    try:
        timeline.extend(_api_event(match.start(), match.group(0), 'strings_blob') for match in API_REGEX.finditer(blob))
    except SCAN_CONTENT_ERRORS as e:
        log_error(scanner_contract_join('API timeline extraction failed: ', scanner_contract_error_message(e)))
    if api_sequence and not any(event.get('kind') == 'api' for event in timeline):
        for index, api in enumerate(api_sequence):
            event = _api_event(1000000 + index, api, 'api_sequence')
            if event is not None:
                timeline.append(event)
    timeline.sort(key=lambda event: (int(event.get('index', 0)), str(event.get('kind', '')), str(event.get('tag', ''))))
    deduped = _dedupe_timeline(timeline)
    return deduped, _ordered_event_tags(deduped)


__all__ = ('build_behavior_timeline',)
