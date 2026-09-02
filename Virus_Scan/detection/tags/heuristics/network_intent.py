"""Bounded tag-classification ownership helpers.

Split from the former oversized classification module so each file owns one
classification domain with one owned implementation and no duplicate execution path.
"""

from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.utils.text_validation import tag_validation_text as _tag_validation_text
from Virus_Scan.detection.contracts.string_predicates import context_regex as _ctx_re, has_any_text as _has_any_text
from Virus_Scan.detection.tags.heuristics.intent_terms import (
    ASSET_RESOURCE_FETCH_TERMS,
    ASSET_RESOURCE_PATH_TERMS,
    C2_TASKING_TERMS,
    COMMAND_EXECUTION_TERMS,
    REMOTE_PAYLOAD_DOWNLOAD_TERMS,
    REMOTE_PAYLOAD_FILE_TERMS,
    RESOURCE_CACHE_TERMS,
)


def classify_network_intent_tags(blob: object, has_url: object=None) -> object:
    """Return precise network-intent tags from source/string content."""
    text = _tag_validation_text(blob)
    if has_url is None:
        has_url = bool(_ctx_re('\b(?:https?|ftp)://', text))
    tags = []
    is_asset_fetch = _has_any_text(text, ASSET_RESOURCE_FETCH_TERMS) and _has_any_text(text, ASSET_RESOURCE_PATH_TERMS)
    if is_asset_fetch:
        tags.append('asset_resource_fetch')
        if _has_any_text(text, ['xmlhttprequest', 'xhr.open', 'fetch(']):
            tags.append('browser_xhr_fetch')
        if _has_any_text(text, RESOURCE_CACHE_TERMS):
            tags.append('game_resource_cache')
    payload_fetch = bool(has_url and _has_any_text(text, REMOTE_PAYLOAD_DOWNLOAD_TERMS) and (_has_any_text(text, REMOTE_PAYLOAD_FILE_TERMS) or _has_any_text(text, ['start-process', 'subprocess', 'os.system', 'createprocess', 'shellexecute', 'iex', 'invoke-expression'])))
    if payload_fetch:
        tags.extend(['network_activity', 'remote_payload_download', 'network_download'])
    c2_tasking = bool(has_url and _has_any_text(text, C2_TASKING_TERMS) and _has_any_text(text, COMMAND_EXECUTION_TERMS))
    if c2_tasking:
        tags.extend(['network_activity', 'c2_or_remote_command', 'c2_beacon', 'network_c2', 'backdoor_or_c2', 'remote_command_channel'])
    if has_url and (not tags):
        tags.append('url_present')
        tags.append('reference_url')
    return ordered_unique_tags(tags)
