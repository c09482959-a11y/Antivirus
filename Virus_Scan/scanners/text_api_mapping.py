"""Scanner-owned API-to-tag and primary behavior mapping."""

from Virus_Scan.contracts.api_behavior import API_NAME_TEXT_UNAVAILABLE, api_call_values, canonical_api_text
from Virus_Scan.scanners.text_api_policy import map_api_to_group
from Virus_Scan.scanners.text_policy import (
    API_GROUP_INFERRED_TAGS as _API_GROUP_INFERRED_TAGS,
    API_GROUP_TAGS as _API_GROUP_TAGS,
    API_SPECIFIC_TAGS as _API_SPECIFIC_TAGS,
)
from Virus_Scan.scanners.text_spyware_gate import gate_spyware_collection_chains
from Virus_Scan.utils.tagging import DETECTION_STAGE_DEGRADED_TAG, TAG_NORMALIZATION_FAILURE_EVIDENCE, canonical_raw_tag_name, normalize_tags, ordered_unique_tags


def api_to_timeline_tag(api: object) -> object:
    """Convert an API name into the closest concrete scanner tag."""
    api_s = canonical_api_text(api)
    api_l = api_s.lower()
    if api_l in _API_SPECIFIC_TAGS:
        return _API_SPECIFIC_TAGS[api_l]
    return _API_GROUP_TAGS.get(map_api_to_group(api_s), 'api_call')


def primary_behavior_for_tag(tag: object) -> object:
    low = canonical_raw_tag_name(tag).strip().lower()
    behavior = 'other_behavior'
    if any(x in low for x in ('exec', 'process', 'cmd', 'powershell', 'shell')):
        behavior = 'execution'
    elif any(x in low for x in ('network', 'download', 'url', 'socket', 'connect', 'c2')):
        behavior = 'network'
    elif any(x in low for x in ('credential', 'token', 'password', 'lsass')):
        behavior = 'credential_access'
    elif any(x in low for x in ('persist', 'registry', 'service', 'scheduled')):
        behavior = 'persistence'
    elif any(x in low for x in ('memory', 'inject', 'thread')):
        behavior = 'injection'
    elif any(x in low for x in ('evasion', 'amsi', 'etw', 'defender')):
        behavior = 'defense_evasion'
    elif any(x in low for x in ('collection', 'screenshot', 'keylog', 'clipboard')):
        behavior = 'collection'
    return behavior


def _add_specific_api_tags(tagset: object, api_l: object) -> object:
    if 'getasynckeystate' in api_l:
        tagset.update({'keylogging_behavior', 'input_capture'})
    if 'bitblt' in api_l or 'printwindow' in api_l:
        tagset.update({'screenshot_capture', 'screen_capture'})
    if 'getforegroundwindow' in api_l or 'getdc' in api_l:
        tagset.update({'user_activity_monitoring', 'spyware_behavior'})
    injection_writes = {'writeprocessmemory', 'ntwritevirtualmemory'}
    injection_exec = {'createremotethread', 'createremotethreadex', 'ntcreatethreadex', 'queueuserapc', 'setthreadcontext'}
    if bool(injection_writes & api_l) and bool(injection_exec & api_l):
        tagset.add('process_injection')


def infer_tags_from_api(api_calls: object, tags: object = None) -> object:
    """Convert API calls into atomic behavior observations; chain identity stays canonical."""
    tagset = set(ordered_unique_tags(tags))
    api_calls = api_call_values(api_calls)
    api_l = {canonical_api_text(api).lower() for api in api_calls}
    groups = {map_api_to_group(api) for api in api_calls}
    if API_NAME_TEXT_UNAVAILABLE in api_l:
        tagset.add(TAG_NORMALIZATION_FAILURE_EVIDENCE)
        tagset.add(DETECTION_STAGE_DEGRADED_TAG)
    for group in groups:
        tagset.update(_API_GROUP_INFERRED_TAGS.get(group, ()))
    _add_specific_api_tags(tagset, api_l)
    return normalize_tags(gate_spyware_collection_chains(sorted(tagset)))


__all__ = (
    'api_to_timeline_tag',
    'infer_tags_from_api',
    'primary_behavior_for_tag',
)
