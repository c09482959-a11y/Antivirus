"""Canonical generic family heuristic tag enrichment ownership."""

from Virus_Scan.contracts.no_hook_materialization import no_hook_sequence_items, no_hook_text
from Virus_Scan.detection.contracts.probability import safe_clamp
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags


def family_heuristic_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='family_heuristic_text_missing',
        unsupported_reason='family_heuristic_text_rejected',
    )
    if reason:
        return ''
    return text.lower()


def family_heuristic_text_set(values: object) -> object:
    out = set()
    for value in no_hook_sequence_items(values):
        text = family_heuristic_text(value)
        if text:
            out.add(text)
    return out


def enhanced_family_heuristics(path: object, tags: object, strings_blob: object='', api_calls: object=None) -> object:
    del path  # Explicitly unused contract parameters.
    tagset = {tag.lower() for tag in normalize_tags(tags)}
    blob = family_heuristic_text(strings_blob)
    apis = family_heuristic_text_set(api_calls)
    new_tags = set(tagset)
    score = 0.0
    if any(x in blob for x in ('vssadmin delete shadows', 'shadowcopy delete', 'bcdedit /set')):
        new_tags.add('ransomware_behavior')
        score = max(score, 0.75)
    if any(x in blob for x in ('virtualalloc', 'writeprocessmemory', 'createremotethread')) or apis & {'virtualalloc', 'writeprocessmemory', 'createremotethread'}:
        new_tags.add('process_injection')
        score = max(score, 0.65)
    if any(x in blob for x in ('syscall', 'ntprotectvirtualmemory', 'ntallocatevirtualmemory')):
        new_tags.add('syscall_sequence')
        score = max(score, 0.55)
    bounded_score = safe_clamp(score, 0.0, 1.0)
    return {'score': bounded_score, 'tags': sorted(new_tags)}
