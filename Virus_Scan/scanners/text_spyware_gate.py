"""Scanner-owned spyware/exfiltration intent gate for text API tags."""

from Virus_Scan.scanners.text_behavior import _has_confirmed_exfil_proof
from Virus_Scan.scanners.text_extraction import _tag_validation_text
from Virus_Scan.scanners.text_policy import (
    SPYWARE_COLLECTION_TAGS as _COLLECTION_TAGS,
    SPYWARE_SENSITIVE_TAGS as _SENSITIVE_TAGS,
    SPYWARE_SENSITIVE_TEXT_TERMS as _SENSITIVE_TEXT_TERMS,
    SPYWARE_SUPPRESSED_TAGS as _SUPPRESSED_SPYWARE_TAGS,
)
from Virus_Scan.utils.tagging import norm_lower_set, ordered_unique_tags
from Virus_Scan.utils.text_match import has_any_text as _has_any_text


def _allows_spyware_chain(text: object, tagset: object) -> object:
    has_input_or_collection = bool(tagset & _COLLECTION_TAGS)
    has_sensitive = bool(tagset & _SENSITIVE_TAGS) or _has_any_text(text, _SENSITIVE_TEXT_TERMS)
    return has_input_or_collection and has_sensitive and _has_confirmed_exfil_proof(text, tagset)


def gate_spyware_collection_chains(tags: object, path: object = None, strings_blob: object = '') -> object:
    """Suppress spyware/exfil chains unless collection, sensitive target, and transmit proof exist."""
    del path  # Explicitly unused contract parameters.
    tagset = norm_lower_set(tags)
    text = _tag_validation_text(strings_blob)
    allow_spyware_chain = _allows_spyware_chain(text, tagset)
    cleaned = []
    removed = False
    for tag in ordered_unique_tags(tags):
        low = tag.lower()
        if low in _SUPPRESSED_SPYWARE_TAGS and not allow_spyware_chain:
            removed = True
            continue
        if low == 'user_activity_monitoring' and not allow_spyware_chain:
            cleaned.append('input_event_handling')
            removed = True
            continue
        cleaned.append(tag)
    if removed:
        cleaned.append('spyware_chain_intent_gate_suppressed')
    return ordered_unique_tags(cleaned)


__all__ = ('gate_spyware_collection_chains',)
