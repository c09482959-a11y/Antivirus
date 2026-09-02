"""Model-owned behavior sequence admission policy."""
from __future__ import annotations

from Virus_Scan.contracts.detection_observation import DetectionObservation
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_text


def _model_sequence_detached_text(value: object, *, default_text: str = '') -> str:
    text, reason = no_hook_text(
        value,
        missing_reason='missing_model_sequence_text',
        unsupported_reason='unsupported_model_sequence_text',
    )
    replacement_text, replacement_reason = no_hook_text(
        default_text,
        missing_reason='missing_model_sequence_default_text',
        unsupported_reason='unsupported_model_sequence_default_text',
    )
    if replacement_reason:
        replacement_text = ''
    if reason:
        return replacement_text
    text = str.strip(text)
    return text if text != '' else replacement_text

CONTEXT_ONLY_TAGS = frozenset({
    'url_present', 'strict_fast_prefilter_hit', 'asset_resource_fetch',
    'browser_xhr_fetch', 'filetype_asset', 'magic_type_text', 'text_file',
    'renpy_script', 'renpy', 'stage_parallel_runtime_micro_collectors',
})
SEQUENCE_ALLOWED_STRUCTURAL_EXCEPTIONS = frozenset()

def canonical_behavior_event_name(value: object) -> str:
    """Return a reporting name without inventing physical observation identity."""
    if type(value) is str:
        tag = _model_sequence_detached_text(value).lower()
        directness = "reporting_projection"
        modality = "reporting_projection"
    elif type(value) is dict:
        tag_value = ""
        for key in ("tag", "behavior", "event", "raw"):
            candidate = dict.get(value, key)
            if type(candidate) is str and str.__str__(candidate).strip():
                tag_value = candidate
                break
        tag = _model_sequence_detached_text(tag_value).lower()
        directness_value = dict.get(value, "directness", "reporting_projection")
        modality_value = dict.get(value, "modality", "reporting_projection")
        directness = _model_sequence_detached_text(directness_value, default_text="reporting_projection").lower()
        modality = _model_sequence_detached_text(modality_value, default_text="reporting_projection").lower()
    elif type(value) is DetectionObservation:
        tag = _model_sequence_detached_text(value.tag).lower()
        directness = _model_sequence_detached_text(value.directness).lower()
        modality = _model_sequence_detached_text(value.modality).lower()
    else:
        return ''
    if not tag or tag in CONTEXT_ONLY_TAGS:
        return ''
    if directness in {'context', 'unavailable'} and tag not in SEQUENCE_ALLOWED_STRUCTURAL_EXCEPTIONS:
        return ''
    if modality in {'metadata', 'unavailable'} and tag not in SEQUENCE_ALLOWED_STRUCTURAL_EXCEPTIONS:
        return ''
    return tag
