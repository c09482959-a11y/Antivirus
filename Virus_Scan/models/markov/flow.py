from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.runtime.config_values import runtime_value
from Virus_Scan.models.behavior_sequence_contract import canonical_behavior_event_name
from Virus_Scan.models.markov.text_boundary import markov_detached_text, markov_text

_TAG_TO_BEHAVIOR = MappingProxyType(dict(runtime_value('TAG_TO_BEHAVIOR', {})))


def safe_markov_text(value: object, *, default_text: str = '') -> str:
    try:
        return markov_text(value, default_text=default_text)
    except RECOVERABLE_RUNTIME_ERRORS:
        return default_text


def safe_markov_stage_name(value: object) -> str:
    text, _reason = markov_detached_text(value, default_text='unknown')
    if text == '':
        return 'unknown'
    return text


def markov_behavior_event_name(item: object) -> str:
    """Apply Markov-specific normalization after sequence-contract admission."""
    name = canonical_behavior_event_name(item)
    if name == '':
        return ''
    mapped = _TAG_TO_BEHAVIOR.get(name, name)
    mapped_text = safe_markov_text(mapped, default_text=name)
    mapped = mapped_text.lower()
    for prefix in ('api_', 'tag_'):
        mapped = mapped.removeprefix(prefix)
    return mapped


def canonical_behavior_flow(events_or_tags: object) -> tuple[str, ...]:
    """Canonical Markov-owned behavior flow normalization without caller hooks."""
    out: list[str] = []
    last: str | None = None
    if events_or_tags is None:
        iterable: tuple[object, ...] = ()
    elif type(events_or_tags) in (str, bytes, bytearray, bool, int, float):
        iterable = (events_or_tags,)
    elif no_hook_mapping_items(events_or_tags) is not None:
        iterable = (events_or_tags,)
    elif isinstance(events_or_tags, Mapping):
        iterable = ()
    elif type(events_or_tags) in (tuple, list, set, frozenset):
        iterable = tuple(events_or_tags)
    else:
        iterable = ()
    for item in iterable:
        try:
            name = markov_behavior_event_name(item)
            if name in ('', last):
                continue
            out.append(name)
            last = name
        except RECOVERABLE_RUNTIME_ERRORS:
            continue
    return tuple(out)



__all__ = (
    'canonical_behavior_flow',
    'markov_behavior_event_name',
    'safe_markov_stage_name',
    'safe_markov_text',
)
