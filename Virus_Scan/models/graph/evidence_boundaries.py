from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
    no_hook_type_name,
)

_MAPPING_PROXY_TYPE: type = type(MappingProxyType({}))


def graph_evidence_safe_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason='unsupported_graph_text_type',
        unsupported_reason='unsupported_graph_text_type',
    )
    if reason == '':
        return str.strip(text)
    return 'unsupported_graph_text_type:' + no_hook_type_name(value)


def graph_evidence_text(value: object, reason: object) -> object:
    text, text_reason = no_hook_text(
        value,
        missing_reason=reason,
        unsupported_reason=reason,
    )
    if text_reason == '':
        return str.strip(text), ''
    return graph_evidence_safe_text(value), reason


def graph_evidence_sequence(value: object, reason: object) -> object:
    if value is None:
        return (), ''
    if type(value) in (str, bytes, bytearray):
        items = (value,)
    elif type(value) in (tuple, list):
        items = tuple(value)
    elif type(value) in (set, frozenset):
        items = tuple(sorted(value, key=graph_evidence_safe_text))
    else:
        return (), reason
    out = []
    unavailable = ''
    for item in items:
        text, item_reason = graph_evidence_text(item, reason)
        if item_reason and unavailable == '':
            unavailable = item_reason
        out.append(text)
    return tuple(out), unavailable


def graph_evidence_mapping_get(value: object, name: object, default: object=None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for key, item in items:
        if type(key) is str and str.__eq__(key, name) is True:
            return item
    return default


def graph_evidence_metadata_value(metadata: object, *names: object) -> object:
    if metadata is None:
        return '', ''
    items = no_hook_mapping_items(metadata)
    if items is None:
        return '', 'unreadable_graph_metadata'
    for name in names:
        value = graph_evidence_mapping_get(metadata, name)
        if value is None:
            continue
        text, reason = graph_evidence_text(value, 'unreadable_graph_metadata_value')
        if reason:
            return '', reason
        return text, ''
    return '', ''


def graph_evidence_entities(value: object, reason: object) -> object:
    if value is None:
        return (), ''
    if no_hook_mapping_items(value) is not None:
        return (), reason
    values = no_hook_sequence_items(value)
    if len(values) == 0 and value is not None:
        return (), reason
    entities = []
    for item in values:
        if no_hook_mapping_items(item) is not None:
            entities.append(item)
            continue
        entities.append({
            'kind': 'graph_input_unavailable',
            'id': 'non_mapping_transition_entity',
            'label': 'non_mapping_transition_entity',
            'unavailable_reason': 'non_mapping_transition_entity',
            'degraded': True,
            'final_json_must_record': True,
            'replay_record_required': True,
        })
    return tuple(entities), ''


def graph_evidence_mapping(value: object, reason: object) -> object:
    if value is None:
        return {}, ''
    items = no_hook_mapping_items(value)
    if items is None:
        return {}, reason
    out = {}
    for key, raw in items[:128]:
        key_text, key_reason = graph_evidence_text(key, reason)
        if key_reason:
            return out, reason
        out[key_text] = raw
    return out, ''


def graph_evidence_entity_field(entity: object, field: object, default: object, reason: object) -> object:
    if no_hook_mapping_items(entity) is None:
        return default, reason
    value = graph_evidence_mapping_get(entity, field, default)
    text, text_reason = graph_evidence_text(value, reason)
    if text_reason:
        return default, reason
    return text, ''


def graph_evidence_unique_entity_sort_key(key: object) -> object:
    values = no_hook_sequence_items(key)
    if len(values) < 2:
        return (graph_evidence_safe_text(key), '')
    return (graph_evidence_safe_text(values[0]), graph_evidence_safe_text(values[1]))


__all__ = (
    'graph_evidence_entities',
    'graph_evidence_entity_field',
    'graph_evidence_mapping',
    'graph_evidence_mapping_get',
    'graph_evidence_metadata_value',
    'graph_evidence_safe_text',
    'graph_evidence_sequence',
    'graph_evidence_text',
    'graph_evidence_unique_entity_sort_key',
)
