from __future__ import annotations

from types import MappingProxyType

import math

from Virus_Scan.contracts.graph_event_time import (
    coerce_graph_event_time,
    graph_event_time_failure_reason,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_finite_float
from Virus_Scan.models.graph.common_text_boundaries import (
    graph_first_reason_text,
    graph_reasoned_text,
    graph_sequence_result,
    safe_graph_sequence,
    safe_graph_text,
    safe_graph_text_with_reason,
)
from Virus_Scan.runtime.config_values import runtime_value
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.utils.tagging import (
    DETECTION_STAGE_DEGRADED_TAG,
    TAG_NORMALIZATION_FAILURE_EVIDENCE,
    normalize_tags,
)

_MAPPING_PROXY_TYPE: type = type(MappingProxyType({}))

TAG_TO_BEHAVIOR = MappingProxyType(dict(runtime_value('TAG_TO_BEHAVIOR', {})))
ATTACK_GRAPH = MappingProxyType(dict(runtime_value('ATTACK_GRAPH', {})))
ANALYTICAL_EVIDENCE_SCHEMA_VERSION = str(runtime_value('ANALYTICAL_EVIDENCE_SCHEMA_VERSION', 'analytical_evidence_v1'))
CAUSAL_ENTITY_MODEL_VERSION = str(runtime_value('CAUSAL_ENTITY_MODEL_VERSION', 'causal_entity_lineage_v1'))
GLOBAL_TAG_BASELINE = MappingProxyType(dict(runtime_value('GLOBAL_TAG_BASELINE', {})))
MIN_CLUSTER_SIZE = int(runtime_value('MIN_CLUSTER_SIZE', 3))

def normalize_graph_tags_with_reason(value: object, reason: object) -> object:
    values, values_reason = graph_sequence_result(value, reason)
    if values_reason:
        return [TAG_NORMALIZATION_FAILURE_EVIDENCE, DETECTION_STAGE_DEGRADED_TAG], reason
    normalized = tuple(normalize_tags(values))
    if TAG_NORMALIZATION_FAILURE_EVIDENCE in normalized:
        return list(normalized), reason
    return list(normalized), ''

def graph_first_reason(*values: object, default: object='') -> object:
    """Return the first readable non-empty graph unavailable reason.

    Model evidence reasons may originate from caller-owned objects.  Do not
    truth-test them: hostile ``__bool__`` methods must not erase degraded graph
    evidence or replace it with a clean default.
    """
    for value in values:
        if value is None:
            continue
        text = graph_first_reason_text(value)
        if text != '':
            return text
    return graph_first_reason_text(default) if default is not None else ''

def graph_flag_enabled(value: object) -> object:
    """Only explicit True enables graph degraded/failure booleans."""
    return value is True

def graph_finite_float(value: object, *, default: object=0.0, minimum: object=None, maximum: object=None, reason: object='non_numeric_graph_metric') -> object:
    """Return a finite bounded graph metric plus an explicit failure reason.

    Evidence-boundary numeric conversion accepts only repository-owned primitive
    numeric values and exact primitive text/bytes. It never invokes caller-owned
    ``__float__`` or ``__int__`` hooks.
    """
    return no_hook_finite_float(
        value,
        default=default,
        minimum=minimum,
        maximum=maximum,
        reason=reason,
        non_finite_reason='non_finite_graph_metric',
        allow_exact_text=True,
    )


def graph_unit_interval(value: object, *, default: object=0.0, reason: object='non_numeric_graph_metric') -> object:
    """Return a graph-owned 0..1 metric without caller-owned numeric hooks."""
    metric, metric_reason = graph_finite_float(
        value,
        default=default,
        minimum=0.0,
        maximum=1.0,
        reason=reason,
    )
    return metric, metric_reason

def graph_owned_key_matches(key: object, name: object) -> object:
    """Compare owned graph mapping keys without caller-owned equality hooks."""
    if key is name:
        return True
    key_type = type(key)
    matches = False
    if key_type is type(name):
        if key_type is str:
            matches = str.__eq__(key, name) is True
        elif key_type is bytes:
            matches = bytes.__eq__(key, name) is True
        elif key_type is bool:
            matches = bool.__eq__(key, name) is True
        elif key_type is int:
            matches = int.__eq__(key, name) is True
        elif key_type is float:
            matches = math.isfinite(key) and math.isfinite(name) and float.__eq__(key, name) is True
    return matches

def record_graph_input_degraded(where: object, reason: object, **context: object) -> None:
    reason_text = graph_first_reason(reason)
    if reason_text == '':
        return
    record_suppressed_failure(where, reason_text, domain='model', tags=['graph_input_degraded'], context=context)

def safe_graph_metadata_value(metadata: object, *names: object) -> object:
    if metadata is None:
        return '', ''
    for name in names:
        try:
            if type(metadata) is dict:
                value = dict.get(metadata, name)
            elif type(metadata) is _MAPPING_PROXY_TYPE:
                value = _MAPPING_PROXY_TYPE.get(metadata, name)
            else:
                return '', 'unreadable_graph_metadata'
        except RECOVERABLE_RUNTIME_ERRORS:
            return '', 'unreadable_graph_metadata'
        if value is None:
            continue
        text, reason = graph_reasoned_text(value, 'unreadable_graph_metadata_value')
        if reason:
            return '', reason
        return text, ''
    return '', ''

__all__ = (
    'ANALYTICAL_EVIDENCE_SCHEMA_VERSION',
    'ATTACK_GRAPH',
    'CAUSAL_ENTITY_MODEL_VERSION',
    'GLOBAL_TAG_BASELINE',
    'MIN_CLUSTER_SIZE',
    'TAG_TO_BEHAVIOR',
    'coerce_graph_event_time',
    'graph_event_time_failure_reason',
    'normalize_graph_tags_with_reason',
    'record_graph_input_degraded',
    'safe_graph_metadata_value',
    'safe_graph_sequence',
    'safe_graph_text',
    'safe_graph_text_with_reason',
)
