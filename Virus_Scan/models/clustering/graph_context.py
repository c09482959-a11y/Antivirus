from dataclasses import dataclass
from types import MappingProxyType
from collections.abc import Mapping
import math

from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_text,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.graph_state import graph_has_node, graph_node_snapshot, graph_snapshot, graph_vector_node_key
from Virus_Scan.models.clustering.common import cluster_text_sequence, safe_cluster_text


@dataclass(frozen=True)
class ClusterGraphNodeRecord:
    node_key: str
    available: bool
    present: bool
    empty: bool
    corrupt: bool
    unavailable_reason: str
    risk: float | None
    tags: tuple[str, ...]
    edges: tuple[str, ...]
    metadata: Mapping[str, object]

    def to_json(self) -> dict[str, object]:
        metadata = cluster_graph_json_value(self.metadata)
        if not isinstance(metadata, dict):
            metadata = {
                'value': None,
                'unavailable_reason': 'cluster_graph_metadata_materialization_failed',
            }
        return {
            'node_key': self.node_key,
            'available': self.available,
            'present': self.present,
            'empty': self.empty,
            'corrupt': self.corrupt,
            'unavailable_reason': self.unavailable_reason,
            'risk': self.risk,
            'tags': list(self.tags),
            'edges': list(self.edges),
            'metadata': metadata,
        }


_EMPTY_METADATA: Mapping[str, object] = MappingProxyType({})


def cluster_graph_json_value(value: object) -> object:
    return no_hook_materialize(value, reason_prefix='cluster_graph')


def cluster_graph_node_key(node: object) -> object:
    """Return the runtime graph/vector key without leaking hostile text errors."""
    try:
        key = graph_vector_node_key(node)
    except RECOVERABLE_RUNTIME_ERRORS:
        key = None
    key_text = safe_cluster_text(key, default_text='')
    if key_text != '':
        return key_text
    return safe_cluster_text(node, default_text='')


def _empty_record(
    node_key: str,
    *,
    available: bool,
    present: bool,
    corrupt: bool,
    reason: str,
    empty: bool = False,
) -> ClusterGraphNodeRecord:
    return ClusterGraphNodeRecord(
        node_key=node_key,
        available=available,
        present=present,
        empty=empty,
        corrupt=corrupt,
        unavailable_reason=reason,
        risk=None,
        tags=(),
        edges=(),
        metadata=_EMPTY_METADATA,
    )


def _text_tuple(value: object, *, reason: str) -> tuple[tuple[str, ...], str]:
    values, unavailable_reason = cluster_text_sequence(value, reason=reason)
    return values, unavailable_reason or ''


def _risk(value: object) -> tuple[float | None, str]:
    if value is None:
        return None, ''
    if type(value) not in (int, float):
        return None, 'cluster_graph_risk_unavailable'
    number = value + 0.0
    if not math.isfinite(number):
        return None, 'cluster_graph_risk_non_finite'
    return number, ''


def _owned_string_mapping(value: object) -> tuple[dict[str, object] | None, str]:
    items = no_hook_mapping_items(value)
    if items is None:
        return None, 'cluster_graph_mapping_unavailable'
    out: dict[str, object] = {}
    first_reason = ''
    for index, (key, item) in enumerate(items):
        key_text, key_reason = no_hook_text(
            key,
            missing_reason='cluster_graph_mapping_key_missing',
            unsupported_reason='cluster_graph_mapping_key_unavailable',
        )
        if key_reason or key_text == '':
            if first_reason == '':
                first_reason = key_reason or 'cluster_graph_mapping_key_blank'
            key_text = str.__add__('cluster_graph_mapping_key_', int.__str__(index))
        if key_text in out:
            key_text = str.__add__(str.__add__(key_text, '#'), int.__str__(index))
        out[key_text] = item
    return out, first_reason


def cluster_graph_node_snapshot(node: object) -> ClusterGraphNodeRecord:
    """Return immutable clustering-facing graph evidence for one node."""
    node_key = cluster_graph_node_key(node)
    try:
        full_snapshot = graph_snapshot()
    except RECOVERABLE_RUNTIME_ERRORS:
        return _empty_record(node_key, available=False, present=False, corrupt=False, reason='graph_snapshot_unavailable')
    snapshot_data, snapshot_reason = _owned_string_mapping(full_snapshot)
    if snapshot_data is None or snapshot_reason:
        return _empty_record(node_key, available=False, present=False, corrupt=True, reason='graph_snapshot_corrupt')
    try:
        present = graph_has_node(node_key)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _empty_record(node_key, available=False, present=False, corrupt=False, reason='graph_node_presence_unavailable')
    if not present:
        return _empty_record(node_key, available=True, present=False, corrupt=False, reason='graph_node_missing')
    raw_snapshot_data = snapshot_data.get(node_key)
    raw_items = no_hook_mapping_items(raw_snapshot_data) if raw_snapshot_data is not None else None
    if raw_snapshot_data is not None and raw_items is None:
        return _empty_record(node_key, available=False, present=True, corrupt=True, reason='graph_node_snapshot_corrupt')
    if raw_items is not None and len(raw_items) == 0:
        return _empty_record(node_key, available=True, present=True, corrupt=False, reason='', empty=True)
    try:
        data = graph_node_snapshot(node_key)
    except RECOVERABLE_RUNTIME_ERRORS:
        return _empty_record(node_key, available=False, present=True, corrupt=False, reason='graph_node_snapshot_unavailable')
    if data is None:
        return _empty_record(node_key, available=True, present=False, corrupt=False, reason='graph_node_missing')
    materialized, materialized_reason = _owned_string_mapping(data)
    if materialized is None:
        return _empty_record(node_key, available=False, present=True, corrupt=True, reason='graph_node_snapshot_corrupt')
    risk, risk_reason = _risk(materialized.get('risk'))
    tags, tags_reason = _text_tuple(
        materialized.get('tags', ()),
        reason='cluster_graph_tags_unavailable',
    )
    edges, edges_reason = _text_tuple(
        materialized.get('edges', ()),
        reason='cluster_graph_edges_unavailable',
    )
    unavailable_reason = next(
        (reason for reason in (materialized_reason, risk_reason, tags_reason, edges_reason) if reason),
        '',
    )
    metadata = {
        key: value
        for key, value in dict.items(materialized)
        if key not in {'risk', 'tags', 'edges'}
    }
    return ClusterGraphNodeRecord(
        node_key=node_key,
        available=unavailable_reason == '',
        present=True,
        empty=len(materialized) == 0,
        corrupt=unavailable_reason != '',
        unavailable_reason=unavailable_reason,
        risk=risk,
        tags=tags,
        edges=edges,
        metadata=MappingProxyType(metadata),
    )


__all__ = ('ClusterGraphNodeRecord', 'cluster_graph_node_key', 'cluster_graph_node_snapshot')
