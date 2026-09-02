from __future__ import annotations

from Virus_Scan.runtime.cache_state import (
    runtime_cache_by_name,
    runtime_cache_get,
    runtime_cache_set,
)
from Virus_Scan.runtime.graph_state import graph_node_snapshot
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.models.graph.common import safe_graph_text_with_reason
from Virus_Scan.models.graph.contracts import (
    GRAPH_ATTENTION_CONTRACT_VERSION,
    GRAPH_CHAIN_CONTRACT_VERSION,
    GRAPH_CONTEXT_BASELINE_VERSION,
    GRAPH_EXECUTION_CONTRACT_VERSION,
    GRAPH_RISK_MODEL_VERSION,
    GRAPH_RISK_POLICY_VERSION,
    GRAPH_TEMPORAL_CONTRACT_VERSION,
)

GRAPH_RISK_CACHE = runtime_cache_by_name('GRAPH_RISK_CACHE')

GRAPH_CACHE_KEY_NAMESPACE_REJECTED = 'graph_cache_namespace_rejected'
GRAPH_CACHE_KEY_PART_REJECTED = 'graph_cache_key_part_rejected'


def _cache_key_text(value: object, reason: object) -> str:
    text, text_reason = safe_graph_text_with_reason(value, reason)
    if text_reason:
        return str(reason)
    return text


def _mapping_get(value: object, name: str, default: object = None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for key, item in items:
        if isinstance(key, str) and str.__str__(key) == name:
            return item
    return default


def _graph_risk_cache_key(node: object) -> str:
    node_text = _cache_key_text(node, GRAPH_CACHE_KEY_PART_REJECTED)
    snapshot = graph_node_snapshot(node)
    snapshot_version = _cache_key_text(
        _mapping_get(snapshot, 'snapshot_version', 'graph_snapshot_unavailable'),
        GRAPH_CACHE_KEY_PART_REJECTED,
    )
    snapshot_digest = _cache_key_text(
        _mapping_get(snapshot, 'snapshot_digest', 'graph_snapshot_digest_unavailable'),
        GRAPH_CACHE_KEY_PART_REJECTED,
    )
    parts = (
        snapshot_version,
        snapshot_digest,
        GRAPH_RISK_MODEL_VERSION,
        GRAPH_RISK_POLICY_VERSION,
        GRAPH_CONTEXT_BASELINE_VERSION,
        GRAPH_ATTENTION_CONTRACT_VERSION,
        GRAPH_EXECUTION_CONTRACT_VERSION,
        GRAPH_TEMPORAL_CONTRACT_VERSION,
        GRAPH_CHAIN_CONTRACT_VERSION,
        node_text,
    )
    return 'graph_risk_enhanced:' + ':'.join(parts)


def cache_key(namespace: object, *parts: object) -> str:
    namespace_text = _cache_key_text(namespace, GRAPH_CACHE_KEY_NAMESPACE_REJECTED)
    if namespace_text == 'graph_risk_enhanced' and len(parts) == 1:
        return _graph_risk_cache_key(parts[0])
    part_texts = tuple(_cache_key_text(part, GRAPH_CACHE_KEY_PART_REJECTED) for part in parts)
    return namespace_text + ':' + ':'.join(part_texts)


def cache_get(cache: object, key: object, ttl: object = None) -> object:
    return runtime_cache_get(cache, key, ttl=ttl)


def cache_set(cache: object, key: object, value: object) -> object:
    return runtime_cache_set(cache, key, value)


__all__ = ('cache_get', 'cache_key', 'cache_set')
