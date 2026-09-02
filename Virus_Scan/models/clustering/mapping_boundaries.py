"""Clustering-owned no-hook mapping and diagnostic boundary helpers."""
from __future__ import annotations

from Virus_Scan.models.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.models.clustering.common import cluster_mapping, safe_cluster_text


def cluster_mapping_items(value: object, *, reason: object='cluster_mapping_items_unavailable') -> object:
    mapping, mapping_reason = cluster_mapping(value, reason=reason)
    if mapping_reason is not None:
        return (), mapping_reason
    return tuple(dict.items(mapping)), None


def cluster_mapping_keys(value: object, *, reason: object='cluster_mapping_keys_unavailable') -> object:
    mapping, mapping_reason = cluster_mapping(value, reason=reason)
    if mapping_reason is not None:
        return (), mapping_reason
    return tuple(dict.keys(mapping)), None


def cluster_mapping_values(value: object, *, reason: object='cluster_mapping_values_unavailable') -> object:
    mapping, mapping_reason = cluster_mapping(value, reason=reason)
    if mapping_reason is not None:
        return (), mapping_reason
    return tuple(dict.values(mapping)), None


def cluster_mapping_get(value: object, key: object, default: object=None, *, reason: object='cluster_mapping_get_unavailable') -> object:
    mapping, mapping_reason = cluster_mapping(value, reason=reason)
    if mapping_reason is not None:
        return default
    return dict.get(mapping, key, default)


def cluster_reason_token(prefix: object, *parts: object) -> object:
    token = safe_cluster_text(prefix, default_text='cluster_reason')
    for part in parts:
        token = str.__add__(str.__add__(token, '_'), safe_cluster_text(part, default_text='unknown'))
    return token


def cluster_type_diagnostic(prefix: object, value: object) -> object:
    safe_prefix = safe_cluster_text(prefix, default_text='cluster_type_rejected')
    return str.__add__(str.__add__(safe_prefix, ':'), no_hook_type_name(value))


__all__ = (
    'cluster_mapping_get',
    'cluster_mapping_items',
    'cluster_mapping_keys',
    'cluster_mapping_values',
    'cluster_reason_token',
    'cluster_type_diagnostic',
)
