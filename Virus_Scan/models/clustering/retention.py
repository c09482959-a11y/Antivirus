"""Deterministic retention and compaction for canonical microcluster state."""
from __future__ import annotations

from Virus_Scan.runtime.config_values import runtime_value
from Virus_Scan.utils.probability import safe_clamp

from Virus_Scan.models.clustering.common import (
    cluster_int_limit,
    finite_cluster_metric,
    safe_cluster_text,
)
from Virus_Scan.models.clustering.mapping_boundaries import (
    cluster_mapping_items,
    cluster_mapping_keys,
    cluster_mapping_values,
)
from Virus_Scan.models.clustering.microcluster import (
    commit_microcluster_snapshot,
    microcluster_with_fields,
)
from Virus_Scan.models.clustering.microcluster_values import (
    microcluster_mapping,
    microcluster_value,
)
from Virus_Scan.models.clustering.policy import CLUSTER_POLICY
from Virus_Scan.models.clustering.state import (
    benign_clusters,
    cluster_graph_node_snapshot,
    cluster_lock,
    cluster_metadata,
    cluster_signatures,
    cluster_tag_signatures,
    malicious_clusters,
    mixed_clusters,
    node_cluster_map,
    node_feature_vectors,
)


def _all_cluster_ids() -> set[str]:
    ids: set[object] = set(cluster_metadata())
    ids.update(cluster_signatures())
    ids.update(cluster_tag_signatures())
    ids.update(malicious_clusters())
    ids.update(benign_clusters())
    ids.update(mixed_clusters())
    node_values, _reason = cluster_mapping_values(
        node_cluster_map(), reason="node_cluster_map_values_unavailable",
    )
    ids.update(node_values)
    return {
        text
        for raw in ids
        if (text := safe_cluster_text(raw, default_text="")) != ""
    }


def _drop_cluster(cluster_id: str) -> None:
    for store in (malicious_clusters(), benign_clusters(), mixed_clusters()):
        store.pop(cluster_id, None)
    cluster_signatures().pop(cluster_id, None)
    cluster_tag_signatures().pop(cluster_id, None)
    cluster_metadata().pop(cluster_id, None)
    node_items, _reason = cluster_mapping_items(
        node_cluster_map(), reason="node_cluster_map_items_unavailable",
    )
    for node, mapped_cluster in node_items:
        if safe_cluster_text(mapped_cluster, default_text="") == cluster_id:
            node_cluster_map().pop(node, None)
            node_feature_vectors().pop(node, None)


def _cluster_record_last_seen(node: object) -> float:
    record = cluster_graph_node_snapshot(node)
    if not record.available or not record.present or record.corrupt:
        return 0.0
    metadata = record.metadata
    value = metadata.get("last_seen", 0.0) if type(metadata) is dict else 0.0
    return finite_cluster_metric(value, 0.0)


def _retained_members(snapshot: object, member_limit: int) -> frozenset[str]:
    raw = microcluster_value(snapshot, "members", ())
    if type(raw) not in (tuple, list, set, frozenset):
        return frozenset()
    members = {
        text
        for item in raw
        if (text := safe_cluster_text(item, default_text="")) != ""
    }
    if member_limit <= 0 or len(members) <= member_limit:
        return frozenset(members)
    return frozenset(sorted(
        members,
        key=lambda node: (-_cluster_record_last_seen(node), node),
    )[:member_limit])


def _trim_cluster_members(cluster_id: str, member_limit: int) -> None:
    snapshot = cluster_metadata().get(cluster_id)
    if not microcluster_mapping(snapshot):
        _drop_cluster(cluster_id)
        return
    members = _retained_members(snapshot, member_limit)
    node_items, _reason = cluster_mapping_items(
        node_cluster_map(), reason="node_cluster_map_items_unavailable",
    )
    for node, mapped_cluster in node_items:
        if safe_cluster_text(mapped_cluster, default_text="") == cluster_id and node not in members:
            node_cluster_map().pop(node, None)
            node_feature_vectors().pop(node, None)
    try:
        commit_microcluster_snapshot(
            cluster_id,
            microcluster_with_fields(snapshot, members=members),
        )
    except ValueError:
        _drop_cluster(cluster_id)


def _rank_cluster_for_retention(cluster_id: str) -> tuple[float, int, float, str]:
    snapshot = cluster_metadata().get(cluster_id, {})
    confidence = safe_clamp(finite_cluster_metric(
        microcluster_value(snapshot, "confidence", 0.0), 0.0,
    ))
    malicious_ratio = safe_clamp(finite_cluster_metric(
        microcluster_value(snapshot, "malicious_ratio", 0.0), 0.0,
    ))
    trusted = cluster_int_limit(
        microcluster_value(snapshot, "trusted_sample_count", 0), 0,
    )
    updated = finite_cluster_metric(
        microcluster_value(snapshot, "updated_ordinal", 0), 0.0,
    )
    return confidence + malicious_ratio, trusted, updated, cluster_id


def _prune_cluster_count(cluster_limit: int) -> None:
    cluster_ids = {
        cluster_id
        for cluster_id in _all_cluster_ids()
        if microcluster_mapping(cluster_metadata().get(cluster_id))
    }
    if cluster_limit <= 0 or len(cluster_ids) <= cluster_limit:
        return
    keep = set(sorted(
        cluster_ids, key=_rank_cluster_for_retention, reverse=True,
    )[:cluster_limit])
    for cluster_id in sorted(cluster_ids - keep):
        _drop_cluster(cluster_id)


def _prune_node_cluster_map(node_limit: int) -> None:
    if node_limit <= 0 or len(node_cluster_map()) <= node_limit:
        return
    keys, _reason = cluster_mapping_keys(
        node_cluster_map(), reason="node_cluster_map_keys_unavailable",
    )
    ranked = sorted(
        (safe_cluster_text(key, default_text="") for key in keys),
        key=lambda node: (-_cluster_record_last_seen(node), node),
    )
    keep = {node for node in ranked[:node_limit] if node}
    for node in tuple(node_cluster_map()):
        if node not in keep:
            node_cluster_map().pop(node, None)
            node_feature_vectors().pop(node, None)
    metadata_items, _reason = cluster_mapping_items(
        cluster_metadata(), reason="cluster_metadata_items_unavailable",
    )
    for cluster_id, snapshot in metadata_items:
        members = frozenset(
            member for member in _retained_members(snapshot, 0) if member in keep
        )
        try:
            commit_microcluster_snapshot(
                cluster_id,
                microcluster_with_fields(snapshot, members=members),
            )
        except ValueError:
            _drop_cluster(safe_cluster_text(cluster_id, default_text=""))


def _rebuild_derived_indexes() -> None:
    malicious_clusters().clear()
    benign_clusters().clear()
    mixed_clusters().clear()
    cluster_signatures().clear()
    cluster_tag_signatures().clear()
    metadata_items, _reason = cluster_mapping_items(
        cluster_metadata(), reason="cluster_metadata_items_unavailable",
    )
    for cluster_id, snapshot in sorted(metadata_items):
        if not microcluster_mapping(snapshot):
            _drop_cluster(cluster_id)
            continue
        try:
            commit_microcluster_snapshot(cluster_id, snapshot)
        except ValueError:
            _drop_cluster(cluster_id)


def prune_cluster_state_for_retention(
    max_cluster_members: object = None,
    max_cluster_count: object = None,
    max_node_cluster_map: object = None,
) -> None:
    """Bound canonical state and deterministically rebuild all derived indexes."""
    member_limit = max(1, min(
        CLUSTER_POLICY.maximum_members,
        cluster_int_limit(
            max_cluster_members,
            runtime_value("MAX_CLUSTER_MEMBERS", CLUSTER_POLICY.maximum_members),
        ),
    ))
    cluster_limit = max(1, min(
        CLUSTER_POLICY.maximum_cluster_count,
        cluster_int_limit(
            max_cluster_count,
            runtime_value("MAX_CLUSTER_COUNT", CLUSTER_POLICY.maximum_cluster_count),
        ),
    ))
    node_limit = max(1, min(
        CLUSTER_POLICY.maximum_node_assignments,
        cluster_int_limit(
            max_node_cluster_map,
            runtime_value("MAX_NODE_CLUSTER_MAP", CLUSTER_POLICY.maximum_node_assignments),
        ),
    ))
    with cluster_lock():
        for cluster_id in sorted(_all_cluster_ids()):
            if cluster_id in cluster_metadata():
                _trim_cluster_members(cluster_id, member_limit)
            else:
                _drop_cluster(cluster_id)
        _prune_cluster_count(cluster_limit)
        _prune_node_cluster_map(node_limit)
        _rebuild_derived_indexes()


__all__ = ("prune_cluster_state_for_retention",)
