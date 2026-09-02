"""Strict one-schema clustering persistence hydration."""
from __future__ import annotations

import math

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.cluster_state import CLUSTER_STATE_SCHEMA_VERSION
from Virus_Scan.runtime.runtime_flags import runtime_flag_clear

from Virus_Scan.models.clustering.common import safe_cluster_text
from Virus_Scan.models.clustering.feature_registry import ASSIGNMENT_FEATURE_COUNT
from Virus_Scan.models.clustering.mapping_boundaries import cluster_mapping_items
from Virus_Scan.models.clustering.load_decision import (
    cluster_snapshot_load_failure,
    cluster_snapshot_load_rejected,
)
from Virus_Scan.models.clustering.microcluster import commit_microcluster_snapshot
from Virus_Scan.models.clustering.microcluster_record import microcluster_from_record
from Virus_Scan.models.clustering.microcluster_values import microcluster_value
from Virus_Scan.models.clustering.policy import CLUSTER_POLICY
from Virus_Scan.models.clustering.snapshot_learning_keys import cluster_snapshot_learning_keys
from Virus_Scan.models.clustering.state import (
    benign_clusters,
    cluster_applied_learning_keys,
    cluster_lock,
    cluster_metadata,
    cluster_signatures,
    cluster_tag_signatures,
    malicious_clusters,
    mixed_clusters,
    node_cluster_map,
    node_feature_vectors,
)

def _cluster_snapshot_identity(value: object) -> str:
    """Detach an owned snapshot identity without caller hooks."""
    return safe_cluster_text(value, default_text="")


def _exact_nonempty_text(value: object, reason: str) -> str:
    if type(value) is not str:
        raise ValueError(reason)
    text = str.strip(value)
    if text == "":
        raise ValueError(reason)
    return text


def _strict_assignment_vector(value: object, reason: str) -> tuple[float, ...]:
    if type(value) not in (tuple, list) or len(value) != ASSIGNMENT_FEATURE_COUNT:
        raise ValueError(reason)
    out: list[float] = []
    for item in value:
        if type(item) not in (int, float) or isinstance(item, bool):
            raise ValueError(reason)
        number = float(item)
        if not math.isfinite(number):
            raise ValueError(reason)
        out.append(number)
    return tuple(out)


def _snapshot_sections(value: object) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, int]]:
    if type(value) is not dict:
        raise ValueError("cluster_state_not_object")
    if value.get("schema") != CLUSTER_STATE_SCHEMA_VERSION:
        raise ValueError("cluster_state_schema_version_mismatch")
    allowed = {
        "schema", "microclusters", "node_cluster_map", "node_feature_vectors",
        "applied_learning_keys",
    }
    if not set(value) <= allowed:
        raise ValueError("cluster_state_unknown_section")
    microclusters = value.get("microclusters")
    node_map = value.get("node_cluster_map")
    node_vectors = value.get("node_feature_vectors")
    if type(microclusters) is not dict:
        raise ValueError("cluster_microclusters_not_object")
    if type(node_map) is not dict:
        raise ValueError("cluster_node_map_not_object")
    if type(node_vectors) is not dict:
        raise ValueError("cluster_node_vectors_not_object")
    applied, reason = cluster_snapshot_learning_keys(value.get("applied_learning_keys"))
    if reason:
        raise ValueError(reason)
    return microclusters, node_map, node_vectors, applied


def _stage_snapshot(value: object) -> tuple[
    dict[str, object], dict[str, str], dict[str, list[float]], dict[str, int]
]:
    microclusters, raw_node_map, raw_node_vectors, applied = _snapshot_sections(value)
    if len(microclusters) > CLUSTER_POLICY.maximum_cluster_count:
        raise ValueError("cluster_count_limit_exceeded")
    if (
        len(raw_node_map) > CLUSTER_POLICY.maximum_node_assignments
        or len(raw_node_vectors) > CLUSTER_POLICY.maximum_node_assignments
    ):
        raise ValueError("cluster_node_limit_exceeded")
    staged_clusters: dict[str, object] = {}
    microcluster_items, item_reason = cluster_mapping_items(
        microclusters, reason="cluster_microclusters_items_unavailable",
    )
    if item_reason is not None:
        raise ValueError(item_reason)
    for raw_cluster_id, raw_record in sorted(microcluster_items):
        cluster_id = _exact_nonempty_text(raw_cluster_id, "cluster_id_invalid")
        staged_clusters[cluster_id] = microcluster_from_record(raw_record, cluster_id)
    staged_node_map: dict[str, str] = {}
    node_map_items, item_reason = cluster_mapping_items(
        raw_node_map, reason="cluster_node_map_items_unavailable",
    )
    if item_reason is not None:
        raise ValueError(item_reason)
    for raw_node, raw_cluster_id in sorted(node_map_items):
        node = _exact_nonempty_text(raw_node, "cluster_node_id_invalid")
        cluster_id = _exact_nonempty_text(raw_cluster_id, "cluster_node_cluster_id_invalid")
        if cluster_id not in staged_clusters:
            raise ValueError("cluster_node_references_missing_cluster")
        if node in staged_node_map:
            raise ValueError("cluster_node_duplicate")
        staged_node_map[node] = cluster_id
    staged_vectors: dict[str, list[float]] = {}
    node_vector_items, item_reason = cluster_mapping_items(
        raw_node_vectors, reason="cluster_node_vector_items_unavailable",
    )
    if item_reason is not None:
        raise ValueError(item_reason)
    for raw_node, raw_vector in sorted(node_vector_items):
        node = _exact_nonempty_text(raw_node, "cluster_vector_node_id_invalid")
        if node not in staged_node_map:
            raise ValueError("cluster_vector_without_assignment")
        staged_vectors[node] = list(_strict_assignment_vector(
            raw_vector, "cluster_node_vector_invalid",
        ))
    for cluster_id, snapshot in dict.items(staged_clusters):
        members = microcluster_value(snapshot, "members", frozenset())
        member_set = set(members) if type(members) is frozenset else set()
        mapped_members = {
            node for node, mapped_cluster in dict.items(staged_node_map)
            if mapped_cluster == cluster_id
        }
        if member_set != mapped_members:
            raise ValueError("cluster_member_index_mismatch")
        centroid = tuple(microcluster_value(snapshot, "centroid_vector", ()))
        if len(centroid) != ASSIGNMENT_FEATURE_COUNT:
            raise ValueError("cluster_centroid_dimension_mismatch")
    return staged_clusters, staged_node_map, staged_vectors, applied


def _commit_runtime_model_record(value: object) -> bool:
    staged_clusters, staged_node_map, staged_vectors, applied = _stage_snapshot(value)
    with cluster_lock():
        cluster_metadata().clear()
        cluster_signatures().clear()
        cluster_tag_signatures().clear()
        malicious_clusters().clear()
        benign_clusters().clear()
        mixed_clusters().clear()
        node_cluster_map().clear()
        node_feature_vectors().clear()
        cluster_applied_learning_keys().clear()
        for cluster_id, snapshot in sorted(dict.items(staged_clusters)):
            commit_microcluster_snapshot(cluster_id, snapshot)
        node_cluster_map().update(staged_node_map)
        node_feature_vectors().update(staged_vectors)
        cluster_applied_learning_keys().update(applied)
    runtime_flag_clear("runtime_model_state_dirty")
    return True


def load_runtime_model_record(value: object) -> bool:
    """Hydrate clustering from the current validated in-memory record."""
    try:
        return _commit_runtime_model_record(value)
    except (ValueError, TypeError, KeyError) as error:
        return cluster_snapshot_load_rejected(
            safe_cluster_text(error, default_text="cluster_snapshot_invalid")
        )
    except RECOVERABLE_RUNTIME_ERRORS as error:
        return cluster_snapshot_load_failure(error)



__all__ = ("load_runtime_model_record",)
