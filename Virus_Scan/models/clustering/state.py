from Virus_Scan.runtime.cluster_state import cluster_state
from Virus_Scan.runtime.graph_state import graph_vector_node_key
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.clustering.common import safe_cluster_text
from Virus_Scan.models.clustering.graph_context import (
    ClusterGraphNodeRecord,
    cluster_graph_node_snapshot,
)


def node_cluster_map() -> object:
    return cluster_state().node_cluster_map


def malicious_clusters() -> object:
    return cluster_state().malicious_clusters


def benign_clusters() -> object:
    return cluster_state().benign_clusters


def mixed_clusters() -> object:
    return cluster_state().mixed_clusters


def cluster_metadata() -> object:
    return cluster_state().cluster_metadata


def cluster_signatures() -> object:
    return cluster_state().cluster_signatures


def node_feature_vectors() -> object:
    return cluster_state().node_feature_vectors


def cluster_tag_signatures() -> object:
    return cluster_state().cluster_tag_signatures


def cluster_lock() -> object:
    return cluster_state().lock


def cluster_applied_learning_keys() -> object:
    return cluster_state().applied_learning_keys


def cluster_graph_node_key(node: object) -> object:
    """Return the clustering read-side graph/vector key without text leaks."""
    try:
        key = graph_vector_node_key(node)
    except RECOVERABLE_RUNTIME_ERRORS:
        key = None
    key_text = safe_cluster_text(key, default_text='')
    if key_text != '':
        return key_text
    return safe_cluster_text(node, default_text='')


def cluster_node_key(node: object) -> object:
    """Return the canonical runtime cluster/vector lookup key.

    Cluster assignment and vector storage already write through
    ``graph_vector_node_key``. All read-side cluster APIs must use the same key
    so adaptive scoring, explanations, and replay evidence do not split across
    raw caller aliases such as padded path strings.
    """
    return cluster_graph_node_key(node)


__all__ = (
    'ClusterGraphNodeRecord',
    'benign_clusters',
    'cluster_applied_learning_keys',
    'cluster_graph_node_key',
    'cluster_graph_node_snapshot',
    'cluster_lock',
    'cluster_metadata',
    'cluster_node_key',
    'cluster_signatures',
    'cluster_tag_signatures',
    'malicious_clusters',
    'mixed_clusters',
    'node_cluster_map',
    'node_feature_vectors',
)
