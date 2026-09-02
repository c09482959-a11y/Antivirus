from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.runtime.structured_failures import record_suppressed_failure

from Virus_Scan.models.clustering.common import cluster_int_limit, safe_cluster_text
from Virus_Scan.models.clustering.mapping_boundaries import (
    cluster_mapping_keys,
    cluster_type_diagnostic,
)
from Virus_Scan.models.clustering.state import (
    cluster_graph_node_key,
    node_cluster_map,
    node_feature_vectors,
)
from Virus_Scan.models.clustering.policy import CLUSTER_POLICY
from Virus_Scan.models.clustering.feature_registry import ASSIGNMENT_FEATURE_COUNT
from Virus_Scan.models.clustering.microcluster_values import finite_microcluster_vector

def _empty_cluster_vector_failure() -> object:
    return list()


def _log_cluster_storage_failure(reason: object, error: object) -> None:
    log_error(cluster_type_diagnostic(reason, error))


def prune_node_feature_vectors(max_items: object=None) -> None:
    """Keep the node/vector DB bounded and aligned with live cluster mappings."""
    try:
        max_items = max(1, min(
            CLUSTER_POLICY.maximum_node_assignments,
            cluster_int_limit(max_items, CLUSTER_POLICY.maximum_node_assignments),
        ))
        live_node_keys, _live_reason = cluster_mapping_keys(node_cluster_map(), reason='node_cluster_map_unavailable')
        live_nodes = {safe_cluster_text(k, default_text='') for k in live_node_keys}
        if live_nodes:
            vector_keys, _vector_reason = cluster_mapping_keys(node_feature_vectors(), reason='node_feature_vectors_unavailable')
            for key in vector_keys:
                if safe_cluster_text(key, default_text='') not in live_nodes:
                    dict.pop(node_feature_vectors(), key, None)
        overflow = len(node_feature_vectors()) - max_items
        if overflow > 0:
            # Deterministic retention: when no live cluster mapping supplies a
            # recency/risk rank, prune by canonical node key instead of mutable
            # insertion order so replay/randomized input order produces the same
            # retained vector set.
            vector_keys, _vector_reason = cluster_mapping_keys(node_feature_vectors(), reason='node_feature_vectors_unavailable')
            for key in sorted((safe_cluster_text(key, default_text='') for key in vector_keys))[max_items:]:
                dict.pop(node_feature_vectors(), key, None)
    except RECOVERABLE_RUNTIME_ERRORS as e:
        try:
            _log_cluster_storage_failure('node_feature_vector_prune_failed', e)
        except RECOVERABLE_RUNTIME_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except RECOVERABLE_RUNTIME_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc
            finally:
                pass
        finally:
            pass
    finally:
        pass


def store_node_vector(node: object, vector: object) -> object:
    """Canonical in-memory vector DB write used by clustering/context scoring.

    Side-effect contract:
    - stores only an already-built feature vector;
    - never calls scoring, clustering, graph, Markov, temporal, or learning;
    - bounds vector dimensions and total retained vectors;
    - uses one canonical string key so lookups cannot split across aliases.
    """
    key = cluster_graph_node_key(node)
    if key == '':
        return _empty_cluster_vector_failure()
    try:
        clean = finite_microcluster_vector(vector, ASSIGNMENT_FEATURE_COUNT)
        if not clean:
            return _empty_cluster_vector_failure()
        node_feature_vectors()[key] = list(clean)
        if len(node_feature_vectors()) > CLUSTER_POLICY.maximum_node_assignments:
            prune_node_feature_vectors()
        return list(clean)
    except RECOVERABLE_RUNTIME_ERRORS as e:
        try:
            _log_cluster_storage_failure('store_node_vector_failed', e)
        except RECOVERABLE_RUNTIME_ERRORS as _umige_suppressed_exc:
            try:
                record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
            except RECOVERABLE_RUNTIME_ERRORS as _umige_reporting_exc:
                _ = _umige_reporting_exc
            finally:
                pass
        finally:
            pass
        return _empty_cluster_vector_failure()
    finally:
        pass
