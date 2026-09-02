from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.utils.probability import safe_clamp

from Virus_Scan.models.clustering.common import cluster_finite_vector, cluster_text_set, finite_cluster_metric, safe_cluster_text
from Virus_Scan.models.clustering.tag_evidence import cluster_root_tag_projection
from Virus_Scan.models.clustering.metadata import cluster_members_for, cluster_meta_for
from Virus_Scan.models.clustering.feature_registry import ASSIGNMENT_FEATURE_COUNT
from Virus_Scan.models.clustering.microcluster_values import (
    finite_microcluster_vector,
    microcluster_value,
)
from Virus_Scan.models.clustering.risk import cluster_risk_score
from Virus_Scan.models.clustering.state import cluster_metadata, cluster_graph_node_key, cluster_node_key, cluster_signatures, cluster_tag_signatures, node_cluster_map, node_feature_vectors
from Virus_Scan.models.clustering.vectors import cosine_similarity

def adaptive_cluster_signal(node: object, tags: object) -> object:
    """Return bounded cluster evidence without hiding unavailable cluster state.

    The clustering model may be unavailable during cold start or before runtime
    ownership binds cluster state.  Those cases are legitimate zero-signal states,
    but they must remain explainable evidence instead of clean/default output.
    """
    try:
        node_key = cluster_graph_node_key(node)
        cid = safe_cluster_text(node_cluster_map().get(node_key), default_text='')
        if cid == '':
            return {
                'cluster_id': None,
                'cluster_signal': 0.0,
                'cluster_members': 0,
                'cluster_tag_overlap': 0.0,
                'cluster_signal_ready': False,
                'cluster_unavailable_reason': 'cluster_not_assigned',
            }
        meta = cluster_meta_for(cid)
        if microcluster_value(meta, 'influence_enabled', False) is not True:
            return {
                'cluster_id': cid,
                'cluster_signal': 0.0,
                'cluster_members': 0,
                'cluster_tag_overlap': 0.0,
                'cluster_signal_ready': False,
                'cluster_unavailable_reason': 'cluster_influence_not_enabled',
            }
        members = cluster_members_for(cid)
        member_count = len(members)
        ctags = cluster_text_set(cluster_tag_signatures().get(cid, set()), reason='cluster_tag_signature_unavailable')
        if len(ctags) == 0:
            ctags = cluster_text_set(microcluster_value(meta, 'tag_signature', ()), reason='cluster_tag_signature_unavailable')
        _tag_evidence, tag_values, tags_reason = cluster_root_tag_projection(tags)
        if tags_reason:
            return {
                'cluster_id': cid,
                'cluster_signal': 0.0,
                'cluster_members': member_count,
                'cluster_tag_overlap': 0.0,
                'cluster_signal_ready': False,
                'cluster_unavailable_reason': tags_reason,
            }
        tagset = set(tag_values)
        if len(tagset) > 0 or len(ctags) > 0:
            overlap = len(tagset & ctags) / max(1, len(tagset | ctags))
        else:
            overlap = 0.0
        member_ratio = finite_cluster_metric(member_count, 0.0) / 12.0
        maturity = safe_clamp(member_ratio)
        signal = safe_clamp(safe_clamp(overlap) * 0.65 + maturity * 0.35)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error('adaptive cluster signal failed: ' + no_hook_type_name(exc))
        return {
            'cluster_id': None,
            'cluster_signal': 0.0,
            'cluster_members': 0,
            'cluster_tag_overlap': 0.0,
            'cluster_signal_ready': False,
            'cluster_unavailable_reason': 'cluster_signal_failed',
            'cluster_error_type': no_hook_type_name(exc),
        }
    else:
        return {
            'cluster_id': cid,
            'cluster_signal': signal,
            'cluster_members': member_count,
            'cluster_tag_overlap': overlap,
            'cluster_signal_ready': True,
            'cluster_unavailable_reason': None,
        }


def _cluster_node_vector_snapshot(node: object) -> object:
    """Return a finite vector snapshot without caller-owned truthiness fallback."""
    vectors = node_feature_vectors()
    node_key = cluster_graph_node_key(node)
    missing = object()
    value = vectors.get(node_key, missing)
    if value is missing:
        value = vectors.get(node, missing)
    if value is missing:
        return ()
    return finite_microcluster_vector(value, ASSIGNMENT_FEATURE_COUNT)


def cluster_anomaly_boost_evidence(node: object) -> object:
    try:
        cid = node_cluster_map().get(cluster_node_key(node))
        cid_key = safe_cluster_text(cid)
        if cid_key == '':
            return {
                'cluster_anomaly_boost': 0.0,
                'cluster_anomaly_ready': False,
                'cluster_unavailable_reason': 'cluster_not_assigned',
            }
        centroid = finite_microcluster_vector(
            cluster_signatures().get(cid_key), ASSIGNMENT_FEATURE_COUNT,
        )
        vector = _cluster_node_vector_snapshot(node)
        if len(centroid) == 0 or len(vector) == 0:
            return {
                'cluster_anomaly_boost': 0.0,
                'cluster_anomaly_ready': False,
                'cluster_unavailable_reason': 'cluster_vector_unavailable',
                'cluster_id': cid_key,
            }
        meta = cluster_meta_for(cid_key)
        if microcluster_value(meta, 'influence_enabled', False) is not True:
            return {
                'cluster_anomaly_boost': 0.0,
                'cluster_anomaly_ready': False,
                'cluster_unavailable_reason': 'cluster_influence_not_enabled',
                'cluster_id': cid_key,
            }
        sim = cosine_similarity(vector, centroid)
        confidence = safe_clamp(finite_cluster_metric(microcluster_value(meta, 'confidence', 0.0), 0.0))
        anomaly_input = safe_clamp(1.0 - safe_clamp(sim)) * (0.5 + confidence * 0.5)
        return {
            'cluster_anomaly_boost': safe_clamp(anomaly_input),
            'cluster_anomaly_ready': True,
            'cluster_unavailable_reason': None,
            'cluster_id': cid_key,
        }
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        return {
            'cluster_anomaly_boost': 0.0,
            'cluster_anomaly_ready': False,
            'cluster_unavailable_reason': 'cluster_anomaly_boost_failed',
            'cluster_error_type': no_hook_type_name(exc),
        }


def cluster_anomaly_boost(node: object) -> object:
    evidence = cluster_anomaly_boost_evidence(node)
    return safe_clamp(dict.get(evidence, 'cluster_anomaly_boost', 0.0))


def cluster_detection_boost_evidence(node: object) -> object:
    """Small direct score evidence for consumers that want one cluster signal."""
    risk_value = safe_clamp(cluster_risk_score(node))
    anomaly_evidence = cluster_anomaly_boost_evidence(node)
    anomaly_value = safe_clamp(dict.get(anomaly_evidence, 'cluster_anomaly_boost', 0.0))
    detection_boost = safe_clamp(risk_value * 0.75 + anomaly_value * 0.25)
    return {
        'cluster_detection_boost': detection_boost,
        'cluster_detection_ready': dict.get(anomaly_evidence, 'cluster_anomaly_ready', False),
        'cluster_unavailable_reason': dict.get(anomaly_evidence, 'cluster_unavailable_reason', None),
    }


def cluster_detection_boost(node: object) -> object:
    """Small direct score helper for consumers that want one cluster signal."""
    evidence = cluster_detection_boost_evidence(node)
    return safe_clamp(dict.get(evidence, 'cluster_detection_boost', 0.0))
