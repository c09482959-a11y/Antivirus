import math

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.cluster_state import ClusterStateNotConfigured
from Virus_Scan.runtime.constants import GLOBAL_HALF_LIFE
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.utils.probability import safe_clamp

from Virus_Scan.models.clustering.common import (
    cluster_input_sequence,
    cluster_mapping,
    cluster_text_set,
    finite_cluster_metric,
    safe_cluster_text,
)
from Virus_Scan.models.clustering.metadata import cluster_members_for, cluster_meta_for
from Virus_Scan.models.clustering.microcluster_values import microcluster_value
from Virus_Scan.models.clustering.mapping_boundaries import (
    cluster_mapping_get,
)
from Virus_Scan.models.clustering.state import cluster_graph_node_snapshot, cluster_node_key, node_cluster_map

def _cluster_reference_time(meta: object, members: object) -> object:
    """Return a deterministic read-side reference time for cluster scoring.

    Cluster risk is consumed by adaptive scoring and final evidence paths. The
    model reader must not call a live wall clock because equivalent snapshots
    would then score differently during replay. Use the latest finite timestamp
    already present in runtime-owned graph/cluster state instead.
    """
    candidates = []
    safe_meta, meta_reason = cluster_mapping(meta, reason='cluster_meta_unavailable')
    if meta_reason is None:
        candidates.append(finite_cluster_metric(dict.get(safe_meta, 'last_updated', 0.0), 0.0))
        candidates.append(finite_cluster_metric(dict.get(safe_meta, 'updated', 0.0), 0.0))
    for member in cluster_input_sequence(members, reason='cluster_members_unavailable')[0]:
        record = cluster_graph_node_snapshot(member)
        if record.available and record.present and not record.corrupt:
            candidates.append(finite_cluster_metric(cluster_mapping_get(record.metadata, 'last_seen', 0.0, reason='cluster_graph_metadata_unavailable'), 0.0))
    return max(candidates) if len(candidates) > 0 else 0.0


def _cluster_member_last_seen(record: object, default_metric: object) -> object:
    if record.available and record.present and not record.corrupt and cluster_mapping_get(record.metadata, 'last_seen', None, reason='cluster_graph_metadata_unavailable') is not None:
        return finite_cluster_metric(cluster_mapping_get(record.metadata, 'last_seen', default_metric, reason='cluster_graph_metadata_unavailable'), default_metric)
    return default_metric


def cluster_risk_score_evidence(node: object) -> object:
    """Active cluster-risk evidence for graph/threat/Markov fusion."""
    try:
        cid = safe_cluster_text(cluster_mapping_get(node_cluster_map(), cluster_node_key(node), '', reason='node_cluster_map_unavailable'), default_text='')
        if cid == '':
            return {
                'risk': 0.0,
                'ready': False,
                'degraded': True,
                'unavailable_reason': 'cluster_not_assigned',
                'evidence_type': 'cluster_risk',
                'final_json_must_record': True,
                'replay_record_required': True,
            }
        members = cluster_members_for(cid)
        if len(members) < 2:
            return {
                'risk': 0.0,
                'ready': False,
                'degraded': True,
                'unavailable_reason': 'cluster_insufficient_members',
                'evidence_type': 'cluster_risk',
                'cluster_id': cid,
                'cluster_members': len(members),
                'final_json_must_record': True,
                'replay_record_required': True,
            }
        meta = cluster_meta_for(cid)
        if microcluster_value(meta, 'influence_enabled', False) is not True:
            return {
                'risk': 0.0,
                'ready': False,
                'degraded': True,
                'unavailable_reason': 'cluster_influence_not_enabled',
                'evidence_type': 'cluster_risk',
                'cluster_id': cid,
                'cluster_members': len(members),
                'final_json_must_record': True,
                'replay_record_required': True,
            }
        reference_time = _cluster_reference_time(meta, members)
        safe_meta, _meta_reason = cluster_mapping(meta, reason='cluster_meta_unavailable')
        default_last_seen = finite_cluster_metric(dict.get(safe_meta, 'last_updated', reference_time), reference_time)
        weighted_graph = 0.0
        total_weight = 0.0
        for m in members:
            record = cluster_graph_node_snapshot(m)
            last = _cluster_member_last_seen(record, default_last_seen)
            w = math.exp(-max(0.0, reference_time - last) / max(1.0, GLOBAL_HALF_LIFE))
            total_weight += w
            if record.available and record.present and not record.corrupt:
                edge_score = len(record.edges) / 20.0
                node_risk = finite_cluster_metric(record.risk, 0.0) / 100.0
                tag_risk = 0.0
                mtags = cluster_text_set(record.tags, reason='cluster_tags_unavailable')
                if mtags & {'pickle_dangerous_global', 'pickle_reduce_opcode', 'process_injection', 'credential_access', 'ransomware_behavior', 'network_exfiltration'}:
                    tag_risk = 0.35
                edge_component = safe_clamp(finite_cluster_metric(edge_score + node_risk + tag_risk, 0.0))
                weighted_graph += finite_cluster_metric(w, 0.0) * edge_component
        graph_component = safe_clamp(finite_cluster_metric(weighted_graph / max(1e-06, total_weight), 0.0))
        malicious_component = safe_clamp(finite_cluster_metric(dict.get(safe_meta, 'malicious_ratio', 0.0), 0.0))
        confidence = safe_clamp(finite_cluster_metric(dict.get(safe_meta, 'confidence', 0.0), 0.0))
        risk = safe_clamp(finite_cluster_metric(graph_component * 0.55 + malicious_component * 0.3 + confidence * 0.15, 0.0))
        return {
            'risk': risk,
            'ready': True,
            'degraded': False,
            'unavailable_reason': None,
            'evidence_type': 'cluster_risk',
            'cluster_id': cid,
            'cluster_members': len(members),
            'final_json_must_record': False,
            'replay_record_required': True,
        }
    except ClusterStateNotConfigured as _umige_cluster_state_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_cluster_state_exc, domain='runtime')
        except RECOVERABLE_RUNTIME_ERRORS as _umige_reporting_exc:
            _ = _umige_reporting_exc
        return {
            'risk': 0.0,
            'ready': False,
            'degraded': True,
            'unavailable_reason': 'runtime_cluster_state_not_configured',
            'evidence_type': 'cluster_risk',
            'final_json_must_record': True,
            'replay_record_required': True,
        }
    except RECOVERABLE_RUNTIME_ERRORS as _umige_suppressed_exc:
        try:
            record_suppressed_failure('suppressed_exception', _umige_suppressed_exc, domain='runtime')
        except RECOVERABLE_RUNTIME_ERRORS as _umige_reporting_exc:
            _ = _umige_reporting_exc
        return {
            'risk': 0.0,
            'ready': False,
            'degraded': True,
            'unavailable_reason': 'cluster_risk_computation_failed',
            'evidence_type': 'cluster_risk',
            'final_json_must_record': True,
            'replay_record_required': True,
        }


def cluster_risk_score(node: object) -> object:
    """Active cluster detection signal for graph/threat/Markov fusion."""
    return finite_cluster_metric(cluster_mapping_get(cluster_risk_score_evidence(node), 'risk', 0.0, reason='cluster_risk_evidence_unavailable'), 0.0)
