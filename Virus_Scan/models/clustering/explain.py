from Virus_Scan.utils.probability import safe_clamp

from Virus_Scan.models.clustering.common import cluster_text_set, finite_cluster_metric, safe_cluster_text
from Virus_Scan.models.clustering.metadata import cluster_decay, cluster_members_for, cluster_meta_for
from Virus_Scan.models.clustering.microcluster_values import microcluster_value
from Virus_Scan.models.clustering.state import cluster_node_key, cluster_signatures, node_cluster_map
from Virus_Scan.models.clustering.vectors import sanitize_feature_vector

def explain_cluster(node: object) -> object:
    cid = safe_cluster_text(node_cluster_map().get(cluster_node_key(node)), default_text='')
    if cid == '':
        return {'cluster': None, 'reason': 'unclassified'}
    meta = cluster_meta_for(cid)
    confidence = safe_clamp(finite_cluster_metric(microcluster_value(meta, 'confidence', 0.0), 0.0))
    malicious_ratio = safe_clamp(finite_cluster_metric(microcluster_value(meta, 'malicious_ratio', 0.0), 0.0))
    return {
        'cluster': cid,
        'kind': safe_cluster_text(microcluster_value(meta, 'kind', 'mixed'), default_text='mixed'),
        'size': len(cluster_members_for(cid)),
        'confidence': confidence,
        'malicious_ratio': malicious_ratio,
        'decay': cluster_decay(meta),
        'chains': tuple(sorted(cluster_text_set(microcluster_value(meta, 'chain_signature', ()), reason='cluster_chain_signature_unavailable'))[:20]),
        'tags': tuple(sorted(cluster_text_set(microcluster_value(meta, 'tag_signature', ()), reason='cluster_tag_signature_unavailable'))[:30]),
        'sample_nodes': tuple(sorted(cluster_members_for(cid))[:10]),
        'centroid': tuple(sanitize_feature_vector(microcluster_value(meta, 'centroid_vector', ()))),
        'feature_schema_version': microcluster_value(meta, 'feature_schema_version', ''),
        'normalization_version': microcluster_value(meta, 'normalization_version', ''),
        'influence_enabled': microcluster_value(meta, 'influence_enabled', False) is True,
        'drift_alarm': microcluster_value(meta, 'drift_alarm', False) is True,
    }
