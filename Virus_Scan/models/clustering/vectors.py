import math

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.runtime.config_values import runtime_value
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.utils.entropy import tag_entropy
from Virus_Scan.utils.probability import safe_clamp

from Virus_Scan.models.clustering.common import (
    cluster_finite_vector,
    cluster_input_sequence,
    cluster_int_limit,
    cluster_mapping,
    cluster_text_set,
    dominant_engine_context,
    finite_cluster_metric,
    safe_cluster_text,
)
from Virus_Scan.models.clustering.tag_evidence import (
    cluster_root_tag_records,
    cluster_tag_vector_projection,
)
from Virus_Scan.models.clustering.mapping_boundaries import cluster_mapping_get
from Virus_Scan.models.clustering.feature_registry import CLUSTER_FEATURE_REGISTRY
from Virus_Scan.models.clustering.microcluster_values import microcluster_value
from Virus_Scan.models.clustering.state import (
    benign_clusters,
    cluster_graph_node_key,
    cluster_metadata,
    malicious_clusters,
    mixed_clusters,
    node_cluster_map,
)

def _empty_cluster_score_failure(reason: object, error: object=None) -> object:
    if error is not None:
        record_suppressed_failure(reason, error, domain='model')
    return float()


def _cluster_unit_ratio(numerator: object, denominator: object) -> object:
    safe_denominator = finite_cluster_metric(denominator, 0.0)
    if safe_denominator <= 0.0:
        return float()
    return safe_clamp(finite_cluster_metric(numerator, 0.0) / safe_denominator)


def vector_cluster_members_for(cid: object) -> object:
    members = set()
    for store in (malicious_clusters(), benign_clusters(), mixed_clusters()):
        members.update(cluster_text_set(dict.get(store, cid, set()), reason='cluster_members_unavailable'))
    meta = cluster_metadata().get(cid, {})
    members.update(cluster_text_set(
        microcluster_value(meta, 'members', ()), reason='cluster_members_unavailable',
    ))
    return {member for member in members if member}


def cosine_similarity(v1: object, v2: object, node: object=None) -> object:
    """Cluster-owned cosine similarity for feature vectors."""
    del node  # Explicitly unused contract parameters.
    try:
        left, left_reason = cluster_input_sequence(
            v1, reason='cluster_cosine_left_unavailable',
        )
        right, right_reason = cluster_input_sequence(
            v2, reason='cluster_cosine_right_unavailable',
        )
        if left_reason is not None or right_reason is not None or not left or len(left) != len(right):
            return _empty_cluster_score_failure('cluster_cosine_similarity_empty')
        if any(
            type(item) not in (int, float)
            or isinstance(item, bool)
            or not math.isfinite(float(item))
            for item in (*left, *right)
        ):
            return _empty_cluster_score_failure('cluster_cosine_similarity_invalid')
        a = tuple(float(item) for item in left)
        b = tuple(float(item) for item in right)
        dot = sum(x * y for x, y in zip(a, b, strict=False))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na <= 0.0 or nb <= 0.0:
            return _empty_cluster_score_failure('cluster_cosine_similarity_zero_norm')
        return _cluster_unit_ratio(dot, na * nb)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        return _empty_cluster_score_failure('cluster_cosine_similarity_failed', exc)


def sanitize_feature_vector(vector: object, max_dims: object=None) -> list[float]:
    """Convert arbitrary feature vectors into finite bounded float lists.

    The vector DB must be pure storage.  This helper intentionally performs no
    scoring, clustering, graph, temporal, Markov, or learning calls.
    """
    return list(cluster_finite_vector(vector, max_dims=cluster_int_limit(max_dims, 128)))


def json_cluster_prior(tags: object, engine: object) -> object:
    del engine  # Explicitly unused contract parameters.
    _bundle, records, reason = cluster_root_tag_records(tags)
    if reason is not None:
        return _empty_cluster_score_failure(reason)
    if not records:
        return _empty_cluster_score_failure('cluster_tag_input_empty')
    high = set(runtime_value('HIGH_RISK_BUCKETS', set()))
    risky = sum(1 for record in records if record.behavior_bucket in high)
    return _cluster_unit_ratio(float(risky), float(len(records)))


def build_feature_vector(node: object, tags: object, graph_features: object, temporal_features: object, markov_features: object, engine_context: object) -> object:
    """Build the clustering-owned feature vector from finite model evidence only.

    Graph, temporal, Markov, and engine context values can arrive from replayed
    or corrupted snapshots.  The vector is persisted in runtime cluster state and
    later materialized into JSON/replay evidence, so non-finite or non-numeric
    upstream model values must be treated as unavailable numeric input instead
    of leaking ``NaN``/``Infinity`` into clustering evidence or crashing vector
    projection.
    """
    node_key = cluster_graph_node_key(node)
    if type(tags) is TagEvidence:
        tag_input = tags
        raw_observation_count = finite_cluster_metric(
            tags.summary.get('raw_observation_count', 0), 0.0,
        )
    else:
        tag_input, raw_tag_reason = cluster_input_sequence(
            tags, reason='cluster_tag_input_unavailable',
        )
        raw_observation_count = float(len(tag_input)) if raw_tag_reason is None else 0.0
    tag_evidence, root_tags, root_count, correlation_group_count, tags_reason = (
        cluster_tag_vector_projection(tag_input)
    )
    tags = list(root_tags if not tags_reason else ())
    graph_features, _ = cluster_mapping(graph_features)
    temporal_features, _ = cluster_mapping(temporal_features)
    markov_features, _ = cluster_mapping(markov_features)
    engine_context, _ = cluster_mapping(engine_context)
    cid = cluster_mapping_get(node_cluster_map(), node_key, None, reason='node_cluster_map_unavailable')
    cid_text = safe_cluster_text(cid, default_text='')
    cluster_size = len(vector_cluster_members_for(cid_text)) if cid_text != '' else 0
    engine = dominant_engine_context(engine_context, default='other', allow_other=True)
    cluster_risk = json_cluster_prior(tag_evidence, engine)
    cluster_anomaly = 0.0
    values_by_feature = {
        'tag_count': float(raw_observation_count if not tags_reason else 0.0),
        'tag_entropy': finite_cluster_metric(tag_entropy(tags)),
        'unique_tag_count': float(len(root_tags) if not tags_reason else 0),
        'graph_risk': finite_cluster_metric(cluster_mapping_get(graph_features, 'risk', 0.0, reason='cluster_graph_features_unavailable')),
        'graph_anomaly': finite_cluster_metric(cluster_mapping_get(graph_features, 'anomaly', 0.0, reason='cluster_graph_features_unavailable')),
        'temporal_belief': finite_cluster_metric(cluster_mapping_get(temporal_features, 'belief', 0.0, reason='cluster_temporal_features_unavailable')),
        'markov_transition': finite_cluster_metric(cluster_mapping_get(markov_features, 'transition', 0.0, reason='cluster_markov_features_unavailable')),
        'markov_rarity': finite_cluster_metric(cluster_mapping_get(markov_features, 'rarity', 0.0, reason='cluster_markov_features_unavailable')),
        'markov_pair_anomaly': finite_cluster_metric(cluster_mapping_get(markov_features, 'pair_anomaly', 0.0, reason='cluster_markov_features_unavailable')),
        'unity_context': finite_cluster_metric(cluster_mapping_get(engine_context, 'unity', 0.0, reason='cluster_engine_context_unavailable')),
        'renpy_context': finite_cluster_metric(cluster_mapping_get(engine_context, 'renpy', 0.0, reason='cluster_engine_context_unavailable')),
        'rpgm_context': finite_cluster_metric(cluster_mapping_get(engine_context, 'rpgm', 0.0, reason='cluster_engine_context_unavailable')),
        'media_context': finite_cluster_metric(cluster_mapping_get(engine_context, 'media', 0.0, reason='cluster_engine_context_unavailable')),
        'other_context': finite_cluster_metric(cluster_mapping_get(engine_context, 'other', cluster_mapping_get(engine_context, 'unknown', 0.0, reason='cluster_engine_context_unavailable'), reason='cluster_engine_context_unavailable')),
        'cluster_size': finite_cluster_metric(float(cluster_size) / 20.0),
        'cluster_risk': finite_cluster_metric(cluster_risk),
        'cluster_anomaly': finite_cluster_metric(cluster_anomaly),
    }
    return [float(values_by_feature[spec.feature_id]) for spec in CLUSTER_FEATURE_REGISTRY]


__all__ = (
    'build_feature_vector',
    'cosine_similarity',
    'json_cluster_prior',
    'sanitize_feature_vector',
    'vector_cluster_members_for',
)
