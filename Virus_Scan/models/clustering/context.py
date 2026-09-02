from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.utils.probability import safe_clamp

from Virus_Scan.models.clustering.common import (
    MIN_CLUSTER_MEMBERS_FOR_CONTEXT,
    MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT,
    cluster_int_limit,
    cluster_mapping,
    cluster_text_set,
    cluster_context_float,
    finite_cluster_metric,
    safe_cluster_text,
)
from Virus_Scan.models.clustering.tag_evidence import cluster_root_tag_projection
from Virus_Scan.models.clustering.evidence import cluster_signal_unavailable_reason
from Virus_Scan.models.clustering.metadata import cluster_members_for
from Virus_Scan.models.clustering.microcluster_values import microcluster_value
from Virus_Scan.models.clustering.state import cluster_metadata, cluster_node_key, cluster_tag_signatures, node_cluster_map


def _cluster_quality_unavailable(*, reason: object, cluster_id: object = None, members: object = 0, error_type: object | None = None) -> dict[str, object]:
    record: dict[str, object] = {
        'cluster_id': cluster_id,
        'cluster_members': members,
        'cluster_tag_overlap': 0.0,
        'cluster_quality': 0.0,
        'eligible': False,
        'reason': reason,
        'unavailable_reason': reason,
    }
    if error_type is not None:
        record['cluster_error_type'] = error_type
    return record

def context_cluster_quality(node: object, tags: object, adaptive_learning: object=None) -> object:
    """
    Build a bounded vector/cluster quality signal from existing cluster state.

    Returns a quality value in 0..1 plus explainable metadata. This does not
    assign clusters; it only reads the cluster already created elsewhere.
    """
    try:
        adaptive_learning, learning_reason = cluster_mapping(
            adaptive_learning,
            reason='cluster_adaptive_learning_unavailable',
        )
        if learning_reason:
            return _cluster_quality_unavailable(reason=learning_reason)
        cluster_meta, meta_reason = cluster_mapping(
            adaptive_learning.get('cluster'),
            reason='cluster_adaptive_meta_unavailable',
        )
        if meta_reason:
            return _cluster_quality_unavailable(reason=meta_reason)
        cluster_unavailable_reason = cluster_signal_unavailable_reason(cluster_meta)
        if cluster_unavailable_reason:
            return _cluster_quality_unavailable(reason=cluster_unavailable_reason)
        cid = safe_cluster_text(cluster_meta.get('cluster_id'), default_text='')
        if cid == '':
            cid = safe_cluster_text(node_cluster_map().get(cluster_node_key(node)), default_text='')
        if cid == '':
            return {'cluster_id': None, 'cluster_members': 0, 'cluster_tag_overlap': 0.0, 'cluster_quality': 0.0, 'eligible': False, 'reason': 'no_cluster'}
        members = cluster_members_for(cid)
        canonical_meta = cluster_metadata().get(cid, {})
        if microcluster_value(canonical_meta, 'influence_enabled', False) is not True:
            return _cluster_quality_unavailable(
                reason='cluster_influence_not_enabled', cluster_id=cid, members=len(members),
            )
        member_count = cluster_int_limit(cluster_meta.get('cluster_members'), len(members))
        ctags = cluster_text_set(cluster_tag_signatures().get(cid, set()), reason='cluster_tag_signature_unavailable')
        if len(ctags) == 0:
            meta = cluster_metadata().get(cid, {})
            ctags = cluster_text_set(microcluster_value(meta, 'tag_signature', ()), reason='cluster_tag_signature_unavailable')
        _tag_evidence, tag_values, tags_reason = cluster_root_tag_projection(tags)
        if tags_reason:
            return _cluster_quality_unavailable(reason=tags_reason, cluster_id=cid, members=member_count)
        tagset = set(tag_values)
        if len(tagset) > 0 or len(ctags) > 0:
            overlap = len(tagset & ctags) / max(1, len(tagset | ctags))
        else:
            overlap = cluster_context_float(cluster_meta.get('cluster_tag_overlap'), 0.0)
        member_denominator = max(1.0, finite_cluster_metric(MIN_CLUSTER_MEMBERS_FOR_CONTEXT * 2, 1.0))
        member_ratio = finite_cluster_metric(member_count, 0.0) / member_denominator
        maturity = safe_clamp(member_ratio)
        overlap_score = safe_clamp(overlap)
        quality = safe_clamp(overlap_score * 0.7 + maturity * 0.3)
        eligible = member_count >= MIN_CLUSTER_MEMBERS_FOR_CONTEXT and overlap_score >= MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT
        return {
            'cluster_id': cid,
            'cluster_members': member_count,
            'cluster_tag_overlap': overlap_score,
            'cluster_quality': quality,
            'eligible': eligible,
            'reason': 'eligible' if eligible else 'cluster_quality_below_threshold',
        }
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error('context cluster quality failed: ' + no_hook_type_name(exc))
        return _cluster_quality_unavailable(
            reason='cluster_quality_error',
            error_type=no_hook_type_name(exc),
        )
