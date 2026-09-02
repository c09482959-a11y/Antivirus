"""Trust-aware atomic assignment transaction for canonical microclusters."""
from __future__ import annotations

from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.models.clustering.assignment_decision import (
    decide_cluster_assignment,
    observation_update_authority,
)
from Virus_Scan.models.clustering.chain_signatures import (
    cluster_behavior_signature,
    cluster_chain_signature,
)
from Virus_Scan.models.clustering.common import (
    cluster_input_sequence,
    cluster_mapping,
    safe_cluster_text,
)
from Virus_Scan.models.clustering.evidence import cluster_assignment_unavailable
from Virus_Scan.models.clustering.metadata import cluster_engine_prefix, cluster_kind_for_tags
from Virus_Scan.models.clustering.microcluster import (
    commit_microcluster_snapshot,
    empty_microcluster_snapshot,
    microcluster_with_fields,
)
from Virus_Scan.models.clustering.microcluster_update import update_microcluster_snapshot
from Virus_Scan.models.clustering.microcluster_values import (
    microcluster_mapping,
    microcluster_value,
)
from Virus_Scan.models.clustering.normalization import normalize_cluster_vector
from Virus_Scan.models.clustering.policy import CLUSTER_POLICY
from Virus_Scan.models.clustering.state import (
    cluster_applied_learning_keys,
    cluster_graph_node_key,
    cluster_lock,
    cluster_metadata,
    node_cluster_map,
)
from Virus_Scan.models.clustering.storage import store_node_vector
from Virus_Scan.models.clustering.tag_evidence import cluster_root_tag_projection
from Virus_Scan.models.contracts.learning_authority import learning_authorization_failure


def _bounded_record_learning_key(replay_key: str, ordinal: int) -> None:
    applied_keys = cluster_applied_learning_keys()
    applied_keys[replay_key] = ordinal
    if len(applied_keys) <= CLUSTER_POLICY.maximum_learning_keys:
        return
    keep = {
        key
        for _ordinal, key in sorted(
            (
                stored_ordinal if type(stored_ordinal) is int else 0,
                safe_cluster_text(key, default_text=""),
            )
            for key, stored_ordinal in tuple(applied_keys.items())
            )[-CLUSTER_POLICY.maximum_learning_keys:]
        if key
    }
    for key in tuple(applied_keys):
        if key not in keep:
            applied_keys.pop(key, None)


def _cluster_for_observation_digest(observation_digest: str) -> str | None:
    if observation_digest == "":
        return None
    for cluster_id, snapshot in sorted(cluster_metadata().items()):
        digests = microcluster_value(snapshot, "observation_digests", ())
        if type(digests) in (tuple, list) and observation_digest in digests:
            cluster_text = safe_cluster_text(cluster_id, default_text="")
            if cluster_text:
                return cluster_text
    return None


def assign_cluster(
    node: object,
    feature_vector: object,
    engine_context: object = None,
    *,
    learning_decision: object = None,
) -> object:
    return assign_cluster_with_context_tags(
        node,
        feature_vector,
        tags=TagEvidence(),
        engine_context=engine_context,
        learning_decision=learning_decision,
    )


def assign_cluster_with_context_tags(
    node: object,
    feature_vector: object,
    tags: object = None,
    engine_context: object = None,
    *,
    learning_decision: object = None,
) -> object:
    """Score, assign, and conditionally update one canonical microcluster."""
    authorization_reason = learning_authorization_failure(learning_decision, "clustering")
    if authorization_reason is not None:
        return cluster_assignment_unavailable(authorization_reason)
    normalized = normalize_cluster_vector(feature_vector)
    if not normalized.available:
        return cluster_assignment_unavailable(normalized.unavailable_reason)
    try:
        node_key = cluster_graph_node_key(node)
        if node_key == "":
            node_key = safe_cluster_text(node, default_text="")
        if node_key == "":
            return cluster_assignment_unavailable("cluster_node_input_unavailable")
        tag_evidence, signature_tags, tag_reason = cluster_root_tag_projection(tags)
        if tag_reason is not None:
            return cluster_assignment_unavailable(tag_reason)
        chain_evidence = evaluate_chain_evidence(
            tags=tag_evidence,
            match_modes=("anchor", "unordered"),
        )
        engine_mapping, engine_reason = cluster_mapping(
            {"unknown": 1.0} if engine_context is None else engine_context,
            reason="cluster_engine_context_unavailable",
        )
        if engine_reason:
            return cluster_assignment_unavailable(engine_reason)
        context_key = cluster_engine_prefix(engine_mapping, node_key)
        observed_kind = cluster_kind_for_tags(signature_tags)
        if observed_kind == "unavailable":
            return cluster_assignment_unavailable("cluster_tag_input_unavailable")
        update_decision = observation_update_authority(learning_decision, observed_kind)
        chain_signature = cluster_chain_signature(chain_evidence)
        behavior_signature = cluster_behavior_signature(signature_tags)
        signature_identity = tuple(sorted((
            *(f"tag:{value}" for value in signature_tags),
            *(f"chain:{value}" for value in chain_signature),
            *(f"behavior:{value}" for value in behavior_signature),
        )))
    except RECOVERABLE_RUNTIME_ERRORS:
        return cluster_assignment_unavailable("cluster_node_or_evidence_input_unavailable")

    with cluster_lock():
        replay_key = learning_decision.replay_key
        if replay_key in cluster_applied_learning_keys():
            existing_cluster = node_cluster_map().get(node_key)
            if type(existing_cluster) is str and existing_cluster != "":
                return existing_cluster
            return cluster_assignment_unavailable("cluster_idempotent_state_unavailable")
        observation_digest = learning_decision.observation_digest
        duplicate_cluster = _cluster_for_observation_digest(observation_digest)
        if duplicate_cluster is not None:
            return duplicate_cluster
        assignment = decide_cluster_assignment(
            normalized,
            context_key,
            update_decision.authority,
            observed_kind,
            chain_evidence,
            signature_tags,
            signature_identity,
        )
        ordinal = learning_decision.decision_ordinal
        provenance = (f"learning_decision_v1:{replay_key}",)
        existing = cluster_metadata().get(assignment.cluster_id)
        if assignment.created or not microcluster_mapping(existing):
            snapshot = empty_microcluster_snapshot(
                assignment.cluster_id,
                context_key,
                normalized,
                node=node_key,
                observation_digest=observation_digest,
                authority=update_decision.authority,
                observed_kind=observed_kind,
                tags=signature_tags,
                chains=chain_signature,
                behaviors=behavior_signature,
                ordinal=ordinal,
                assignment_evidence=assignment.evidence,
                label_provenance=provenance,
            )
        else:
            snapshot = update_microcluster_snapshot(
                existing,
                normalized,
                node=node_key,
                observation_digest=observation_digest,
                authority=update_decision.authority,
                observed_kind=observed_kind,
                tags=signature_tags,
                chains=chain_signature,
                behaviors=behavior_signature,
                ordinal=ordinal,
                assignment_similarity=assignment.score,
                assignment_evidence=assignment.evidence,
                label_provenance=provenance,
            )
        snapshot = microcluster_with_fields(
            snapshot,
            tag_evidence_summary=tuple(sorted(
                (safe_cluster_text(key), value)
                for key, value in tuple(tag_evidence.summary.items())
                if safe_cluster_text(key)
            )),
            tag_evidence_kinds_consumed=("observed", "normalized", "derived", "composite"),
            last_assignment_threshold=assignment.threshold,
            last_assignment_created=assignment.created,
            update_authority_reason=update_decision.reason,
        )
        node_cluster_map()[node_key] = assignment.cluster_id
        store_node_vector(node_key, normalized.assignment_vector)
        commit_microcluster_snapshot(assignment.cluster_id, snapshot)
        _bounded_record_learning_key(replay_key, ordinal)
        return assignment.cluster_id


__all__ = ("assign_cluster", "assign_cluster_with_context_tags")
