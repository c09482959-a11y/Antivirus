"""Canonical clustering metadata and direct observation update logic."""
from __future__ import annotations

from pathlib import Path
import math

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.models.clustering.chain_signatures import (
    cluster_behavior_signature,
    cluster_chain_signature,
)
from Virus_Scan.models.clustering.common import (
    CLUSTER_HALF_LIFE_SEC,
    cluster_text_sequence,
    cluster_text_set,
    dominant_engine_context,
    finite_cluster_metric,
    safe_cluster_text,
)
from Virus_Scan.models.clustering.microcluster import (
    QUARANTINED,
    commit_microcluster_snapshot,
    empty_microcluster_snapshot,
)
from Virus_Scan.models.clustering.microcluster_update import update_microcluster_snapshot
from Virus_Scan.models.clustering.microcluster_values import (
    microcluster_mapping,
    microcluster_value,
)
from Virus_Scan.models.clustering.normalization import normalize_cluster_vector
from Virus_Scan.models.clustering.state import (
    benign_clusters,
    cluster_metadata,
    malicious_clusters,
    mixed_clusters,
)


def cluster_kind_for_tags(tags: object) -> str:
    tags_text, tags_reason = cluster_text_sequence(tags, reason="cluster_tag_input_unavailable")
    if tags_reason is not None:
        return "unavailable"
    tagset = {tag.lower() for tag in tags_text}
    malicious_terms = {
        "process_injection", "credential_access", "network_exfiltration",
        "ransomware_behavior", "pickle_dangerous_global", "pickle_reduce_opcode",
    }
    if tagset & malicious_terms:
        return "malicious"
    if not tagset or tagset <= {"text_file", "image_asset", "media_asset", "benign_asset"}:
        return "benign"
    return "mixed"


def cluster_engine_prefix(engine_context: object = None, node: object = None) -> str:
    engine = dominant_engine_context(engine_context, default="unknown", allow_other=False)
    node_text = safe_cluster_text(node, default_text="")
    extension = Path(node_text).suffix.lower().replace(".", "") or "noext"
    return f"{engine}_{extension}_cluster_"


def cluster_members_for(cid: object) -> set[str]:
    members: set[str] = set()
    snapshot = cluster_metadata().get(cid, {})
    members.update(cluster_text_set(
        microcluster_value(snapshot, "members", ()), reason="cluster_members_unavailable",
    ))
    for store in (malicious_clusters(), benign_clusters(), mixed_clusters()):
        members.update(cluster_text_set(
            store.get(cid, set()), reason="cluster_members_unavailable",
        ))
    return {member for member in members if member}


def cluster_decay(meta: object, now: object = None) -> float:
    current = finite_cluster_metric(
        microcluster_value(meta, "updated_ordinal", microcluster_value(meta, "last_updated", 0.0))
        if now is None else now,
        0.0,
    )
    last_updated = finite_cluster_metric(
        microcluster_value(meta, "updated_ordinal", microcluster_value(meta, "last_updated", current)),
        current,
    )
    age = max(0.0, current - last_updated)
    return math.exp(-age / max(1.0, CLUSTER_HALF_LIFE_SEC))


def cluster_meta_for(cid: object) -> object:
    return cluster_metadata().get(cid, {})


def cluster_update_metadata(
    cid: object,
    node: object,
    vector: object,
    chain_evidence: ChainEvidence,
    tags: object = None,
    kind: object = None,
) -> object:
    """Apply one explicitly quarantined direct observation to canonical state."""
    cluster_id = safe_cluster_text(cid, default_text="")
    node_key = safe_cluster_text(node, default_text="")
    normalized = normalize_cluster_vector(vector)
    if cluster_id == "" or node_key == "" or not normalized.available:
        return {}
    tagset = cluster_text_set(tags, reason="cluster_tag_input_unavailable")
    chainset = cluster_chain_signature(chain_evidence)
    behaviors = cluster_behavior_signature(tagset)
    observed_kind = safe_cluster_text(kind, default_text="mixed")
    existing = cluster_meta_for(cluster_id)
    ordinal = int(microcluster_value(existing, "updated_ordinal", 0) or 0) + 1
    if microcluster_mapping(existing):
        snapshot = update_microcluster_snapshot(
            existing, normalized, node=node_key, observation_digest="",
            authority=QUARANTINED, observed_kind=observed_kind,
            tags=tagset, chains=chainset, behaviors=behaviors, ordinal=ordinal,
            assignment_similarity=1.0,
        )
    else:
        snapshot = empty_microcluster_snapshot(
            cluster_id, cluster_id.rsplit("cluster_", 1)[0], normalized,
            node=node_key, observation_digest="", authority=QUARANTINED,
            observed_kind=observed_kind, tags=tagset, chains=chainset,
            behaviors=behaviors, ordinal=ordinal,
        )
    commit_microcluster_snapshot(cluster_id, snapshot)
    return snapshot


__all__ = (
    "cluster_decay",
    "cluster_engine_prefix",
    "cluster_kind_for_tags",
    "cluster_members_for",
    "cluster_meta_for",
    "cluster_update_metadata",
)
