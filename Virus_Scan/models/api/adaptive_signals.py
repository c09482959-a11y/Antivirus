"""Public adaptive model signal contract for detection scoring.

Detection scoring owns score fusion and caps, but the underlying model signals
remain owned by their canonical model modules.  Adaptive scoring callers use this
bounded public API instead of importing Markov, profile, clustering, or graph
implementation modules directly.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_type_name
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence, normalize_tag_evidence
from Virus_Scan.models.api.text_boundary import public_first_unavailable_reason

from Virus_Scan.models.contracts.model_feature_bundle import make_model_feature_bundle

from Virus_Scan.models.clustering.anomaly import adaptive_cluster_signal as cluster_adaptive_signal_owner
from Virus_Scan.models.clustering.common import (
    MIN_CLUSTER_MEMBERS_FOR_CONTEXT as MIN_CLUSTER_MEMBERS_FOR_CONTEXT_OWNER,
    MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT as MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT_OWNER,
)
from Virus_Scan.models.clustering.context import context_cluster_quality as cluster_context_quality_owner
from Virus_Scan.models.clustering.risk import (
    cluster_risk_score_evidence as cluster_risk_score_evidence_owner,
)
from Virus_Scan.models.graph.relationships import (
    compute_graph_relationship_layer as graph_relationship_layer_owner,
)
from Virus_Scan.models.graph.risk import (
    get_graph_risk_enhanced_evidence as graph_risk_enhanced_evidence_owner,
)
from Virus_Scan.models.markov.api import (
    adaptive_markov_signal as markov_adaptive_signal_owner,
    canonical_behavior_flow as markov_canonical_behavior_flow_owner,
    compute_markov_features as markov_compute_features_owner,
)
from Virus_Scan.models.profiles.adaptive_signal import (
    adaptive_profile_signal as profile_adaptive_signal_owner,
    extension_profile_anomaly as profile_extension_anomaly_owner,
)
from Virus_Scan.models.profiles.coordinated_validation import (
    coordinated_model_validation_signal as profile_coordinated_validation_signal_owner,
)

MIN_CLUSTER_MEMBERS_FOR_CONTEXT = MIN_CLUSTER_MEMBERS_FOR_CONTEXT_OWNER
MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT = MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT_OWNER


def public_adaptive_event_sequence_with_reason(value: Iterable[object] | None) -> tuple[tuple[object, ...], str | None]:
    """Normalize public event inputs without caller-owned iteration hooks.

    Exact built-in mappings remain one observation. Unknown mapping-like or
    iterable objects are rejected before ``__iter__``/mapping methods can run.
    """
    if value is None:
        return (), None
    if type(value) in (str, bytes, bytearray, bool, int, float):
        return (value,), None
    if no_hook_mapping_items(value) is not None:
        return (value,), None
    if isinstance(value, Mapping):
        return (), "unsupported_adaptive_public_mapping_sequence"
    if type(value) in (tuple, list, set, frozenset):
        return tuple(value), None
    return (), "non_iterable_adaptive_public_sequence"


def public_adaptive_event_sequence(value: Iterable[object] | None) -> tuple[object, ...]:
    return public_adaptive_event_sequence_with_reason(value)[0]


def public_adaptive_tag_evidence(value: object) -> TagEvidence:
    """Normalize raw public observations once; preserve canonical bundles."""
    if type(value) is TagEvidence:
        return value
    return normalize_tag_evidence(public_adaptive_event_sequence(value))


def immutable_adaptive_signal(values: Mapping[str, object], *, model_version: str) -> Mapping[str, object]:
    """Freeze public adaptive model evidence before detection scoring consumes it.

    Do not use truthiness or arbitrary mapping methods on caller-owned
    mappings. Exact built-in dict and mapping-proxy values remain readable;
    unsupported mapping implementations become explicit degraded evidence.
    """
    if no_hook_mapping_items(values) is not None:
        source = values
    elif isinstance(values, Mapping):
        source = {
            "ready": False,
            "score": 0.0,
            "degraded": True,
            "unavailable_reason": "unsupported_adaptive_public_mapping",
            "values_type": no_hook_type_name(values),
            "final_json_must_record": True,
            "replay_record_required": True,
        }
    else:
        source = {}
    return make_model_feature_bundle(source, model_version=model_version)


def adaptive_signal_unavailable(reason: str, *, evidence_type: str, model_version: str) -> Mapping[str, object]:
    return immutable_adaptive_signal(
        {
            "ready": False,
            "degraded": True,
            "unavailable_reason": reason,
            "evidence_type": evidence_type,
            "model_evidence_ready": False,
            "score": 0.0,
            "final_json_must_record": True,
            "replay_record_required": True,
        },
        model_version=model_version,
    )


def first_adaptive_reason(*reasons: str | None) -> str | None:
    return public_first_unavailable_reason(*reasons)


def coordinated_validation_unavailable(reason: str = "coordinated_model_validation_failed") -> Mapping[str, object]:
    return immutable_adaptive_signal(
        {
            "version": "adaptive_bucket_vector_validation_unavailable_v1",
            "ready": False,
            "reason": reason,
            "unavailable_reason": reason,
            "degraded": True,
            "evidence_type": "profile_coordinated_validation",
            "bucket_validation": {
                "bucket_anomaly": 0.0,
                "ready": False,
                "reason": reason,
                "unavailable_reason": reason,
            },
            "vector_validation": {
                "anomaly": 0.0,
                "ready": False,
                "reason": reason,
                "unavailable_reason": reason,
            },
            "timeline_validation": {
                "anomaly": 0.0,
                "ready": False,
                "reason": reason,
                "unavailable_reason": reason,
            },
            "final_json_must_record": True,
            "replay_record_required": True,
        },
        model_version="profile_coordinated_validation_adaptive_signal_v1",
    )


def graph_risk_enhanced_evidence(node: object) -> Mapping[str, object]:
    """Read enhanced graph risk with explicit unavailable evidence.

    Adaptive scoring must not interpret graph-model failures as clean zero
    probability. This public adaptive-signal boundary gives scoring and final
    JSON a reason whenever the risk value cannot be trusted.
    """
    try:
        evidence = graph_risk_enhanced_evidence_owner(node)
    except RECOVERABLE_RUNTIME_ERRORS:
        evidence = {
            "risk": 0.0,
            "ready": False,
            "degraded": True,
            "unavailable_reason": "graph_risk_public_call_failed",
            "evidence_type": "graph_risk",
            "final_json_must_record": True,
            "replay_record_required": True,
        }
    return immutable_adaptive_signal(evidence, model_version="graph_risk_adaptive_signal_v1")


def adaptive_signal_float_field(evidence: object, key: str, *, default: float = 0.0) -> float:
    """Read a numeric evidence field without truth-testing caller-owned values."""
    if not isinstance(evidence, Mapping):
        return default
    try:
        value = evidence.get(key, default)
    except RECOVERABLE_RUNTIME_ERRORS:
        return default
    if value is None:
        return default
    try:
        return float(value)
    except RECOVERABLE_RUNTIME_ERRORS:
        return default


def get_graph_risk_enhanced(node: object) -> float:
    """Read graph risk through the canonical graph model owner."""
    return adaptive_signal_float_field(graph_risk_enhanced_evidence(node), "risk")


def compute_graph_relationship_layer(
    node: object,
    *,
    tags: object = None,
) -> Mapping[str, object]:
    """Return immutable graph relationship evidence through the canonical graph model owner."""
    if type(tags) is TagEvidence:
        tag_evidence = tags
        tag_reason = None
    else:
        tag_values, tag_reason = public_adaptive_event_sequence_with_reason(tags)
        tag_evidence = public_adaptive_tag_evidence(tag_values) if tag_reason is None else TagEvidence()
    malformed_reason = first_adaptive_reason(tag_reason)
    if malformed_reason:
        return immutable_adaptive_signal(
            {
                "name": "Layer 3 Graph Score",
                "score": 0.0,
                "graph_features": {
                    "risk": 0.0,
                    "base_risk": 0.0,
                    "anomaly": 0.0,
                    "graph_features_ready": False,
                    "graph_unavailable_reason": malformed_reason,
                },
                "graph_relationship_ready": False,
                "graph_unavailable_reason": malformed_reason,
                "phase_hits": (),
                "propagated_chains": (),
                "hits": ("graph_relationship_unavailable",),
                "summary": "relationships_unavailable",
                "degraded": True,
                "unavailable_reason": malformed_reason,
                "final_json_must_record": True,
                "replay_record_required": True,
            },
            model_version="graph_relationship_adaptive_signal_v1",
        )
    try:
        result = graph_relationship_layer_owner(node, tags=tag_evidence)
    except RECOVERABLE_RUNTIME_ERRORS:
        result = {
            "name": "Layer 3 Graph Score",
            "score": 0.0,
            "graph_features": {
                "risk": 0.0,
                "base_risk": 0.0,
                "anomaly": 0.0,
                "graph_features_ready": False,
                "graph_unavailable_reason": "graph_relationship_public_call_failed",
            },
            "graph_relationship_ready": False,
            "graph_unavailable_reason": "graph_relationship_public_call_failed",
            "phase_hits": (),
            "propagated_chains": (),
            "hits": ("graph_relationship_unavailable",),
            "summary": "relationships_unavailable",
            "degraded": True,
            "unavailable_reason": "graph_relationship_public_call_failed",
            "final_json_must_record": True,
            "replay_record_required": True,
        }
    return immutable_adaptive_signal(
        result,
        model_version="graph_relationship_adaptive_signal_v1",
    )


def canonical_behavior_flow(events: Iterable[object] | None) -> tuple[str, ...]:
    """Canonicalize behavior flow through the canonical Markov model owner."""
    return markov_canonical_behavior_flow_owner(public_adaptive_event_sequence(events))


def compute_markov_features(prev_stage: object, behavior_flow: Iterable[object], curr_stage: object) -> Mapping[str, object]:
    """Return Markov feature evidence through the canonical Markov model owner."""
    return markov_compute_features_owner(prev_stage, public_adaptive_event_sequence(behavior_flow), curr_stage)


def adaptive_markov_signal(prev_stage: object, curr_stage: object, ordered_events: Iterable[object] | None) -> Mapping[str, object]:
    """Return adaptive Markov evidence through the canonical Markov model owner."""
    return markov_adaptive_signal_owner(prev_stage, curr_stage, public_adaptive_event_sequence(ordered_events))


def cluster_risk_score_evidence(node: object) -> Mapping[str, object]:
    """Read cluster risk with explicit unavailable evidence for scoring."""
    try:
        evidence = cluster_risk_score_evidence_owner(node)
    except RECOVERABLE_RUNTIME_ERRORS:
        evidence = {
            "risk": 0.0,
            "ready": False,
            "degraded": True,
            "unavailable_reason": "cluster_risk_public_call_failed",
            "evidence_type": "cluster_risk",
            "final_json_must_record": True,
            "replay_record_required": True,
        }
    return immutable_adaptive_signal(evidence, model_version="cluster_risk_adaptive_signal_v1")


def cluster_risk_score(node: object) -> float:
    """Read cluster risk through the canonical clustering model owner."""
    return adaptive_signal_float_field(cluster_risk_score_evidence(node), "risk")


def context_cluster_quality(
    node: object,
    tags: Iterable[object] | None,
    *,
    adaptive_learning: Mapping[str, object] | None = None,
) -> Mapping[str, object]:
    """Return immutable context cluster evidence through the canonical clustering owner."""
    return immutable_adaptive_signal(
        cluster_context_quality_owner(node, public_adaptive_tag_evidence(tags), adaptive_learning=adaptive_learning if isinstance(adaptive_learning, Mapping) else None),
        model_version="cluster_context_quality_adaptive_signal_v1",
    )


def adaptive_cluster_signal(node: object, tags: Iterable[object] | None) -> Mapping[str, object]:
    """Return immutable adaptive cluster evidence through the canonical clustering model owner."""
    return immutable_adaptive_signal(
        cluster_adaptive_signal_owner(node, public_adaptive_tag_evidence(tags)),
        model_version="cluster_adaptive_signal_v1",
    )


def adaptive_profile_signal(
    node: object,
    tags: Iterable[object] | None,
    *,
    preliminary_risk: object = 0.0,
    strings_blob: object = "",
) -> Mapping[str, object]:
    """Return immutable adaptive profile evidence through the canonical profile model owner."""
    try:
        return immutable_adaptive_signal(
            profile_adaptive_signal_owner(
                node,
                public_adaptive_tag_evidence(tags),
                preliminary_risk=preliminary_risk,
                strings_blob=strings_blob,
            ),
            model_version="profile_adaptive_signal_v1",
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        return adaptive_signal_unavailable(
            "profile_adaptive_signal_public_input_invalid",
            evidence_type="profile_adaptive_signal",
            model_version="profile_adaptive_signal_v1",
        )


def extension_profile_anomaly(
    engine: object,
    file_path: object,
    tags: Iterable[object] | None,
    baseline_risk: object,
    *,
    strings_blob: object = "",
    api_calls: Iterable[object] | None = None,
    ordered_events: Iterable[object] | None = None,
) -> Mapping[str, object]:
    """Return immutable profile anomaly evidence through the canonical profile model owner."""
    try:
        return immutable_adaptive_signal(
            profile_extension_anomaly_owner(
                engine,
                file_path,
                public_adaptive_tag_evidence(tags),
                baseline_risk,
                strings_blob=strings_blob,
                api_calls=public_adaptive_event_sequence(api_calls),
                ordered_events=public_adaptive_event_sequence(ordered_events),
            ),
            model_version="profile_extension_anomaly_adaptive_signal_v1",
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        return adaptive_signal_unavailable(
            "profile_extension_anomaly_public_input_invalid",
            evidence_type="profile_extension_anomaly",
            model_version="profile_extension_anomaly_adaptive_signal_v1",
        )


def coordinated_model_validation_signal(
    engine: object,
    file_path: object,
    tags: Iterable[object] | None,
    *,
    strings_blob: object = "",
    api_calls: Iterable[object] | None = None,
    ordered_events: Iterable[object] | None = None,
) -> Mapping[str, object]:
    """Return immutable coordinated validation evidence through the canonical profile model owner."""
    try:
        return immutable_adaptive_signal(
            profile_coordinated_validation_signal_owner(
                engine,
                file_path,
                public_adaptive_tag_evidence(tags),
                strings_blob=strings_blob,
                api_calls=public_adaptive_event_sequence(api_calls),
                ordered_events=public_adaptive_event_sequence(ordered_events),
            ),
            model_version="profile_coordinated_validation_adaptive_signal_v1",
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        return coordinated_validation_unavailable()


__all__ = (
    "MIN_CLUSTER_MEMBERS_FOR_CONTEXT",
    "MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT",
    "adaptive_cluster_signal",
    "adaptive_markov_signal",
    "adaptive_profile_signal",
    "canonical_behavior_flow",
    "cluster_risk_score",
    "cluster_risk_score_evidence",
    "compute_graph_relationship_layer",
    "compute_markov_features",
    "context_cluster_quality",
    "coordinated_model_validation_signal",
    "extension_profile_anomaly",
    "get_graph_risk_enhanced",
    "graph_risk_enhanced_evidence",
)
