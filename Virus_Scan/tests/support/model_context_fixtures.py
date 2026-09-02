"""Canonical context-only ModelContextSnapshot fixtures."""
from __future__ import annotations

from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.contracts.model_projection_identity import model_projection_identity


def model_projection_identity_fixture(scan_session_snapshot: object = None):
    if scan_session_snapshot is None:
        from Virus_Scan.tests.support.scan_session_fixtures import scan_session_snapshot_fixture
        scan_session_snapshot = scan_session_snapshot_fixture()
    return model_projection_identity(scan_session_snapshot)


def model_context_snapshot_fixture(
    *,
    source_artifact_evidence_digest: str = "a" * 64,
    projection_identity: object = None,
    scan_session_snapshot: object = None,
    graph_features: object = None,
    temporal_features: object = None,
    markov_features: object = None,
    engine_context: object = None,
    profile_context: object = None,
    behavior_flow: object = (),
    feature_vector: object = (),
    cluster_id: object = None,
    attack_family_classifier_context: object = None,
    failure_evidence: object = (),
) -> ModelContextSnapshot:
    if projection_identity is None:
        projection_identity = model_projection_identity_fixture(scan_session_snapshot)
    if profile_context is None:
        profile_context = {
            "active_profile": "other",
            "engine_confidence": {"active_profile": "other", "failure_evidence": ()},
        }
    cluster_context = (
        {"cluster_id": cluster_id}
        if cluster_id is None or type(cluster_id) in (str, int, float, bool)
        else {}
    )
    return ModelContextSnapshot(
        source_artifact_evidence_digest=source_artifact_evidence_digest,
        projection_identity=projection_identity,
        graph_features={} if graph_features is None else graph_features,
        temporal_features={} if temporal_features is None else temporal_features,
        markov_features={} if markov_features is None else markov_features,
        engine_context={} if engine_context is None else engine_context,
        profile_context=profile_context,
        behavior_flow=behavior_flow,
        feature_vector=feature_vector,
        cluster_context=cluster_context,
        attack_family_classifier_context=(
            {} if attack_family_classifier_context is None else attack_family_classifier_context
        ),
        failure_evidence=failure_evidence,
    )


__all__ = ("model_context_snapshot_fixture", "model_projection_identity_fixture")
