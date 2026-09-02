from __future__ import annotations

from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from types import MappingProxyType

import pytest

from Virus_Scan.contracts.artifact_evidence_snapshot import (
    ARTIFACT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    ArtifactEvidenceSnapshot,
    DeterministicEvidenceDerivation,
)
from Virus_Scan.contracts.artifact_read_snapshot import build_artifact_read_snapshot
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.tests.support.model_context_fixtures import model_projection_identity_fixture
from Virus_Scan.contracts.yara_hits import unavailable_yara_scan_result
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.chain_registry import (
    CHAIN_REGISTRY_DIGEST,
    CHAIN_REGISTRY_VERSION,
)


def _artifact_snapshot(tmp_path: Path) -> ArtifactEvidenceSnapshot:
    path = tmp_path / "artifact.txt"
    if not path.exists():
        path.write_bytes(b"artifact-evidence-phase2\n")
    read_snapshot = build_artifact_read_snapshot(path)
    return ArtifactEvidenceSnapshot(
        artifact_read_snapshot=read_snapshot,
        physical_observations=(),
        static_program_analyses=(),
        yara_scan_result=unavailable_yara_scan_result("yara_disabled", status="disabled"),
        tag_evidence=TagEvidence(),
        chain_evidence=ChainEvidence(
            registry_version=CHAIN_REGISTRY_VERSION,
            registry_digest=CHAIN_REGISTRY_DIGEST,
        ),
        parser_analysis_limitations=("yara_disabled",),
        evidence_completeness="partial",
    )


def test_phase2_artifact_evidence_snapshot_has_only_evidence_authority(tmp_path: Path) -> None:
    snapshot = _artifact_snapshot(tmp_path)
    names = {item.name for item in fields(ArtifactEvidenceSnapshot)}
    assert snapshot.schema_version == ARTIFACT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION
    assert snapshot.semantic_digest
    assert snapshot.content_sha256 == snapshot.artifact_read_snapshot.content_sha256
    assert snapshot.physical_root_ids == ()
    assert snapshot.to_record()["evidence_authority"] == "physical_and_deterministic_only"
    for forbidden in (
        "graph_features", "temporal_features", "markov_features", "engine_context",
        "profile_context", "feature_vector", "cluster_context",
        "attack_family_classifier_context", "generator_intent", "virustotal",
        "attack_mapping_result",
    ):
        assert forbidden not in names


def test_phase2_model_context_has_digest_only_one_way_reference(tmp_path: Path) -> None:
    evidence = _artifact_snapshot(tmp_path)
    graph = {"risk": 0.75, "nested": {"reachable": True}}
    context = ModelContextSnapshot(
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest=evidence.semantic_digest,
        graph_features=graph,
        temporal_features={"belief": 0.25},
        markov_features={"rarity": 0.5},
        engine_context={"family": "unknown"},
        profile_context={"maturity": 0.1},
        feature_vector=(1.0, 0.0),
        cluster_context={"cluster_id": "cluster-1"},
        attack_family_classifier_context={"probability": 0.9},
    )
    names = {item.name for item in fields(ModelContextSnapshot)}
    assert context.source_artifact_evidence_digest == evidence.semantic_digest
    assert context.to_record()["evidence_authority"] == "context_only"
    assert context.to_record()["official_decision_effect"] == "none"
    assert type(context.graph_features) is type(MappingProxyType({}))
    assert type(context.graph_features["nested"]) is type(MappingProxyType({}))
    graph["risk"] = 0.0
    assert context.graph_features["risk"] == 0.75
    for forbidden in (
        "tag_evidence", "chain_evidence", "physical_root_ids",
        "physical_observations", "yara_scan_result", "attack_mapping_result",
    ):
        assert forbidden not in names


def test_phase2_snapshots_are_frozen_and_semantically_deterministic(tmp_path: Path) -> None:
    evidence = _artifact_snapshot(tmp_path)
    duplicate = _artifact_snapshot(tmp_path)
    assert duplicate.semantic_digest == evidence.semantic_digest
    context_a = ModelContextSnapshot(
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest=evidence.semantic_digest,
        graph_features={"b": 2, "a": 1},
    )
    context_b = ModelContextSnapshot(
        projection_identity=model_projection_identity_fixture(),
        source_artifact_evidence_digest=evidence.semantic_digest,
        graph_features={"a": 1, "b": 2},
    )
    assert context_a.semantic_digest == context_b.semantic_digest
    with pytest.raises(FrozenInstanceError):
        evidence.evidence_completeness = "complete"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        context_a.semantic_digest = "0" * 64  # type: ignore[misc]


def test_phase2_model_context_requires_exact_evidence_digest() -> None:
    with pytest.raises(ValueError, match="model_context_source_evidence_digest_invalid"):
        ModelContextSnapshot(
        projection_identity=model_projection_identity_fixture(),source_artifact_evidence_digest="not-a-digest")


def test_phase2_deterministic_derivation_requires_physical_roots(tmp_path: Path) -> None:
    evidence = _artifact_snapshot(tmp_path)
    derivation = DeterministicEvidenceDerivation(
        derivation_id="deriv_example",
        derivation_kind="static_relation",
        producer_id="phase2_test",
        producer_version="v1",
        source_root_ids=("obs_missing",),
        output_evidence_ids=("tag_ev_example",),
    )
    with pytest.raises(ValueError, match="artifact_evidence_derivation_root_not_physical"):
        ArtifactEvidenceSnapshot(
            artifact_read_snapshot=evidence.artifact_read_snapshot,
            physical_observations=(),
            static_program_analyses=(),
            yara_scan_result=evidence.yara_scan_result,
            tag_evidence=TagEvidence(),
            chain_evidence=evidence.chain_evidence,
            parser_analysis_limitations=(),
            evidence_completeness="partial",
            deterministic_derivations=(derivation,),
        )


def test_phase2_model_context_rejects_nonfinite_and_mutable_authority_payloads(tmp_path: Path) -> None:
    evidence = _artifact_snapshot(tmp_path)
    with pytest.raises(ValueError, match="model_context_nonfinite_value"):
        ModelContextSnapshot(
        projection_identity=model_projection_identity_fixture(),
            source_artifact_evidence_digest=evidence.semantic_digest,
            graph_features={"risk": float("nan")},
        )
    with pytest.raises(TypeError, match="model_context_value_type_invalid"):
        ModelContextSnapshot(
        projection_identity=model_projection_identity_fixture(),
            source_artifact_evidence_digest=evidence.semantic_digest,
            graph_features={"authority": object()},
        )
