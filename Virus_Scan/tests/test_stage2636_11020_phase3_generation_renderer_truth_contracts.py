"""Phase 3 authority-boundary tests for generation intent, renderer input, and artifact truth."""
from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

from Virus_Scan.stress.static_semantic_renderer import render_static_semantic_artifact
from Virus_Scan.stress.static_semantic_schema import (
    ArtifactEvidenceTruth,
    ArtifactRendererSpecification,
    CorpusFixtureDefinition,
    CorpusGenerationIntent,
    CorpusGenerationRecord,
    ExpectedAttackDecision,
    STATIC_SEMANTIC_PARTITION_SCHEDULE,
)
from Virus_Scan.stress.static_semantic_templates import STATIC_SEMANTIC_FIXTURES

_ROOT = Path(__file__).resolve().parents[2]


def test_phase3_renderer_contract_has_zero_generator_or_attack_label_authority() -> None:
    fixture = STATIC_SEMANTIC_FIXTURES[0]
    intent = fixture.generation_intent
    renderer = fixture.renderer_specification
    assert type(intent) is CorpusGenerationIntent
    assert type(renderer) is ArtifactRendererSpecification
    assert type(fixture) is CorpusFixtureDefinition
    assert hasattr(intent, "desired_technique_ids")
    assert hasattr(intent, "malware_class")
    assert not hasattr(renderer, "desired_technique_ids")
    assert not hasattr(renderer, "malware_class")
    assert not hasattr(renderer, "coverage_cohort")
    assert not hasattr(renderer, "desired_parser_status")
    assert "inert_never_execute" in renderer.safety_constraints


def test_phase3_same_renderer_and_sample_id_is_independent_of_hidden_intent() -> None:
    fixture = STATIC_SEMANTIC_FIXTURES[0]
    renderer = fixture.renderer_specification
    altered_intent = replace(
        fixture.generation_intent,
        malware_class="control",
        coverage_cohort="label_independence_control",
        desired_technique_ids=("T1055",),
    )
    altered_fixture = CorpusFixtureDefinition(altered_intent, renderer)
    sample_id = "phase3-renderer-label-independence"
    assert render_static_semantic_artifact(sample_id, fixture.renderer_specification) == (
        render_static_semantic_artifact(sample_id, altered_fixture.renderer_specification)
    )


def test_phase3_generation_record_cannot_be_passed_to_renderer() -> None:
    partition, collected_at, seed = STATIC_SEMANTIC_PARTITION_SCHEDULE[0]
    generation = CorpusGenerationRecord(
        sample_id="phase3-generation-boundary",
        partition=partition,
        partition_seed=seed,
        collected_at=collected_at,
        fixture_definition=STATIC_SEMANTIC_FIXTURES[0],
    )
    with pytest.raises(TypeError, match="renderer_specification_invalid"):
        render_static_semantic_artifact(generation.sample_id, generation)  # type: ignore[arg-type]


def test_phase3_artifact_truth_and_expected_policy_decision_are_distinct_immutable_contracts() -> None:
    truth = ArtifactEvidenceTruth(
        sample_id="phase3-artifact-truth",
        artifact_sha256="a" * 64,
        artifact_size=10,
        artifact_format="python",
        platform="Windows",
        parser_status="complete",
        operation_kinds=("process_open",),
        reachability=(),
        flow=(),
        resource_identities=("pid:4242",),
    )
    decision = ExpectedAttackDecision(
        technique_id="T1055",
        artifact_evidence_digest=truth.digest,
        policy_manifest_digest="b" * 64,
        artifact_behavior_satisfied=True,
        policy_decision="candidate",
    )
    assert decision.artifact_evidence_digest == truth.digest
    assert not hasattr(truth, "desired_technique_ids")
    assert not hasattr(truth, "malware_class")
    assert not hasattr(truth, "policy_decision")
    with pytest.raises(FrozenInstanceError):
        truth.platform = "Linux"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        decision.policy_decision = "rejected"  # type: ignore[misc]


def test_phase3_legacy_conflated_contracts_are_deleted_and_renderer_is_structurally_isolated() -> None:
    schema_source = (_ROOT / "Virus_Scan/stress/static_semantic_schema.py").read_text(encoding="utf-8")
    renderer_source = (_ROOT / "Virus_Scan/stress/static_semantic_renderer.py").read_text(encoding="utf-8")
    production_sources = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (_ROOT / "Virus_Scan").rglob("*.py")
        if "/tests/" not in path.as_posix()
    )
    assert "class StaticSemanticTemplate" not in schema_source
    assert "class StaticSemanticLatentTruth" not in schema_source
    assert "StaticSemanticTemplate" not in production_sources
    assert "StaticSemanticLatentTruth" not in production_sources
    assert "CorpusGenerationIntent" not in renderer_source
    assert "CorpusGenerationRecord" not in renderer_source
    assert "desired_technique_ids" not in renderer_source
    assert "malware_class" not in renderer_source
