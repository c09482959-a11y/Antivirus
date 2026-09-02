from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.evaluation.attack_production_runtime import ALL_PARTITIONS, select_production_samples
from tools.evaluation.evaluate_mitre_attack_mapping import evaluate
from Virus_Scan.detection.attack.evaluation_contracts import (
    AttackEvaluationCorpusManifest,
    AttackEvaluationPartitionCount,
    AttackEvaluationSample,
    AttackTechniqueExpectation,
)
from Virus_Scan.stress.attack_synthetic_corpus import (
    SYNTHETIC_ATTACK_CONTROL_COUNT,
    SYNTHETIC_ATTACK_GENERATION_POLICY_DIGEST,
    SYNTHETIC_ATTACK_MALWARE_COUNT,
    build_synthetic_attack_corpus,
)
from Virus_Scan.stress.attack_synthetic_schema import SYNTHETIC_REQUIRED_CHALLENGE_KINDS
from Virus_Scan.stress.attack_synthetic_templates import (
    MALWARE_SYNTHETIC_ATTACK_FIXTURES,
    SYNTHETIC_ATTACK_TECHNIQUE_IDS,
    SYNTHETIC_ATTACK_FIXTURES,
)
from Virus_Scan.stress.static_semantic_schema import CorpusFixtureDefinition


_CANDIDATE_TECHNIQUES = {"T1003", "T1021", "T1055", "T1059.001", "T1105"}
_UNSUPPORTED_TECHNIQUES = {"T1041", "T1059"}
_QUARANTINED_TECHNIQUES = {"T1562.001"}


def test_synthetic_fixtures_split_hidden_intent_from_renderer_specification() -> None:
    assert all(type(fixture) is CorpusFixtureDefinition for fixture in SYNTHETIC_ATTACK_FIXTURES)
    positive = tuple(
        fixture for fixture in MALWARE_SYNTHETIC_ATTACK_FIXTURES
        if fixture.generation_intent.desired_technique_ids
    )
    assert positive
    assert all(fixture.generation_intent.desired_operation_kinds for fixture in positive)
    assert all(fixture.generation_intent.desired_reachability for fixture in positive)
    assert all(
        fixture.generation_intent.desired_artifact_implementation_state == "expected"
        for fixture in positive
    )
    assert any(fixture.renderer_specification.renderer_kind == "managed_pe" for fixture in SYNTHETIC_ATTACK_FIXTURES)
    assert any(fixture.renderer_specification.renderer_kind == "native_elf_x86_64" for fixture in SYNTHETIC_ATTACK_FIXTURES)
    assert all(not hasattr(fixture.renderer_specification, "desired_technique_ids") for fixture in SYNTHETIC_ATTACK_FIXTURES)


def test_synthetic_malware_intents_cover_current_attack_policy_surfaces() -> None:
    covered = {
        technique_id: tuple(
            fixture.generation_intent.generation_id
            for fixture in MALWARE_SYNTHETIC_ATTACK_FIXTURES
            if technique_id in fixture.generation_intent.desired_technique_ids
        )
        for technique_id in SYNTHETIC_ATTACK_TECHNIQUE_IDS
    }
    assert all(covered.values())
    assert set(covered) == _CANDIDATE_TECHNIQUES | _UNSUPPORTED_TECHNIQUES | _QUARANTINED_TECHNIQUES

def test_full_synthetic_manifest_is_static_semantic_label_opaque_and_deterministic(
    tmp_path: Path,
) -> None:
    build = build_synthetic_attack_corpus(
        tmp_path / "one" / "artifacts", repository_digest="9" * 64,
    )
    manifest = build.manifest
    assert manifest.malware_sample_count == SYNTHETIC_ATTACK_MALWARE_COUNT == 5_000
    assert manifest.control_sample_count == SYNTHETIC_ATTACK_CONTROL_COUNT == 5_000
    assert len(manifest.samples) == len(build.pending_artifacts) == 10_000
    assert manifest.corpus_evidence_class == "synthetic_development"
    assert manifest.label_review_status == "artifact_byte_oracle"
    assert manifest.generation_policy_digest == SYNTHETIC_ATTACK_GENERATION_POLICY_DIGEST
    assert manifest.corpus_id == "umige-stage2636-11020-static-attack-matrix"
    assert manifest.corpus_version == "stage2636_11020_static_attack_matrix_v7"
    assert all(
        tuple(item.technique_id for item in sample.technique_expectations)
        == tuple(sorted(SYNTHETIC_ATTACK_TECHNIQUE_IDS))
        for sample in manifest.samples
    )
    assert all(
        sample.evidence_domain == "synthetic_engineering"
        and sample.eligible_for_production_metrics is False
        and sample.eligible_for_policy_promotion is False
        and sample.eligible_for_production_calibration is False
        for sample in manifest.samples
    )

    sidecars = dict(build.sidecars)
    assert set(sidecars) == {
        "synthetic_generation_intent_manifest.json",
        "synthetic_challenge_pair_manifest.json",
        "synthetic_metadata_manifest.json",
        "synthetic_artifact_truth_manifest.json",
        "synthetic_safety_report.json",
        "synthetic_leakage_report.json",
    }
    pair_manifest = sidecars["synthetic_challenge_pair_manifest.json"]
    assert pair_manifest["pair_count"] == 5_000
    assert len(pair_manifest["records"]) == 5_000
    challenge_counts = dict(pair_manifest["challenge_counts"])
    assert set(SYNTHETIC_REQUIRED_CHALLENGE_KINDS) <= set(challenge_counts)
    assert all(challenge_counts[kind] > 0 for kind in SYNTHETIC_REQUIRED_CHALLENGE_KINDS)
    assert sidecars["synthetic_artifact_truth_manifest.json"]["agreement_count"] == 10_000
    assert sidecars["synthetic_safety_report.json"]["safe_count"] == 10_000
    assert sidecars["synthetic_safety_report.json"]["unsafe_count"] == 0
    assert sidecars["synthetic_leakage_report.json"]["violation_count"] == 0

    generation_by_sample = {
        record["sample_id"]: record
        for record in sidecars["synthetic_generation_intent_manifest.json"]["records"]
    }
    truth_by_sample = {
        record["sample_id"]: record
        for record in sidecars["synthetic_artifact_truth_manifest.json"]["records"]
    }
    payload_by_path = dict(build.pending_artifacts)
    sample_by_id = {sample.sample_id: sample for sample in manifest.samples}
    for record in pair_manifest["records"]:
        positive = sample_by_id[record["positive_sample_id"]]
        control = sample_by_id[record["control_sample_id"]]
        assert positive.malware_class == "malware"
        assert control.malware_class == "control"
        assert positive.partition == control.partition
        assert record["validation"] == "satisfied"
        assert record["positive_artifact_evidence_digest"] != record["control_artifact_evidence_digest"]
    for sample in manifest.samples:
        artifact_path = Path(sample.artifact_path)
        payload = payload_by_path[artifact_path]
        assert artifact_path.is_absolute()
        lowered = sample.artifact_path.replace("\\", "/").casefold()
        generation = generation_by_sample[sample.sample_id]
        intent = generation["fixture_definition"]["generation_intent"]
        truth_record = truth_by_sample[sample.sample_id]
        assert intent["generation_id"].casefold() not in lowered
        assert "/malware/" not in lowered and "/control/" not in lowered
        assert intent["malware_class"].casefold() not in Path(sample.artifact_path).name.casefold()
        assert b"template_id=" not in payload
        assert b"malware_class=" not in payload
        assert b"technique_ids=" not in payload
        # Manifest expectations are owned by artifact truth plus frozen policy,
        # never by membership in hidden desired_technique_ids.
        assert tuple(item.to_record() for item in sample.technique_expectations) == tuple(
            truth_record["attack_expectations"]
        )
        assert "generation_id" not in truth_record
        assert "malware_class" not in truth_record
        assert "desired_technique_ids" not in truth_record

    selected = select_production_samples(
        manifest, partition=ALL_PARTITIONS, limit=10_000,
    )
    assert len(selected) == 10_000
    assert sum(item.malware_class == "malware" for item in selected) == 5_000
    assert sum(item.malware_class == "control" for item in selected) == 5_000
    projection = manifest.to_record()
    assert json.dumps(projection, sort_keys=True, allow_nan=False)
    assert manifest.digest == manifest.digest


def _expectation() -> AttackTechniqueExpectation:
    return AttackTechniqueExpectation(
        "T1003", "rejected", "Synthetic negative oracle.",
        ("synthetic:test",), "artifact_implementation", "Windows",
        "static_structure",
    )


def _synthetic_manifest(path: Path) -> AttackEvaluationCorpusManifest:
    path.write_bytes(b"synthetic")
    sample = AttackEvaluationSample(
        sample_id="synthetic-one",
        partition="development",
        source_family="synthetic-development-family",
        related_group="synthetic-development-group",
        package_campaign_id="synthetic-development-campaign",
        collection_session="synthetic-development-session",
        malware_class="control",
        sample_category="clean_software",
        artifact_path=str(path),
        artifact_sha256="b3cc0475bb78a5026098858e9889acf666d31062d513d303314eca31d36e72f2",
        artifact_size=9,
        acquisition_provenance="Synthetic development fixture.",
        collected_at="2026-03-01T00:00:00Z",
        platform="Windows",
        file_type="text_fixture",
        technique_expectations=(_expectation(),),
        evidence_domain="synthetic_engineering",
        eligible_for_production_metrics=False,
        eligible_for_policy_promotion=False,
        eligible_for_production_calibration=False,
    )
    return AttackEvaluationCorpusManifest(
        corpus_id="synthetic-test",
        corpus_version="synthetic-test-v1",
        corpus_evidence_class="synthetic_development",
        label_review_status="artifact_byte_oracle",
        generation_policy_digest="7" * 64,
        policy_version="policy-test",
        repository_version="repository-test",
        repository_digest="8" * 64,
        policy_frozen_at="2026-06-01T00:00:00Z",
        frozen_at="2026-07-15T00:00:00Z",
        reviewer_ids=("synthetic-a", "synthetic-b"),
        adjudicator_ids=("synthetic-c",),
        reviewed_technique_ids=("T1003",),
        partition_counts=(
            AttackEvaluationPartitionCount("development", 0, 1),
            AttackEvaluationPartitionCount("future_time_holdout", 0, 0),
            AttackEvaluationPartitionCount("locked_holdout", 0, 0),
            AttackEvaluationPartitionCount("validation", 0, 0),
        ),
        samples=(sample,),
    )


def test_evaluator_distinguishes_synthetic_from_independent(tmp_path: Path) -> None:
    manifest = _synthetic_manifest(tmp_path / "sample.bin")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest.to_record()), encoding="utf-8")
    result = evaluate(corpus_path=manifest_path, include_process=False)
    assert result["synthetic_development_corpus_available"] is True
    assert result["independent_corpus_available"] is False
    assert result["corpus_reference_run_ready"] is False
    assert result["production_path_evaluation_available"] is False
    assert result["model_metrics_available"] is False
    assert result["semantic_validity_10_10_supported"] is False
    assert "synthetic_labels_not_operational_ground_truth" in result[
        "unresolved_limitations"
    ]


def test_evidence_class_review_contracts_are_fail_closed() -> None:
    values = dict(
        corpus_id="bad",
        corpus_version="bad",
        corpus_evidence_class="synthetic_development",
        label_review_status="independent_adjudicated",
        generation_policy_digest="7" * 64,
        policy_version="policy",
        repository_version="repository",
        repository_digest="8" * 64,
        policy_frozen_at="2026-06-01T00:00:00Z",
        frozen_at="2026-07-15T00:00:00Z",
        reviewer_ids=("a", "b"),
        adjudicator_ids=("c",),
        reviewed_technique_ids=("T1003",),
        partition_counts=(
            AttackEvaluationPartitionCount("development", 0, 0),
            AttackEvaluationPartitionCount("future_time_holdout", 0, 0),
            AttackEvaluationPartitionCount("locked_holdout", 0, 0),
            AttackEvaluationPartitionCount("validation", 0, 0),
        ),
        samples=(),
    )
    with pytest.raises(ValueError, match="synthetic_review_status_invalid"):
        AttackEvaluationCorpusManifest(**values)
