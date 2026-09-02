from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.evaluation.evaluate_mitre_attack_mapping import (
    CORPUS_VERSION,
    EVALUATION_VERSION,
    acceptance,
    evaluate,
)
from Virus_Scan.detection.attack.evaluation_contracts import (
    ATTACK_EVALUATION_CORPUS_VERSION,
    ATTACK_EVALUATION_PARTITIONS,
    AttackEvaluationCorpusManifest,
    AttackEvaluationPartitionCount,
    AttackEvaluationSample,
    AttackTechniqueExpectation,
)
from Virus_Scan.detection.attack.versioning import ATTACK_EVALUATION_PROVENANCE


def _expectation(technique_id: str, **changes: object) -> AttackTechniqueExpectation:
    values: dict[str, object] = {
        "technique_id": technique_id,
        "expected_state": "rejected",
        "label_rationale": "Independent review found no supported implementation.",
        "label_evidence_refs": ("review:evidence:1",),
        "supported_claim_scope": "artifact_implementation",
        "platform": "Windows",
        "modality": "static_structure",
    }
    values.update(changes)
    return AttackTechniqueExpectation(**values)


def _sample(path: Path, **changes: object) -> AttackEvaluationSample:
    path.write_bytes(b"benign-control")
    values: dict[str, object] = {
        "sample_id": "sample-1",
        "partition": "locked_holdout",
        "source_family": "independent-family-a",
        "related_group": "package-family-a",
        "package_campaign_id": "campaign-a",
        "collection_session": "collection-2026-01",
        "malware_class": "control",
        "sample_category": "clean_software",
        "artifact_path": str(path),
        "artifact_sha256": (
            "1fd4b02bb5e0f740e7a74838df6d5def2c85dd5089e6d5335a85d3c578b201af"
        ),
        "artifact_size": len(b"benign-control"),
        "acquisition_provenance": "Independent signed-software control collection.",
        "collected_at": "2026-01-10T00:00:00Z",
        "platform": "Windows",
        "file_type": "portable_executable",
        "technique_expectations": (
            _expectation("T1003"),
            _expectation(
                "T1021",
                expected_state="unavailable",
                label_evidence_refs=(),
                supported_claim_scope="unavailable",
                modality="unavailable",
            ),
        ),
        "evidence_domain": "independent_external",
        "eligible_for_production_metrics": False,
        "eligible_for_policy_promotion": False,
        "eligible_for_production_calibration": False,
        "scanner_boundary": "production_file_scan",
    }
    values.update(changes)
    return AttackEvaluationSample(**values)


def _counts(*samples: AttackEvaluationSample) -> tuple[AttackEvaluationPartitionCount, ...]:
    return tuple(
        AttackEvaluationPartitionCount(
            partition=partition,
            malware_count=sum(
                item.partition == partition and item.malware_class == "malware"
                for item in samples
            ),
            control_count=sum(
                item.partition == partition and item.malware_class == "control"
                for item in samples
            ),
        )
        for partition in ATTACK_EVALUATION_PARTITIONS
    )


def _manifest(*samples: AttackEvaluationSample, **changes: object) -> AttackEvaluationCorpusManifest:
    values: dict[str, object] = {
        "corpus_id": "corpus-a",
        "corpus_version": "2026.07.15-review-freeze-1",
        "corpus_evidence_class": "independent_external",
        "label_review_status": "independent_adjudicated",
        "generation_policy_digest": "",
        "policy_version": "policy-a",
        "repository_version": "enterprise-attack-v19.1",
        "repository_digest": "2" * 64,
        "policy_frozen_at": "2026-01-15T00:00:00Z",
        "frozen_at": "2026-07-15T00:00:00Z",
        "reviewer_ids": ("reviewer-a", "reviewer-b"),
        "adjudicator_ids": ("adjudicator-a",),
        "reviewed_technique_ids": ("T1003", "T1021"),
        "partition_counts": _counts(*samples),
        "samples": samples,
    }
    values.update(changes)
    return AttackEvaluationCorpusManifest(**values)


def test_attack_mapping_evaluation_is_independent_corpus_fail_closed(
    tmp_path: Path,
) -> None:
    manifest = evaluate(corpus_path=tmp_path / "missing.json", include_process=False)
    assert manifest["corpus_version"] == CORPUS_VERSION
    assert CORPUS_VERSION == ATTACK_EVALUATION_CORPUS_VERSION
    assert manifest["evaluation_scope"] == (
        "independent_multilabel_corpus_unavailable_fail_closed"
    )
    assert manifest["independent_corpus_available"] is False
    assert manifest["registry_derived_ground_truth"] is False
    assert manifest["post_scanner_evidence_injection_allowed"] is False
    assert manifest["production_path_evaluation_available"] is False
    assert manifest["model_metrics_available"] is False
    assert manifest["semantic_validity_10_10_supported"] is False
    assert manifest["confirmed_enabled_count"] == 0
    assert all(acceptance(manifest).values())


def test_attack_mapping_evaluation_provenance_and_zero_score_policy(
    tmp_path: Path,
) -> None:
    manifest = evaluate(corpus_path=tmp_path / "missing.json", include_process=False)
    assert EVALUATION_VERSION == ATTACK_EVALUATION_PROVENANCE
    assert manifest["candidate_and_rejected_zero_probability_contract"] is True
    assert manifest["all_confirmed_enabled_have_independent_holdout"] is True
    assert manifest["evaluation_rows"] == ()


def test_missing_corpus_digest_excludes_absolute_manifest_path(tmp_path: Path) -> None:
    first = evaluate(corpus_path=tmp_path / "one" / "missing.json", include_process=False)
    second = evaluate(corpus_path=tmp_path / "two" / "missing.json", include_process=False)
    assert first["manifest_digest"] == second["manifest_digest"]


def test_multilabel_sample_rejects_duplicate_or_incomplete_expectations(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="duplicate_technique_expectation"):
        _sample(
            tmp_path / "duplicate.bin",
            technique_expectations=(_expectation("T1003"), _expectation("T1003")),
        )
    incomplete = _sample(
        tmp_path / "incomplete.bin",
        technique_expectations=(_expectation("T1003"),),
    )
    with pytest.raises(ValueError, match="expectation_set_incomplete"):
        _manifest(incomplete)


def test_unavailable_expectation_is_explicit_and_nonclaiming() -> None:
    expectation = _expectation(
        "T1021",
        expected_state="unavailable",
        label_evidence_refs=(),
        supported_claim_scope="unavailable",
        modality="unavailable",
    )
    assert expectation.expected_state == "unavailable"
    with pytest.raises(ValueError, match="unavailable_scope_invalid"):
        _expectation(
            "T1021",
            expected_state="unavailable",
            label_evidence_refs=(),
        )


def test_manifest_requires_independent_review_and_adjudication(tmp_path: Path) -> None:
    sample = _sample(tmp_path / "review.bin")
    with pytest.raises(ValueError, match="independent_reviewers_required"):
        _manifest(sample, reviewer_ids=("reviewer-a",))
    with pytest.raises(ValueError, match="review_adjudication_independence_invalid"):
        _manifest(
            sample,
            reviewer_ids=("reviewer-a", "reviewer-b"),
            adjudicator_ids=("reviewer-a",),
        )


def test_manifest_keeps_every_grouping_identity_in_one_partition(
    tmp_path: Path,
) -> None:
    first = _sample(
        tmp_path / "one.bin",
        sample_id="one",
        partition="development",
        collected_at="2026-01-01T00:00:00Z",
    )
    second = _sample(
        tmp_path / "two.bin",
        sample_id="two",
        partition="locked_holdout",
        artifact_sha256="3" * 64,
    )
    with pytest.raises(ValueError, match="source_group_leakage"):
        _manifest(first, second)


def test_future_time_partition_must_be_after_policy_freeze(tmp_path: Path) -> None:
    sample = _sample(
        tmp_path / "future.bin",
        partition="future_time_holdout",
        collected_at="2026-01-10T00:00:00Z",
    )
    with pytest.raises(ValueError, match="future_time_invalid"):
        _manifest(sample)


def test_manifest_declared_counts_must_match_samples(tmp_path: Path) -> None:
    sample = _sample(tmp_path / "count.bin")
    wrong = tuple(
        AttackEvaluationPartitionCount(
            partition=partition,
            malware_count=0,
            control_count=0,
        )
        for partition in ATTACK_EVALUATION_PARTITIONS
    )
    with pytest.raises(ValueError, match="partition_count_mismatch"):
        _manifest(sample, partition_counts=wrong)


def test_old_single_technique_schema_has_no_reader() -> None:
    with pytest.raises(ValueError, match="sample_fields_invalid"):
        AttackEvaluationSample.from_record({
            "sample_id": "old",
            "partition": "locked_holdout",
            "expected_state": "rejected",
            "technique_id": "T1003",
        })


def test_multilabel_manifest_round_trip_digest_and_evaluator_status(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "corpus" / "sample.bin"
    artifact.parent.mkdir()
    sample = _sample(artifact)
    manifest = _manifest(sample)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest.to_record(), sort_keys=True), encoding="utf-8")
    loaded = AttackEvaluationCorpusManifest.from_path(path)
    assert loaded == manifest
    assert loaded.digest == manifest.digest
    status = evaluate(corpus_path=path, include_process=False)
    assert status["independent_corpus_available"] is True
    assert status["corpus"]["artifact_status"]["all_artifacts_available"] is True
    assert status["corpus_reference_run_ready"] is False
    assert status["production_path_evaluation_available"] is False
