from __future__ import annotations

import json
from pathlib import Path

import pytest

from Virus_Scan.detection.attack.evaluation_contracts import (
    ATTACK_EVALUATION_CORPUS_VERSION,
    AttackEvaluationCorpusManifest,
    AttackEvaluationSample,
    AttackTechniqueExpectation,
)


class HostileString(str):
    def __str__(self) -> str:
        raise AssertionError("hostile __str__ executed")


class HostileTuple(tuple):
    def __iter__(self):
        raise AssertionError("hostile iterator executed")


def test_expectation_rejects_hostile_string_and_tuple_subclasses() -> None:
    with pytest.raises(TypeError, match="attack_evaluation_technique_invalid"):
        AttackTechniqueExpectation(
            technique_id=HostileString("T1003"),
            expected_state="rejected",
            label_rationale="review",
            label_evidence_refs=("evidence",),
            supported_claim_scope="artifact_implementation",
            platform="Windows",
            modality="static_structure",
        )
    with pytest.raises(TypeError, match="label_evidence_refs_invalid"):
        AttackTechniqueExpectation(
            technique_id="T1003",
            expected_state="rejected",
            label_rationale="review",
            label_evidence_refs=HostileTuple(("evidence",)),
            supported_claim_scope="artifact_implementation",
            platform="Windows",
            modality="static_structure",
        )


def test_manifest_json_duplicate_keys_and_nonfinite_values_fail(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"corpus_id":"a","corpus_id":"b"}', encoding="utf-8")
    with pytest.raises(ValueError, match="attack_evaluation_json_duplicate_key"):
        AttackEvaluationCorpusManifest.from_path(duplicate)
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"x":NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="attack_evaluation_json_nonfinite"):
        AttackEvaluationCorpusManifest.from_path(nonfinite)


def test_manifest_schema_version_is_single_current_version(tmp_path: Path) -> None:
    path = tmp_path / "legacy.json"
    record = {
        "corpus_id": "legacy",
        "policy_version": "policy",
        "frozen_at": "2026-01-01T00:00:00Z",
        "reviewer_ids": ["reviewer"],
        "samples": [],
        "version": "stage2636_10011_attack_independent_corpus_v1",
    }
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(ValueError, match="manifest_fields_invalid"):
        AttackEvaluationCorpusManifest.from_path(path)
    assert ATTACK_EVALUATION_CORPUS_VERSION == (
        "stage2636_11008_attack_multilabel_corpus_v3"
    )


def test_sample_from_record_requires_exact_builtin_list_for_expectations() -> None:
    with pytest.raises(TypeError, match="attack_evaluation_expectations_invalid"):
        AttackEvaluationSample.from_record({
            "sample_id": "sample",
            "partition": "development",
            "source_family": "family",
            "related_group": "group",
            "package_campaign_id": "campaign",
            "collection_session": "session",
            "malware_class": "malware",
            "sample_category": "malware_artifact",
            "artifact_path": "/external/sample.bin",
            "artifact_sha256": "1" * 64,
            "artifact_size": 1,
            "acquisition_provenance": "reviewed",
            "collected_at": "2026-01-01T00:00:00Z",
            "platform": "Windows",
            "file_type": "portable_executable",
            "technique_expectations": (),
            "evidence_domain": "synthetic_engineering",
            "eligible_for_production_metrics": False,
            "eligible_for_policy_promotion": False,
            "eligible_for_production_calibration": False,
            "scanner_boundary": "production_file_scan",
        })
