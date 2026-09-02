from __future__ import annotations

from dataclasses import replace

import pytest

from Virus_Scan.detection.attack.contracts import AttackDatasetVersion
from Virus_Scan.detection.attack.mapping.contracts import (
    AttackMappingDecision,
    AttackMappingResult,
    AttackTechniquePolicy,
    aggregate_attack_probability,
)
from Virus_Scan.detection.attack.versioning import (
    ATTACK_EVALUATION_PROVENANCE,
    ATTACK_MAPPING_POLICY_VERSION,
    ATTACK_REPOSITORY_SCHEMA_VERSION,
)

_DATASET = "a" * 40
_REPOSITORY = "b" * 64


def _decision(**changes: object) -> AttackMappingDecision:
    values: dict[str, object] = {
        "technique_id": "T1003",
        "parent_technique_id": "",
        "tactic_ids": ("TA0006",),
        "technique_name": "OS Credential Dumping",
        "parent_technique_name": "",
        "tactic_names": ("Credential Access",),
        "dataset_version": _DATASET,
        "status": "candidate",
        "policy_implementation_ids": ("local.t1003.lsass_dump",),
        "required_chain_ids": ("anchor:api_lsass_minidump",),
        "required_data_component_ids": (),
        "required_platforms": ("windows",),
        "required_modalities": ("dynamic_runtime", "host_telemetry", "static_control_flow"),
        "implementation_requirement_digests": (),
        "implementation_evaluation_manifest_digests": (),
        "strategy_ids": (),
        "analytic_ids": (),
        "policy_admission_state": "candidate_only",
        "policy_requirement_digest_set": (),
        "policy_evaluation_manifest_digest": "",
        "policy_calibration_artifact_id": "",
        "implementation_ids": ("local.t1003.lsass_dump",),
        "claim_scopes": ("artifact_implementation",),
        "execution_observed": False,
        "evidence_ids": ("chain:anchor:api_lsass_minidump",),
        "root_evidence_ids": ("obs_" + "1" * 40,),
        "evidence_types": ("chain:confirmed:local_artifact",),
        "rejected_evidence_ids": (),
        "missing_requirements": ("implementation_not_confirmed_enabled",),
        "observed_data_component_ids": (),
        "unavailable_fields": (),
        "direct_evidence_count": 1,
        "inferred_evidence_count": 0,
        "evidence_completeness": 0.999999,
        "probability": 0.0,
        "probability_unavailable_reason": "candidate_not_scoreable",
        "support": 1,
        "policy_version": ATTACK_MAPPING_POLICY_VERSION,
        "parent_scoring_policy": "most_specific_wins",
        "correlation_group": "credential_access",
        "calibration_artifact_id": "",
        "rejection_reason": "",
        "unavailable_reason": "",
        "revoked": False,
        "deprecated": False,
    }
    values.update(changes)
    return AttackMappingDecision(**values)


def _result(
    decisions: tuple[AttackMappingDecision, ...] | None = None,
    **changes: object,
) -> AttackMappingResult:
    selected = (_decision(),) if decisions is None else decisions
    values: dict[str, object] = {
        "repository_digest": _REPOSITORY,
        "dataset_version": _DATASET,
        "decisions": selected,
        "probability": aggregate_attack_probability(selected),
        "probability_unavailable_reason": "no_confirmed_techniques",
        "ready": True,
        "unavailable_reason": "",
        "policy_version": ATTACK_MAPPING_POLICY_VERSION,
        "evaluation_provenance": ATTACK_EVALUATION_PROVENANCE,
    }
    values.update(changes)
    return AttackMappingResult(**values)


def test_dataset_version_requires_one_verified_git_blob_identity() -> None:
    valid = AttackDatasetVersion(
        dataset_version=_DATASET,
        schema_version=ATTACK_REPOSITORY_SCHEMA_VERSION,
        source_ref="master",
        expected_git_blob_sha1=_DATASET,
        computed_git_blob_sha1=_DATASET,
        local_sha256="c" * 64,
    )
    assert valid.dataset_version == valid.expected_git_blob_sha1
    for changes in (
        {"dataset_version": "d" * 40},
        {"computed_git_blob_sha1": "d" * 40},
        {"schema_version": "obsolete-schema"},
    ):
        values = {
            "dataset_version": _DATASET,
            "schema_version": ATTACK_REPOSITORY_SCHEMA_VERSION,
            "source_ref": "master",
            "expected_git_blob_sha1": _DATASET,
            "computed_git_blob_sha1": _DATASET,
            "local_sha256": "c" * 64,
            **changes,
        }
        with pytest.raises(ValueError):
            AttackDatasetVersion(**values)


def test_candidate_mapping_is_nonprobabilistic_and_lifecycle_strict() -> None:
    assert _decision().probability == 0.0
    with pytest.raises(ValueError, match="candidate_probability"):
        _decision(probability=0.1)
    with pytest.raises(ValueError, match="positive_lifecycle"):
        _decision(revoked=True)
    with pytest.raises(ValueError, match="positive_lifecycle"):
        _decision(deprecated=True)


def test_confirmed_probability_requires_calibration() -> None:
    confirmed = _decision(
        status="confirmed",
        missing_requirements=(),
        evidence_completeness=1.0,
        probability_unavailable_reason="confirmed_calibration_unavailable",
    )
    assert confirmed.probability == 0.0
    with pytest.raises(ValueError, match="calibration_required"):
        _decision(
            status="confirmed",
            missing_requirements=(),
            evidence_completeness=1.0,
            probability=0.8,
            probability_unavailable_reason="",
        )


def test_mapping_decision_requires_official_deterministic_identity() -> None:
    with pytest.raises(ValueError, match="technique_invalid"):
        _decision(technique_id="TA0006")
    with pytest.raises(ValueError, match="tactic_invalid"):
        _decision(tactic_ids=("T1003",))
    with pytest.raises(ValueError, match="tactics_invalid"):
        _decision(tactic_ids=("TA0006", "TA0002"))
    with pytest.raises(ValueError, match="evidence_invalid"):
        _decision(evidence_ids=("z", "a"))
    with pytest.raises(ValueError, match="dataset_invalid"):
        _decision(dataset_version="not-a-git-identity")


def test_mapping_result_rejects_duplicate_inconsistent_or_forged_probability() -> None:
    decision = _decision()
    assert _result().probability == 0.0
    with pytest.raises(ValueError, match="decision_identity"):
        _result((decision, decision))
    with pytest.raises(ValueError, match="decision_dataset_mismatch"):
        _result((replace(decision, dataset_version="d" * 40),))
    with pytest.raises(ValueError, match="probability_mismatch"):
        _result(probability=0.01, probability_unavailable_reason="")
    with pytest.raises(ValueError, match="repository_digest"):
        _result(repository_digest="not-a-digest")


def test_unavailable_mapping_result_cannot_publish_stale_identity_or_decisions() -> None:
    unavailable = AttackMappingResult(
        repository_digest="",
        dataset_version="",
        decisions=(),
        probability=0.0,
        probability_unavailable_reason="",
        ready=False,
        unavailable_reason="mitre_repository_unavailable",
        policy_version=ATTACK_MAPPING_POLICY_VERSION,
        evaluation_provenance=ATTACK_EVALUATION_PROVENANCE,
    )
    assert unavailable.ready is False
    with pytest.raises(ValueError, match="unavailable_contract"):
        _result(
            ready=False,
            unavailable_reason="unavailable",
            probability=0.0,
            probability_unavailable_reason="",
        )
    with pytest.raises(ValueError, match="policy_invalid"):
        _result(policy_version="legacy-policy")


def test_technique_policy_rejects_handcrafted_probability_authority() -> None:
    policy = AttackTechniquePolicy(
        "T1003",
        ("local.t1003.lsass_dump",),
        "candidate_only",
        ("artifact_implementation",),
        "most_specific_wins",
        "credential_access",
        (),
        "",
        "",
    )
    assert not hasattr(policy, "confidence")
    assert not hasattr(policy, "tag_ids")
