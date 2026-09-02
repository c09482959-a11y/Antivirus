"""Stage2636.10011 Phase 13 calibrated ATT&CK probability contracts."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from Virus_Scan.detection.attack.calibration import (
    ATTACK_CALIBRATION_ARTIFACTS,
    ATTACK_CALIBRATION_FEATURE_POLICY_SCHEMA_DIGEST,
    ATTACK_FINAL_FUSION_CALIBRATION_STATE,
    AttackCalibrationArtifact,
    resolve_attack_probability,
)
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.attack.mapping.contracts import AttackTechniquePolicy
from Virus_Scan.detection.attack.versioning import ATTACK_MAPPING_POLICY_VERSION

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64
_DIGEST_D = "d" * 64
_DIGEST_E = "e" * 64


def _policy(**changes: object) -> AttackTechniquePolicy:
    values: dict[str, object] = {
        "technique_id": "T1003",
        "implementation_ids": ("implementation.t1003.test",),
        "admission_state": "production_mature",
        "supported_claim_scopes": ("artifact_implementation",),
        "parent_scoring_policy": "most_specific_wins",
        "correlation_group": "credential_access",
        "requirement_digest_set": (_DIGEST_A,),
        "evaluation_manifest_digest": _DIGEST_B,
        "calibration_artifact_id": "calibration.t1003.test",
        "policy_version": ATTACK_MAPPING_POLICY_VERSION,
    }
    values.update(changes)
    return AttackTechniquePolicy(**values)


def _artifact(**changes: object) -> AttackCalibrationArtifact:
    values: dict[str, object] = {
        "calibration_id": "calibration.t1003.test",
        "feature_policy_schema_digest": ATTACK_CALIBRATION_FEATURE_POLICY_SCHEMA_DIGEST,
        "technique_ids": ("T1003",),
        "evaluation_manifest_digest": _DIGEST_B,
        "requirement_digest_set": (_DIGEST_A,),
        "training_partition_manifest_digest": _DIGEST_C,
        "out_of_fold_prediction_digest": _DIGEST_D,
        "calibration_method": "platt",
        "intercept": -2.0,
        "slope": 4.0,
        "brier_score": 0.1,
        "log_loss": 0.2,
        "expected_calibration_error": 0.03,
        "sample_count": 400,
        "valid_claim_scopes": ("artifact_implementation",),
        "valid_platforms": ("Windows",),
        "future_time_validation_digest": _DIGEST_E,
        "policy_version": ATTACK_MAPPING_POLICY_VERSION,
    }
    values.update(changes)
    return AttackCalibrationArtifact(**values)


def test_current_release_has_no_fabricated_calibration_or_mature_policy() -> None:
    assert ATTACK_CALIBRATION_ARTIFACTS == ()
    assert not any(
        policy.admission_state == "production_mature"
        for policy in ATTACK_TECHNIQUE_POLICIES
    )


def test_platt_artifact_is_deterministic_and_traceable() -> None:
    artifact = _artifact()
    first = artifact.probability(0.75)
    second = artifact.probability(0.75)
    assert first == second == 0.731059
    outcome = resolve_attack_probability(
        _policy(),
        raw_score=0.75,
        claim_scopes=("artifact_implementation",),
        platforms=("Windows",),
        artifacts=(artifact,),
    )
    assert outcome.probability == first
    assert outcome.calibration_artifact_id == artifact.calibration_id
    assert outcome.unavailable_reason == ""


@pytest.mark.parametrize(
    ("artifact_changes", "reason"),
    (
        ({"technique_ids": ("T1021",)}, "calibration_technique_mismatch"),
        ({"evaluation_manifest_digest": _DIGEST_C}, "calibration_evaluation_mismatch"),
        ({"requirement_digest_set": (_DIGEST_D,)}, "calibration_requirement_mismatch"),
        ({"valid_claim_scopes": ("runtime_behavior",)}, "calibration_claim_scope_mismatch"),
        ({"valid_platforms": ("Linux",)}, "calibration_platform_mismatch"),
    ),
)
def test_stale_or_mismatched_calibration_is_zero(
    artifact_changes: dict[str, object], reason: str,
) -> None:
    outcome = resolve_attack_probability(
        _policy(),
        raw_score=1.0,
        claim_scopes=("artifact_implementation",),
        platforms=("Windows",),
        artifacts=(_artifact(**artifact_changes),),
    )
    assert outcome.probability == 0.0
    assert outcome.calibration_artifact_id == ""
    assert outcome.unavailable_reason == reason


def test_missing_artifact_is_explicitly_unavailable() -> None:
    outcome = resolve_attack_probability(
        _policy(),
        raw_score=1.0,
        claim_scopes=("artifact_implementation",),
        platforms=("Windows",),
        artifacts=(),
    )
    assert outcome.probability == 0.0
    assert outcome.unavailable_reason == "calibration_artifact_missing"


def test_non_mature_policy_cannot_use_valid_artifact() -> None:
    policy = replace(
        _policy(),
        admission_state="confirmed_enabled",
        calibration_artifact_id="",
    )
    outcome = resolve_attack_probability(
        policy,
        raw_score=1.0,
        claim_scopes=("artifact_implementation",),
        platforms=("Windows",),
        artifacts=(_artifact(),),
    )
    assert outcome.probability == 0.0
    assert outcome.unavailable_reason == "policy_not_production_mature"


def test_hostile_calibration_carriers_execute_no_hooks() -> None:
    class HostileText(str):
        def __str__(self) -> str:
            raise AssertionError("hostile __str__ executed")

        def __bool__(self) -> bool:
            raise AssertionError("hostile __bool__ executed")

    class HostileTuple(tuple):
        def __iter__(self):
            raise AssertionError("hostile __iter__ executed")

    with pytest.raises(TypeError):
        _artifact(calibration_id=HostileText("calibration.t1003.test"))
    with pytest.raises(TypeError):
        _artifact(technique_ids=HostileTuple(("T1003",)))


def test_final_fusion_excludes_mitre_until_out_of_sample_refit() -> None:
    model_caps = Path(
        "Virus_Scan/detection/scoring/adaptive/model_caps.py"
    ).read_text(encoding="utf-8")
    probabilities = Path(
        "Virus_Scan/detection/scoring/adaptive/log_odds_probabilities.py"
    ).read_text(encoding="utf-8")
    fusion = Path(
        "Virus_Scan/detection/scoring/adaptive/log_odds_fusion.py"
    ).read_text(encoding="utf-8")
    assert "'p_mitre': 1.25" not in model_caps
    assert "0.30 * available_feature_probability(probs, 'p_mitre'" not in probabilities
    assert "0.28 * safe_logit_probability(attack_chain" not in fusion
    assert "ATTACK_FINAL_FUSION_CALIBRATION_STATE" in fusion
    assert "attack_final_fusion_calibration_state" in fusion
