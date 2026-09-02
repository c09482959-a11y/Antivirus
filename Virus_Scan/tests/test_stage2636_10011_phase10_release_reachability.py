from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from Virus_Scan.contracts.chain_evidence import ChainRule, ChainStep
from Virus_Scan.detection.attack.admission import attack_technique_admission_index
from Virus_Scan.detection.attack.alignment import TagStixAlignmentSpec
from Virus_Scan.detection.attack.calibration import (
    ATTACK_CALIBRATION_FEATURE_POLICY_SCHEMA_DIGEST,
    AttackCalibrationArtifact,
)
from Virus_Scan.detection.attack.capabilities import ScannerCapabilitySpec
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID,
    AttackAnalyticImplementationSpec,
)
from Virus_Scan.detection.attack.mapping.contracts import AttackTechniquePolicy
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICY_BY_ID
from Virus_Scan.detection.attack.release_validation import (
    AttackEndToEndFixtureSpec,
    validate_attack_release,
)
from Virus_Scan.detection.attack.versioning import ATTACK_MAPPING_POLICY_VERSION
from Virus_Scan.detection.registries.chain_registry import (
    CANONICAL_CHAIN_RULES,
    CHAIN_REGISTRY_VERSION,
    chain_rule,
)
from Virus_Scan.detection.registries.tag_taxonomy_registry import (
    TAG_DEFINITION_BY_ID,
)
from Virus_Scan.tests.test_stage2636_10011_attack_stix_defensive_contracts import (
    _snapshot,
)

_TEST_SOURCE = "Virus_Scan/tests/test_stage2636_10011_phase10_release_reachability.py"
_CHAIN = chain_rule("anchor:api_lsass_minidump")
assert _CHAIN is not None


def _implementation(
    *,
    admission_state: str = "candidate_only",
    support_mode: str = "local_artifact",
    requirement_digest: str = "",
    evaluation_digest: str = "",
) -> AttackAnalyticImplementationSpec:
    official = support_mode == "exact_official"
    return AttackAnalyticImplementationSpec(
        implementation_id="test.t1003.release",
        technique_id="T1003",
        strategy_id="DET0001" if official else "",
        analytic_id="AN0001" if official else "",
        chain_ids=(_CHAIN.chain_id,),
        required_data_component_ids=("DC0001",) if official else (),
        support_mode=support_mode,
        claim_scope="artifact_implementation",
        platforms=("windows",),
        required_modalities=("static_structure",),
        requirement_digest=requirement_digest,
        evaluation_manifest_digest=evaluation_digest,
        admission_state=admission_state,
    )


def _policy(
    implementation_id: str = "test.t1003.release",
    *,
    admission_state: str = "candidate_only",
    requirement_digests: tuple[str, ...] = (),
    evaluation_digest: str = "",
    calibration_id: str = "",
) -> AttackTechniquePolicy:
    return AttackTechniquePolicy(
        technique_id="T1003",
        implementation_ids=(implementation_id,),
        admission_state=admission_state,
        supported_claim_scopes=("artifact_implementation",),
        parent_scoring_policy="most_specific_wins",
        correlation_group="credential_access",
        requirement_digest_set=requirement_digests,
        evaluation_manifest_digest=evaluation_digest,
        calibration_artifact_id=calibration_id,
        policy_version=ATTACK_MAPPING_POLICY_VERSION,
    )


def _capability(
    *,
    producer_id: str = "test_phase10_scanner",
    fields: tuple[str, ...] = (
        "artifact_identity", "modality", "producer_id", "process_identity",
        "target_identity",
    ),
    tags: tuple[str, ...] = (
        "lsass_access", "openprocess", "minidumpwritedump", "memory_dump",
        "credential_dump_attempt",
    ),
    modalities: tuple[str, ...] = ("static_structure",),
    platforms: tuple[str, ...] = ("Windows",),
) -> ScannerCapabilitySpec:
    return ScannerCapabilitySpec(
        capability_id="test.phase10.scanner." + producer_id,
        producer_id=producer_id,
        source_paths=(_TEST_SOURCE,),
        observable_tag_ids=tuple(sorted(tags)),
        supported_modalities=tuple(sorted(modalities)),
        supported_platforms=tuple(sorted(platforms)),
        emitted_observation_fields=tuple(sorted(fields)),
        capability_state="production_reachable",
        limitation_reasons=(),
    )


def _fixture(
    *,
    boundary: str = "scanner_input",
    injects: bool = False,
    platform: str = "windows",
    modalities: tuple[str, ...] = ("static_structure",),
    claim_scope: str = "artifact_implementation",
) -> AttackEndToEndFixtureSpec:
    return AttackEndToEndFixtureSpec(
        fixture_id="fixture.t1003.release",
        technique_id="T1003",
        implementation_id="test.t1003.release",
        producer_ids=("test_phase10_scanner",),
        source_path=_TEST_SOURCE,
        input_boundary=boundary,
        injects_tag_or_chain_evidence=injects,
        platform=platform,
        modalities=modalities,
        claim_scope=claim_scope,
    )


def _validate(**overrides):
    values = {
        "alignments": (),
        "capabilities": (),
        "implementations": (_implementation(),),
        "policies": (_policy(),),
        "chains": (_CHAIN,),
        "fixtures": (),
        "source_root": Path.cwd(),
    }
    values.update(overrides)
    return validate_attack_release(_snapshot(), **values)


def test_current_candidate_policy_has_no_false_scoreable_reachability() -> None:
    report = _validate()
    assert report.valid
    assert report.issue_codes == ()
    assert report.confirmed_enabled_technique_ids == ()
    assert report.confirmed_reachable_technique_ids == ()
    assert report.to_record()["valid"] is True


def test_every_canonical_chain_leaf_term_has_one_taxonomy_definition() -> None:
    chain_ids = {item.chain_id for item in CANONICAL_CHAIN_RULES}
    terms = {
        term
        for item in CANONICAL_CHAIN_RULES
        for step in item.steps
        for term in step.alternatives
    }
    terms.update(
        term
        for item in CANONICAL_CHAIN_RULES
        for term in (*item.optional_evidence, *item.forbidden_evidence)
    )
    assert terms.difference(chain_ids).difference(TAG_DEFINITION_BY_ID) == set()


def test_revoked_live_technique_is_retired_and_implementation_quarantined() -> None:
    policy = ATTACK_TECHNIQUE_POLICY_BY_ID["T1562.001"]
    implementation = ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID[
        "local.t1562.001.security_tool_impairment"
    ]
    admission = attack_technique_admission_index(_snapshot())["T1562.001"]
    assert policy.admission_state == "retired"
    assert policy.supported_claim_scopes == ()
    assert implementation.admission_state == "quarantined"
    assert admission.admission_state == "retired"
    assert admission.official_identity_state == "official_missing_repository_bound"
    assert admission.scanner_producer_ids == ()
    assert admission.term_reachable_chain_ids == ()


def test_active_alignment_requires_real_producer_fields_and_current_digest() -> None:
    snapshot = _snapshot()
    alignment = TagStixAlignmentSpec(
        tag_id="lsass_access",
        data_component_ids=("DC0001",),
        supported_modalities=("static_structure",),
        supported_platforms=("Windows",),
        required_observation_fields=("artifact_identity", "target_identity"),
        producer_ids=("missing_phase10_scanner",),
        alignment_state="exact",
        dataset_requirement_digest=snapshot.analytic_requirement_digest_by_id["AN0001"],
    )
    missing = _validate(alignments=(alignment,), capabilities=())
    assert "active_alignment_producer_missing:lsass_access" in missing.issue_codes

    stale = replace(
        alignment,
        producer_ids=("test_phase10_scanner",),
        dataset_requirement_digest="0" * 64,
    )
    incomplete = _validate(
        alignments=(stale,),
        capabilities=(_capability(fields=("artifact_identity",)),),
    )
    assert "active_alignment_requirement_digest_stale:lsass_access" in incomplete.issue_codes
    assert "active_alignment_required_field_unproduced:lsass_access" in incomplete.issue_codes


def test_missing_chain_tag_chain_reference_and_policy_reference_fail_closed() -> None:
    unknown_chain = ChainRule(
        chain_id="test.phase10.unknown",
        version=CHAIN_REGISTRY_VERSION,
        family="generic",
        match_mode="unordered",
        steps=(ChainStep(("phase10_unknown_observation",)),),
        minimum_distinct_roots=1,
        confidence=0.5,
        operational_severity=10.0,
        score_points=1.0,
    )
    missing_tag = _validate(
        implementations=(), policies=(), chains=(unknown_chain,),
    )
    assert (
        "chain_tag_missing:test.phase10.unknown:phase10_unknown_observation"
        in missing_tag.issue_codes
    )

    missing_chain = _validate(chains=())
    assert "implementation_chain_missing:test.t1003.release" in missing_chain.issue_codes

    missing_policy_implementation = _validate(
        implementations=(), chains=(), policies=(_policy("missing.phase10.impl"),),
    )
    assert "policy_implementation_missing:T1003" in missing_policy_implementation.issue_codes


def test_official_binding_digest_and_components_must_match_live_snapshot() -> None:
    implementation = _implementation(
        support_mode="exact_official", requirement_digest="0" * 64,
    )
    report = _validate(implementations=(implementation,))
    assert (
        "official_implementation_requirement_digest_mismatch:test.t1003.release"
        in report.issue_codes
    )


def test_confirmation_requires_bound_evaluation_digest_and_scanner_fixture() -> None:
    evaluation_digest = "a" * 64
    implementation = _implementation(
        admission_state="confirmed_enabled",
        evaluation_digest=evaluation_digest,
    )
    policy = _policy(
        admission_state="confirmed_enabled",
        requirement_digests=("b" * 64,),
        evaluation_digest=evaluation_digest,
    )
    report = _validate(implementations=(implementation,), policies=(policy,))
    assert report.confirmed_enabled_technique_ids == ("T1003",)
    assert report.confirmed_reachable_technique_ids == ()
    assert (
        "confirmed_implementation_requirement_digest_mismatch:test.t1003.release"
        in report.issue_codes
    )
    assert "confirmed_implementation_fixture_missing:T1003" in report.issue_codes


def test_fixture_must_enter_at_scanner_boundary_with_matching_capability_context() -> None:
    bypass = _fixture(boundary="post_scanner_injected", injects=True)
    report = _validate(
        capabilities=(_capability(),), fixtures=(bypass,),
    )
    assert "fixture_bypasses_scanner_boundary:fixture.t1003.release" in report.issue_codes

    mismatch = _fixture(
        platform="linux", modalities=("network_telemetry",),
        claim_scope="runtime_behavior",
    )
    report = _validate(
        capabilities=(_capability(),), fixtures=(mismatch,),
    )
    assert "fixture_claim_scope_mismatch:fixture.t1003.release" in report.issue_codes
    assert "fixture_modality_mismatch:fixture.t1003.release" in report.issue_codes
    assert "fixture_platform_mismatch:fixture.t1003.release" in report.issue_codes
    assert "fixture_capability_modality_unavailable:fixture.t1003.release" in report.issue_codes
    assert "fixture_capability_platform_unavailable:fixture.t1003.release" in report.issue_codes


def test_fixture_producer_must_emit_every_chain_term_and_required_field() -> None:
    fixture = _fixture()
    incomplete = _capability(
        fields=("artifact_identity",),
        tags=("lsass_access",),
    )
    report = _validate(capabilities=(incomplete,), fixtures=(fixture,))
    assert "fixture_required_field_unproduced:fixture.t1003.release" in report.issue_codes
    assert "fixture_chain_term_unproduced:fixture.t1003.release" in report.issue_codes


def test_release_validator_rejects_foreign_tuple_owner_without_iteration() -> None:
    class TrapTuple(tuple):
        called = False

        def __iter__(self):
            type(self).called = True
            raise AssertionError("hook executed")

    hostile = TrapTuple(())
    with pytest.raises(TypeError, match="alignments_invalid"):
        validate_attack_release(_snapshot(), alignments=hostile)
    assert TrapTuple.called is False


def test_production_mature_policy_requires_exact_calibration_artifact() -> None:
    requirement_digest = "b" * 64
    evaluation_digest = "a" * 64
    calibration_id = "calibration.t1003.release"
    implementation = _implementation(
        admission_state="confirmed_enabled",
        support_mode="exact_official",
        requirement_digest=requirement_digest,
        evaluation_digest=evaluation_digest,
    )
    policy = _policy(
        admission_state="production_mature",
        requirement_digests=(requirement_digest,),
        evaluation_digest=evaluation_digest,
        calibration_id=calibration_id,
    )
    missing = _validate(implementations=(implementation,), policies=(policy,))
    assert "production_mature_calibration_missing:T1003" in missing.issue_codes

    artifact = AttackCalibrationArtifact(
        calibration_id=calibration_id,
        feature_policy_schema_digest=ATTACK_CALIBRATION_FEATURE_POLICY_SCHEMA_DIGEST,
        technique_ids=("T1003",),
        evaluation_manifest_digest=evaluation_digest,
        requirement_digest_set=(requirement_digest,),
        training_partition_manifest_digest="c" * 64,
        out_of_fold_prediction_digest="d" * 64,
        calibration_method="platt",
        intercept=-2.0,
        slope=4.0,
        brier_score=0.1,
        log_loss=0.2,
        expected_calibration_error=0.03,
        sample_count=400,
        valid_claim_scopes=("artifact_implementation",),
        valid_platforms=("windows",),
        future_time_validation_digest="e" * 64,
        policy_version=ATTACK_MAPPING_POLICY_VERSION,
    )
    bound = _validate(
        implementations=(implementation,), policies=(policy,), calibrations=(artifact,),
    )
    assert "production_mature_calibration_missing:T1003" not in bound.issue_codes
    assert bound.calibration_count == 1
