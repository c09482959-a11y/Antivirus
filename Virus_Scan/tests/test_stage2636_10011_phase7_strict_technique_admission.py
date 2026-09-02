"""Stage2636.10011 Phase 7 strict technique admission contracts."""
from __future__ import annotations

from Virus_Scan.tests.support.attack_mapping_contract_fixtures import attack_mapping_evidence_fixture

from dataclasses import replace

from Virus_Scan.tests.support.attack_mapping_contract_fixtures import (
    attack_chain_contract_fixture, attack_contract_repository,
)
from Virus_Scan.detection.attack.mapping.contracts import (
    AttackMappingDecision,
    aggregate_attack_probability,
)
from Virus_Scan.detection.attack.mapping.mapper import map_attack_evidence
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.attack.versioning import ATTACK_MAPPING_POLICY_VERSION
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence

_DATASET = "a" * 40


def _policy(technique_id: str):
    return next(
        item for item in ATTACK_TECHNIQUE_POLICIES
        if item.technique_id == technique_id
    )


def _confirmed_decision(
    technique_id: str,
    *,
    parent_technique_id: str = "",
    root: str,
    probability: float,
) -> AttackMappingDecision:
    return AttackMappingDecision(
        technique_id=technique_id,
        parent_technique_id=parent_technique_id,
        tactic_ids=("TA0002",),
        technique_name="fixture technique",
        parent_technique_name="fixture parent" if parent_technique_id else "",
        tactic_names=("Execution",),
        dataset_version=_DATASET,
        status="confirmed",
        policy_implementation_ids=("implementation:" + technique_id.lower(),),
        required_chain_ids=("chain:" + technique_id.lower(),),
        required_data_component_ids=(),
        required_platforms=("windows",),
        required_modalities=("static_control_flow",),
        implementation_requirement_digests=(),
        implementation_evaluation_manifest_digests=(),
        strategy_ids=(),
        analytic_ids=(),
        policy_admission_state="confirmed_enabled",
        policy_requirement_digest_set=(),
        policy_evaluation_manifest_digest="",
        policy_calibration_artifact_id="calibration:" + technique_id.lower(),
        implementation_ids=("implementation:" + technique_id.lower(),),
        claim_scopes=("artifact_implementation",),
        execution_observed=False,
        evidence_ids=("chain:" + technique_id.lower(),),
        root_evidence_ids=(root,),
        evidence_types=("chain:confirmed:local_artifact",),
        rejected_evidence_ids=(),
        missing_requirements=(),
        observed_data_component_ids=(),
        unavailable_fields=(),
        direct_evidence_count=1,
        inferred_evidence_count=0,
        evidence_completeness=1.0,
        probability=probability,
        probability_unavailable_reason=(
            "" if probability > 0.0 else "confirmed_calibration_unavailable"
        ),
        support=1,
        policy_version=ATTACK_MAPPING_POLICY_VERSION,
        parent_scoring_policy="most_specific_wins",
        correlation_group="group:" + technique_id.lower(),
        calibration_artifact_id="calibration:" + technique_id.lower(),
        rejection_reason="",
        unavailable_reason="",
        revoked=False,
        deprecated=False,
    )


def test_confirmed_chain_under_candidate_only_policy_is_candidate_and_zero() -> None:
    policy = _policy("T1003")
    result = map_attack_evidence(
        attack_contract_repository(),
        attack_mapping_evidence_fixture(TagEvidence.from_records(()), attack_chain_contract_fixture(policy, "phase7", status="confirmed", root_count=2)),
    )
    decision = next(item for item in result.decisions if item.technique_id == "T1003")
    assert decision.status == "candidate"
    assert decision.probability == 0.0
    assert decision.implementation_ids == policy.implementation_ids
    assert decision.claim_scopes == ("artifact_implementation",)
    assert "implementation_not_confirmed_enabled:local.t1003.lsass_dump" in (
        decision.missing_requirements
    )
    assert result.probability == 0.0
    assert result.probability_unavailable_reason == "no_confirmed_techniques"


def test_partial_artifact_chain_is_rejected_and_never_scores() -> None:
    policy = _policy("T1055")
    result = map_attack_evidence(
        attack_contract_repository(),
        attack_mapping_evidence_fixture(TagEvidence.from_records(()), attack_chain_contract_fixture(policy, "phase7", status="partial", root_count=2)),
    )
    decision = next(item for item in result.decisions if item.technique_id == "T1055")
    assert decision.status == "rejected"
    assert decision.rejection_reason == "insufficient_implementation_evidence"
    assert decision.probability == 0.0
    assert decision.evidence_completeness == 0.0
    assert decision.implementation_ids == ()


def test_blocked_chain_has_rejection_precedence() -> None:
    policy = _policy("T1003")
    chain = attack_chain_contract_fixture(policy, "phase7", status="confirmed", root_count=2)
    blocked = replace(
        chain.decisions[0],
        status="blocked",
        scoreable=False,
    )
    result = map_attack_evidence(
        attack_contract_repository(),
        attack_mapping_evidence_fixture(TagEvidence.from_records(()), replace(chain, decisions=(blocked,))),
    )
    decision = next(
        item for item in result.decisions if item.technique_id == "T1003"
    )
    assert decision.status == "rejected"
    assert decision.rejection_reason == "blocked_chain_evidence"
    assert decision.probability == 0.0


def test_unsupported_sensor_policies_are_unavailable_not_negative_or_candidate() -> None:
    result = map_attack_evidence(
        attack_contract_repository(), attack_mapping_evidence_fixture(TagEvidence.from_records(()), attack_chain_contract_fixture(
            _policy("T1041"), "phase7", status="confirmed", root_count=2,
        )),
    )
    decision = next(item for item in result.decisions if item.technique_id == "T1041")
    assert decision.status == "unavailable"
    assert decision.unavailable_reason == "unsupported_by_sensors"
    assert decision.rejection_reason == ""
    assert decision.probability == 0.0


def test_required_static_analysis_limitation_is_unavailable_not_false_negative() -> None:
    policy = _policy("T1003")
    tags = TagEvidence.from_records(())
    chains = attack_chain_contract_fixture(
        policy, "phase13", status="confirmed", root_count=2,
    )
    evidence = attack_mapping_evidence_fixture(
        tags,
        chains,
        completeness="partial",
        limitations=(
            "evidence_discovery_unavailable:implementation:local.t1003.lsass_dump:"
            "chain:anchor:api_lsass_minidump:step:0:operation:deferred_resource_budget",
        ),
    )
    result = map_attack_evidence(attack_contract_repository(), evidence)
    decision = next(item for item in result.decisions if item.technique_id == "T1003")
    assert decision.status == "unavailable"
    assert decision.unavailable_reason == "required_analysis_unavailable"
    assert decision.rejection_reason == ""
    assert decision.evidence_ids
    assert decision.root_evidence_ids
    assert decision.execution_observed is False


def test_child_with_shared_roots_suppresses_parent_probability() -> None:
    root = "obs_" + "1" * 40
    parent = _confirmed_decision("T1059", root=root, probability=0.7)
    child = _confirmed_decision(
        "T1059.001",
        parent_technique_id="T1059",
        root=root,
        probability=0.8,
    )
    assert aggregate_attack_probability((parent, child)) == 0.8


def test_parent_and_child_with_independent_roots_can_both_contribute() -> None:
    parent = _confirmed_decision(
        "T1059", root="obs_" + "1" * 40, probability=0.7,
    )
    child = _confirmed_decision(
        "T1059.001",
        parent_technique_id="T1059",
        root="obs_" + "2" * 40,
        probability=0.8,
    )
    assert aggregate_attack_probability((parent, child)) == 0.94


def test_policy_registry_has_no_direct_tag_or_handcrafted_probability_fields() -> None:
    assert ATTACK_TECHNIQUE_POLICIES
    assert all(not hasattr(policy, "tag_ids") for policy in ATTACK_TECHNIQUE_POLICIES)
    assert all(not hasattr(policy, "confidence") for policy in ATTACK_TECHNIQUE_POLICIES)
    assert all(
        policy.admission_state in {"candidate_only", "unsupported_by_sensors", "retired"}
        for policy in ATTACK_TECHNIQUE_POLICIES
    )
