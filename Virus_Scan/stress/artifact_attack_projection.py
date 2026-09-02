"""Pure policy projection from artifact-derived truth to expected ATT&CK state."""
from __future__ import annotations

from Virus_Scan.detection.attack.evaluation_contracts import AttackTechniqueExpectation
from Virus_Scan.stress.artifact_attack_policy_data import (
    ARTIFACT_ATTACK_ORACLE_POLICY_DIGEST,
    ARTIFACT_ATTACK_REQUIREMENT_BY_ID,
    ATTACK_ADMISSION_BY_TECHNIQUE,
)
from Virus_Scan.stress.static_semantic_schema import ArtifactEvidenceTruth, ExpectedAttackDecision


def _reachable_count(truth: ArtifactEvidenceTruth, kind: str) -> int:
    return sum(
        item.minimum_count
        for item in truth.reachability
        if item.operation_kind == kind
        and item.reachability_state in {"entrypoint_reachable", "locally_reachable", "conditionally_reachable"}
    )


def _relation_satisfied(truth: ArtifactEvidenceTruth, requirement: object) -> bool:
    for relation in truth.flow:
        if (
            relation.source_operation_kind != requirement.source_operation_kind
            or relation.sink_operation_kind != requirement.sink_operation_kind
        ):
            continue
        if requirement.require_connected and relation.connected is not True:
            continue
        if requirement.require_same_resource and relation.same_resource is not True:
            continue
        return True
    return False


def artifact_behavior_satisfied(truth: ArtifactEvidenceTruth, technique_id: str) -> bool | None:
    requirement = ARTIFACT_ATTACK_REQUIREMENT_BY_ID.get(technique_id)
    if requirement is None:
        return None
    operations = set(truth.operation_kinds)
    resources = "\n".join((*truth.resource_identities, *truth.resolved_call_identities)).casefold()
    operations_satisfied = set(requirement.required_operations).issubset(operations)
    resources_satisfied = all(token.casefold() in resources for token in requirement.required_resources)
    launch_count_satisfied = (
        requirement.minimum_process_launch_count == 0
        or _reachable_count(truth, "process_launch") >= requirement.minimum_process_launch_count
    )
    reachability_satisfied = all(_reachable_count(truth, kind) >= 1 for kind in requirement.required_operations)
    relations_satisfied = all(
        _relation_satisfied(truth, relation) for relation in requirement.required_relations
    )
    if (
        operations_satisfied
        and resources_satisfied
        and launch_count_satisfied
        and reachability_satisfied
        and relations_satisfied
    ):
        return True
    if truth.evidence_completeness != "complete" or truth.parser_status != "complete":
        return None
    return False


def expected_attack_decision(truth: ArtifactEvidenceTruth, technique_id: str) -> ExpectedAttackDecision:
    behavior = artifact_behavior_satisfied(truth, technique_id)
    admission = ATTACK_ADMISSION_BY_TECHNIQUE.get(technique_id)
    # Artifact behavior truth and policy admission are distinct from evidence
    # completeness.  A container/member or otherwise partial analysis may
    # physically recover the required behavior, but it cannot authorize a
    # local ATT&CK decision until the claim boundary is complete.
    if truth.evidence_completeness != "complete" or truth.parser_status != "complete":
        decision = "unavailable"
    elif behavior is None:
        decision = "unavailable"
    elif behavior is False:
        decision = "rejected"
    elif admission == "candidate_only":
        decision = "candidate"
    elif admission == "confirmed_enabled":
        decision = "confirmed"
    elif admission == "quarantined":
        decision = "rejected"
    else:
        decision = "unavailable"
    return ExpectedAttackDecision(
        technique_id=technique_id,
        artifact_evidence_digest=truth.digest,
        policy_manifest_digest=ARTIFACT_ATTACK_ORACLE_POLICY_DIGEST,
        artifact_behavior_satisfied=behavior,
        policy_decision=decision,
    )


def artifact_attack_expectations(
    truth: ArtifactEvidenceTruth,
    technique_ids: tuple[str, ...],
) -> tuple[AttackTechniqueExpectation, ...]:
    if type(truth) is not ArtifactEvidenceTruth or type(technique_ids) is not tuple:
        raise TypeError("artifact_attack_expectation_input_invalid")
    out=[]
    for technique_id in technique_ids:
        decision=expected_attack_decision(truth, technique_id)
        state=decision.policy_decision
        if state == "unavailable":
            refs=()
            scope="unavailable"; modality="unavailable"
            rationale=(
                "Independent artifact-byte truth cannot support an admitted local decision "
                "under the frozen ATT&CK policy or required analysis completeness."
            )
        else:
            refs=("artifact-evidence:"+truth.digest,"policy:"+ARTIFACT_ATTACK_ORACLE_POLICY_DIGEST)
            scope="artifact_implementation"; modality="static_control_flow"
            rationale=(
                "Expected state is projected exclusively from independently derived artifact "
                "evidence through the frozen local ATT&CK policy; generator labels have no authority."
            )
        out.append(AttackTechniqueExpectation(
            technique_id=technique_id, expected_state=state,
            label_rationale=rationale, label_evidence_refs=refs,
            supported_claim_scope=scope, platform=truth.platform, modality=modality,
        ))
    return tuple(out)

__all__=("artifact_attack_expectations","artifact_behavior_satisfied","expected_attack_decision")
