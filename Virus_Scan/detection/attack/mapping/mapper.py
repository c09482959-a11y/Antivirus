"""Canonical strict-admission ATT&CK implementation mapper."""
from __future__ import annotations

from Virus_Scan.contracts.artifact_evidence_snapshot import ArtifactEvidenceSnapshot
from Virus_Scan.contracts.chain_evidence import ChainDecision, ChainEvidence
from Virus_Scan.detection.api.attack_repository_contracts import AttackRepositorySnapshot
from Virus_Scan.detection.attack.calibration import resolve_attack_probability
from Virus_Scan.detection.attack.domain_contracts import (
    AttackSubTechnique,
    AttackTactic,
    AttackTechnique,
)
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID,
    AttackAnalyticImplementationSpec,
)
from Virus_Scan.detection.attack.mapping.contracts import (
    AttackMappingDecision,
    AttackMappingResult,
    AttackTechniquePolicy,
    aggregate_attack_probability,
)
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.attack.repository import technique_by_id
from Virus_Scan.detection.attack.versioning import (
    ATTACK_EVALUATION_PROVENANCE,
    ATTACK_MAPPING_POLICY_VERSION,
)

_HARD_UNMET_REQUIREMENTS = frozenset({
    "required_platform_unsupported",
    "required_modality_unsupported",
})
_CONFIRMATION_ADMISSION = frozenset({"confirmed_enabled", "production_mature"})


def _implementations(
    policy: AttackTechniquePolicy,
) -> tuple[AttackAnalyticImplementationSpec, ...]:
    return tuple(
        ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID[implementation_id]
        for implementation_id in policy.implementation_ids
    )


def _chain_matches(
    chain_evidence: ChainEvidence,
    policy: AttackTechniquePolicy,
) -> tuple[tuple[ChainDecision, AttackAnalyticImplementationSpec], ...]:
    implementations = _implementations(policy)
    implementation_by_chain = {
        chain_id: implementation
        for implementation in implementations
        for chain_id in implementation.chain_ids
    }
    matches: list[tuple[ChainDecision, AttackAnalyticImplementationSpec]] = []
    for decision in chain_evidence.decisions:
        # Context-only matcher identities (for example ``chain_ev_*`` timeline
        # projections) are useful for bounded candidate reporting but have no
        # ATT&CK evidence authority.  Official mapping consumes only decisions
        # whose matched steps resolve to canonical physical observation roots.
        if not decision.candidate.physically_rooted:
            continue
        implementation = implementation_by_chain.get(decision.candidate.chain_id)
        if implementation is None:
            continue
        if implementation.claim_scope == "artifact_implementation":
            if decision.status not in {"confirmed", "blocked"}:
                continue
        elif decision.status not in {"confirmed", "candidate", "partial", "blocked"}:
            continue
        matches.append((decision, implementation))
    return tuple(matches)


def _chain_evidence_sets(
    matches: tuple[tuple[ChainDecision, AttackAnalyticImplementationSpec], ...],
) -> tuple[
    set[str], set[str], set[str], set[str], set[str], set[str], set[str], set[str]
]:
    evidence_ids: set[str] = set()
    roots: set[str] = set()
    direct_roots: set[str] = set()
    inferred_roots: set[str] = set()
    evidence_types: set[str] = set()
    rejected_ids: set[str] = set()
    unavailable_fields: set[str] = set()
    missing_requirements: set[str] = set()
    for chain, implementation in matches:
        evidence_id = "chain:" + chain.candidate.chain_id
        if chain.status == "blocked":
            rejected_ids.add(evidence_id)
        else:
            evidence_ids.add(evidence_id)
        evidence_types.add(
            "chain:" + chain.status + ":" + implementation.support_mode
        )
        for step in chain.candidate.matched_steps:
            event = step.event
            roots.add(event.root_evidence_id)
            if event.directness == "direct":
                direct_roots.add(event.root_evidence_id)
            else:
                inferred_roots.add(event.root_evidence_id)
            if event.unavailable_reason:
                unavailable_fields.add(event.unavailable_reason)
            if event.integrity_status == "unavailable":
                unavailable_fields.add("integrity_status")
        for requirement in chain.candidate.unmet_requirements:
            missing_requirements.add(requirement)
            if requirement.endswith("_unavailable") or requirement.startswith(
                "required_field_unavailable:"
            ):
                unavailable_fields.add(requirement)
    return (
        evidence_ids,
        roots,
        direct_roots,
        inferred_roots,
        evidence_types,
        rejected_ids,
        unavailable_fields,
        missing_requirements,
    )


def _implementation_confirmation_ready(
    snapshot: AttackRepositorySnapshot,
    policy: AttackTechniquePolicy,
    implementation: AttackAnalyticImplementationSpec,
    chain: ChainDecision,
) -> bool:
    if policy.admission_state not in _CONFIRMATION_ADMISSION:
        return False
    if implementation.admission_state != "confirmed_enabled":
        return False
    if chain.status != "confirmed" or chain.candidate.unmet_requirements:
        return False
    if implementation.claim_scope not in policy.supported_claim_scopes:
        return False
    if implementation.evaluation_manifest_digest != policy.evaluation_manifest_digest:
        return False
    if implementation.support_mode == "exact_official":
        live_digest = snapshot.analytic_requirement_digest_by_id.get(
            implementation.analytic_id
        )
        if (
            live_digest != implementation.requirement_digest
            or live_digest not in policy.requirement_digest_set
        ):
            return False
    elif policy.requirement_digest_set:
        return False
    return True


def _candidate_completeness(
    matches: tuple[tuple[ChainDecision, AttackAnalyticImplementationSpec], ...],
) -> float:
    values: list[float] = []
    for chain, _implementation in matches:
        if chain.status == "blocked":
            continue
        value = chain.candidate.support
        if chain.status == "confirmed":
            value = 0.999999
        elif chain.status == "candidate":
            value = min(0.95, value)
        else:
            value = min(0.75, value)
        if value > 0.0:
            values.append(value)
    return round(max(values, default=0.0), 6)


def _analysis_limitations(
    evidence: ArtifactEvidenceSnapshot,
    policy: AttackTechniquePolicy,
) -> tuple[str, ...]:
    prefixes = tuple(
        prefix
        for implementation_id in policy.implementation_ids
        for prefix in (
            "evidence_discovery_unresolved:implementation:" + implementation_id + ":",
            "evidence_discovery_unavailable:implementation:" + implementation_id + ":",
        )
    )
    return tuple(
        limitation
        for limitation in evidence.parser_analysis_limitations
        if limitation.startswith(prefixes)
    )


def _rejection_reason(
    policy: AttackTechniquePolicy,
    matches: tuple[tuple[ChainDecision, AttackAnalyticImplementationSpec], ...],
) -> str:
    if policy.admission_state == "quarantined":
        return "mapping_quarantined"
    if policy.admission_state == "retired":
        return "mapping_retired"
    if any(chain.status == "blocked" for chain, _implementation in matches):
        return "blocked_chain_evidence"
    return ""


def _unavailable_reason(
    evidence: ArtifactEvidenceSnapshot,
    policy: AttackTechniquePolicy,
    unavailable_fields: set[str],
    missing_requirements: set[str],
) -> str:
    if policy.admission_state == "unsupported_by_sensors":
        return "unsupported_by_sensors"
    if evidence.evidence_completeness == "unavailable":
        return "artifact_evidence_unavailable"
    if _HARD_UNMET_REQUIREMENTS.intersection(missing_requirements):
        return "unsupported_platform_or_modality"
    if unavailable_fields:
        return "required_observation_unavailable"
    if _analysis_limitations(evidence, policy):
        return "required_analysis_unavailable"
    return ""


def _decision(
    snapshot: AttackRepositorySnapshot,
    evidence: ArtifactEvidenceSnapshot,
    policy: AttackTechniquePolicy,
) -> AttackMappingDecision:
    technique = technique_by_id(snapshot, policy.technique_id)
    matches = _chain_matches(evidence.chain_evidence, policy)
    (
        evidence_ids,
        roots,
        direct_roots,
        inferred_roots,
        evidence_types,
        rejected_ids,
        unavailable_fields,
        missing_requirements,
    ) = _chain_evidence_sets(matches)
    implementations = _implementations(policy)
    technique_name = ""
    parent_technique_name = ""
    tactic_names: tuple[str, ...] = ()
    if type(technique) in (AttackTechnique, AttackSubTechnique):
        technique_name = technique.name
        tactic_name_values: list[str] = []
        for tactic_id in technique.tactic_ids:
            tactic = snapshot.by_attack_id.get(tactic_id)
            if type(tactic) is not AttackTactic:
                raise ValueError("attack_mapping_tactic_metadata_missing")
            tactic_name_values.append(tactic.name)
        tactic_names = tuple(tactic_name_values)
        if type(technique) is AttackSubTechnique:
            parent = next(
                (
                    item
                    for item in snapshot.objects
                    if type(item) is AttackTechnique
                    and item.attack_id == technique.parent_attack_id
                ),
                None,
            )
            if type(parent) is AttackTechnique:
                parent_technique_name = parent.name
    implementation_ids = {
        implementation.implementation_id
        for chain, implementation in matches
        if chain.status != "blocked"
    }
    claim_scopes = {
        implementation.claim_scope
        for chain, implementation in matches
        if chain.status != "blocked" and implementation.claim_scope != "unavailable"
    }
    data_components = {
        component_id
        for chain, implementation in matches
        if chain.status != "blocked"
        for component_id in implementation.required_data_component_ids
    }
    for implementation in implementations:
        if implementation.support_mode != "unsupported" and not implementation.requirement_digest:
            missing_requirements.add(
                "requirement_digest_unbound:" + implementation.implementation_id
            )
        if implementation.admission_state != "confirmed_enabled":
            missing_requirements.add(
                "implementation_not_confirmed_enabled:" + implementation.implementation_id
            )
        if not implementation.evaluation_manifest_digest:
            missing_requirements.add(
                "evaluation_manifest_unbound:" + implementation.implementation_id
            )
    status = "rejected"
    rejection = ""
    unavailable_reason = ""
    parent_technique_id = ""
    confirmed_implementations: tuple[AttackAnalyticImplementationSpec, ...] = ()
    if technique is None:
        rejection = "official_technique_missing"
    elif technique.revoked:
        rejection = "official_technique_revoked"
    elif technique.deprecated:
        rejection = "official_technique_deprecated"
    else:
        if type(technique) is AttackSubTechnique:
            parent_technique_id = technique.parent_attack_id
        rejection = _rejection_reason(policy, matches)
        if not rejection:
            unavailable_reason = _unavailable_reason(
                evidence, policy, unavailable_fields, missing_requirements,
            )
        if unavailable_reason:
            status = "unavailable"
        elif not rejection:
            confirmed = tuple(
                (chain, implementation)
                for chain, implementation in matches
                if _implementation_confirmation_ready(
                    snapshot, policy, implementation, chain
                )
            )
            if confirmed:
                status = "confirmed"
                confirmed_implementations = tuple(
                    implementation for _chain, implementation in confirmed
                )
                implementation_ids = {
                    implementation.implementation_id
                    for _chain, implementation in confirmed
                }
                claim_scopes = {
                    implementation.claim_scope
                    for _chain, implementation in confirmed
                }
                data_components = {
                    component_id
                    for _chain, implementation in confirmed
                    for component_id in implementation.required_data_component_ids
                }
                missing_requirements.clear()
            elif evidence_ids and roots:
                status = "candidate"
            else:
                rejection = "insufficient_implementation_evidence"
    completeness = 1.0 if status == "confirmed" else (
        _candidate_completeness(matches)
        if status in {"candidate", "unavailable"} else 0.0
    )
    if status == "candidate" and completeness <= 0.0:
        status = "rejected"
        rejection = "insufficient_implementation_evidence"
    probability = 0.0
    calibration_artifact_id = ""
    if status == "confirmed":
        calibration = resolve_attack_probability(
            policy,
            raw_score=completeness,
            claim_scopes=tuple(sorted(claim_scopes)),
            platforms=tuple(sorted({
                platform
                for implementation in confirmed_implementations
                for platform in implementation.platforms
            })),
        )
        probability = calibration.probability
        calibration_artifact_id = calibration.calibration_artifact_id
        probability_unavailable_reason = calibration.unavailable_reason
        if probability_unavailable_reason:
            missing_requirements.add(
                "probability_unavailable:" + probability_unavailable_reason
            )
    elif status == "candidate":
        probability_unavailable_reason = "candidate_not_scoreable"
    elif status == "unavailable":
        probability_unavailable_reason = "unavailable_not_scoreable"
    else:
        probability_unavailable_reason = "rejected_not_scoreable"
    execution_observed = (
        status in {"confirmed", "candidate"}
        and bool({"runtime_behavior", "host_telemetry", "network_telemetry"}.intersection(claim_scopes))
    )
    return AttackMappingDecision(
        technique_id=policy.technique_id,
        parent_technique_id=parent_technique_id,
        tactic_ids=() if technique is None else technique.tactic_ids,
        technique_name=technique_name,
        parent_technique_name=parent_technique_name,
        tactic_names=tactic_names,
        dataset_version=snapshot.version.dataset_version,
        status=status,
        policy_implementation_ids=policy.implementation_ids,
        required_chain_ids=tuple(sorted({
            chain_id for implementation in implementations for chain_id in implementation.chain_ids
        })),
        required_data_component_ids=tuple(sorted({
            component_id
            for implementation in implementations
            for component_id in implementation.required_data_component_ids
        })),
        required_platforms=tuple(sorted({
            platform for implementation in implementations for platform in implementation.platforms
        })),
        required_modalities=tuple(sorted({
            modality
            for implementation in implementations
            for modality in implementation.required_modalities
        })),
        implementation_requirement_digests=tuple(sorted({
            implementation.requirement_digest
            for implementation in implementations
            if implementation.requirement_digest
        })),
        implementation_evaluation_manifest_digests=tuple(sorted({
            implementation.evaluation_manifest_digest
            for implementation in implementations
            if implementation.evaluation_manifest_digest
        })),
        strategy_ids=tuple(sorted({
            implementation.strategy_id
            for implementation in implementations
            if implementation.strategy_id
        })),
        analytic_ids=tuple(sorted({
            implementation.analytic_id
            for implementation in implementations
            if implementation.analytic_id
        })),
        policy_admission_state=policy.admission_state,
        policy_requirement_digest_set=policy.requirement_digest_set,
        policy_evaluation_manifest_digest=policy.evaluation_manifest_digest,
        policy_calibration_artifact_id=policy.calibration_artifact_id,
        implementation_ids=tuple(sorted(implementation_ids)) if status != "rejected" else (),
        claim_scopes=tuple(sorted(claim_scopes)) if status != "rejected" else (),
        execution_observed=execution_observed,
        evidence_ids=tuple(sorted(evidence_ids)) if status != "rejected" else (),
        root_evidence_ids=tuple(sorted(roots)) if status != "rejected" else (),
        evidence_types=tuple(sorted(evidence_types)),
        rejected_evidence_ids=tuple(sorted(rejected_ids)),
        missing_requirements=(
            tuple(sorted(missing_requirements)) if status != "rejected" else ()
        ),
        observed_data_component_ids=(
            tuple(sorted(data_components)) if status != "rejected" else ()
        ),
        unavailable_fields=(
            tuple(sorted(unavailable_fields)) if status != "rejected" else ()
        ),
        direct_evidence_count=len(direct_roots) if status != "rejected" else 0,
        inferred_evidence_count=len(inferred_roots - direct_roots) if status != "rejected" else 0,
        evidence_completeness=completeness if status != "rejected" else 0.0,
        probability=probability,
        probability_unavailable_reason=probability_unavailable_reason,
        support=len(roots) if status != "rejected" else 0,
        policy_version=policy.policy_version,
        parent_scoring_policy=policy.parent_scoring_policy,
        correlation_group=policy.correlation_group,
        calibration_artifact_id=calibration_artifact_id,
        rejection_reason=rejection,
        unavailable_reason=unavailable_reason,
        revoked=False if technique is None else technique.revoked,
        deprecated=False if technique is None else technique.deprecated,
    )


def map_attack_evidence(
    snapshot: AttackRepositorySnapshot,
    evidence: ArtifactEvidenceSnapshot,
) -> AttackMappingResult:
    if type(snapshot) is not AttackRepositorySnapshot:
        raise TypeError("attack_repository_snapshot_required")
    if type(evidence) is not ArtifactEvidenceSnapshot:
        raise TypeError("canonical_attack_mapping_evidence_required")
    decisions = tuple(
        _decision(snapshot, evidence, policy)
        for policy in ATTACK_TECHNIQUE_POLICIES
    )
    probability = aggregate_attack_probability(decisions)
    probability_reason = ""
    if probability == 0.0:
        probability_reason = (
            "no_confirmed_techniques"
            if not any(item.status == "confirmed" for item in decisions)
            else "confirmed_techniques_not_calibrated"
        )
    return AttackMappingResult(
        repository_digest=snapshot.digest,
        dataset_version=snapshot.version.dataset_version,
        decisions=decisions,
        probability=probability,
        probability_unavailable_reason=probability_reason,
        ready=True,
        unavailable_reason="",
        policy_version=ATTACK_MAPPING_POLICY_VERSION,
        evaluation_provenance=ATTACK_EVALUATION_PROVENANCE,
    )


__all__ = ("map_attack_evidence",)
