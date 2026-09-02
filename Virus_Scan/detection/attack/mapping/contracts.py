"""Immutable strict-admission ATT&CK technique policy and decision contracts."""
from __future__ import annotations

from Virus_Scan.detection.api.attack_mapping_contracts import ATTACK_MAPPING_SCHEMA_VERSION

from Virus_Scan.contracts.numeric_boundaries import exact_bounded_nonnegative_int
from Virus_Scan.contracts.text_boundaries import exact_bounded_text

from dataclasses import dataclass

from Virus_Scan.detection.attack.validation import bounded_float, exact_hex, exact_text_tuple, official_attack_id, ordered_text_tuple
from Virus_Scan.detection.attack.versioning import (
    ATTACK_EVALUATION_PROVENANCE,
    ATTACK_MAPPING_POLICY_VERSION,
)

ATTACK_TECHNIQUE_ADMISSION_STATES = frozenset({
    "repository_only",
    "unsupported_by_sensors",
    "draft",
    "candidate_only",
    "confirmed_enabled",
    "production_mature",
    "quarantined",
    "retired",
})
ATTACK_PARENT_SCORING_POLICIES = frozenset({
    "most_specific_wins",
    "independent_roots_only",
})
_MAPPING_STATES = frozenset({"confirmed", "candidate", "rejected", "unavailable"})


def _digest_tuple(value: object, reason: str, *, maximum_items: int = 32) -> tuple[str, ...]:
    values = ordered_text_tuple(value, reason, maximum_items=maximum_items)
    return tuple(exact_hex(item, reason, length=64) for item in values)


@dataclass(frozen=True, slots=True)
class AttackTechniquePolicy:
    """One immutable technique admission policy; matching logic remains in Chains."""

    technique_id: str
    implementation_ids: tuple[str, ...]
    admission_state: str
    supported_claim_scopes: tuple[str, ...]
    parent_scoring_policy: str
    correlation_group: str
    requirement_digest_set: tuple[str, ...]
    evaluation_manifest_digest: str
    calibration_artifact_id: str
    policy_version: str = ATTACK_MAPPING_POLICY_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttackTechniquePolicy:
            raise TypeError("attack_technique_policy_owner_invalid")
        technique = official_attack_id(
            self.technique_id, "attack_technique_policy_technique_invalid",
        )
        if not technique.startswith("T") or technique.startswith("TA"):
            raise ValueError("attack_technique_policy_technique_invalid")
        implementation_ids = ordered_text_tuple(
            self.implementation_ids,
            "attack_technique_policy_implementations_invalid",
            maximum_items=16,
        )
        admission = exact_bounded_text(
            self.admission_state,
            "attack_technique_policy_admission_invalid",
            maximum=32,
        )
        if admission not in ATTACK_TECHNIQUE_ADMISSION_STATES:
            raise ValueError("attack_technique_policy_admission_invalid")
        scopes = ordered_text_tuple(
            self.supported_claim_scopes,
            "attack_technique_policy_claim_scopes_invalid",
            maximum_items=16,
        )
        parent_policy = exact_bounded_text(
            self.parent_scoring_policy,
            "attack_technique_policy_parent_scoring_invalid",
            maximum=32,
        )
        if parent_policy not in ATTACK_PARENT_SCORING_POLICIES:
            raise ValueError("attack_technique_policy_parent_scoring_invalid")
        correlation_group = exact_bounded_text(
            self.correlation_group,
            "attack_technique_policy_group_invalid",
            maximum=128,
        )
        requirement_digests = _digest_tuple(
            self.requirement_digest_set,
            "attack_technique_policy_requirement_digest_invalid",
        )
        evaluation_digest = exact_bounded_text(
            self.evaluation_manifest_digest,
            "attack_technique_policy_evaluation_digest_invalid",
            maximum=64,
            allow_blank=True,
        )
        calibration_id = exact_bounded_text(
            self.calibration_artifact_id,
            "attack_technique_policy_calibration_invalid",
            maximum=128,
            allow_blank=True,
        )
        if admission in {"confirmed_enabled", "production_mature"}:
            if not implementation_ids or not scopes or not requirement_digests:
                raise ValueError("attack_technique_policy_confirmation_fields_required")
            evaluation_digest = exact_hex(
                evaluation_digest,
                "attack_technique_policy_evaluation_digest_invalid",
                length=64,
            )
        elif evaluation_digest:
            raise ValueError("attack_technique_policy_inactive_evaluation_digest_invalid")
        if admission == "production_mature" and not calibration_id:
            raise ValueError("attack_technique_policy_calibration_required")
        if admission != "production_mature" and calibration_id:
            raise ValueError("attack_technique_policy_inactive_calibration_invalid")
        if admission == "unsupported_by_sensors" and scopes:
            raise ValueError("attack_technique_policy_unsupported_scope_invalid")
        if admission not in {"repository_only", "unsupported_by_sensors", "retired"} and not implementation_ids:
            raise ValueError("attack_technique_policy_implementation_required")
        if self.policy_version != ATTACK_MAPPING_POLICY_VERSION:
            raise ValueError("attack_technique_policy_version_invalid")
        object.__setattr__(self, "technique_id", technique)
        object.__setattr__(self, "implementation_ids", implementation_ids)
        object.__setattr__(self, "admission_state", admission)
        object.__setattr__(self, "supported_claim_scopes", scopes)
        object.__setattr__(self, "parent_scoring_policy", parent_policy)
        object.__setattr__(self, "correlation_group", correlation_group)
        object.__setattr__(self, "requirement_digest_set", requirement_digests)
        object.__setattr__(self, "evaluation_manifest_digest", evaluation_digest)
        object.__setattr__(self, "calibration_artifact_id", calibration_id)
        object.__setattr__(self, "policy_version", ATTACK_MAPPING_POLICY_VERSION)

    def to_record(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "implementation_ids": self.implementation_ids,
            "admission_state": self.admission_state,
            "supported_claim_scopes": self.supported_claim_scopes,
            "parent_scoring_policy": self.parent_scoring_policy,
            "correlation_group": self.correlation_group,
            "requirement_digest_set": self.requirement_digest_set,
            "evaluation_manifest_digest": self.evaluation_manifest_digest,
            "calibration_artifact_id": self.calibration_artifact_id,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True, slots=True)
class AttackMappingDecision:
    technique_id: str
    parent_technique_id: str
    tactic_ids: tuple[str, ...]
    technique_name: str
    parent_technique_name: str
    tactic_names: tuple[str, ...]
    dataset_version: str
    status: str
    policy_implementation_ids: tuple[str, ...]
    required_chain_ids: tuple[str, ...]
    required_data_component_ids: tuple[str, ...]
    required_platforms: tuple[str, ...]
    required_modalities: tuple[str, ...]
    implementation_requirement_digests: tuple[str, ...]
    implementation_evaluation_manifest_digests: tuple[str, ...]
    strategy_ids: tuple[str, ...]
    analytic_ids: tuple[str, ...]
    policy_admission_state: str
    policy_requirement_digest_set: tuple[str, ...]
    policy_evaluation_manifest_digest: str
    policy_calibration_artifact_id: str
    implementation_ids: tuple[str, ...]
    claim_scopes: tuple[str, ...]
    execution_observed: bool
    evidence_ids: tuple[str, ...]
    root_evidence_ids: tuple[str, ...]
    evidence_types: tuple[str, ...]
    rejected_evidence_ids: tuple[str, ...]
    missing_requirements: tuple[str, ...]
    observed_data_component_ids: tuple[str, ...]
    unavailable_fields: tuple[str, ...]
    direct_evidence_count: int
    inferred_evidence_count: int
    evidence_completeness: float
    probability: float
    probability_unavailable_reason: str
    support: int
    policy_version: str
    parent_scoring_policy: str
    correlation_group: str
    calibration_artifact_id: str
    rejection_reason: str
    unavailable_reason: str
    revoked: bool
    deprecated: bool

    def __post_init__(self) -> None:
        if type(self) is not AttackMappingDecision:
            raise TypeError("attack_mapping_owner_invalid")
        technique = official_attack_id(self.technique_id)
        if not technique.startswith("T") or technique.startswith("TA"):
            raise ValueError("attack_mapping_technique_invalid")
        parent = exact_bounded_text(
            self.parent_technique_id,
            "attack_mapping_parent_invalid",
            maximum=16,
            allow_blank=True,
        )
        if parent:
            parent = official_attack_id(parent, "attack_mapping_parent_invalid")
            if not parent.startswith("T") or parent.startswith("TA") or parent == technique:
                raise ValueError("attack_mapping_parent_invalid")
        tactics = ordered_text_tuple(
            self.tactic_ids, "attack_mapping_tactics_invalid", maximum_items=32,
        )
        if any(
            not official_attack_id(item, "attack_mapping_tactic_invalid").startswith("TA")
            for item in tactics
        ):
            raise ValueError("attack_mapping_tactic_invalid")
        technique_name = exact_bounded_text(
            self.technique_name,
            "attack_mapping_technique_name_invalid",
            maximum=256,
            allow_blank=True,
        )
        parent_technique_name = exact_bounded_text(
            self.parent_technique_name,
            "attack_mapping_parent_name_invalid",
            maximum=256,
            allow_blank=True,
        )
        tactic_names = exact_text_tuple(
            self.tactic_names,
            "attack_mapping_tactic_names_invalid",
            maximum_items=32,
        )
        if len(tactic_names) != len(tactics):
            raise ValueError("attack_mapping_tactic_names_invalid")
        dataset = exact_hex(
            self.dataset_version, "attack_mapping_dataset_invalid", length=40,
        )
        status = exact_bounded_text(
            self.status, "attack_mapping_status_invalid", maximum=16,
        )
        if status not in _MAPPING_STATES:
            raise ValueError("attack_mapping_status_invalid")
        policy_implementation_ids = ordered_text_tuple(
            self.policy_implementation_ids,
            "attack_mapping_policy_implementations_invalid",
            maximum_items=16,
        )
        required_chain_ids = ordered_text_tuple(
            self.required_chain_ids,
            "attack_mapping_required_chains_invalid",
            maximum_items=64,
        )
        required_data_components = ordered_text_tuple(
            self.required_data_component_ids,
            "attack_mapping_required_data_components_invalid",
            maximum_items=64,
        )
        if any(
            not official_attack_id(item, "attack_mapping_required_data_component_invalid").startswith("DC")
            for item in required_data_components
        ):
            raise ValueError("attack_mapping_required_data_component_invalid")
        required_platforms = ordered_text_tuple(
            self.required_platforms,
            "attack_mapping_required_platforms_invalid",
            maximum_items=64,
        )
        required_modalities = ordered_text_tuple(
            self.required_modalities,
            "attack_mapping_required_modalities_invalid",
            maximum_items=32,
        )
        implementation_requirement_digests = _digest_tuple(
            self.implementation_requirement_digests,
            "attack_mapping_implementation_requirement_digest_invalid",
            maximum_items=32,
        )
        implementation_evaluation_digests = _digest_tuple(
            self.implementation_evaluation_manifest_digests,
            "attack_mapping_implementation_evaluation_digest_invalid",
            maximum_items=32,
        )
        strategy_ids = ordered_text_tuple(
            self.strategy_ids,
            "attack_mapping_strategy_ids_invalid",
            maximum_items=16,
        )
        if any(
            not official_attack_id(item, "attack_mapping_strategy_id_invalid").startswith("DET")
            for item in strategy_ids
        ):
            raise ValueError("attack_mapping_strategy_id_invalid")
        analytic_ids = ordered_text_tuple(
            self.analytic_ids,
            "attack_mapping_analytic_ids_invalid",
            maximum_items=16,
        )
        if any(
            not official_attack_id(item, "attack_mapping_analytic_id_invalid").startswith("AN")
            for item in analytic_ids
        ):
            raise ValueError("attack_mapping_analytic_id_invalid")
        policy_admission_state = exact_bounded_text(
            self.policy_admission_state,
            "attack_mapping_policy_admission_invalid",
            maximum=32,
        )
        if policy_admission_state not in ATTACK_TECHNIQUE_ADMISSION_STATES:
            raise ValueError("attack_mapping_policy_admission_invalid")
        policy_requirement_digests = _digest_tuple(
            self.policy_requirement_digest_set,
            "attack_mapping_policy_requirement_digest_invalid",
            maximum_items=32,
        )
        policy_evaluation_digest = exact_bounded_text(
            self.policy_evaluation_manifest_digest,
            "attack_mapping_policy_evaluation_digest_invalid",
            maximum=64,
            allow_blank=True,
        )
        if policy_evaluation_digest:
            policy_evaluation_digest = exact_hex(
                policy_evaluation_digest,
                "attack_mapping_policy_evaluation_digest_invalid",
                length=64,
            )
        policy_calibration_id = exact_bounded_text(
            self.policy_calibration_artifact_id,
            "attack_mapping_policy_calibration_invalid",
            maximum=128,
            allow_blank=True,
        )
        tuple_fields = (
            ("implementation_ids", 16),
            ("claim_scopes", 16),
            ("evidence_ids", 128),
            ("root_evidence_ids", 128),
            ("evidence_types", 128),
            ("rejected_evidence_ids", 128),
            ("missing_requirements", 128),
            ("unavailable_fields", 128),
        )
        materialized: dict[str, tuple[str, ...]] = {}
        for name, maximum in tuple_fields:
            materialized[name] = ordered_text_tuple(
                getattr(self, name), "attack_mapping_evidence_invalid",
                maximum_items=maximum,
            )
        data_components = ordered_text_tuple(
            self.observed_data_component_ids,
            "attack_mapping_data_components_invalid",
            maximum_items=64,
        )
        if any(
            not official_attack_id(item, "attack_mapping_data_component_invalid").startswith("DC")
            for item in data_components
        ):
            raise ValueError("attack_mapping_data_component_invalid")
        if set(materialized["evidence_ids"]).intersection(
            materialized["rejected_evidence_ids"]
        ):
            raise ValueError("attack_mapping_evidence_conflict")
        if type(self.execution_observed) is not bool:
            raise TypeError("attack_mapping_execution_observed_invalid")
        execution_observed = self.execution_observed
        direct = exact_bounded_nonnegative_int(
            self.direct_evidence_count,
            "attack_mapping_direct_count_invalid",
            maximum=128,
        )
        inferred = exact_bounded_nonnegative_int(
            self.inferred_evidence_count,
            "attack_mapping_inferred_count_invalid",
            maximum=128,
        )
        support = exact_bounded_nonnegative_int(
            self.support, "attack_mapping_support_invalid", maximum=128,
        )
        if support != len(materialized["root_evidence_ids"]) or direct + inferred > support:
            raise ValueError("attack_mapping_support_mismatch")
        completeness = bounded_float(
            self.evidence_completeness,
            "attack_mapping_completeness_invalid",
        )
        probability = bounded_float(
            self.probability, "attack_mapping_probability_invalid",
        )
        probability_reason = exact_bounded_text(
            self.probability_unavailable_reason,
            "attack_mapping_probability_unavailable_invalid",
            maximum=256,
            allow_blank=True,
        )
        parent_policy = exact_bounded_text(
            self.parent_scoring_policy,
            "attack_mapping_parent_scoring_invalid",
            maximum=32,
        )
        if parent_policy not in ATTACK_PARENT_SCORING_POLICIES:
            raise ValueError("attack_mapping_parent_scoring_invalid")
        reason = exact_bounded_text(
            self.rejection_reason,
            "attack_mapping_rejection_invalid",
            maximum=256,
            allow_blank=True,
        )
        unavailable_reason = exact_bounded_text(
            self.unavailable_reason,
            "attack_mapping_unavailable_invalid",
            maximum=256,
            allow_blank=True,
        )
        calibration_id = exact_bounded_text(
            self.calibration_artifact_id,
            "attack_mapping_calibration_invalid",
            maximum=128,
            allow_blank=True,
        )
        if self.policy_version != ATTACK_MAPPING_POLICY_VERSION:
            raise ValueError("attack_mapping_policy_invalid")
        if type(self.revoked) is not bool or type(self.deprecated) is not bool:
            raise TypeError("attack_mapping_lifecycle_flags_invalid")
        if status == "rejected":
            if (
                not reason or unavailable_reason
                or probability != 0.0
                or completeness != 0.0
                or execution_observed
            ):
                raise ValueError("attack_mapping_rejected_contract_invalid")
        elif status == "unavailable":
            if (
                reason or not unavailable_reason
                or probability != 0.0
                or completeness >= 1.0
                or execution_observed
                or self.revoked or self.deprecated
            ):
                raise ValueError("attack_mapping_unavailable_contract_invalid")
        else:
            if reason or unavailable_reason or self.revoked or self.deprecated:
                raise ValueError("attack_mapping_positive_lifecycle_invalid")
            if not materialized["implementation_ids"] or not materialized["evidence_ids"] or support < 1:
                raise ValueError("attack_mapping_positive_evidence_required")
        if status == "candidate":
            if probability != 0.0 or not 0.0 < completeness < 1.0:
                raise ValueError("attack_mapping_candidate_probability_invalid")
        if status == "confirmed":
            if completeness != 1.0 or direct < 1 or not materialized["claim_scopes"]:
                raise ValueError("attack_mapping_confirmed_contract_invalid")
        runtime_scopes = {"runtime_behavior", "host_telemetry", "network_telemetry"}
        if execution_observed and not runtime_scopes.intersection(materialized["claim_scopes"]):
            raise ValueError("attack_mapping_execution_scope_invalid")
        if materialized["claim_scopes"] == ("artifact_implementation",) and execution_observed:
            raise ValueError("attack_mapping_static_execution_invalid")
        if probability > 0.0:
            if status != "confirmed" or not calibration_id or probability_reason:
                raise ValueError("attack_mapping_probability_calibration_required")
        elif calibration_id or not probability_reason:
            raise ValueError("attack_mapping_probability_unavailable_required")
        object.__setattr__(self, "technique_id", technique)
        object.__setattr__(self, "parent_technique_id", parent)
        object.__setattr__(self, "tactic_ids", tactics)
        object.__setattr__(self, "technique_name", technique_name)
        object.__setattr__(self, "parent_technique_name", parent_technique_name)
        object.__setattr__(self, "tactic_names", tactic_names)
        object.__setattr__(self, "dataset_version", dataset)
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "policy_implementation_ids", policy_implementation_ids)
        object.__setattr__(self, "required_chain_ids", required_chain_ids)
        object.__setattr__(self, "required_data_component_ids", required_data_components)
        object.__setattr__(self, "required_platforms", required_platforms)
        object.__setattr__(self, "required_modalities", required_modalities)
        object.__setattr__(self, "implementation_requirement_digests", implementation_requirement_digests)
        object.__setattr__(self, "implementation_evaluation_manifest_digests", implementation_evaluation_digests)
        object.__setattr__(self, "strategy_ids", strategy_ids)
        object.__setattr__(self, "analytic_ids", analytic_ids)
        object.__setattr__(self, "policy_admission_state", policy_admission_state)
        object.__setattr__(self, "policy_requirement_digest_set", policy_requirement_digests)
        object.__setattr__(self, "policy_evaluation_manifest_digest", policy_evaluation_digest)
        object.__setattr__(self, "policy_calibration_artifact_id", policy_calibration_id)
        for name, value in materialized.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "execution_observed", execution_observed)
        object.__setattr__(self, "observed_data_component_ids", data_components)
        object.__setattr__(self, "direct_evidence_count", direct)
        object.__setattr__(self, "inferred_evidence_count", inferred)
        object.__setattr__(self, "evidence_completeness", completeness)
        object.__setattr__(self, "probability", probability)
        object.__setattr__(self, "probability_unavailable_reason", probability_reason)
        object.__setattr__(self, "support", support)
        object.__setattr__(self, "policy_version", ATTACK_MAPPING_POLICY_VERSION)
        object.__setattr__(self, "parent_scoring_policy", parent_policy)
        object.__setattr__(self, "correlation_group", exact_bounded_text(
            self.correlation_group, "attack_mapping_group_invalid", maximum=128,
        ))
        object.__setattr__(self, "calibration_artifact_id", calibration_id)
        object.__setattr__(self, "rejection_reason", reason)
        object.__setattr__(self, "unavailable_reason", unavailable_reason)

    def to_record(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "parent_technique_id": self.parent_technique_id,
            "tactic_ids": self.tactic_ids,
            "technique_name": self.technique_name,
            "parent_technique_name": self.parent_technique_name,
            "tactic_names": self.tactic_names,
            "dataset_version": self.dataset_version,
            "status": self.status,
            "policy_implementation_ids": self.policy_implementation_ids,
            "required_chain_ids": self.required_chain_ids,
            "required_data_component_ids": self.required_data_component_ids,
            "required_platforms": self.required_platforms,
            "required_modalities": self.required_modalities,
            "implementation_requirement_digests": self.implementation_requirement_digests,
            "implementation_evaluation_manifest_digests": self.implementation_evaluation_manifest_digests,
            "strategy_ids": self.strategy_ids,
            "analytic_ids": self.analytic_ids,
            "policy_admission_state": self.policy_admission_state,
            "policy_requirement_digest_set": self.policy_requirement_digest_set,
            "policy_evaluation_manifest_digest": self.policy_evaluation_manifest_digest,
            "policy_calibration_artifact_id": self.policy_calibration_artifact_id,
            "implementation_ids": self.implementation_ids,
            "claim_scopes": self.claim_scopes,
            "execution_observed": self.execution_observed,
            "evidence_ids": self.evidence_ids,
            "root_evidence_ids": self.root_evidence_ids,
            "evidence_types": self.evidence_types,
            "rejected_evidence_ids": self.rejected_evidence_ids,
            "missing_requirements": self.missing_requirements,
            "observed_data_component_ids": self.observed_data_component_ids,
            "unavailable_fields": self.unavailable_fields,
            "evidence_directness": (
                "mixed" if self.direct_evidence_count and self.inferred_evidence_count
                else "direct" if self.direct_evidence_count
                else "inferred" if self.inferred_evidence_count else "none"
            ),
            "direct_evidence_count": self.direct_evidence_count,
            "inferred_evidence_count": self.inferred_evidence_count,
            "evidence_completeness": self.evidence_completeness,
            "probability": self.probability,
            "probability_unavailable_reason": self.probability_unavailable_reason,
            "support": self.support,
            "policy_version": self.policy_version,
            "parent_scoring_policy": self.parent_scoring_policy,
            "correlation_group": self.correlation_group,
            "calibration_artifact_id": self.calibration_artifact_id,
            "rejection_reason": self.rejection_reason,
            "unavailable_reason": self.unavailable_reason,
            "revoked": self.revoked,
            "deprecated": self.deprecated,
        }


def _most_specific_confirmed(
    decisions: tuple[AttackMappingDecision, ...],
) -> tuple[AttackMappingDecision, ...]:
    confirmed = tuple(item for item in decisions if item.status == "confirmed")
    excluded: set[str] = set()
    by_id = {item.technique_id: item for item in confirmed}
    for child in confirmed:
        parent = by_id.get(child.parent_technique_id)
        if parent is None:
            continue
        if set(child.root_evidence_ids).intersection(parent.root_evidence_ids):
            if child.parent_scoring_policy == "most_specific_wins":
                excluded.add(parent.technique_id)
    return tuple(item for item in confirmed if item.technique_id not in excluded)


def aggregate_attack_probability(decisions: tuple[AttackMappingDecision, ...]) -> float:
    if type(decisions) is not tuple or any(
        type(item) is not AttackMappingDecision for item in decisions
    ):
        raise TypeError("attack_mapping_decisions_required")
    groups: list[tuple[set[str], set[str], float]] = []
    for decision in _most_specific_confirmed(decisions):
        if decision.probability <= 0.0:
            continue
        roots = set(decision.root_evidence_ids)
        correlations = {decision.correlation_group}
        probability = decision.probability
        matched = [
            index
            for index, (known_roots, known_groups, _value) in enumerate(groups)
            if roots.intersection(known_roots) or correlations.intersection(known_groups)
        ]
        for index in reversed(matched):
            known_roots, known_groups, known_probability = groups.pop(index)
            roots.update(known_roots)
            correlations.update(known_groups)
            probability = max(probability, known_probability)
        groups.append((roots, correlations, probability))
    remaining = 1.0
    for _roots, _correlations, probability in sorted(
        groups, key=lambda item: (tuple(sorted(item[1])), tuple(sorted(item[0]))),
    ):
        remaining *= 1.0 - probability
    return round(min(0.98, 1.0 - remaining), 6)


@dataclass(frozen=True, slots=True)
class AttackMappingResult:
    repository_digest: str
    dataset_version: str
    decisions: tuple[AttackMappingDecision, ...]
    probability: float
    probability_unavailable_reason: str
    ready: bool
    unavailable_reason: str
    policy_version: str
    evaluation_provenance: str

    def __post_init__(self) -> None:
        if type(self) is not AttackMappingResult:
            raise TypeError("attack_mapping_owner_invalid")
        if type(self.ready) is not bool:
            raise TypeError("attack_mapping_ready_invalid")
        if type(self.decisions) is not tuple or len(self.decisions) > 128 or any(
            type(item) is not AttackMappingDecision for item in self.decisions
        ):
            raise TypeError("attack_mapping_decisions_invalid")
        probability = bounded_float(
            self.probability, "attack_mapping_probability_invalid",
        )
        reason = exact_bounded_text(
            self.unavailable_reason,
            "attack_mapping_unavailable_reason_invalid",
            maximum=256,
            allow_blank=True,
        )
        probability_reason = exact_bounded_text(
            self.probability_unavailable_reason,
            "attack_mapping_probability_unavailable_invalid",
            maximum=256,
            allow_blank=True,
        )
        if self.ready:
            digest = exact_hex(
                self.repository_digest,
                "attack_mapping_repository_digest_invalid",
                length=64,
            )
            dataset = exact_hex(
                self.dataset_version, "attack_mapping_dataset_invalid", length=40,
            )
            if reason or not self.decisions:
                raise ValueError("attack_mapping_ready_contract_invalid")
            technique_ids = tuple(item.technique_id for item in self.decisions)
            if technique_ids != tuple(sorted(set(technique_ids))):
                raise ValueError("attack_mapping_decision_identity_invalid")
            if any(item.dataset_version != dataset for item in self.decisions):
                raise ValueError("attack_mapping_decision_dataset_mismatch")
            if probability != aggregate_attack_probability(self.decisions):
                raise ValueError("attack_mapping_probability_mismatch")
            if probability == 0.0 and not probability_reason:
                raise ValueError("attack_mapping_probability_unavailable_required")
            if probability > 0.0 and probability_reason:
                raise ValueError("attack_mapping_probability_unavailable_conflict")
        else:
            digest = exact_bounded_text(
                self.repository_digest,
                "attack_mapping_repository_digest_invalid",
                maximum=64,
                allow_blank=True,
            )
            dataset = exact_bounded_text(
                self.dataset_version,
                "attack_mapping_dataset_invalid",
                maximum=40,
                allow_blank=True,
            )
            if (
                digest or dataset or self.decisions or probability != 0.0
                or not reason or probability_reason
            ):
                raise ValueError("attack_mapping_unavailable_contract_invalid")
        if self.policy_version != ATTACK_MAPPING_POLICY_VERSION:
            raise ValueError("attack_mapping_policy_invalid")
        if self.evaluation_provenance != ATTACK_EVALUATION_PROVENANCE:
            raise ValueError("attack_mapping_evaluation_invalid")
        object.__setattr__(self, "repository_digest", digest)
        object.__setattr__(self, "dataset_version", dataset)
        object.__setattr__(self, "probability", probability)
        object.__setattr__(self, "probability_unavailable_reason", probability_reason)
        object.__setattr__(self, "unavailable_reason", reason)
        object.__setattr__(self, "policy_version", ATTACK_MAPPING_POLICY_VERSION)
        object.__setattr__(self, "evaluation_provenance", ATTACK_EVALUATION_PROVENANCE)

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": ATTACK_MAPPING_SCHEMA_VERSION,
            "repository_digest": self.repository_digest,
            "dataset_version": self.dataset_version,
            "ready": self.ready,
            "probability": self.probability,
            "probability_unavailable_reason": self.probability_unavailable_reason,
            "unavailable_reason": self.unavailable_reason,
            "policy_version": self.policy_version,
            "evaluation_provenance": self.evaluation_provenance,
            "confirmed": tuple(
                item.to_record() for item in self.decisions if item.status == "confirmed"
            ),
            "candidate": tuple(
                item.to_record() for item in self.decisions if item.status == "candidate"
            ),
            "rejected": tuple(
                item.to_record() for item in self.decisions if item.status == "rejected"
            ),
            "unavailable": tuple(
                item.to_record() for item in self.decisions if item.status == "unavailable"
            ),
        }


__all__ = (
    "ATTACK_PARENT_SCORING_POLICIES",
    "ATTACK_TECHNIQUE_ADMISSION_STATES",
    "AttackMappingDecision",
    "AttackMappingResult",
    "AttackTechniquePolicy",
    "aggregate_attack_probability",
)
