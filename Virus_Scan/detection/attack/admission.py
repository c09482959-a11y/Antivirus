"""Repository-bound, evidence-derived ATT&CK technique admission records."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.detection.api.attack_repository_contracts import AttackRepositorySnapshot
from Virus_Scan.detection.attack.capabilities import (
    SCANNER_CAPABILITIES,
    ScannerCapabilitySpec,
)
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID,
    AttackAnalyticImplementationSpec,
)
from Virus_Scan.detection.attack.mapping.contracts import AttackTechniquePolicy
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.attack.repository import technique_by_id
from Virus_Scan.detection.attack.validation import (
    exact_hex,
    official_attack_id,
    ordered_text_tuple,
)
from Virus_Scan.detection.registries.chain_registry import CHAIN_RULE_INDEX

ATTACK_TECHNIQUE_ADMISSION_VERSION = "stage2636_11020_technique_admission_v2"
_ADMISSION_STATES = frozenset({"candidate_only", "unsupported_by_sensors", "retired"})
_CALIBRATION_STATES = frozenset({"unavailable", "bound"})
_IDENTITY_STATES = frozenset({
    "official_active_repository_bound",
    "official_revoked_repository_bound",
    "official_missing_repository_bound",
})


@dataclass(frozen=True, slots=True)
class AttackTechniqueAdmissionRecord:
    """One repository-bound truthful disposition for a reviewed technique policy."""

    technique_id: str
    repository_digest: str
    dataset_version: str
    official_identity_state: str
    implementation_ids: tuple[str, ...]
    strategy_ids: tuple[str, ...]
    analytic_ids: tuple[str, ...]
    required_data_component_ids: tuple[str, ...]
    requirement_digest_set: tuple[str, ...]
    supported_platforms: tuple[str, ...]
    required_modalities: tuple[str, ...]
    required_observation_fields: tuple[str, ...]
    scanner_producer_ids: tuple[str, ...]
    chain_ids: tuple[str, ...]
    term_reachable_chain_ids: tuple[str, ...]
    confirmed_reachable_chain_ids: tuple[str, ...]
    end_to_end_fixture_ids: tuple[str, ...]
    admission_state: str
    evaluation_manifest_digest: str
    calibration_status: str
    unresolved_limitations: tuple[str, ...]
    version: str = ATTACK_TECHNIQUE_ADMISSION_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttackTechniqueAdmissionRecord:
            raise TypeError("attack_admission_owner_invalid")
        technique_id = official_attack_id(
            self.technique_id, "attack_admission_technique_invalid",
        )
        repository_digest = exact_hex(
            self.repository_digest, "attack_admission_repository_digest_invalid", length=64,
        )
        dataset_version = exact_hex(
            self.dataset_version, "attack_admission_dataset_version_invalid", length=40,
        )
        identity_state = exact_bounded_text(
            self.official_identity_state,
            "attack_admission_identity_state_invalid",
            maximum=64,
        )
        if identity_state not in _IDENTITY_STATES:
            raise ValueError("attack_admission_identity_state_invalid")
        implementation_ids = ordered_text_tuple(
            self.implementation_ids,
            "attack_admission_implementations_invalid",
            maximum_items=16,
        )
        strategy_ids = ordered_text_tuple(
            self.strategy_ids, "attack_admission_strategies_invalid", maximum_items=16,
        )
        analytic_ids = ordered_text_tuple(
            self.analytic_ids, "attack_admission_analytics_invalid", maximum_items=64,
        )
        data_components = ordered_text_tuple(
            self.required_data_component_ids,
            "attack_admission_data_components_invalid",
            maximum_items=128,
        )
        requirement_digests = ordered_text_tuple(
            self.requirement_digest_set,
            "attack_admission_requirement_digests_invalid",
            maximum_items=64,
        )
        if any(not official_attack_id(item).startswith("DET") for item in strategy_ids):
            raise ValueError("attack_admission_strategies_invalid")
        if any(not official_attack_id(item).startswith("AN") for item in analytic_ids):
            raise ValueError("attack_admission_analytics_invalid")
        if any(not official_attack_id(item).startswith("DC") for item in data_components):
            raise ValueError("attack_admission_data_components_invalid")
        requirement_digests = tuple(
            exact_hex(item, "attack_admission_requirement_digests_invalid", length=64)
            for item in requirement_digests
        )
        platforms = ordered_text_tuple(
            self.supported_platforms,
            "attack_admission_platforms_invalid",
            maximum_items=32,
        )
        modalities = ordered_text_tuple(
            self.required_modalities,
            "attack_admission_modalities_invalid",
            maximum_items=16,
        )
        fields = ordered_text_tuple(
            self.required_observation_fields,
            "attack_admission_fields_invalid",
            maximum_items=32,
        )
        producers = ordered_text_tuple(
            self.scanner_producer_ids,
            "attack_admission_producers_invalid",
            maximum_items=32,
        )
        chain_ids = ordered_text_tuple(
            self.chain_ids, "attack_admission_chains_invalid", maximum_items=32,
        )
        term_reachable = ordered_text_tuple(
            self.term_reachable_chain_ids,
            "attack_admission_term_reachable_invalid",
            maximum_items=32,
        )
        confirmed_reachable = ordered_text_tuple(
            self.confirmed_reachable_chain_ids,
            "attack_admission_confirmed_reachable_invalid",
            maximum_items=32,
        )
        fixtures = ordered_text_tuple(
            self.end_to_end_fixture_ids,
            "attack_admission_fixtures_invalid",
            maximum_items=32,
        )
        admission = exact_bounded_text(
            self.admission_state, "attack_admission_state_invalid", maximum=32,
        )
        evaluation_digest = exact_bounded_text(
            self.evaluation_manifest_digest,
            "attack_admission_evaluation_invalid",
            maximum=64,
            allow_blank=True,
        )
        calibration = exact_bounded_text(
            self.calibration_status,
            "attack_admission_calibration_invalid",
            maximum=32,
        )
        limitations = ordered_text_tuple(
            self.unresolved_limitations,
            "attack_admission_limitations_invalid",
            maximum_items=64,
        )
        if admission not in _ADMISSION_STATES:
            raise ValueError("attack_admission_state_invalid")
        if calibration not in _CALIBRATION_STATES:
            raise ValueError("attack_admission_calibration_invalid")
        if not limitations:
            raise ValueError("attack_admission_limitations_required")
        if identity_state == "official_missing_repository_bound":
            if strategy_ids or analytic_ids or data_components or requirement_digests:
                raise ValueError("attack_admission_missing_official_fields_invalid")
        if identity_state == "official_revoked_repository_bound" and admission != "retired":
            raise ValueError("attack_admission_revoked_state_invalid")
        if identity_state == "official_active_repository_bound" and admission == "retired":
            raise ValueError("attack_admission_active_state_invalid")
        if evaluation_digest or calibration != "unavailable":
            raise ValueError("attack_admission_unvalidated_artifact_invalid")
        if confirmed_reachable or fixtures:
            raise ValueError("attack_admission_unvalidated_reachability_invalid")
        if admission in {"unsupported_by_sensors", "retired"} and producers:
            raise ValueError("attack_admission_inactive_producers_invalid")
        if not set(term_reachable).issubset(chain_ids):
            raise ValueError("attack_admission_reachable_chain_invalid")
        object.__setattr__(self, "technique_id", technique_id)
        object.__setattr__(self, "repository_digest", repository_digest)
        object.__setattr__(self, "dataset_version", dataset_version)
        object.__setattr__(self, "official_identity_state", identity_state)
        object.__setattr__(self, "implementation_ids", implementation_ids)
        object.__setattr__(self, "strategy_ids", strategy_ids)
        object.__setattr__(self, "analytic_ids", analytic_ids)
        object.__setattr__(self, "required_data_component_ids", data_components)
        object.__setattr__(self, "requirement_digest_set", requirement_digests)
        object.__setattr__(self, "supported_platforms", platforms)
        object.__setattr__(self, "required_modalities", modalities)
        object.__setattr__(self, "required_observation_fields", fields)
        object.__setattr__(self, "scanner_producer_ids", producers)
        object.__setattr__(self, "chain_ids", chain_ids)
        object.__setattr__(self, "term_reachable_chain_ids", term_reachable)
        object.__setattr__(self, "confirmed_reachable_chain_ids", confirmed_reachable)
        object.__setattr__(self, "end_to_end_fixture_ids", fixtures)
        object.__setattr__(self, "admission_state", admission)
        object.__setattr__(self, "evaluation_manifest_digest", evaluation_digest)
        object.__setattr__(self, "calibration_status", calibration)
        object.__setattr__(self, "unresolved_limitations", limitations)
        object.__setattr__(self, "version", exact_bounded_text(
            self.version, "attack_admission_version_invalid", maximum=128,
        ))

    def to_record(self) -> dict[str, object]:
        return {
            "technique_id": self.technique_id,
            "repository_digest": self.repository_digest,
            "dataset_version": self.dataset_version,
            "official_identity_state": self.official_identity_state,
            "implementation_ids": self.implementation_ids,
            "strategy_ids": self.strategy_ids,
            "analytic_ids": self.analytic_ids,
            "required_data_component_ids": self.required_data_component_ids,
            "requirement_digest_set": self.requirement_digest_set,
            "supported_platforms": self.supported_platforms,
            "required_modalities": self.required_modalities,
            "required_observation_fields": self.required_observation_fields,
            "scanner_producer_ids": self.scanner_producer_ids,
            "chain_ids": self.chain_ids,
            "term_reachable_chain_ids": self.term_reachable_chain_ids,
            "confirmed_reachable_chain_ids": self.confirmed_reachable_chain_ids,
            "end_to_end_fixture_ids": self.end_to_end_fixture_ids,
            "admission_state": self.admission_state,
            "evaluation_manifest_digest": self.evaluation_manifest_digest,
            "calibration_status": self.calibration_status,
            "unresolved_limitations": self.unresolved_limitations,
            "version": self.version,
        }


def _required_chain_fields(chain_ids: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted({
        field
        for chain_id in chain_ids
        for field in CHAIN_RULE_INDEX[chain_id].required_fields
    }))


def _chain_has_observable_terms(chain_id: str, observable: frozenset[str]) -> bool:
    rule = CHAIN_RULE_INDEX[chain_id]
    return all(any(term in observable for term in step.alternatives) for step in rule.steps)


def _official_requirements(
    snapshot: AttackRepositorySnapshot,
    technique_id: str,
) -> tuple[object | None, tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    technique = technique_by_id(snapshot, technique_id)
    if technique is None:
        return None, (), (), (), ()
    strategies = tuple(snapshot.strategies_by_technique_id.get(technique_id, ()))
    analytics = tuple(
        analytic
        for strategy in strategies
        for analytic_stix_id in strategy.analytic_stix_ids
        for analytic in (snapshot.analytic_by_stix_id.get(analytic_stix_id),)
        if analytic is not None
    )
    data_components = tuple(sorted({
        component.attack_id
        for analytic in analytics
        for component in snapshot.data_components_by_analytic_id.get(analytic.attack_id, ())
    }))
    requirement_digests = tuple(sorted({
        snapshot.analytic_requirement_digest_by_id[analytic.attack_id]
        for analytic in analytics
        if analytic.attack_id in snapshot.analytic_requirement_digest_by_id
    }))
    return (
        technique,
        tuple(sorted(strategy.attack_id for strategy in strategies)),
        tuple(sorted(analytic.attack_id for analytic in analytics)),
        data_components,
        requirement_digests,
    )


def _admission_record(
    snapshot: AttackRepositorySnapshot,
    policy: AttackTechniquePolicy,
    *,
    capabilities: tuple[ScannerCapabilitySpec, ...],
    implementation_by_id: Mapping[str, AttackAnalyticImplementationSpec],
) -> AttackTechniqueAdmissionRecord:
    implementations = tuple(implementation_by_id[item] for item in policy.implementation_ids)
    chain_ids = tuple(sorted({
        chain_id for implementation in implementations for chain_id in implementation.chain_ids
    }))
    platforms = tuple(sorted({
        platform for implementation in implementations for platform in implementation.platforms
    }))
    modalities = tuple(sorted({
        modality
        for implementation in implementations
        for modality in implementation.required_modalities
    }))
    fields = _required_chain_fields(chain_ids)
    observable = frozenset(
        tag for capability in capabilities for tag in capability.observable_tag_ids
    )
    term_reachable = tuple(
        chain_id for chain_id in chain_ids if _chain_has_observable_terms(chain_id, observable)
    )
    chain_terms = {
        term
        for chain_id in chain_ids
        for step in CHAIN_RULE_INDEX[chain_id].steps
        for term in step.alternatives
    }
    relevant_capabilities = tuple(
        capability
        for capability in capabilities
        if set(capability.observable_tag_ids).intersection(chain_terms)
    )
    producers = tuple(sorted({item.producer_id for item in relevant_capabilities}))
    if policy.admission_state in {"unsupported_by_sensors", "retired"}:
        producers = ()
        term_reachable = ()
    technique, strategies, analytics, data_components, requirement_digests = (
        _official_requirements(snapshot, policy.technique_id)
    )
    if technique is None:
        identity_state = "official_missing_repository_bound"
    elif technique.revoked or technique.deprecated:
        identity_state = "official_revoked_repository_bound"
    else:
        identity_state = "official_active_repository_bound"
    limitations = {
        "calibration_artifact_unavailable",
        "end_to_end_reachability_fixture_unavailable",
        "evaluation_manifest_unavailable",
    }
    if technique is None:
        limitations.add("official_technique_missing_from_bound_repository")
    elif not strategies or not analytics:
        limitations.add("official_detection_strategy_or_analytic_unavailable")
    if policy.admission_state == "unsupported_by_sensors":
        limitations.add("local_sensor_implementation_unavailable")
    elif policy.admission_state == "retired":
        limitations.update({
            "official_technique_revoked_in_bound_repository",
            "local_implementation_quarantined",
        })
    else:
        limitations.add("local_artifact_scope_not_official_runtime_analytic")
        if data_components:
            limitations.add("official_runtime_data_components_not_satisfied_by_static_artifact")
        limitations.update(
            reason
            for capability in relevant_capabilities
            for reason in capability.limitation_reasons
        )
        if len(term_reachable) != len(chain_ids):
            limitations.add("one_or_more_chain_term_sets_unreachable")
    return AttackTechniqueAdmissionRecord(
        technique_id=policy.technique_id,
        repository_digest=snapshot.digest,
        dataset_version=snapshot.version.dataset_version,
        official_identity_state=identity_state,
        implementation_ids=policy.implementation_ids,
        strategy_ids=strategies,
        analytic_ids=analytics,
        required_data_component_ids=data_components,
        requirement_digest_set=requirement_digests,
        supported_platforms=platforms,
        required_modalities=modalities,
        required_observation_fields=fields,
        scanner_producer_ids=producers,
        chain_ids=chain_ids,
        term_reachable_chain_ids=term_reachable,
        confirmed_reachable_chain_ids=(),
        end_to_end_fixture_ids=(),
        admission_state=policy.admission_state,
        evaluation_manifest_digest="",
        calibration_status="unavailable",
        unresolved_limitations=tuple(sorted(limitations)),
    )


def build_attack_technique_admission_records(
    snapshot: AttackRepositorySnapshot,
    *,
    policies: tuple[AttackTechniquePolicy, ...] = ATTACK_TECHNIQUE_POLICIES,
    capabilities: tuple[ScannerCapabilitySpec, ...] = SCANNER_CAPABILITIES,
    implementation_by_id: Mapping[str, AttackAnalyticImplementationSpec] = (
        ATTACK_ANALYTIC_IMPLEMENTATION_BY_ID
    ),
) -> tuple[AttackTechniqueAdmissionRecord, ...]:
    """Build the only admission records from one immutable repository snapshot."""
    if type(snapshot) is not AttackRepositorySnapshot:
        raise TypeError("attack_admission_repository_required")
    if type(policies) is not tuple or any(type(item) is not AttackTechniquePolicy for item in policies):
        raise TypeError("attack_admission_policies_invalid")
    if type(capabilities) is not tuple or any(type(item) is not ScannerCapabilitySpec for item in capabilities):
        raise TypeError("attack_admission_capabilities_invalid")
    if not isinstance(implementation_by_id, Mapping):
        raise TypeError("attack_admission_implementation_index_invalid")
    records = tuple(
        _admission_record(
            snapshot,
            policy,
            capabilities=capabilities,
            implementation_by_id=implementation_by_id,
        )
        for policy in policies
    )
    if len({item.technique_id for item in records}) != len(records):
        raise ValueError("attack_admission_duplicate_technique")
    return records


def attack_technique_admission_index(
    snapshot: AttackRepositorySnapshot,
) -> Mapping[str, AttackTechniqueAdmissionRecord]:
    records = build_attack_technique_admission_records(snapshot)
    return MappingProxyType({item.technique_id: item for item in records})


def attack_technique_admission_manifest(
    snapshot: AttackRepositorySnapshot,
) -> dict[str, object]:
    records_owned = build_attack_technique_admission_records(snapshot)
    records = tuple(item.to_record() for item in records_owned)
    digest = sha256(json.dumps(
        records, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    return {
        "version": ATTACK_TECHNIQUE_ADMISSION_VERSION,
        "repository_digest": snapshot.digest,
        "dataset_version": snapshot.version.dataset_version,
        "digest": digest,
        "record_count": len(records),
        "candidate_only_count": sum(
            item.admission_state == "candidate_only" for item in records_owned
        ),
        "unsupported_count": sum(
            item.admission_state == "unsupported_by_sensors" for item in records_owned
        ),
        "retired_count": sum(item.admission_state == "retired" for item in records_owned),
        "confirmed_reachable_count": sum(
            bool(item.confirmed_reachable_chain_ids) for item in records_owned
        ),
        "records": records,
    }


__all__ = (
    "ATTACK_TECHNIQUE_ADMISSION_VERSION",
    "AttackTechniqueAdmissionRecord",
    "attack_technique_admission_index",
    "attack_technique_admission_manifest",
    "build_attack_technique_admission_records",
)
