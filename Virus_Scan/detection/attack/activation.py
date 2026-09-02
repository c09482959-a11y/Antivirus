"""Canonical ATT&CK repository/policy activation and semantic-drift owner."""
from __future__ import annotations

from Virus_Scan.detection.api.attack_activation_contracts import AttackActivationRecord
from Virus_Scan.detection.api.attack_repository_contracts import AttackRepositorySnapshot
from Virus_Scan.detection.attack.alignment import (
    TAG_STIX_ALIGNMENT_SPECS,
    TagStixAlignmentSpec,
)
from Virus_Scan.detection.attack.calibration import (
    ATTACK_CALIBRATION_ARTIFACTS,
    AttackCalibrationArtifact,
)
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATIONS,
    AttackAnalyticImplementationSpec,
)
from Virus_Scan.detection.attack.mapping.contracts import AttackTechniquePolicy
from Virus_Scan.detection.attack.mapping.registry import ATTACK_TECHNIQUE_POLICIES
from Virus_Scan.detection.attack.repository import technique_by_id

_ACTIVE_ALIGNMENT_STATES = frozenset({"exact", "partial"})
_ACTIVE_POLICY_STATES = frozenset({"confirmed_enabled", "production_mature"})


def _inactive_lifecycle(item: object | None) -> bool:
    return item is None or (
        object.__getattribute__(item, "revoked") is True
        or object.__getattribute__(item, "deprecated") is True
    )


def _alignment_current(
    alignment: TagStixAlignmentSpec,
    snapshot: AttackRepositorySnapshot,
) -> bool:
    return (
        alignment.dataset_requirement_digest
        in snapshot.analytic_requirement_digest_by_id.values()
        and set(alignment.data_component_ids).issubset(snapshot.data_component_by_attack_id)
    )


def _official_implementation_current(
    implementation: AttackAnalyticImplementationSpec,
    snapshot: AttackRepositorySnapshot,
) -> bool:
    if implementation.support_mode != "exact_official":
        return True
    analytic = snapshot.analytic_by_attack_id.get(implementation.analytic_id)
    strategy = snapshot.strategy_by_attack_id.get(implementation.strategy_id)
    return (
        analytic is not None
        and strategy is not None
        and snapshot.analytic_requirement_digest_by_id.get(implementation.analytic_id)
        == implementation.requirement_digest
        and set(implementation.required_data_component_ids).issubset(
            snapshot.data_component_by_attack_id
        )
        and strategy in snapshot.strategies_by_technique_id.get(
            implementation.technique_id, ()
        )
        and analytic in snapshot.analytics_by_strategy_id.get(
            implementation.strategy_id, ()
        )
    )


def build_attack_activation_record(
    snapshot: AttackRepositorySnapshot,
    *,
    alignments: object = TAG_STIX_ALIGNMENT_SPECS,
    implementations: object = ATTACK_ANALYTIC_IMPLEMENTATIONS,
    policies: object = ATTACK_TECHNIQUE_POLICIES,
    calibrations: object = ATTACK_CALIBRATION_ARTIFACTS,
) -> AttackActivationRecord:
    if type(snapshot) is not AttackRepositorySnapshot:
        raise TypeError("attack_activation_repository_required")
    typed_inputs = (
        (alignments, TagStixAlignmentSpec, "attack_activation_alignments_invalid"),
        (implementations, AttackAnalyticImplementationSpec, "attack_activation_implementations_invalid"),
        (policies, AttackTechniquePolicy, "attack_activation_policies_invalid"),
        (calibrations, AttackCalibrationArtifact, "attack_activation_calibrations_invalid"),
    )
    for values, owner, reason in typed_inputs:
        if type(values) is not tuple or len(values) > 4096:
            raise TypeError(reason)
        if any(type(item) is not owner for item in values):
            raise TypeError(reason)

    active_alignments: set[str] = set()
    quarantined_alignments: set[str] = set()
    for alignment in alignments:
        if alignment.alignment_state not in _ACTIVE_ALIGNMENT_STATES:
            continue
        target = active_alignments if _alignment_current(alignment, snapshot) else quarantined_alignments
        target.add(alignment.tag_id)

    implementation_by_id = {item.implementation_id: item for item in implementations}
    if len(implementation_by_id) != len(implementations):
        raise ValueError("attack_activation_duplicate_implementation")
    active_implementations: set[str] = set()
    quarantined_implementations: set[str] = set()
    for implementation in implementations:
        technique = technique_by_id(snapshot, implementation.technique_id)
        invalid = _inactive_lifecycle(technique) or not _official_implementation_current(
            implementation, snapshot,
        )
        if implementation.admission_state == "quarantined" or invalid:
            quarantined_implementations.add(implementation.implementation_id)
        elif implementation.admission_state == "confirmed_enabled":
            active_implementations.add(implementation.implementation_id)

    active_policies: set[str] = set()
    quarantined_policies: set[str] = set()
    retired_policies: set[str] = set()
    policy_by_id = {item.technique_id: item for item in policies}
    if len(policy_by_id) != len(policies):
        raise ValueError("attack_activation_duplicate_policy")
    live_requirement_digests = set(snapshot.analytic_requirement_digest_by_id.values())
    for policy in policies:
        technique = technique_by_id(snapshot, policy.technique_id)
        if policy.admission_state == "retired" or (
            technique is not None and _inactive_lifecycle(technique)
        ):
            retired_policies.add(policy.technique_id)
            continue
        if technique is None or policy.admission_state == "quarantined":
            quarantined_policies.add(policy.technique_id)
            continue
        if policy.admission_state in _ACTIVE_POLICY_STATES:
            valid = (
                bool(policy.implementation_ids)
                and set(policy.implementation_ids).issubset(active_implementations)
                and set(policy.requirement_digest_set).issubset(live_requirement_digests)
            )
            (active_policies if valid else quarantined_policies).add(policy.technique_id)

    calibration_by_id = {item.calibration_id: item for item in calibrations}
    if len(calibration_by_id) != len(calibrations):
        raise ValueError("attack_activation_duplicate_calibration")
    active_calibrations: set[str] = set()
    quarantined_calibrations: set[str] = set()
    for policy_id in active_policies:
        policy = policy_by_id[policy_id]
        if policy.admission_state != "production_mature":
            continue
        artifact = calibration_by_id.get(policy.calibration_artifact_id)
        valid = artifact is not None and (
            artifact.evaluation_manifest_digest == policy.evaluation_manifest_digest
            and artifact.requirement_digest_set == policy.requirement_digest_set
            and policy.technique_id in artifact.technique_ids
        )
        (active_calibrations if valid else quarantined_calibrations).add(
            policy.calibration_artifact_id
        )

    return AttackActivationRecord(
        dataset_version=snapshot.version.dataset_version,
        repository_digest=snapshot.digest,
        active_alignment_ids=tuple(sorted(active_alignments)),
        quarantined_alignment_ids=tuple(sorted(quarantined_alignments)),
        active_implementation_ids=tuple(sorted(active_implementations)),
        quarantined_implementation_ids=tuple(sorted(quarantined_implementations)),
        active_policy_ids=tuple(sorted(active_policies)),
        quarantined_policy_ids=tuple(sorted(quarantined_policies)),
        retired_policy_ids=tuple(sorted(retired_policies)),
        active_calibration_ids=tuple(sorted(active_calibrations)),
        quarantined_calibration_ids=tuple(sorted(quarantined_calibrations)),
    )


__all__ = (
    "build_attack_activation_record",
)
