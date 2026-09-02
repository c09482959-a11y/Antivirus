"""Evaluation-only validation for artifact-backed synthetic ATT&CK challenge pairs."""
from __future__ import annotations

from Virus_Scan.stress.attack_synthetic_schema import (
    SyntheticAttackChallengePairDefinition,
)
from Virus_Scan.detection.attack.evaluation_contracts import AttackTechniqueExpectation
from Virus_Scan.stress.static_semantic_schema import ArtifactEvidenceTruth


def _operation_set(truth: ArtifactEvidenceTruth) -> set[str]:
    return set(truth.operation_kinds)


def _reachable_set(truth: ArtifactEvidenceTruth, state: str) -> set[str]:
    return {
        item.operation_kind for item in truth.reachability
        if item.reachability_state == state
    }


def _flow_pairs(truth: ArtifactEvidenceTruth, connected: bool) -> set[tuple[str, str]]:
    return {
        (item.source_operation_kind, item.sink_operation_kind)
        for item in truth.flow if item.connected is connected
    }


def _require(condition: bool, challenge_id: str, reason: str) -> None:
    if not condition:
        raise ValueError(
            "synthetic_attack_challenge_pair_invalid:" + challenge_id + ":" + reason
        )


def _validate_relations(
    definition: SyntheticAttackChallengePairDefinition,
    positive: ArtifactEvidenceTruth,
    control: ArtifactEvidenceTruth,
) -> None:
    kinds = set(definition.challenge_kinds)
    positive_ops = _operation_set(positive)
    control_ops = _operation_set(control)
    challenge_id = definition.challenge_id
    if kinds & {"documentation_only", "strings_only_false_positive", "yara_only_control"}:
        _require(not (positive_ops & control_ops), challenge_id, "control_behavior_present")
    if kinds & {"dead_code", "unreachable_behavior"}:
        desired = set(definition.positive_fixture.generation_intent.desired_operation_kinds)
        _require(desired <= positive_ops <= control_ops, challenge_id, "operation_parity_missing")
        _require(desired <= _reachable_set(positive, "entrypoint_reachable"), challenge_id, "positive_unreachable")
        _require(desired <= _reachable_set(control, "unreachable"), challenge_id, "control_reachable")
    if "incomplete_operation_sequence" in kinds:
        _require(bool(positive_ops - control_ops), challenge_id, "sequence_not_incomplete")
    if "wrong_target_resource" in kinds:
        _require(positive_ops == control_ops, challenge_id, "operation_identity_changed")
        _require(set(positive.resource_identities) != set(control.resource_identities), challenge_id, "resource_identity_not_changed")
        _require(_flow_pairs(positive, True) == _flow_pairs(control, True), challenge_id, "flow_identity_changed")
    if "disconnected_flow" in kinds:
        connected = _flow_pairs(positive, True)
        _require(bool(connected), challenge_id, "positive_connected_flow_missing")
        _require(positive_ops == control_ops, challenge_id, "operation_identity_changed")
        _require(connected <= _flow_pairs(control, False), challenge_id, "control_flow_not_disconnected")
    if "unresolved_dynamic_behavior" in kinds:
        _require(control.evidence_completeness != "complete", challenge_id, "control_not_partial")
        _require(bool(control.analysis_limitations), challenge_id, "control_limitation_missing")
    if kinds & {"supported_static_behavior", "behavior_detectable_without_yara", "yara_corroborated_behavior"}:
        _require(positive.evidence_completeness == "complete", challenge_id, "positive_not_complete")
        _require(bool(positive_ops), challenge_id, "positive_behavior_missing")


def _validate_unsupported_policy(
    definition: SyntheticAttackChallengePairDefinition,
    decisions: tuple[AttackTechniqueExpectation, ...],
) -> None:
    if "unsupported_physically_present_behavior" not in definition.challenge_kinds:
        return
    desired = set(definition.positive_fixture.generation_intent.desired_technique_ids)
    matched = {
        item.technique_id for item in decisions
        if item.technique_id in desired
        and item.expected_state == "unavailable"
    }
    _require(bool(matched), definition.challenge_id, "unsupported_physical_behavior_missing")


def validate_synthetic_attack_challenge_pair(
    definition: SyntheticAttackChallengePairDefinition,
    positive: ArtifactEvidenceTruth,
    control: ArtifactEvidenceTruth,
    positive_decisions: tuple[AttackTechniqueExpectation, ...],
) -> dict[str, object]:
    """Validate a declared adversarial relation without creating evidence authority."""
    if type(definition) is not SyntheticAttackChallengePairDefinition:
        raise TypeError("synthetic_attack_challenge_pair_definition_invalid")
    if type(positive) is not ArtifactEvidenceTruth or type(control) is not ArtifactEvidenceTruth:
        raise TypeError("synthetic_attack_challenge_pair_truth_invalid")
    if type(positive_decisions) is not tuple or any(
        type(item) is not AttackTechniqueExpectation for item in positive_decisions
    ):
        raise TypeError("synthetic_attack_challenge_pair_decisions_invalid")
    _require(positive.sample_id != control.sample_id, definition.challenge_id, "sample_identity_shared")
    _require(positive.artifact_sha256 != control.artifact_sha256, definition.challenge_id, "artifact_identity_shared")
    _validate_relations(definition, positive, control)
    _validate_unsupported_policy(definition, positive_decisions)
    return {
        **definition.to_hidden_record(),
        "control_artifact_evidence_digest": control.digest,
        "control_sample_id": control.sample_id,
        "positive_artifact_evidence_digest": positive.digest,
        "positive_sample_id": positive.sample_id,
        "validation": "satisfied",
    }


__all__ = ("validate_synthetic_attack_challenge_pair",)
