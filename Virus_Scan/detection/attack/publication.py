"""Strict JSON admission for official ATT&CK mapping publication."""
from __future__ import annotations

from Virus_Scan.detection.api.attack_mapping_contracts import ATTACK_MAPPING_SCHEMA_VERSION

import json
from math import isfinite

from Virus_Scan.detection.api.attack_repository_status_contracts import (
    validate_published_repository_status,
)
from Virus_Scan.detection.attack.mapping.contracts import (
    AttackMappingDecision,
    AttackMappingResult,
    aggregate_attack_probability,
)
from Virus_Scan.detection.attack.mapping.registry import (
    ATTACK_TECHNIQUE_POLICIES,
    ATTACK_TECHNIQUE_POLICY_BY_ID,
)
from Virus_Scan.detection.attack.validation import official_attack_id
from Virus_Scan.detection.attack.versioning import (
    ATTACK_EVALUATION_PROVENANCE,
    ATTACK_MAPPING_POLICY_VERSION,
)

_DECISION_FIELDS = frozenset({
    "technique_id",
    "parent_technique_id",
    "tactic_ids",
    "technique_name",
    "parent_technique_name",
    "tactic_names",
    "dataset_version",
    "status",
    "policy_implementation_ids",
    "required_chain_ids",
    "required_data_component_ids",
    "required_platforms",
    "required_modalities",
    "implementation_requirement_digests",
    "implementation_evaluation_manifest_digests",
    "strategy_ids",
    "analytic_ids",
    "policy_admission_state",
    "policy_requirement_digest_set",
    "policy_evaluation_manifest_digest",
    "policy_calibration_artifact_id",
    "implementation_ids",
    "claim_scopes",
    "execution_observed",
    "evidence_ids",
    "root_evidence_ids",
    "evidence_types",
    "rejected_evidence_ids",
    "missing_requirements",
    "observed_data_component_ids",
    "unavailable_fields",
    "evidence_directness",
    "direct_evidence_count",
    "inferred_evidence_count",
    "evidence_completeness",
    "probability",
    "probability_unavailable_reason",
    "support",
    "policy_version",
    "parent_scoring_policy",
    "correlation_group",
    "calibration_artifact_id",
    "rejection_reason",
    "unavailable_reason",
    "revoked",
    "deprecated",
})
_TOP_FIELDS = frozenset({
    "schema_version",
    "repository_digest",
    "dataset_version",
    "ready",
    "probability",
    "probability_unavailable_reason",
    "unavailable_reason",
    "policy_version",
    "evaluation_provenance",
    "confirmed",
    "candidate",
    "rejected",
    "unavailable",
    "mapping_scope",
    "technique_ids_claimed",
    "repository_status",
    "verified_yara_observation_count",
    "yara_alignment_count",
})


def _reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in out:
            raise ValueError("official_attack_evidence_duplicate_key")
        out[str.__str__(key)] = value
    return out


def _reject_constant(_value: str) -> object:
    raise ValueError("official_attack_evidence_nonfinite")


def _text(
    value: object,
    reason: str,
    *,
    blank: bool = False,
    maximum: int = 256,
) -> str:
    if type(value) is not str or len(value) > maximum or (not blank and value == ""):
        raise ValueError(reason)
    return str.__str__(value)


def _text_tuple(
    value: object,
    reason: str,
    *,
    maximum: int = 128,
) -> tuple[str, ...]:
    if (
        type(value) is not list
        or len(value) > maximum
        or any(type(item) is not str or item == "" for item in value)
    ):
        raise TypeError(reason)
    out = tuple(str.__str__(item) for item in value)
    if len(out) != len(set(out)):
        raise ValueError(reason)
    return out


def _integer(value: object, reason: str, *, maximum: int = 1_000_000) -> int:
    if (
        type(value) is not int
        or type(value) is bool
        or value < 0
        or value > maximum
    ):
        raise TypeError(reason)
    return value


def _probability(value: object, reason: str) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    number = float(value)
    if not isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(reason)
    return number


def _decision(raw: object, status: str) -> AttackMappingDecision:
    if type(raw) is not dict or set(raw) != _DECISION_FIELDS or raw.get("status") != status:
        raise ValueError("official_attack_decision_schema_invalid")
    technique_id = official_attack_id(raw.get("technique_id"))
    policy = ATTACK_TECHNIQUE_POLICY_BY_ID.get(technique_id)
    if policy is None:
        raise ValueError("official_attack_decision_technique_unregistered")
    implementation_ids = _text_tuple(
        raw.get("implementation_ids"),
        "official_attack_implementation_ids_invalid",
        maximum=16,
    )
    if any(item not in policy.implementation_ids for item in implementation_ids):
        raise ValueError("official_attack_implementation_policy_mismatch")
    policy_implementation_ids = _text_tuple(
        raw.get("policy_implementation_ids"),
        "official_attack_policy_implementation_ids_invalid",
        maximum=16,
    )
    if policy_implementation_ids != policy.implementation_ids:
        raise ValueError("official_attack_policy_implementation_mismatch")
    claim_scopes = _text_tuple(
        raw.get("claim_scopes"),
        "official_attack_claim_scopes_invalid",
        maximum=16,
    )
    if any(item not in policy.supported_claim_scopes for item in claim_scopes):
        raise ValueError("official_attack_claim_scope_policy_mismatch")
    direct = _integer(
        raw.get("direct_evidence_count"),
        "official_attack_direct_count_invalid",
        maximum=128,
    )
    inferred = _integer(
        raw.get("inferred_evidence_count"),
        "official_attack_inferred_count_invalid",
        maximum=128,
    )
    support = _integer(
        raw.get("support"), "official_attack_support_invalid", maximum=128,
    )
    completeness = _probability(
        raw.get("evidence_completeness"),
        "official_attack_completeness_invalid",
    )
    probability = _probability(
        raw.get("probability"), "official_attack_decision_probability_invalid",
    )
    decision = AttackMappingDecision(
        technique_id=technique_id,
        parent_technique_id=_text(
            raw.get("parent_technique_id"),
            "official_attack_parent_invalid",
            blank=True,
            maximum=16,
        ),
        tactic_ids=_text_tuple(
            raw.get("tactic_ids"), "official_attack_tactics_invalid", maximum=32,
        ),
        technique_name=_text(
            raw.get("technique_name"),
            "official_attack_technique_name_invalid",
            blank=True,
            maximum=256,
        ),
        parent_technique_name=_text(
            raw.get("parent_technique_name"),
            "official_attack_parent_name_invalid",
            blank=True,
            maximum=256,
        ),
        tactic_names=_text_tuple(
            raw.get("tactic_names"),
            "official_attack_tactic_names_invalid",
            maximum=32,
        ),
        dataset_version=_text(
            raw.get("dataset_version"),
            "official_attack_dataset_invalid",
            maximum=40,
        ),
        status=status,
        policy_implementation_ids=policy_implementation_ids,
        required_chain_ids=_text_tuple(
            raw.get("required_chain_ids"),
            "official_attack_required_chains_invalid",
            maximum=64,
        ),
        required_data_component_ids=_text_tuple(
            raw.get("required_data_component_ids"),
            "official_attack_required_data_components_invalid",
            maximum=64,
        ),
        required_platforms=_text_tuple(
            raw.get("required_platforms"),
            "official_attack_required_platforms_invalid",
            maximum=64,
        ),
        required_modalities=_text_tuple(
            raw.get("required_modalities"),
            "official_attack_required_modalities_invalid",
            maximum=32,
        ),
        implementation_requirement_digests=_text_tuple(
            raw.get("implementation_requirement_digests"),
            "official_attack_implementation_requirement_digests_invalid",
            maximum=32,
        ),
        implementation_evaluation_manifest_digests=_text_tuple(
            raw.get("implementation_evaluation_manifest_digests"),
            "official_attack_implementation_evaluation_digests_invalid",
            maximum=32,
        ),
        strategy_ids=_text_tuple(
            raw.get("strategy_ids"),
            "official_attack_strategy_ids_invalid",
            maximum=16,
        ),
        analytic_ids=_text_tuple(
            raw.get("analytic_ids"),
            "official_attack_analytic_ids_invalid",
            maximum=16,
        ),
        policy_admission_state=_text(
            raw.get("policy_admission_state"),
            "official_attack_policy_admission_invalid",
            maximum=32,
        ),
        policy_requirement_digest_set=_text_tuple(
            raw.get("policy_requirement_digest_set"),
            "official_attack_policy_requirement_digests_invalid",
            maximum=32,
        ),
        policy_evaluation_manifest_digest=_text(
            raw.get("policy_evaluation_manifest_digest"),
            "official_attack_policy_evaluation_digest_invalid",
            blank=True,
            maximum=64,
        ),
        policy_calibration_artifact_id=_text(
            raw.get("policy_calibration_artifact_id"),
            "official_attack_policy_calibration_invalid",
            blank=True,
            maximum=128,
        ),
        implementation_ids=implementation_ids,
        claim_scopes=claim_scopes,
        execution_observed=raw.get("execution_observed"),
        evidence_ids=_text_tuple(
            raw.get("evidence_ids"), "official_attack_evidence_ids_invalid",
        ),
        root_evidence_ids=_text_tuple(
            raw.get("root_evidence_ids"), "official_attack_root_ids_invalid",
        ),
        evidence_types=_text_tuple(
            raw.get("evidence_types"), "official_attack_evidence_types_invalid",
        ),
        rejected_evidence_ids=_text_tuple(
            raw.get("rejected_evidence_ids"),
            "official_attack_rejected_ids_invalid",
        ),
        missing_requirements=_text_tuple(
            raw.get("missing_requirements"),
            "official_attack_missing_requirements_invalid",
        ),
        observed_data_component_ids=_text_tuple(
            raw.get("observed_data_component_ids"),
            "official_attack_data_components_invalid",
            maximum=64,
        ),
        unavailable_fields=_text_tuple(
            raw.get("unavailable_fields"),
            "official_attack_unavailable_fields_invalid",
        ),
        direct_evidence_count=direct,
        inferred_evidence_count=inferred,
        evidence_completeness=completeness,
        probability=probability,
        probability_unavailable_reason=_text(
            raw.get("probability_unavailable_reason"),
            "official_attack_decision_probability_unavailable_invalid",
            blank=probability > 0.0,
        ),
        support=support,
        policy_version=_text(
            raw.get("policy_version"), "official_attack_policy_invalid", maximum=128,
        ),
        parent_scoring_policy=_text(
            raw.get("parent_scoring_policy"),
            "official_attack_parent_scoring_invalid",
            maximum=32,
        ),
        correlation_group=_text(
            raw.get("correlation_group"),
            "official_attack_group_invalid",
            maximum=128,
        ),
        calibration_artifact_id=_text(
            raw.get("calibration_artifact_id"),
            "official_attack_calibration_invalid",
            blank=True,
            maximum=128,
        ),
        rejection_reason=_text(
            raw.get("rejection_reason"),
            "official_attack_rejection_invalid",
            blank=True,
        ),
        unavailable_reason=_text(
            raw.get("unavailable_reason"),
            "official_attack_unavailable_reason_invalid",
            blank=True,
        ),
        revoked=raw.get("revoked"),
        deprecated=raw.get("deprecated"),
    )
    if (
        decision.policy_version != policy.policy_version
        or decision.parent_scoring_policy != policy.parent_scoring_policy
        or decision.correlation_group != policy.correlation_group
        or decision.policy_admission_state != policy.admission_state
        or decision.policy_requirement_digest_set != policy.requirement_digest_set
        or decision.policy_evaluation_manifest_digest != policy.evaluation_manifest_digest
        or decision.policy_calibration_artifact_id != policy.calibration_artifact_id
    ):
        raise ValueError("official_attack_decision_policy_mismatch")
    if (
        decision.probability > 0.0
        and decision.calibration_artifact_id != policy.calibration_artifact_id
    ):
        raise ValueError("official_attack_calibration_policy_mismatch")
    if decision.to_record()["evidence_directness"] != raw.get("evidence_directness"):
        raise ValueError("official_attack_directness_invalid")
    return decision


def parse_official_attack_probability_evidence(value: str) -> dict[str, object]:
    if type(value) is not str or len(value) > 2 * 1024 * 1024:
        raise TypeError("official_attack_evidence_json_invalid")
    raw = json.loads(
        value,
        object_pairs_hook=_reject_pairs,
        parse_constant=_reject_constant,
    )
    if type(raw) is not dict or set(raw) != _TOP_FIELDS:
        raise ValueError("official_attack_evidence_schema_invalid")
    if raw.get("schema_version") != ATTACK_MAPPING_SCHEMA_VERSION:
        raise ValueError("official_attack_evidence_version_invalid")
    if raw.get("mapping_scope") != "official_attack_techniques":
        raise ValueError("official_attack_mapping_scope_invalid")
    ready = raw.get("ready")
    claimed = raw.get("technique_ids_claimed")
    if type(ready) is not bool or type(claimed) is not bool:
        raise TypeError("official_attack_readiness_invalid")
    buckets: dict[str, tuple[AttackMappingDecision, ...]] = {}
    decisions_by_id: dict[str, AttackMappingDecision] = {}
    for status in ("confirmed", "candidate", "rejected", "unavailable"):
        values = raw.get(status)
        if type(values) is not list or len(values) > len(ATTACK_TECHNIQUE_POLICIES):
            raise TypeError("official_attack_decisions_invalid")
        parsed = tuple(_decision(item, status) for item in values)
        buckets[status] = parsed
        for decision in parsed:
            if decision.technique_id in decisions_by_id:
                raise ValueError("official_attack_duplicate_decision")
            decisions_by_id[decision.technique_id] = decision
    policy_ids = {policy.technique_id for policy in ATTACK_TECHNIQUE_POLICIES}
    if ready and set(decisions_by_id) != policy_ids:
        raise ValueError("official_attack_decision_set_incomplete")
    if not ready and decisions_by_id:
        raise ValueError("official_attack_unavailable_decisions_invalid")
    ordered = tuple(
        decisions_by_id[policy.technique_id]
        for policy in ATTACK_TECHNIQUE_POLICIES
        if policy.technique_id in decisions_by_id
    )
    probability = _probability(
        raw.get("probability"), "official_attack_probability_invalid",
    )
    if probability != aggregate_attack_probability(ordered):
        raise ValueError("official_attack_probability_mismatch")
    result = AttackMappingResult(
        repository_digest=_text(
            raw.get("repository_digest"),
            "official_attack_repository_digest_invalid",
            blank=not ready,
            maximum=64,
        ),
        dataset_version=_text(
            raw.get("dataset_version"),
            "official_attack_dataset_invalid",
            blank=not ready,
            maximum=40,
        ),
        decisions=ordered,
        probability=probability,
        probability_unavailable_reason=_text(
            raw.get("probability_unavailable_reason"),
            "official_attack_probability_unavailable_invalid",
            blank=not ready or probability > 0.0,
        ),
        ready=ready,
        unavailable_reason=_text(
            raw.get("unavailable_reason"),
            "official_attack_unavailable_reason_invalid",
            blank=ready,
        ),
        policy_version=_text(
            raw.get("policy_version"),
            "official_attack_policy_invalid",
            maximum=128,
        ),
        evaluation_provenance=_text(
            raw.get("evaluation_provenance"),
            "official_attack_evaluation_invalid",
            maximum=128,
        ),
    )
    if (
        result.policy_version != ATTACK_MAPPING_POLICY_VERSION
        or result.evaluation_provenance != ATTACK_EVALUATION_PROVENANCE
    ):
        raise ValueError("official_attack_policy_version_mismatch")
    if claimed is not bool(buckets["confirmed"]):
        raise ValueError("official_attack_claimed_state_invalid")
    record = result.to_record()
    record["mapping_scope"] = "official_attack_techniques"
    record["technique_ids_claimed"] = claimed
    record["repository_status"] = validate_published_repository_status(
        raw.get("repository_status"), result
    )
    record["verified_yara_observation_count"] = _integer(
        raw.get("verified_yara_observation_count"),
        "official_attack_yara_observation_count_invalid",
        maximum=256,
    )
    record["yara_alignment_count"] = _integer(
        raw.get("yara_alignment_count"),
        "official_attack_yara_alignment_count_invalid",
        maximum=512,
    )
    return record


__all__ = ("parse_official_attack_probability_evidence",)
