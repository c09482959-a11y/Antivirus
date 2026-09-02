"""Pure publication projection for evidence-backed ATT&CK decision explainability.

This module does not evaluate ATT&CK, Chains, YARA, or static analysis.  It joins
already-frozen canonical evidence with the immutable official mapping result and
context-only discovery provenance so publication can expose the authority chain.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.artifact_evidence_snapshot import ArtifactEvidenceSnapshot
from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.chain_evidence import ChainDecision, ChainRule
from Virus_Scan.contracts.evidence_discovery_plan import EvidenceDiscoveryPlan
from Virus_Scan.detection.api.attack_explainability_contracts import (
    ATTACK_EXPLAINABILITY_SCHEMA_VERSION,
)
from Virus_Scan.detection.attack.candidate_retrieval import AttackCandidateRetrievalResult
from Virus_Scan.detection.attack.mapping.contracts import AttackMappingDecision, AttackMappingResult
from Virus_Scan.detection.models.stage_value_utils import freeze_detection_value, thaw_detection_value
_YARA_ROLES = frozenset({"corroborated", "not_used", "absent"})


def _chain_index(evidence: ArtifactEvidenceSnapshot) -> dict[str, ChainDecision]:
    index: dict[str, ChainDecision] = {}
    for item in evidence.chain_evidence.decisions:
        chain_id = item.candidate.chain_id
        if chain_id in index:
            raise ValueError("attack_explainability_chain_identity_duplicate")
        index[chain_id] = item
    return index


def _step_requirements(rule: ChainRule) -> tuple[str, ...]:
    return tuple(
        f"{index}:" + "|".join(step.alternatives) + (":optional" if step.optional else ":required")
        for index, step in enumerate(rule.steps)
    )


def _relation_requirement_record(relation: object) -> dict[str, object]:
    record = relation.to_record()
    record["requirement_kind"] = "verified_static_relation"
    return record


def _correlation_requirements(rule: ChainRule) -> tuple[str, ...]:
    values = []
    for name in (
        "same_actor", "same_target", "same_artifact", "same_host",
        "same_process", "same_connection", "platform_match",
    ):
        if getattr(rule, name) is True:
            values.append(name)
    values.extend("required_platform:" + value for value in rule.required_platforms)
    values.extend("required_modality:" + value for value in rule.required_modalities)
    values.extend("required_field:" + value for value in rule.required_fields)
    return tuple(values)


def _matched_step_records(chain: ChainDecision) -> tuple[dict[str, object], ...]:
    return tuple({
        "step_index": step.step_index,
        "matched_alternative": step.alternative,
        "evidence_id": step.event.evidence_id,
        "root_evidence_id": step.event.root_evidence_id,
        "term": step.event.term,
        "source": step.event.source,
        "modality": step.event.modality,
        "platform": step.event.platform,
        "directness": step.event.directness,
        "integrity_status": step.event.integrity_status,
    } for step in chain.candidate.matched_steps)


def _chain_requirement_record(chain_id: str, chain: ChainDecision | None) -> dict[str, object]:
    if chain is None:
        return {
            "chain_id": chain_id, "chain_status": "missing", "satisfied": False,
            "step_requirements": (), "matched_steps": (), "relation_requirements": (),
            "correlation_requirements": (), "unmet_requirements": ("required_chain_missing",),
            "matched_evidence_ids": (), "root_evidence_ids": (),
        }
    return {
        "chain_id": chain_id,
        "chain_status": chain.status,
        "satisfied": chain.status == "confirmed" and not chain.candidate.unmet_requirements,
        "step_requirements": _step_requirements(chain.rule),
        "matched_steps": _matched_step_records(chain),
        "relation_requirements": tuple(
            _relation_requirement_record(item) for item in chain.rule.static_relations
        ),
        "correlation_requirements": _correlation_requirements(chain.rule),
        "unmet_requirements": chain.candidate.unmet_requirements,
        "matched_evidence_ids": tuple(
            step.event.evidence_id for step in chain.candidate.matched_steps
        ),
        "root_evidence_ids": tuple(sorted(chain.candidate.distinct_root_ids)),
    }


def _observation_root_record(item: object) -> dict[str, object]:
    return {
        "root_evidence_id": item.root_observation_id,
        "source_kind": "physical_observation",
        "tag": item.tag,
        "producer_id": item.producer_id,
        "stage_id": item.stage_id,
        "modality": item.modality,
        "platform": item.platform,
        "directness": item.directness,
        "integrity_status": item.integrity_status,
        "source_location": item.source_location.to_record(),
    }


def _yara_root_record(hit: object) -> dict[str, object]:
    return {
        "root_evidence_id": hit.root_observation_id,
        "source_kind": "yara_physical_hit",
        "rule_identity_digest": hit.rule_identity.digest,
        "rule_name": hit.rule_identity.rule_name,
        "package_kind": hit.rule_identity.package_kind,
        "integrity_status": hit.integrity_status,
        "source_trust": hit.source_trust,
        "source_location": hit.source_location.to_record(),
    }


def _root_index(evidence: ArtifactEvidenceSnapshot) -> dict[str, dict[str, object]]:
    index = {
        item.root_observation_id: _observation_root_record(item)
        for item in evidence.physical_observations
    }
    for hit in evidence.yara_scan_result.hits:
        if hit.root_observation_id in index:
            raise ValueError("attack_explainability_physical_root_duplicate")
        index[hit.root_observation_id] = _yara_root_record(hit)
    return index


def _decision_roots(
    decision: AttackMappingDecision,
    roots: Mapping[str, dict[str, object]],
) -> tuple[dict[str, object], ...]:
    records = []
    for root_id in decision.root_evidence_ids:
        record = roots.get(root_id)
        if record is None:
            raise ValueError("attack_explainability_mapping_root_not_physical")
        records.append(record)
    return tuple(records)


def _yara_role(
    decision: AttackMappingDecision,
    evidence: ArtifactEvidenceSnapshot,
) -> dict[str, object]:
    yara_roots = {hit.root_observation_id for hit in evidence.yara_scan_result.hits}
    used = tuple(sorted(yara_roots.intersection(decision.root_evidence_ids)))
    role = "corroborated" if used else "not_used" if yara_roots else "absent"
    if role not in _YARA_ROLES:
        raise AssertionError("attack_explainability_yara_role_invalid")
    return {
        "role": role,
        "used_root_evidence_ids": used,
        "physical_hit_count": len(evidence.yara_scan_result.hits),
        "verified_hit_count": sum(hit.verified for hit in evidence.yara_scan_result.hits),
        "authority_bounded_to_reviewed_evidence": True,
    }


def _model_assistance(
    decision: AttackMappingDecision,
    candidate: AttackCandidateRetrievalResult,
    plan: EvidenceDiscoveryPlan,
) -> dict[str, object]:
    ranked = next((item for item in candidate.candidates if item.technique_id == decision.technique_id), None)
    queries = tuple(
        item.to_record() for item in plan.queries if item.technique_id == decision.technique_id
    )
    return {
        "candidate_rank": 0 if ranked is None else ranked.rank,
        "candidate_score": 0.0 if ranked is None else ranked.score,
        "discovery_queries": queries,
        "evidence_authority": "context_only",
        "official_decision_effect": "none",
    }


def _decision_record(
    decision: AttackMappingDecision,
    evidence: ArtifactEvidenceSnapshot,
    chains: Mapping[str, ChainDecision],
    roots: Mapping[str, dict[str, object]],
    candidate: AttackCandidateRetrievalResult,
    plan: EvidenceDiscoveryPlan,
) -> dict[str, object]:
    requirements = tuple(
        _chain_requirement_record(chain_id, chains.get(chain_id))
        for chain_id in decision.required_chain_ids
    )
    return {
        "technique_id": decision.technique_id,
        "status": decision.status,
        "claim_scopes": decision.claim_scopes,
        "execution_observed": decision.execution_observed,
        "requirements": requirements,
        "physical_roots": _decision_roots(decision, roots),
        "deterministic_derivations": tuple(
            {"derivation_kind": "chain_evidence", **record}
            for record in requirements if record["chain_status"] != "missing"
        ),
        "missing_requirements": decision.missing_requirements,
        "unavailable_fields": decision.unavailable_fields,
        "yara": _yara_role(decision, evidence),
        "model_assistance": _model_assistance(decision, candidate, plan),
    }


@dataclass(frozen=True, slots=True)
class AttackExplainabilitySnapshot:
    """Immutable pure publication projection; it cannot alter ATT&CK decisions."""

    source_artifact_evidence_digest: str
    attack_mapping_digest: str
    candidate_retrieval_digest: str
    discovery_plan_digest: str
    decisions: tuple[Mapping[str, object], ...]
    semantic_digest: str

    def __post_init__(self) -> None:
        if type(self) is not AttackExplainabilitySnapshot:
            raise TypeError("attack_explainability_snapshot_owner_invalid")
        digests = {
            "source_artifact_evidence_digest": self.source_artifact_evidence_digest,
            "attack_mapping_digest": self.attack_mapping_digest,
            "candidate_retrieval_digest": self.candidate_retrieval_digest,
            "discovery_plan_digest": self.discovery_plan_digest,
        }
        for name, value in digests.items():
            if (
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise ValueError("attack_explainability_" + name + "_invalid")
        if type(self.decisions) is not tuple:
            raise TypeError("attack_explainability_decisions_invalid")
        frozen_decisions = []
        for item in self.decisions:
            if not isinstance(item, Mapping):
                raise TypeError("attack_explainability_decision_record_invalid")
            frozen = freeze_detection_value(thaw_detection_value(item))
            if not isinstance(frozen, Mapping):
                raise TypeError("attack_explainability_decision_record_invalid")
            frozen_decisions.append(frozen)
        object.__setattr__(self, "decisions", tuple(frozen_decisions))
        computed = canonical_json_sha256(self._semantic_record())
        if self.semantic_digest != computed:
            raise ValueError("attack_explainability_semantic_digest_mismatch")

    def _semantic_record(self) -> dict[str, object]:
        return {
            "schema_version": ATTACK_EXPLAINABILITY_SCHEMA_VERSION,
            "source_artifact_evidence_digest": self.source_artifact_evidence_digest,
            "attack_mapping_digest": self.attack_mapping_digest,
            "candidate_retrieval_digest": self.candidate_retrieval_digest,
            "discovery_plan_digest": self.discovery_plan_digest,
            "decisions": tuple(thaw_detection_value(item) for item in self.decisions),
            "projection_role": "explainability_only",
            "official_decision_effect": "none",
        }

    def to_record(self) -> dict[str, object]:
        record = self._semantic_record()
        record["semantic_digest"] = self.semantic_digest
        return record


def build_attack_explainability(
    evidence: ArtifactEvidenceSnapshot,
    mapping: AttackMappingResult,
    candidate: AttackCandidateRetrievalResult,
    plan: EvidenceDiscoveryPlan,
) -> AttackExplainabilitySnapshot:
    if type(evidence) is not ArtifactEvidenceSnapshot:
        raise TypeError("attack_explainability_evidence_required")
    if type(mapping) is not AttackMappingResult:
        raise TypeError("attack_explainability_mapping_required")
    if type(candidate) is not AttackCandidateRetrievalResult:
        raise TypeError("attack_explainability_candidate_required")
    if type(plan) is not EvidenceDiscoveryPlan:
        raise TypeError("attack_explainability_discovery_plan_required")
    if plan.candidate_retrieval_digest != candidate.semantic_digest:
        raise ValueError("attack_explainability_candidate_plan_mismatch")
    chains = _chain_index(evidence)
    roots = _root_index(evidence)
    records = tuple(
        _decision_record(item, evidence, chains, roots, candidate, plan)
        for item in mapping.decisions
    )
    core = {
        "schema_version": ATTACK_EXPLAINABILITY_SCHEMA_VERSION,
        "source_artifact_evidence_digest": evidence.semantic_digest,
        "attack_mapping_digest": canonical_json_sha256(mapping.to_record()),
        "candidate_retrieval_digest": candidate.semantic_digest,
        "discovery_plan_digest": plan.semantic_digest,
        "decisions": records,
        "projection_role": "explainability_only",
        "official_decision_effect": "none",
    }
    return AttackExplainabilitySnapshot(
        source_artifact_evidence_digest=evidence.semantic_digest,
        attack_mapping_digest=core["attack_mapping_digest"],
        candidate_retrieval_digest=candidate.semantic_digest,
        discovery_plan_digest=plan.semantic_digest,
        decisions=tuple(freeze_detection_value(item) for item in records),
        semantic_digest=canonical_json_sha256(core),
    )


__all__ = (
    "ATTACK_EXPLAINABILITY_SCHEMA_VERSION",
    "AttackExplainabilitySnapshot",
    "build_attack_explainability",
)
