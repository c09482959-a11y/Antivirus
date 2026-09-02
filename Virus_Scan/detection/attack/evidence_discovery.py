"""Canonical ATT&CK evidence-discovery planner with zero evidence authority.

The ATT&CK implementation and Chain registries define the complete static search
space.  Candidate/model context can alter only priority ordering.  Budget or
frontend limitations defer queries visibly; they never remove requirements or
turn missing analysis into negative evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from types import MappingProxyType

from Virus_Scan.contracts.artifact_evidence_snapshot import ArtifactEvidenceSnapshot
from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.evidence_discovery_plan import (
    EVIDENCE_DISCOVERY_QUERY_KINDS,
    EvidenceDiscoveryBudget,
    EvidenceDiscoveryPlan,
    EvidenceDiscoveryQuery,
)
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.detection.attack.candidate_retrieval import AttackCandidateRetrievalResult
from Virus_Scan.detection.attack.implementations import (
    ATTACK_ANALYTIC_IMPLEMENTATIONS,
    AttackAnalyticImplementationSpec,
    attack_analytic_implementation_manifest,
)
from Virus_Scan.detection.registries.chain_registry import (
    CHAIN_REGISTRY_DIGEST,
    CHAIN_RULE_INDEX,
    ChainRule,
)

_ADMITTED_STATES = frozenset({"candidate_only", "confirmed_enabled"})
_STATIC_MODALITIES = frozenset({"static_control_flow", "static_structure"})
_KIND_COST = MappingProxyType({
    "resolve_required_operation": 2,
    "prove_entrypoint_reachability": 2,
    "recover_call_arguments": 3,
    "resolve_target_resource": 3,
    "resolve_indirect_control_flow": 4,
    "trace_value_flow": 5,
})
_KIND_PRIORITY = MappingProxyType({
    "resolve_required_operation": 60,
    "prove_entrypoint_reachability": 55,
    "resolve_target_resource": 50,
    "recover_call_arguments": 45,
    "resolve_indirect_control_flow": 40,
    "trace_value_flow": 35,
})


@dataclass(frozen=True, slots=True)
class _QueryPrototype:
    technique_id: str
    implementation_id: str
    chain_id: str
    requirement_id: str
    query_kind: str
    already_satisfied: bool


def _admitted_static_implementations(
    implementations: tuple[AttackAnalyticImplementationSpec, ...],
) -> tuple[AttackAnalyticImplementationSpec, ...]:
    if type(implementations) is not tuple or any(
        type(item) is not AttackAnalyticImplementationSpec for item in implementations
    ):
        raise TypeError("evidence_discovery_implementations_invalid")
    return tuple(sorted((
        item for item in implementations
        if item.admission_state in _ADMITTED_STATES
        and bool(set(item.required_modalities) & _STATIC_MODALITIES)
    ), key=lambda item: (item.technique_id, item.implementation_id)))


def _confirmed_chain_ids(evidence: ArtifactEvidenceSnapshot) -> frozenset[str]:
    return frozenset(
        decision.candidate.chain_id
        for decision in evidence.chain_evidence.decisions
        if decision.status == "confirmed"
    )


def _prototype(
    implementation: AttackAnalyticImplementationSpec,
    rule: ChainRule,
    requirement_suffix: str,
    query_kind: str,
    confirmed: bool,
) -> _QueryPrototype:
    return _QueryPrototype(
        technique_id=implementation.technique_id,
        implementation_id=implementation.implementation_id,
        chain_id=rule.chain_id,
        requirement_id=(
            "implementation:" + implementation.implementation_id
            + ":chain:" + rule.chain_id + ":" + requirement_suffix
        ),
        query_kind=query_kind,
        already_satisfied=confirmed,
    )


def _chain_query_prototypes(
    implementation: AttackAnalyticImplementationSpec,
    rule: ChainRule,
    *,
    confirmed: bool,
) -> tuple[_QueryPrototype, ...]:
    rows: list[_QueryPrototype] = []
    static_control = "static_control_flow" in rule.required_modalities
    for index, step in enumerate(rule.steps):
        if step.optional:
            continue
        rows.append(_prototype(
            implementation, rule, f"step:{index}:operation",
            "resolve_required_operation", confirmed,
        ))
        if static_control:
            rows.append(_prototype(
                implementation, rule, f"step:{index}:reachability",
                "prove_entrypoint_reachability", confirmed,
            ))
    relation_needs_resource = any(item.same_resource for item in rule.static_relations)
    if rule.same_target or "target_identity" in rule.required_fields or relation_needs_resource:
        rows.append(_prototype(
            implementation, rule, "identity:target_resource",
            "resolve_target_resource", confirmed,
        ))
    if (
        rule.same_actor or rule.same_process
        or bool({"actor_identity", "process_identity"} & set(rule.required_fields))
    ):
        rows.append(_prototype(
            implementation, rule, "identity:call_arguments",
            "recover_call_arguments", confirmed,
        ))
    for ordinal, relation in enumerate(rule.static_relations):
        if relation.require_control_flow_path:
            rows.append(_prototype(
                implementation, rule, f"relation:{ordinal}:control_flow",
                "resolve_indirect_control_flow", confirmed,
            ))
        if relation.require_data_flow_path or relation.require_same_value:
            rows.append(_prototype(
                implementation, rule, f"relation:{ordinal}:data_flow",
                "trace_value_flow", confirmed,
            ))
    return tuple(rows)


def _baseline_prototypes(
    evidence: ArtifactEvidenceSnapshot,
    implementations: tuple[AttackAnalyticImplementationSpec, ...],
) -> tuple[_QueryPrototype, ...]:
    confirmed = _confirmed_chain_ids(evidence)
    rows: list[_QueryPrototype] = []
    for implementation in _admitted_static_implementations(implementations):
        for chain_id in implementation.chain_ids:
            rule = CHAIN_RULE_INDEX.get(chain_id)
            if type(rule) is not ChainRule:
                raise RuntimeError("evidence_discovery_chain_requirement_missing")
            rows.extend(_chain_query_prototypes(
                implementation, rule, confirmed=chain_id in confirmed,
            ))
    identities = tuple(
        (item.implementation_id, item.chain_id, item.requirement_id, item.query_kind)
        for item in rows
    )
    if len(set(identities)) != len(identities):
        raise RuntimeError("evidence_discovery_requirement_duplicate")
    return tuple(rows)


def _candidate_priority(result: AttackCandidateRetrievalResult) -> dict[str, tuple[int, str]]:
    if type(result) is not AttackCandidateRetrievalResult:
        raise TypeError("evidence_discovery_candidate_retrieval_required")
    priorities: dict[str, tuple[int, str]] = {}
    for candidate in result.candidates:
        if candidate.technique_id not in {
            item.technique_id for item in ATTACK_ANALYTIC_IMPLEMENTATIONS
            if item.admission_state in _ADMITTED_STATES
        }:
            continue
        boost = min(10_000, int(round(candidate.score * 1_000)) + max(0, 100 - candidate.rank))
        priorities[candidate.technique_id] = (
            boost,
            f"candidate_rank:{candidate.rank}:score:{candidate.score:.6f}",
        )
    return priorities


def _query_id(prototype: _QueryPrototype) -> str:
    digest = sha256((
        prototype.technique_id + "\0" + prototype.implementation_id + "\0"
        + prototype.chain_id + "\0" + prototype.requirement_id + "\0"
        + prototype.query_kind
    ).encode("utf-8", "strict")).hexdigest()[:40]
    return "edq_" + digest


def _priority(prototype: _QueryPrototype, candidates: dict[str, tuple[int, str]]) -> tuple[int, tuple[str, ...]]:
    candidate_boost, candidate_reason = candidates.get(
        prototype.technique_id, (0, "baseline_registry_requirement"),
    )
    priority = 10_000 + _KIND_PRIORITY[prototype.query_kind] + candidate_boost
    return priority, (candidate_reason,)


def build_evidence_discovery_plan(
    provisional_evidence: ArtifactEvidenceSnapshot,
    model_context: ModelContextSnapshot,
    candidate_retrieval: AttackCandidateRetrievalResult,
    *,
    frontend_capability_query_kinds: tuple[str, ...],
    resource_budget: EvidenceDiscoveryBudget,
    implementations: tuple[AttackAnalyticImplementationSpec, ...] = ATTACK_ANALYTIC_IMPLEMENTATIONS,
) -> EvidenceDiscoveryPlan:
    """Build one complete context-only refinement plan for admitted static requirements."""
    if type(provisional_evidence) is not ArtifactEvidenceSnapshot:
        raise TypeError("evidence_discovery_artifact_evidence_required")
    if type(model_context) is not ModelContextSnapshot:
        raise TypeError("evidence_discovery_model_context_required")
    if model_context.source_artifact_evidence_digest != provisional_evidence.semantic_digest:
        raise ValueError("evidence_discovery_model_context_source_mismatch")
    if type(candidate_retrieval) is not AttackCandidateRetrievalResult:
        raise TypeError("evidence_discovery_candidate_retrieval_required")
    if type(resource_budget) is not EvidenceDiscoveryBudget:
        raise TypeError("evidence_discovery_budget_required")
    if type(frontend_capability_query_kinds) is not tuple:
        raise TypeError("evidence_discovery_frontend_capabilities_invalid")
    capability_kinds = tuple(sorted(set(frontend_capability_query_kinds)))
    if (
        len(capability_kinds) != len(frontend_capability_query_kinds)
        or any(type(item) is not str or item not in EVIDENCE_DISCOVERY_QUERY_KINDS for item in capability_kinds)
    ):
        raise ValueError("evidence_discovery_frontend_capabilities_invalid")

    candidate_priorities = _candidate_priority(candidate_retrieval)
    prototypes = _baseline_prototypes(provisional_evidence, implementations)
    ranked = sorted(
        prototypes,
        key=lambda item: (
            item.already_satisfied,
            -_priority(item, candidate_priorities)[0],
            item.technique_id,
            item.implementation_id,
            item.chain_id,
            item.requirement_id,
            item.query_kind,
        ),
    )
    selected_count = 0
    selected_cost = 0
    queries: list[EvidenceDiscoveryQuery] = []
    for item in ranked:
        priority, rationale = _priority(item, candidate_priorities)
        supported = item.query_kind in capability_kinds
        cost = _KIND_COST[item.query_kind]
        if item.already_satisfied:
            state = "already_satisfied"
        elif not supported:
            state = "deferred_frontend_capability"
        elif (
            selected_count >= resource_budget.maximum_query_count
            or selected_cost + cost > resource_budget.maximum_cost_units
        ):
            state = "deferred_resource_budget"
        else:
            state = "selected"
            selected_count += 1
            selected_cost += cost
        queries.append(EvidenceDiscoveryQuery(
            query_id=_query_id(item),
            requirement_id=item.requirement_id,
            technique_id=item.technique_id,
            implementation_id=item.implementation_id,
            chain_id=item.chain_id,
            query_kind=item.query_kind,
            estimated_cost_units=cost,
            priority=priority,
            frontend_supported=supported,
            execution_state=state,
            context_rationale=rationale,
        ))

    implementation_manifest = attack_analytic_implementation_manifest()
    # The concrete query set itself is an additional deterministic binding to the
    # canonical registries.  This value is intentionally not an evidence root.
    _ = canonical_json_sha256(tuple(
        (item.requirement_id, item.query_kind) for item in queries
    ))
    return EvidenceDiscoveryPlan(
        source_artifact_evidence_digest=provisional_evidence.semantic_digest,
        model_context_digest=model_context.semantic_digest,
        candidate_retrieval_digest=candidate_retrieval.semantic_digest,
        attack_implementation_manifest_digest=str(implementation_manifest["digest"]),
        chain_registry_digest=CHAIN_REGISTRY_DIGEST,
        frontend_capability_query_kinds=capability_kinds,
        budget=resource_budget,
        queries=tuple(queries),
    )


__all__ = ("build_evidence_discovery_plan",)
