"""Immutable context-only contracts for bounded evidence discovery planning.

The plan records *where to look*, never what is true.  Every query corresponds
only to a canonical ATT&CK implementation/Chain requirement and therefore has
zero evidence or technique-decision authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.text_boundaries import exact_bounded_text

EVIDENCE_DISCOVERY_PLAN_SCHEMA_VERSION = "stage2636_11020_evidence_discovery_plan_v1"
EVIDENCE_DISCOVERY_BUDGET_SCHEMA_VERSION = "stage2636_11020_evidence_discovery_budget_v1"
EVIDENCE_DISCOVERY_QUERY_SCHEMA_VERSION = "stage2636_11020_evidence_discovery_query_v1"

EVIDENCE_DISCOVERY_QUERY_KINDS = frozenset({
    "prove_entrypoint_reachability",
    "recover_call_arguments",
    "resolve_indirect_control_flow",
    "resolve_required_operation",
    "resolve_target_resource",
    "trace_value_flow",
})
EVIDENCE_DISCOVERY_QUERY_STATES = frozenset({
    "already_satisfied",
    "selected",
    "deferred_frontend_capability",
    "deferred_resource_budget",
})
_HEX = frozenset("0123456789abcdef")
_MAX_QUERIES = 4096


def _digest(value: object, reason: str) -> str:
    if type(value) is not str:
        raise TypeError(reason)
    text = str.__str__(value).strip().lower()
    if len(text) != 64 or any(character not in _HEX for character in text):
        raise ValueError(reason)
    return text


def _text(value: object, reason: str, *, maximum: int = 512) -> str:
    return exact_bounded_text(value, reason, maximum=maximum)


def _texts(
    value: object,
    reason: str,
    *,
    maximum_items: int = _MAX_QUERIES,
    maximum_text: int = 512,
) -> tuple[str, ...]:
    if type(value) is not tuple or len(value) > maximum_items:
        raise TypeError(reason)
    items = tuple(_text(item, reason, maximum=maximum_text) for item in value)
    if tuple(sorted(set(items))) != items:
        raise ValueError(reason)
    return items


@dataclass(frozen=True, slots=True)
class EvidenceDiscoveryBudget:
    """Deterministic upper bound for one evidence-refinement generation."""

    maximum_query_count: int
    maximum_cost_units: int
    schema_version: str = EVIDENCE_DISCOVERY_BUDGET_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not EvidenceDiscoveryBudget:
            raise TypeError("evidence_discovery_budget_owner_invalid")
        if (
            type(self.maximum_query_count) is not int
            or self.maximum_query_count < 0
            or self.maximum_query_count > _MAX_QUERIES
        ):
            raise ValueError("evidence_discovery_budget_query_count_invalid")
        if (
            type(self.maximum_cost_units) is not int
            or self.maximum_cost_units < 0
            or self.maximum_cost_units > 1_000_000
        ):
            raise ValueError("evidence_discovery_budget_cost_invalid")
        if self.schema_version != EVIDENCE_DISCOVERY_BUDGET_SCHEMA_VERSION:
            raise ValueError("evidence_discovery_budget_schema_invalid")

    def to_record(self) -> dict[str, object]:
        return {
            "maximum_cost_units": self.maximum_cost_units,
            "maximum_query_count": self.maximum_query_count,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class EvidenceDiscoveryQuery:
    """One logical evidence search for one canonical requirement."""

    query_id: str
    requirement_id: str
    technique_id: str
    implementation_id: str
    chain_id: str
    query_kind: str
    estimated_cost_units: int
    priority: int
    frontend_supported: bool
    execution_state: str
    context_rationale: tuple[str, ...] = ()
    schema_version: str = EVIDENCE_DISCOVERY_QUERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not EvidenceDiscoveryQuery:
            raise TypeError("evidence_discovery_query_owner_invalid")
        query_id = _text(self.query_id, "evidence_discovery_query_id_invalid", maximum=96)
        if not query_id.startswith("edq_"):
            raise ValueError("evidence_discovery_query_id_invalid")
        requirement_id = _text(
            self.requirement_id, "evidence_discovery_requirement_id_invalid", maximum=512,
        )
        technique_id = _text(
            self.technique_id, "evidence_discovery_technique_id_invalid", maximum=16,
        )
        if not technique_id.startswith("T"):
            raise ValueError("evidence_discovery_technique_id_invalid")
        implementation_id = _text(
            self.implementation_id, "evidence_discovery_implementation_id_invalid", maximum=128,
        )
        chain_id = _text(self.chain_id, "evidence_discovery_chain_id_invalid", maximum=256)
        query_kind = _text(
            self.query_kind, "evidence_discovery_query_kind_invalid", maximum=64,
        )
        if query_kind not in EVIDENCE_DISCOVERY_QUERY_KINDS:
            raise ValueError("evidence_discovery_query_kind_invalid")
        if (
            type(self.estimated_cost_units) is not int
            or self.estimated_cost_units < 1
            or self.estimated_cost_units > 100_000
        ):
            raise ValueError("evidence_discovery_query_cost_invalid")
        if type(self.priority) is not int or self.priority < 0 or self.priority > 1_000_000:
            raise ValueError("evidence_discovery_query_priority_invalid")
        if type(self.frontend_supported) is not bool:
            raise TypeError("evidence_discovery_frontend_support_invalid")
        execution_state = _text(
            self.execution_state, "evidence_discovery_query_state_invalid", maximum=64,
        )
        if execution_state not in EVIDENCE_DISCOVERY_QUERY_STATES:
            raise ValueError("evidence_discovery_query_state_invalid")
        if execution_state == "selected" and not self.frontend_supported:
            raise ValueError("evidence_discovery_selected_query_frontend_unsupported")
        if execution_state == "deferred_frontend_capability" and self.frontend_supported:
            raise ValueError("evidence_discovery_frontend_defer_state_invalid")
        rationale = _texts(
            self.context_rationale,
            "evidence_discovery_context_rationale_invalid",
            maximum_items=16,
            maximum_text=256,
        )
        if self.schema_version != EVIDENCE_DISCOVERY_QUERY_SCHEMA_VERSION:
            raise ValueError("evidence_discovery_query_schema_invalid")
        object.__setattr__(self, "query_id", query_id)
        object.__setattr__(self, "requirement_id", requirement_id)
        object.__setattr__(self, "technique_id", technique_id)
        object.__setattr__(self, "implementation_id", implementation_id)
        object.__setattr__(self, "chain_id", chain_id)
        object.__setattr__(self, "query_kind", query_kind)
        object.__setattr__(self, "execution_state", execution_state)
        object.__setattr__(self, "context_rationale", rationale)

    def to_record(self) -> dict[str, object]:
        return {
            "chain_id": self.chain_id,
            "context_rationale": self.context_rationale,
            "estimated_cost_units": self.estimated_cost_units,
            "execution_state": self.execution_state,
            "frontend_supported": self.frontend_supported,
            "implementation_id": self.implementation_id,
            "priority": self.priority,
            "query_id": self.query_id,
            "query_kind": self.query_kind,
            "requirement_id": self.requirement_id,
            "schema_version": self.schema_version,
            "technique_id": self.technique_id,
        }


@dataclass(frozen=True, slots=True)
class EvidenceDiscoveryPlan:
    """One complete bounded ordering of canonical evidence-search requirements."""

    source_artifact_evidence_digest: str
    model_context_digest: str
    candidate_retrieval_digest: str
    attack_implementation_manifest_digest: str
    chain_registry_digest: str
    frontend_capability_query_kinds: tuple[str, ...]
    budget: EvidenceDiscoveryBudget
    queries: tuple[EvidenceDiscoveryQuery, ...]
    semantic_digest: str = ""
    schema_version: str = EVIDENCE_DISCOVERY_PLAN_SCHEMA_VERSION
    requirement_ids: tuple[str, ...] = field(default_factory=tuple, init=False)
    selected_query_ids: tuple[str, ...] = field(default_factory=tuple, init=False)
    unavailable_requirement_ids: tuple[str, ...] = field(default_factory=tuple, init=False)

    def __post_init__(self) -> None:
        if type(self) is not EvidenceDiscoveryPlan:
            raise TypeError("evidence_discovery_plan_owner_invalid")
        source = _digest(
            self.source_artifact_evidence_digest,
            "evidence_discovery_source_evidence_digest_invalid",
        )
        model = _digest(self.model_context_digest, "evidence_discovery_model_context_digest_invalid")
        candidate = _digest(
            self.candidate_retrieval_digest,
            "evidence_discovery_candidate_digest_invalid",
        )
        implementation = _digest(
            self.attack_implementation_manifest_digest,
            "evidence_discovery_implementation_manifest_digest_invalid",
        )
        chain = _digest(self.chain_registry_digest, "evidence_discovery_chain_registry_digest_invalid")
        capabilities = _texts(
            self.frontend_capability_query_kinds,
            "evidence_discovery_frontend_capabilities_invalid",
            maximum_items=len(EVIDENCE_DISCOVERY_QUERY_KINDS),
            maximum_text=64,
        )
        if any(item not in EVIDENCE_DISCOVERY_QUERY_KINDS for item in capabilities):
            raise ValueError("evidence_discovery_frontend_capabilities_invalid")
        if type(self.budget) is not EvidenceDiscoveryBudget:
            raise TypeError("evidence_discovery_budget_required")
        if type(self.queries) is not tuple or len(self.queries) > _MAX_QUERIES:
            raise TypeError("evidence_discovery_queries_invalid")
        if any(type(item) is not EvidenceDiscoveryQuery for item in self.queries):
            raise TypeError("evidence_discovery_query_owner_invalid")
        ids = tuple(item.query_id for item in self.queries)
        if len(set(ids)) != len(ids):
            raise ValueError("evidence_discovery_query_id_duplicate")
        requirement_ids = tuple(sorted({item.requirement_id for item in self.queries}))
        selected_ids = tuple(item.query_id for item in self.queries if item.execution_state == "selected")
        unavailable_ids = tuple(sorted({
            item.requirement_id
            for item in self.queries
            if item.execution_state in {
                "deferred_frontend_capability", "deferred_resource_budget",
            }
        }))
        if self.schema_version != EVIDENCE_DISCOVERY_PLAN_SCHEMA_VERSION:
            raise ValueError("evidence_discovery_plan_schema_invalid")
        object.__setattr__(self, "source_artifact_evidence_digest", source)
        object.__setattr__(self, "model_context_digest", model)
        object.__setattr__(self, "candidate_retrieval_digest", candidate)
        object.__setattr__(self, "attack_implementation_manifest_digest", implementation)
        object.__setattr__(self, "chain_registry_digest", chain)
        object.__setattr__(self, "frontend_capability_query_kinds", capabilities)
        object.__setattr__(self, "requirement_ids", requirement_ids)
        object.__setattr__(self, "selected_query_ids", selected_ids)
        object.__setattr__(self, "unavailable_requirement_ids", unavailable_ids)
        computed = canonical_json_sha256(self._semantic_record())
        supplied = self.semantic_digest
        if supplied not in ("", computed):
            _digest(supplied, "evidence_discovery_plan_semantic_digest_invalid")
            raise ValueError("evidence_discovery_plan_semantic_digest_mismatch")
        object.__setattr__(self, "semantic_digest", computed)

    def _semantic_record(self) -> dict[str, object]:
        return {
            "attack_implementation_manifest_digest": self.attack_implementation_manifest_digest,
            "budget": self.budget.to_record(),
            "candidate_retrieval_digest": self.candidate_retrieval_digest,
            "chain_registry_digest": self.chain_registry_digest,
            "frontend_capability_query_kinds": self.frontend_capability_query_kinds,
            "model_context_digest": self.model_context_digest,
            "queries": tuple(item.to_record() for item in self.queries),
            "schema_version": self.schema_version,
            "source_artifact_evidence_digest": self.source_artifact_evidence_digest,
        }

    def to_record(self) -> dict[str, object]:
        record = self._semantic_record()
        record.update({
            "evidence_authority": "context_only",
            "official_decision_effect": "none",
            "requirement_ids": self.requirement_ids,
            "selected_query_ids": self.selected_query_ids,
            "semantic_digest": self.semantic_digest,
            "unavailable_requirement_ids": self.unavailable_requirement_ids,
        })
        return record


__all__ = (
    "EVIDENCE_DISCOVERY_BUDGET_SCHEMA_VERSION",
    "EVIDENCE_DISCOVERY_PLAN_SCHEMA_VERSION",
    "EVIDENCE_DISCOVERY_QUERY_KINDS",
    "EVIDENCE_DISCOVERY_QUERY_SCHEMA_VERSION",
    "EVIDENCE_DISCOVERY_QUERY_STATES",
    "EvidenceDiscoveryBudget",
    "EvidenceDiscoveryPlan",
    "EvidenceDiscoveryQuery",
)
