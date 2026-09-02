"""Immutable contracts for canonical graph risk projection."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from Virus_Scan.runtime.graph_state import GRAPH_SNAPSHOT_SCHEMA_VERSION

GRAPH_RISK_MODEL_VERSION = "graph_risk_model_v2"
GRAPH_RISK_POLICY_VERSION = "graph_risk_policy_v3"
GRAPH_ATTENTION_CONTRACT_VERSION = "graph_attention_v2"
GRAPH_EXECUTION_CONTRACT_VERSION = "graph_execution_v2"
GRAPH_TEMPORAL_CONTRACT_VERSION = "graph_temporal_v1"
GRAPH_CONTEXT_BASELINE_VERSION = "graph_context_baseline_v1"
GRAPH_CHAIN_CONTRACT_VERSION = "graph_chain_contract_v1"
GRAPH_RISK_EVIDENCE_VERSION = "graph_risk_evidence_v3"


@dataclass(frozen=True, slots=True)
class GraphRiskPolicy:
    version: str
    structural_weight: float
    attention_weight: float
    execution_weight: float
    temporal_weight: float
    anomaly_weight: float
    decision_threshold: float
    selection_evidence: str
    max_structural_edges: int
    minimum_baseline_support: int
    maximum_attention_work: int
    explanation_edge_types: frozenset[str]

    @property
    def weights(self) -> MappingProxyType[str, float]:
        return MappingProxyType({
            "structural": self.structural_weight,
            "attention": self.attention_weight,
            "execution": self.execution_weight,
            "temporal": self.temporal_weight,
            "context_anomaly": self.anomaly_weight,
        })


GRAPH_RISK_POLICY = GraphRiskPolicy(
    version=GRAPH_RISK_POLICY_VERSION,
    structural_weight=0.24,
    attention_weight=0.14,
    execution_weight=0.42,
    temporal_weight=0.14,
    anomaly_weight=0.06,
    decision_threshold=0.55,
    selection_evidence="stage2636_09_labeled_validation_execution_weighted",
    max_structural_edges=200,
    minimum_baseline_support=8,
    maximum_attention_work=1200,
    explanation_edge_types=frozenset({
        "cluster", "cluster_explanation", "cluster_peer_explanation",
        "graph_member_explanation", "cluster_attack_explanation",
    }),
)


@dataclass(frozen=True, slots=True)
class GraphComponentEvidence:
    name: str
    value: float
    ready: bool
    support_count: int
    maturity: float
    unavailable_reason: str | None
    provenance: tuple[str, ...]
    version: str

    def to_record(self) -> dict[str, object]:
        return {
            "name": self.name,
            "value": self.value,
            "ready": self.ready,
            "support_count": self.support_count,
            "maturity": self.maturity,
            "unavailable_reason": self.unavailable_reason,
            "provenance": self.provenance,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class GraphRiskEvidence:
    risk: float
    ready: bool
    degraded: bool
    component_degraded: bool
    unavailable_reason: str | None
    component_unavailable_reasons: tuple[str, ...]
    confidence: float
    maturity: float
    snapshot_version: str
    snapshot_digest: str
    node_id: str
    node_type: str
    update_ordinal: int
    policy_version: str
    model_version: str
    cache_key: str
    source: str
    structural: GraphComponentEvidence
    attention: GraphComponentEvidence
    execution: GraphComponentEvidence
    temporal: GraphComponentEvidence
    context_anomaly: GraphComponentEvidence

    def to_record(self) -> dict[str, object]:
        components = {
            "structural": self.structural.to_record(),
            "attention": self.attention.to_record(),
            "execution": self.execution.to_record(),
            "temporal": self.temporal.to_record(),
            "context_anomaly": self.context_anomaly.to_record(),
        }
        return {
            "evidence_version": GRAPH_RISK_EVIDENCE_VERSION,
            "risk": self.risk,
            "ready": self.ready,
            "degraded": self.degraded,
            "component_degraded": self.component_degraded,
            "unavailable_reason": self.unavailable_reason,
            "component_unavailable_reasons": self.component_unavailable_reasons,
            "confidence": self.confidence,
            "maturity": self.maturity,
            "snapshot_version": self.snapshot_version,
            "snapshot_digest": self.snapshot_digest,
            "node_id": self.node_id,
            "node_type": self.node_type,
            "update_ordinal": self.update_ordinal,
            "policy_version": self.policy_version,
            "decision_threshold": GRAPH_RISK_POLICY.decision_threshold,
            "policy_selection_evidence": GRAPH_RISK_POLICY.selection_evidence,
            "model_version": self.model_version,
            "attention_contract_version": GRAPH_ATTENTION_CONTRACT_VERSION,
            "execution_contract_version": GRAPH_EXECUTION_CONTRACT_VERSION,
            "temporal_contract_version": GRAPH_TEMPORAL_CONTRACT_VERSION,
            "context_baseline_version": GRAPH_CONTEXT_BASELINE_VERSION,
            "chain_contract_version": GRAPH_CHAIN_CONTRACT_VERSION,
            "components": components,
            "structural_risk": self.structural.value,
            "attention": self.attention.value,
            "execution": self.execution.value,
            "temporal_relationship_risk": self.temporal.value,
            "context_baseline_anomaly": self.context_anomaly.value,
            "cache_key": self.cache_key,
            "source": self.source,
            "evidence_type": "graph_risk",
            "final_json_must_record": self.degraded or self.component_degraded,
            "replay_record_required": True,
        }


def unavailable_component(name: str, reason: str, version: str) -> GraphComponentEvidence:
    return GraphComponentEvidence(
        name=name,
        value=0.0,
        ready=False,
        support_count=0,
        maturity=0.0,
        unavailable_reason=reason,
        provenance=(),
        version=version,
    )


__all__ = (
    "GRAPH_ATTENTION_CONTRACT_VERSION",
    "GRAPH_CHAIN_CONTRACT_VERSION",
    "GRAPH_CONTEXT_BASELINE_VERSION",
    "GRAPH_EXECUTION_CONTRACT_VERSION",
    "GRAPH_RISK_EVIDENCE_VERSION",
    "GRAPH_RISK_MODEL_VERSION",
    "GRAPH_RISK_POLICY",
    "GRAPH_RISK_POLICY_VERSION",
    "GRAPH_SNAPSHOT_SCHEMA_VERSION",
    "GRAPH_TEMPORAL_CONTRACT_VERSION",
    "GraphComponentEvidence",
    "GraphRiskEvidence",
    "GraphRiskPolicy",
    "unavailable_component",
)
