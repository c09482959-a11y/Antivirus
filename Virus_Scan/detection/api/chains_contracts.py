"""Public canonical chain contracts for repository-level callers."""

from Virus_Scan.contracts.chain_evidence import (
    ChainCandidate,
    ChainDecision,
    ChainEvent,
    ChainEvidence,
    ChainEvidenceGeneration,
    ChainRuleOutcome,
    ChainExplanation,
    ChainRule,
    ChainStep,
    MatchedChainStep,
)
from Virus_Scan.detection.chains.composite.attack_authority import (
    has_concrete_attack_chain,
    high_gate_attack_chain_details,
)
from Virus_Scan.detection.chains.composite.audit_report import runtime_tag_chain_audit_report
from Virus_Scan.detection.chains.composite.behavior_intent import behavior_intent_filter_tags
from Virus_Scan.detection.chains.composite.behavior_mapping import chain_expected_behavior_mapping
from Virus_Scan.detection.chains.composite.threat_intel import compute_threat_intel_layer
from Virus_Scan.detection.api.chain_evaluation import (
    evaluate_chain_evidence,
    evaluate_chain_evidence_generation,
)
from Virus_Scan.detection.chains.execution.compiled_registry import (
    COMPILED_CHAIN_REGISTRY_DIGEST,
    COMPILED_CHAIN_REGISTRY_VERSION,
)
from Virus_Scan.detection.chains.execution.anchors import (
    published_chain_names,
    published_chain_records,
)
from Virus_Scan.detection.chains.execution.syscall_sequence import detect_syscall_sequence_model
from Virus_Scan.detection.correlation.behavioral.behavior_flow import detection_behavior_flow
from Virus_Scan.detection.correlation.temporal.behavior_timeline import build_behavior_timeline
from Virus_Scan.detection.correlation.temporal.timeline import (
    extension_timeline_anomaly,
    real_ordered_event_names,
    real_timeline_events,
    timeline_event_behavior,
    timeline_transitions,
)
from Virus_Scan.detection.explainability.evidence_builder import (
    build_explanation_bundle,
    explain_behavior_patterns,
)
from Virus_Scan.detection.registries.chain_registry import (
    CANONICAL_CHAIN_RULES,
    CHAIN_REGISTRY_DIGEST,
    CHAIN_REGISTRY_VERSION,
    CHAIN_RULE_MIGRATION_MANIFEST,
    chain_registry_manifest,
    chain_rule,
    chain_rules,
)
from Virus_Scan.detection.scoring.escalation.anchor_scores import high_gate_authority


__all__ = (
    "CANONICAL_CHAIN_RULES",
    "COMPILED_CHAIN_REGISTRY_DIGEST",
    "COMPILED_CHAIN_REGISTRY_VERSION",
    "CHAIN_REGISTRY_DIGEST",
    "CHAIN_REGISTRY_VERSION",
    "CHAIN_RULE_MIGRATION_MANIFEST",
    "ChainCandidate",
    "ChainDecision",
    "ChainEvent",
    "ChainEvidence",
    "ChainEvidenceGeneration",
    "ChainExplanation",
    "ChainRule",
    "ChainRuleOutcome",
    "ChainStep",
    "MatchedChainStep",
    "behavior_intent_filter_tags",
    "build_behavior_timeline",
    "build_explanation_bundle",
    "chain_expected_behavior_mapping",
    "chain_registry_manifest",
    "chain_rule",
    "chain_rules",
    "compute_threat_intel_layer",
    "detect_syscall_sequence_model",
    "detection_behavior_flow",
    "evaluate_chain_evidence",
    "evaluate_chain_evidence_generation",
    "explain_behavior_patterns",
    "extension_timeline_anomaly",
    "has_concrete_attack_chain",
    "high_gate_attack_chain_details",
    "high_gate_authority",
    "published_chain_names",
    "published_chain_records",
    "real_ordered_event_names",
    "real_timeline_events",
    "runtime_tag_chain_audit_report",
    "timeline_event_behavior",
    "timeline_transitions",
)
