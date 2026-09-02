"""Private cache and aggregation support for the canonical graph-risk owner."""
from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.models.graph.cache import GRAPH_RISK_CACHE
from Virus_Scan.models.graph.common import graph_finite_float, graph_unit_interval
from Virus_Scan.models.graph.common_text_boundaries import graph_exception_message
from Virus_Scan.models.graph.contracts import (
    GRAPH_ATTENTION_CONTRACT_VERSION,
    GRAPH_CONTEXT_BASELINE_VERSION,
    GRAPH_EXECUTION_CONTRACT_VERSION,
    GRAPH_RISK_EVIDENCE_VERSION,
    GRAPH_RISK_MODEL_VERSION,
    GRAPH_RISK_POLICY,
    GRAPH_TEMPORAL_CONTRACT_VERSION,
    GraphComponentEvidence,
    unavailable_component,
)

GRAPH_RISK_CACHE_UNAVAILABLE = object()
_COMPONENT_WEIGHTS = (
    ("structural", GRAPH_RISK_POLICY.structural_weight),
    ("attention", GRAPH_RISK_POLICY.attention_weight),
    ("execution", GRAPH_RISK_POLICY.execution_weight),
    ("temporal", GRAPH_RISK_POLICY.temporal_weight),
    ("context_anomaly", GRAPH_RISK_POLICY.anomaly_weight),
)


def _bounded_cached_risk(value: object) -> object:
    metric, reason = graph_finite_float(value, reason="graph_risk_cache_value_unavailable")
    if reason != "" or metric < 0.0 or metric > 1.0:
        return GRAPH_RISK_CACHE_UNAVAILABLE
    return metric


def scalar_cache_record(value: float, key: str, node: object) -> dict[str, object]:
    reason = "graph_risk_component_cache_unavailable"
    components = {
        "structural": unavailable_component("structural", reason, GRAPH_RISK_MODEL_VERSION).to_record(),
        "attention": unavailable_component("attention", reason, GRAPH_ATTENTION_CONTRACT_VERSION).to_record(),
        "execution": unavailable_component("execution", reason, GRAPH_EXECUTION_CONTRACT_VERSION).to_record(),
        "temporal": unavailable_component("temporal", reason, GRAPH_TEMPORAL_CONTRACT_VERSION).to_record(),
        "context_anomaly": unavailable_component("context_anomaly", reason, GRAPH_CONTEXT_BASELINE_VERSION).to_record(),
    }
    return {
        "evidence_version": GRAPH_RISK_EVIDENCE_VERSION,
        "risk": value,
        "ready": False,
        "degraded": True,
        "component_degraded": True,
        "unavailable_reason": reason,
        "component_unavailable_reasons": (reason,),
        "confidence": 0.0,
        "maturity": 0.0,
        "snapshot_version": "graph_snapshot_unavailable",
        "snapshot_digest": "graph_snapshot_digest_unavailable",
        "node_id": no_hook_type_name(node),
        "node_type": "unavailable",
        "update_ordinal": 0,
        "policy_version": GRAPH_RISK_POLICY.version,
        "decision_threshold": GRAPH_RISK_POLICY.decision_threshold,
        "policy_selection_evidence": GRAPH_RISK_POLICY.selection_evidence,
        "model_version": GRAPH_RISK_MODEL_VERSION,
        "components": components,
        "structural_risk": 0.0,
        "attention": 0.0,
        "execution": 0.0,
        "temporal_relationship_risk": 0.0,
        "context_baseline_anomaly": 0.0,
        "cache_key": key,
        "source": "cache_projection",
        "evidence_type": "graph_risk",
        "final_json_must_record": True,
        "replay_record_required": True,
    }


def validated_cached_graph_risk(
    value: object,
    *,
    key: str,
    node: object,
    snapshot: Mapping[str, object] | None,
) -> object:
    if value is None:
        return GRAPH_RISK_CACHE_UNAVAILABLE
    items = no_hook_mapping_items(value)
    if items is None:
        metric = _bounded_cached_risk(value)
        if metric is GRAPH_RISK_CACHE_UNAVAILABLE:
            return metric
        return scalar_cache_record(metric, key, node)
    record = dict(items)
    metric = _bounded_cached_risk(dict.get(record, "risk"))
    if metric is GRAPH_RISK_CACHE_UNAVAILABLE:
        return metric
    if dict.get(record, "evidence_version") != GRAPH_RISK_EVIDENCE_VERSION:
        return GRAPH_RISK_CACHE_UNAVAILABLE
    if dict.get(record, "policy_version") != GRAPH_RISK_POLICY.version:
        return GRAPH_RISK_CACHE_UNAVAILABLE
    if dict.get(record, "model_version") != GRAPH_RISK_MODEL_VERSION:
        return GRAPH_RISK_CACHE_UNAVAILABLE
    if snapshot is None or dict.get(record, "snapshot_digest") != snapshot.get("snapshot_digest"):
        return GRAPH_RISK_CACHE_UNAVAILABLE
    record["risk"] = metric
    record["source"] = "cache"
    record["cache_key"] = key
    return record


def remove_corrupt_cache_entry(key: str, node: object) -> dict[str, object] | None:
    log_error("ignored corrupt cached graph risk for " + no_hook_type_name(node))
    try:
        GRAPH_RISK_CACHE.pop(key, None)
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error(graph_exception_message("graph risk cache cleanup failed: ", exc))
        return {
            "risk": 0.0,
            "ready": False,
            "degraded": True,
            "unavailable_reason": "graph_risk_cache_cleanup_failed",
            "evidence_type": "graph_risk",
            "final_json_must_record": True,
            "replay_record_required": True,
        }
    return None


def combine_components(
    components: dict[str, GraphComponentEvidence],
) -> tuple[float, float, float, tuple[str, ...]]:
    weighted = 0.0
    ready_weight = 0.0
    confidence = 0.0
    total_weight = sum(weight for _name, weight in _COMPONENT_WEIGHTS)
    reasons: list[str] = []
    for name, weight in _COMPONENT_WEIGHTS:
        component = dict.__getitem__(components, name)
        if component.ready:
            weighted += component.value * weight
            ready_weight += weight
            confidence += component.maturity * weight
        elif component.unavailable_reason is not None:
            reasons.append(component.unavailable_reason)
    normalized = 0.0 if ready_weight <= 0.0 else weighted / ready_weight
    confidence = 0.0 if total_weight <= 0.0 else confidence / total_weight
    maturity = 0.0 if ready_weight <= 0.0 else confidence * total_weight / ready_weight
    return (
        normalized,
        graph_unit_interval(confidence)[0],
        graph_unit_interval(maturity)[0],
        tuple(dict.fromkeys(reasons)),
    )


__all__ = (
    "GRAPH_RISK_CACHE_UNAVAILABLE",
    "combine_components",
    "remove_corrupt_cache_entry",
    "validated_cached_graph_risk",
)
