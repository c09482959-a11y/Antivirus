"""Profile-gated robust context baseline anomaly for graph components."""
from __future__ import annotations

import math

from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_finite_float,
    no_hook_mapping_items,
)
from Virus_Scan.models.graph.contracts import (
    GRAPH_CONTEXT_BASELINE_VERSION,
    GRAPH_RISK_POLICY,
    GraphComponentEvidence,
    unavailable_component,
)

_COMPONENT_NAMES = ("structural", "attention", "execution", "temporal")


def _mapping(value: object) -> dict[object, object] | None:
    items = no_hook_mapping_items(value)
    return None if items is None else dict(items)




def _context_key(snapshot: dict[object, object]) -> str | None:
    context = _mapping(snapshot.get("context"))
    if context is None:
        return None
    parts: list[str] = []
    for name in ("engine", "extension", "node_type"):
        value = context.get(name)
        text = str.__str__(value) if isinstance(value, str) else "unknown"
        parts.append(name + ":" + text)
    return "|".join(parts)

def context_baseline_component(
    snapshot: object,
    components: dict[str, GraphComponentEvidence],
) -> GraphComponentEvidence:
    if type(snapshot) is not dict:
        return unavailable_component(
            "context_anomaly", "graph_snapshot_unavailable",
            GRAPH_CONTEXT_BASELINE_VERSION,
        )
    baseline = _mapping(snapshot.get("context_baseline"))
    if baseline is None:
        return unavailable_component(
            "context_anomaly", "graph_context_baseline_unavailable",
            GRAPH_CONTEXT_BASELINE_VERSION,
        )
    version = baseline.get("version")
    if not isinstance(version, str) or str.__str__(version) != GRAPH_CONTEXT_BASELINE_VERSION:
        return unavailable_component(
            "context_anomaly", "graph_context_baseline_version_unavailable",
            GRAPH_CONTEXT_BASELINE_VERSION,
        )
    if baseline.get("trusted") is not True:
        return unavailable_component(
            "context_anomaly", "graph_context_baseline_not_trusted",
            GRAPH_CONTEXT_BASELINE_VERSION,
        )
    expected_context = _context_key(snapshot)
    baseline_context = baseline.get("context_key")
    if (
        expected_context is None
        or not isinstance(baseline_context, str)
        or str.__str__(baseline_context) != expected_context
    ):
        return unavailable_component(
            "context_anomaly", "graph_context_baseline_context_mismatch",
            GRAPH_CONTEXT_BASELINE_VERSION,
        )
    support, support_reason = no_hook_exact_nonnegative_int(
        baseline.get("support_count"), default=0,
        reason="graph_context_baseline_support_unavailable",
    )
    if support_reason or support < GRAPH_RISK_POLICY.minimum_baseline_support:
        return unavailable_component(
            "context_anomaly", "graph_context_baseline_cold_start",
            GRAPH_CONTEXT_BASELINE_VERSION,
        )
    center = _mapping(baseline.get("median"))
    scale = _mapping(baseline.get("iqr"))
    if center is None or scale is None:
        return unavailable_component(
            "context_anomaly", "graph_context_baseline_statistics_unavailable",
            GRAPH_CONTEXT_BASELINE_VERSION,
        )
    z_values: list[float] = []
    used: list[str] = []
    for name in _COMPONENT_NAMES:
        component = components.get(name)
        if component is None or not component.ready:
            continue
        median, median_reason = no_hook_finite_float(
            center.get(name), default=0.0, minimum=0.0, maximum=1.0,
            reason="graph_context_baseline_median_unavailable",
        )
        iqr, iqr_reason = no_hook_finite_float(
            scale.get(name), default=0.0, minimum=0.0,
            reason="graph_context_baseline_iqr_unavailable",
        )
        if median_reason or iqr_reason or iqr <= 0.0:
            continue
        z_values.append(max(0.0, component.value - median) / max(0.02, iqr))
        used.append(name)
    if not z_values:
        return unavailable_component(
            "context_anomaly", "graph_context_baseline_dimensions_unavailable",
            GRAPH_CONTEXT_BASELINE_VERSION,
        )
    ranked = sorted(z_values, reverse=True)[:2]
    robust_z = sum(ranked) / len(ranked)
    value = min(1.0, max(0.0, 1.0 - math.exp(-robust_z / 3.0)))
    context_key = baseline.get("context_key")
    context_text = str.__str__(context_key) if isinstance(context_key, str) else "unavailable"
    return GraphComponentEvidence(
        name="context_anomaly", value=value, ready=True,
        support_count=support, maturity=min(1.0, support / 32.0),
        unavailable_reason=None,
        provenance=(
            "context_key:" + context_text,
            "robust_dimensions:" + ",".join(used),
            "baseline_support:" + str(support),
        ),
        version=GRAPH_CONTEXT_BASELINE_VERSION,
    )


__all__ = ("context_baseline_component",)
