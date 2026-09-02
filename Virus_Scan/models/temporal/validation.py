"""Canonical v5 projection of independent temporal evidence families."""
from __future__ import annotations

from typing import Final

from Virus_Scan.contracts.tag_evidence import (
    active_tag_evidence_records,
    distinct_root_tag_evidence_records,
)
from Virus_Scan.detection.api.tag_evidence_contracts import scoreable_tag_evidence
from Virus_Scan.models.api.markov_contracts import canonical_behavior_flow
from Virus_Scan.models.temporal.event_materialization import (
    materialize_temporal_events,
)
from Virus_Scan.models.temporal.evidence import TEMPORAL_HIGH_RISK_TAGS
from Virus_Scan.models.temporal.policy import (
    TEMPORAL_POLICY_VERSION,
    temporal_burst_policy_evidence,
    temporal_delay_policy_evidence,
    temporal_phase_progression_evidence,
)
from Virus_Scan.models.temporal.text_boundary import temporal_boundary_stage
from Virus_Scan.models.temporal.validation_support import (
    TEMPORAL_FUSION_VERSION,
    TEMPORAL_FUSION_WEIGHTS,
    temporal_chain_projection,
    temporal_dwell_projection,
    temporal_fusion_strength,
    temporal_markov_projection,
    temporal_observed_delay_projection,
)
from Virus_Scan.runtime.temporal_state import temporal_node_state_snapshot

TEMPORAL_VALIDATION_VERSION: Final[str] = (
    "temporal_validation_v5_separated_evidence"
)


def compute_temporal_validation(
    node: object,
    tags: object = None,
    prev_stage: object = None,
    curr_stage: object = None,
    markov: object = None,
    *,
    ordered_events: object = (),
    engine: object = "other",
    temporal_baselines: object = None,
) -> dict[str, object]:
    """Return separated learned, policy, Markov, chain, and state evidence."""
    consumed_kinds = frozenset({
        "observed", "normalized", "derived", "composite",
    })
    tag_evidence = scoreable_tag_evidence(
        tags, allowed_evidence_kinds=consumed_kinds,
    )
    root_records = distinct_root_tag_evidence_records(
        tag_evidence.records, allowed_evidence_kinds=consumed_kinds,
    )
    flow = tuple(canonical_behavior_flow(tuple(
        record.canonical_tag_id for record in root_records
    )))
    previous = temporal_boundary_stage(prev_stage, default="unknown")
    current = temporal_boundary_stage(curr_stage, default="unknown")
    node_text = node if type(node) is str and node else "<unknown>"
    engine_text = engine if type(engine) is str and engine else "other"
    events, validations = materialize_temporal_events(
        ordered_events=ordered_events,
        behavior_flow=flow,
        observation_id="validation:" + node_text,
        previous_stage=previous,
        current_stage=current,
    )
    phase = temporal_phase_progression_evidence(events)
    burst = temporal_burst_policy_evidence(events)
    delay_policy = temporal_delay_policy_evidence(events)
    observed_delay = temporal_observed_delay_projection(events)
    dwell = temporal_dwell_projection(
        temporal_baselines,
        engine=engine_text,
        node=node_text,
        events=events,
    )
    markov_evidence = temporal_markov_projection(
        markov, previous, flow, current,
    )
    chain = temporal_chain_projection(events)
    runtime_state = temporal_node_state_snapshot(node_text)
    ordered = {
        "ready": bool(events),
        "event_count": len(events),
        "distinct_source_evidence_count": len({
            event.source_evidence_id for event in events
        }),
        "synthetic_order_count": sum(
            event.timestamp_kind == "synthetic_order" for event in events
        ),
        "events": tuple(event.to_record() for event in events),
        "validations": tuple(record.to_record() for record in validations),
    }
    fusion = temporal_fusion_strength(
        dwell=dwell,
        phase=phase,
        burst=burst,
        delay=delay_policy,
        markov=markov_evidence,
    )
    anchor_roots = {
        record.root_observation_id
        for record in active_tag_evidence_records(tag_evidence.records)
        if record.canonical_tag_id in TEMPORAL_HIGH_RISK_TAGS
    }
    degraded_reasons = sorted({
        reason
        for validation in validations
        for reason in validation.reasons
    })
    if markov_evidence["degraded"] is True:
        degraded_reasons.append("markov_features_invalid")
    ready = bool(events)
    unavailable = (
        "cold_start_no_temporal_validation_support"
        if not ready else degraded_reasons[0] if degraded_reasons else None
    )
    hits = tuple(sorted(
        name for condition, name in (
            (bool(phase["strength"]), "temporal_phase_policy"),
            (bool(burst["strength"]), "temporal_burst_policy"),
            (
                any(row["strength"] for row in delay_policy),
                "temporal_delay_policy",
            ),
            (bool(dwell["ready"]), "temporal_learned_dwell"),
            (
                markov_evidence["degraded"] is True,
                "temporal_markov_feature_failure_evidence",
            ),
            (
                markov_evidence["ready"] is True
                and float(markov_evidence["anomaly"]) >= 0.6,
                "temporal_markov_high_anomaly",
            ),
        ) if condition
    ))
    return {
        "score": round(fusion * 18.0, 6),
        "evidence_strength": fusion,
        "fusion_version": TEMPORAL_FUSION_VERSION,
        "fusion_weights": TEMPORAL_FUSION_WEIGHTS,
        "hits": hits,
        "anchor_count": len(anchor_roots),
        "ordered_sequence_evidence": ordered,
        "observed_delay_evidence": observed_delay,
        "learned_dwell_evidence": dwell,
        "phase_progression_evidence": phase,
        "high_risk_burst_evidence": burst,
        "dangerous_delay_policy_evidence": delay_policy,
        "hidden_state_evidence": dict(runtime_state["hidden_state"]),
        "markov_transition_evidence": markov_evidence,
        "chain_evidence": chain,
        "chain_records": chain["records"],
        "chain_identities": chain["identities"],
        "chain_score_contribution": 0.0,
        "events": ordered["events"],
        "ready": ready,
        "degraded": bool(degraded_reasons),
        "unavailable_reason": unavailable,
        "evidence_type": "temporal_validation",
        "temporal_model_version": TEMPORAL_VALIDATION_VERSION,
        "temporal_policy_version": TEMPORAL_POLICY_VERSION,
        "tag_evidence_summary": dict(tag_evidence.summary),
        "evidence_kinds_consumed": (
            "observed", "normalized", "derived", "composite",
        ),
    }


__all__ = (
    "TEMPORAL_FUSION_VERSION",
    "TEMPORAL_FUSION_WEIGHTS",
    "TEMPORAL_VALIDATION_VERSION",
    "compute_temporal_validation",
)
