"""Context-conditioned Markov feature projection.

This owner consumes immutable posterior-predictive probability records.  It
never recomputes raw maximum-likelihood ratios, owns no known-dangerous chain
policy, and normalizes flow likelihood by effective transition count.
"""
from __future__ import annotations

from itertools import pairwise

from Virus_Scan.contracts.markov_learning import (
    MARKOV_CONTEXT_EXACT,
    MARKOV_MODEL_VERSION,
)
from Virus_Scan.models.contracts.model_feature_bundle import make_model_feature_bundle
from Virus_Scan.models.markov.feature_boundaries import (
    _markov_mapping_int,
)
from Virus_Scan.models.markov.feature_support import (
    markov_tag_rarity_score,
    ready_probability,
    record_confidence,
    record_fallback_level,
    record_reason,
    surprisal_projection,
)
from Virus_Scan.models.markov.flow import canonical_behavior_flow, safe_markov_stage_name
from Virus_Scan.models.markov.probability import (
    markov_pair_probability,
    markov_stage_probability,
)
from Virus_Scan.models.markov.sequence_probability import markov_sequence_probability
from Virus_Scan.utils.probability import safe_clamp

_FEATURE_MODEL_VERSION = "markov_feature_bundle_v3_contextual_dirichlet"

def markov_transition_score(
    prev_stage: object,
    tags: object,
    curr_stage: object,
    *,
    context_identity: object = None,
    engine: object = "other",
    snapshot: object = None,
) -> float:
    """Return smoothed stage-transition anomaly, neutral when unavailable."""
    record = markov_stage_probability(
        prev_stage,
        tags,
        curr_stage,
        context_identity=context_identity,
        engine=engine,
        snapshot=snapshot,
    )
    probability = ready_probability(record)
    return 0.0 if probability is None else safe_clamp(1.0 - probability)


def tag_pair_anomaly(
    tags: object,
    *,
    prev_stage: object = None,
    context_identity: object = None,
    engine: object = "other",
    snapshot: object = None,
) -> float:
    """Return length-normalized anomaly from smoothed ordered pair posteriors."""
    flow = canonical_behavior_flow(tags)
    probabilities = tuple(
        probability
        for left, right in pairwise(flow)
        if (
            probability := ready_probability(
                markov_pair_probability(
                    left,
                    right,
                    prev_stage=prev_stage,
                    context_identity=context_identity,
                    engine=engine,
                    snapshot=snapshot,
                )
            )
        ) is not None
    )
    _average_surprisal, anomaly = surprisal_projection(probabilities)
    return anomaly


def compute_markov_features(
    prev_stage: object,
    tags: object,
    curr_stage: object,
    *,
    context_identity: object = None,
    engine: object = "other",
    snapshot: object = None,
) -> object:
    """Publish learned Markov likelihood, maturity, fallback, and anomaly facts."""
    flow = canonical_behavior_flow(tags)
    previous_stage = safe_markov_stage_name(prev_stage)
    current_stage = safe_markov_stage_name(curr_stage)
    if len(flow) < 2:
        return make_model_feature_bundle(
            {
                "ready": False,
                "transition": 0.0,
                "rarity": 0.0,
                "pair_anomaly": 0.0,
                "sequence_anomaly": 0.0,
                "average_surprisal": 0.0,
                "minimum_supported_transition_probability": None,
                "supported_transitions": 0,
                "fallback_transitions": 0,
                "unavailable_transitions": 0,
                "confidence": 0.0,
                "flow": flow,
                "reason": "insufficient_behavior_flow",
                "support": 0,
                "model_state_version": MARKOV_MODEL_VERSION,
            },
            model_version=_FEATURE_MODEL_VERSION,
        )

    stage_record = markov_stage_probability(
        previous_stage,
        flow,
        current_stage,
        context_identity=context_identity,
        engine=engine,
        snapshot=snapshot,
    )
    pair_records = tuple(
        markov_pair_probability(
            left,
            right,
            prev_stage=previous_stage,
            context_identity=context_identity,
            engine=engine,
            snapshot=snapshot,
        )
        for left, right in pairwise(flow)
    )
    sequence_record = markov_sequence_probability(
        previous_stage,
        flow,
        current_stage,
        context_identity=context_identity,
        engine=engine,
        snapshot=snapshot,
    )

    pair_probabilities = tuple(
        probability
        for record in pair_records
        if (probability := ready_probability(record)) is not None
    )
    stage_probability = ready_probability(stage_record)
    sequence_probability = ready_probability(sequence_record)
    _pair_average_surprisal, pair_anomaly = surprisal_projection(pair_probabilities)
    supported_probabilities = (
        *pair_probabilities,
        *((stage_probability,) if stage_probability is not None else ()),
    )
    average_surprisal, _full_flow_anomaly = surprisal_projection(supported_probabilities)

    supported_transitions = len(pair_probabilities) + int(stage_probability is not None)
    total_transitions = len(pair_records) + 1
    unavailable_transitions = total_transitions - supported_transitions
    ready_records = tuple(
        record
        for record in (stage_record, *pair_records)
        if ready_probability(record) is not None
    )
    fallback_transitions = sum(
        record_fallback_level(record) != MARKOV_CONTEXT_EXACT
        for record in ready_records
    )
    confidence = min(
        (record_confidence(record) for record in ready_records),
        default=0.0,
    )
    minimum_probability = min(
        (*pair_probabilities, *((stage_probability,) if stage_probability is not None else ())),
        default=None,
    )
    sequence_anomaly = (
        0.0 if sequence_probability is None
        else safe_clamp(1.0 - sequence_probability)
    )
    transition = (
        0.0 if stage_probability is None
        else safe_clamp(1.0 - stage_probability)
    )
    ready = sequence_probability is not None and unavailable_transitions == 0
    reason = None if ready else record_reason(
        sequence_record,
        "insufficient_markov_support",
    )
    support = _markov_mapping_int(sequence_record, "support", 0)
    context_support = _markov_mapping_int(sequence_record, "context_support", 0)
    fallback_level = record_fallback_level(sequence_record)

    # The global rarity baseline remains a separate learned side signal.  It is
    # published only when the posterior sequence itself is mature.
    rarity = markov_tag_rarity_score(flow) if ready else 0.0
    if not ready:
        pair_anomaly = 0.0
        average_surprisal = 0.0
        transition = 0.0
        sequence_anomaly = 0.0
        confidence = 0.0
        minimum_probability = None

    return make_model_feature_bundle(
        {
            "ready": ready,
            "reason": reason,
            "support": int(support),
            "context_support": int(context_support),
            "transition": safe_clamp(transition),
            "rarity": safe_clamp(rarity),
            "pair_anomaly": safe_clamp(pair_anomaly),
            "sequence_anomaly": safe_clamp(sequence_anomaly),
            "average_surprisal": average_surprisal,
            "minimum_supported_transition_probability": minimum_probability,
            "supported_transitions": supported_transitions,
            "fallback_transitions": fallback_transitions,
            "unavailable_transitions": unavailable_transitions,
            "confidence": safe_clamp(confidence),
            "fallback_level": fallback_level,
            "flow": flow,
            "previous_stage": previous_stage,
            "current_stage": current_stage,
            "model_state_version": MARKOV_MODEL_VERSION,
        },
        model_version=_FEATURE_MODEL_VERSION,
    )


__all__ = (
    "compute_markov_features",
    "markov_transition_score",
    "tag_pair_anomaly",
)
