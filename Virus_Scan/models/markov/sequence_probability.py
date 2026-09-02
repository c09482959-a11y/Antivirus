"""Canonical full-flow posterior probability for the Markov model."""
from __future__ import annotations

import math

from Virus_Scan.contracts.markov_learning import (
    MARKOV_CONTEXT_GLOBAL,
    MARKOV_MINIMUM_SUPPORT,
    MARKOV_SMOOTHING_ALPHA,
    MARKOV_SMOOTHING_NAME,
    MARKOV_STATE_SCHEMA_VERSION,
    MARKOV_UNSEEN_BUCKET_COUNT,
)
from Virus_Scan.models.contracts.probability_record import make_markov_probability_record
from Virus_Scan.models.markov.flow import canonical_behavior_flow, safe_markov_stage_name
from Virus_Scan.models.markov.posterior import FALLBACK_RANK
from Virus_Scan.models.markov.probability import (
    markov_pair_probability,
    markov_stage_probability,
)

def markov_sequence_probability(
    prev_stage: object,
    behavior_flow: object,
    curr_stage: object,
    *,
    context_identity: object = None,
    engine: object = "other",
    snapshot: object = None,
) -> object:
    """Return the geometric mean posterior for all flow and stage transitions."""
    flow = canonical_behavior_flow(behavior_flow)
    source = safe_markov_stage_name(prev_stage)
    target = safe_markov_stage_name(curr_stage)
    stage_record = markov_stage_probability(
        source,
        flow,
        target,
        context_identity=context_identity,
        engine=engine,
        snapshot=snapshot,
    )
    pair_records = tuple(
        markov_pair_probability(
            left,
            right,
            prev_stage=source,
            context_identity=context_identity,
            engine=engine,
            snapshot=snapshot,
        )
        for left, right in zip(flow, flow[1:], strict=False)
    )
    records = (stage_record, *pair_records)
    reason = next(
        (
            str(record.get("reason"))
            for record in records
            if record.get("ready") is not True and record.get("reason")
        ),
        None,
    )
    ready = bool(records) and reason is None
    probabilities = tuple(
        float(record["probability"])
        for record in records
        if record.get("ready") is True and record.get("probability") is not None
    )
    probability = (
        math.exp(sum(math.log(max(1e-300, value)) for value in probabilities) / len(probabilities))
        if ready and len(probabilities) == len(records)
        else None
    )
    support = min((int(record.get("support") or 0) for record in records), default=0)
    count = int(stage_record.get("count") or 0)
    vocab = max((int(record.get("vocab") or 0) for record in records), default=MARKOV_UNSEEN_BUCKET_COUNT)
    worst_record = max(
        records,
        key=lambda record: FALLBACK_RANK.get(
            str(record.get("fallback_level") or MARKOV_CONTEXT_GLOBAL), 99,
        ),
    )
    fallback_level = str(
        worst_record.get("fallback_level") or MARKOV_CONTEXT_GLOBAL
    )
    confidence = min(
        (float(record.get("fallback_confidence") or 0.0) for record in records),
        default=0.0,
    )
    context_support = min(
        (int(record.get("context_support") or 0) for record in records),
        default=0,
    )
    context_key = worst_record.get("context_key")
    return make_markov_probability_record(
        ready=ready,
        probability=probability,
        support=support,
        count=count,
        vocab=vocab,
        smoothing=MARKOV_SMOOTHING_NAME,
        reason=reason,
        source=source,
        target=target,
        flow=flow,
        model_version="markov_sequence_contextual_dirichlet_v2",
        alpha=MARKOV_SMOOTHING_ALPHA,
        unseen_bucket_policy="explicit_single_unseen_target",
        unseen_bucket_count=MARKOV_UNSEEN_BUCKET_COUNT,
        minimum_support=MARKOV_MINIMUM_SUPPORT,
        fallback_level=fallback_level,
        fallback_confidence=confidence,
        context_support=context_support,
        state_schema=MARKOV_STATE_SCHEMA_VERSION,
        context_key=context_key,
        previous_stage=source,
    )


__all__ = ("markov_sequence_probability",)
