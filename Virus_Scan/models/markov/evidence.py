from __future__ import annotations

from Virus_Scan.contracts.markov_learning import (
    MARKOV_CONTEXT_GLOBAL,
    MARKOV_MINIMUM_SUPPORT,
    MARKOV_MODEL_VERSION,
    MARKOV_SMOOTHING_ALPHA,
    MARKOV_SMOOTHING_NAME,
    MARKOV_STATE_SCHEMA_VERSION,
    MARKOV_UNSEEN_BUCKET_COUNT,
)
from Virus_Scan.models.contracts.probability_record import make_markov_probability_record
from Virus_Scan.models.markov.flow import canonical_behavior_flow, safe_markov_stage_name


def markov_probability_unavailable(
    reason: str,
    *,
    source: object = "unknown",
    target: object = "unknown",
    flow: object = (),
    previous_stage: object = None,
) -> object:
    source_text = safe_markov_stage_name(source)
    target_text = safe_markov_stage_name(target)
    previous_stage_text = (
        None if previous_stage is None else safe_markov_stage_name(previous_stage)
    )
    return make_markov_probability_record(
        ready=False,
        probability=None,
        support=0,
        count=0,
        vocab=MARKOV_UNSEEN_BUCKET_COUNT,
        smoothing=MARKOV_SMOOTHING_NAME,
        reason=reason,
        source=source_text,
        target=target_text,
        flow=canonical_behavior_flow(flow),
        model_version=MARKOV_MODEL_VERSION,
        alpha=MARKOV_SMOOTHING_ALPHA,
        unseen_bucket_policy="explicit_single_unseen_target",
        unseen_bucket_count=MARKOV_UNSEEN_BUCKET_COUNT,
        minimum_support=MARKOV_MINIMUM_SUPPORT,
        fallback_level=MARKOV_CONTEXT_GLOBAL,
        fallback_confidence=0.0,
        context_support=0,
        state_schema=MARKOV_STATE_SCHEMA_VERSION,
        previous_stage=previous_stage_text,
    )


__all__ = ("markov_probability_unavailable",)
