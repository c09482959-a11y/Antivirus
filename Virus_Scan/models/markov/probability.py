"""Canonical pair and stage posterior-predictive Markov probabilities."""
from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.markov_learning import (
    MARKOV_CONTEXT_GLOBAL,
    markov_context_support_key,
    markov_event_transition_key,
    markov_event_vocabulary_key,
    markov_stage_transition_key,
    markov_stage_vocabulary_key,
)
from Virus_Scan.models.markov.evidence import markov_probability_unavailable
from Virus_Scan.models.markov.flow import (
    canonical_behavior_flow,
    markov_behavior_event_name,
    safe_markov_stage_name,
)
from Virus_Scan.models.markov.posterior import (
    counter_facts,
    malformed_pair_input,
    probability_record,
    query_context_levels,
    select_candidate,
)

def markov_pair_probability(
    source_event: object,
    target_event: object,
    *,
    prev_stage: object = None,
    context_identity: object = None,
    engine: object = "other",
    snapshot: object = None,
) -> object:
    """Return a smoothed source-event posterior with deterministic fallback."""
    try:
        source = markov_behavior_event_name(source_event)
        target = markov_behavior_event_name(target_event)
    except RECOVERABLE_RUNTIME_ERRORS:
        return markov_probability_unavailable(
            "malformed_markov_pair_public_input",
            source=source_event,
            target=target_event,
            previous_stage=prev_stage,
        )
    if source == "" or target == "":
        if malformed_pair_input(source_event) or malformed_pair_input(target_event):
            return markov_probability_unavailable(
                "malformed_markov_pair_public_input",
                source=source,
                target=target,
                previous_stage=prev_stage,
            )
        facts = {
            "support": 0,
            "count": 0,
            "vocabulary_size": 0,
            "context_support": 0,
            "error": "",
        }
        return probability_record(
            ready=False,
            reason="insufficient_behavior_flow",
            facts=facts,
            level=MARKOV_CONTEXT_GLOBAL,
            context_key=None,
            source=source,
            target=target,
        )
    if prev_stage is None:
        return markov_probability_unavailable(
            "markov_previous_stage_unavailable",
            source=source,
            target=target,
            previous_stage=None,
        )
    previous_stage = safe_markov_stage_name(prev_stage)
    if previous_stage == "unknown":
        return markov_probability_unavailable(
            "markov_previous_stage_unavailable",
            source=source,
            target=target,
            previous_stage=previous_stage,
        )
    levels = query_context_levels(context_identity, engine)
    if levels is None:
        return markov_probability_unavailable(
            "markov_context_identity_unavailable",
            source=source,
            target=target,
            previous_stage=previous_stage,
        )
    candidates: list[tuple[str, str | None, dict[str, object]]] = []
    for level, context_key in levels:
        facts = counter_facts(
            snapshot,
            transition_key=markov_event_transition_key(
                context_key=context_key,
                previous_stage=previous_stage,
                source_event=source,
            ),
            target=target,
            vocabulary_key=markov_event_vocabulary_key(context_key),
            context_support_key=markov_context_support_key(context_key),
        )
        candidates.append((level, context_key, facts))
    return select_candidate(
        tuple(candidates),
        insufficient_reason="insufficient_markov_pair_support",
        source=source,
        target=target,
        previous_stage=previous_stage,
    )


def markov_stage_probability(
    prev_stage: object,
    behavior_flow: object,
    curr_stage: object,
    *,
    context_identity: object = None,
    engine: object = "other",
    snapshot: object = None,
) -> object:
    """Return a context/previous-stage conditioned stage posterior."""
    flow = canonical_behavior_flow(behavior_flow)
    target = safe_markov_stage_name(curr_stage)
    source = safe_markov_stage_name(prev_stage)
    if source == "unknown" or target == "unknown":
        return markov_probability_unavailable(
            "markov_stage_identity_unavailable",
            source=source,
            target=target,
            flow=flow,
            previous_stage=source,
        )
    if len(flow) < 2:
        facts = {
            "support": 0,
            "count": 0,
            "vocabulary_size": 0,
            "context_support": 0,
            "error": "",
        }
        return probability_record(
            ready=False,
            reason="insufficient_behavior_flow",
            facts=facts,
            level=MARKOV_CONTEXT_GLOBAL,
            context_key=None,
            source=source,
            target=target,
            flow=flow,
            previous_stage=source,
        )
    levels = query_context_levels(context_identity, engine)
    if levels is None:
        return markov_probability_unavailable(
            "markov_context_identity_unavailable",
            source=source,
            target=target,
            flow=flow,
            previous_stage=source,
        )
    candidates: list[tuple[str, str | None, dict[str, object]]] = []
    for level, context_key in levels:
        facts = counter_facts(
            snapshot,
            transition_key=markov_stage_transition_key(
                context_key=context_key,
                previous_stage=source,
                behavior_flow=flow,
            ),
            target=target,
            vocabulary_key=markov_stage_vocabulary_key(context_key),
            context_support_key=markov_context_support_key(context_key),
        )
        candidates.append((level, context_key, facts))
    return select_candidate(
        tuple(candidates),
        insufficient_reason="insufficient_markov_stage_support",
        source=source,
        target=target,
        flow=flow,
        previous_stage=source,
    )


__all__ = (
    "markov_pair_probability",
    "markov_stage_probability",
)
