"""Canonical posterior-predictive support for the Markov model.

This module owns immutable smoothing, context fallback selection, and evidence
record construction.  Public probability entry points remain in their bounded
pair/stage and sequence owners.
"""
from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from Virus_Scan.contracts.markov_learning import (
    MARKOV_CONTEXT_ENGINE,
    MARKOV_CONTEXT_EXACT,
    MARKOV_CONTEXT_GLOBAL,
    MARKOV_MINIMUM_SUPPORT,
    MARKOV_MODEL_VERSION,
    MARKOV_SMOOTHING_ALPHA,
    MARKOV_SMOOTHING_NAME,
    MARKOV_STATE_SCHEMA_VERSION,
    MARKOV_UNSEEN_BUCKET_COUNT,
    markov_context_levels,
    markov_global_context_key,
)
from Virus_Scan.models.contracts.probability_record import make_markov_probability_record
from Virus_Scan.models.markov.counters import (
    counter_support,
    counter_target_count,
    markov_first_reason,
    snapshot_transition_counter,
)
from Virus_Scan.models.markov.text_boundary import markov_detached_text

FALLBACK_CONFIDENCE = MappingProxyType({
    MARKOV_CONTEXT_EXACT: 1.0,
    MARKOV_CONTEXT_ENGINE: 0.75,
    MARKOV_CONTEXT_GLOBAL: 0.5,
})
FALLBACK_RANK = MappingProxyType({
    MARKOV_CONTEXT_EXACT: 0,
    MARKOV_CONTEXT_ENGINE: 1,
    MARKOV_CONTEXT_GLOBAL: 2,
})

def malformed_pair_input(value: object) -> bool:
    if value is None or isinstance(value, (str, bytes, int, float, bool, Mapping)):
        return False
    _text, reason = markov_detached_text(value, default_text="")
    return reason == "unsupported_markov_text"


def query_context_levels(
    context_identity: object, engine: object
) -> tuple[tuple[str, str], ...] | None:
    if context_identity is None:
        return ((MARKOV_CONTEXT_GLOBAL, markov_global_context_key()),)
    if type(context_identity) is not tuple or type(engine) is not str:
        return None
    try:
        return markov_context_levels(
            engine=str.strip(str.__str__(engine)) or "other",
            context_identity=context_identity,
        )
    except (TypeError, ValueError):
        return None


def counter_facts(
    snapshot: object,
    *,
    transition_key: object,
    target: str,
    vocabulary_key: object | None,
    context_support_key: object | None,
) -> dict[str, object]:
    counter, snapshot_error = snapshot_transition_counter(snapshot, transition_key)
    support, counter_vocab, support_error = counter_support(counter)
    count, count_error = counter_target_count(counter, target)
    vocabulary_size = counter_vocab
    vocabulary_error = ""
    if vocabulary_key is not None:
        vocabulary_counter, vocabulary_snapshot_error = snapshot_transition_counter(
            snapshot, vocabulary_key,
        )
        _vocabulary_support, explicit_vocab, vocabulary_support_error = counter_support(
            vocabulary_counter,
        )
        vocabulary_error = markov_first_reason(
            vocabulary_snapshot_error, vocabulary_support_error,
        )
        if explicit_vocab > 0:
            vocabulary_size = explicit_vocab
    context_support = support
    context_error = ""
    if context_support_key is not None:
        context_counter, context_snapshot_error = snapshot_transition_counter(
            snapshot, context_support_key,
        )
        context_support, _context_vocab, context_support_error = counter_support(
            context_counter,
        )
        context_error = markov_first_reason(
            context_snapshot_error, context_support_error,
        )
    error = markov_first_reason(
        snapshot_error,
        support_error,
        count_error,
        vocabulary_error,
        context_error,
    )
    return {
        "support": support,
        "count": count,
        "vocabulary_size": vocabulary_size,
        "context_support": context_support,
        "error": error,
    }


def posterior_probability(count: int, support: int, vocabulary_size: int) -> float:
    vocabulary_with_unseen = max(1, vocabulary_size) + MARKOV_UNSEEN_BUCKET_COUNT
    denominator = support + MARKOV_SMOOTHING_ALPHA * vocabulary_with_unseen
    return (count + MARKOV_SMOOTHING_ALPHA) / denominator


def fallback_confidence(level: str, support: int, context_support: int) -> float:
    maturity_support = max(support, context_support)
    maturity = maturity_support / max(
        1.0, float(maturity_support + MARKOV_MINIMUM_SUPPORT)
    )
    return max(0.0, min(1.0, FALLBACK_CONFIDENCE[level] * maturity))


def probability_record(
    *,
    ready: bool,
    reason: str | None,
    facts: dict[str, object],
    level: str,
    context_key: str | None,
    source: str,
    target: str,
    flow: tuple[str, ...] = (),
    previous_stage: str | None = None,
    model_version: str = MARKOV_MODEL_VERSION,
) -> object:
    support = int(facts["support"])
    count = int(facts["count"])
    observed_vocab = int(facts["vocabulary_size"])
    context_support = int(facts["context_support"])
    vocabulary_with_unseen = max(1, observed_vocab) + MARKOV_UNSEEN_BUCKET_COUNT
    probability = (
        posterior_probability(count, support, observed_vocab) if ready else None
    )
    return make_markov_probability_record(
        ready=ready,
        probability=probability,
        support=support,
        count=count,
        vocab=vocabulary_with_unseen,
        smoothing=MARKOV_SMOOTHING_NAME,
        reason=reason,
        source=source,
        target=target,
        flow=flow,
        model_version=model_version,
        alpha=MARKOV_SMOOTHING_ALPHA,
        unseen_bucket_policy="explicit_single_unseen_target",
        unseen_bucket_count=MARKOV_UNSEEN_BUCKET_COUNT,
        minimum_support=MARKOV_MINIMUM_SUPPORT,
        fallback_level=level,
        fallback_confidence=fallback_confidence(level, support, context_support),
        context_support=context_support,
        state_schema=MARKOV_STATE_SCHEMA_VERSION,
        context_key=context_key,
        previous_stage=previous_stage,
    )


def select_candidate(
    candidates: tuple[tuple[str, str | None, dict[str, object]], ...],
    *,
    insufficient_reason: str,
    source: str,
    target: str,
    flow: tuple[str, ...] = (),
    previous_stage: str | None = None,
    model_version: str = MARKOV_MODEL_VERSION,
) -> object:
    first_nonempty: tuple[str, str | None, dict[str, object]] | None = None
    last_candidate = candidates[-1]
    for level, context_key, facts in candidates:
        error = str(facts["error"])
        if error != "":
            return probability_record(
                ready=False,
                reason=error,
                facts=facts,
                level=level,
                context_key=context_key,
                source=source,
                target=target,
                flow=flow,
                previous_stage=previous_stage,
                model_version=model_version,
            )
        support = int(facts["support"])
        if support > 0 and first_nonempty is None:
            first_nonempty = (level, context_key, facts)
        if support >= MARKOV_MINIMUM_SUPPORT:
            return probability_record(
                ready=True,
                reason=None,
                facts=facts,
                level=level,
                context_key=context_key,
                source=source,
                target=target,
                flow=flow,
                previous_stage=previous_stage,
                model_version=model_version,
            )
    level, context_key, facts = first_nonempty or last_candidate
    return probability_record(
        ready=False,
        reason=insufficient_reason,
        facts=facts,
        level=level,
        context_key=context_key,
        source=source,
        target=target,
        flow=flow,
        previous_stage=previous_stage,
        model_version=model_version,
    )


__all__ = (
    "FALLBACK_RANK",
    "counter_facts",
    "malformed_pair_input",
    "probability_record",
    "query_context_levels",
    "select_candidate",
)
