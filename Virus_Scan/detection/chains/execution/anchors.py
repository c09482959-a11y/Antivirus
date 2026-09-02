"""Single canonical evaluator for behavior Chains and explicit anchors."""

from __future__ import annotations

from collections import Counter
import hashlib
import json

from Virus_Scan.contracts.chain_evidence import (
    ChainDecision,
    ChainEvent,
    ChainEvidence,
    ChainEvidenceGeneration,
    ChainRule,
    ChainRuleOutcome,
)
from Virus_Scan.detection.chains.execution.compiled_registry import (
    COMPILED_CHAIN_REGISTRY,
    COMPILED_CHAIN_REGISTRY_DIGEST,
    COMPILED_CHAIN_REGISTRY_VERSION,
    ChainEventIndex,
    CompiledChainRule,
    build_chain_event_index,
)
from Virus_Scan.detection.chains.execution.event_materialization import (
    merge_chain_events,
    sequence_chain_events,
    tag_chain_events,
)
from Virus_Scan.detection.chains.execution.matching import evaluate_compiled_chain_rule
from Virus_Scan.detection.chains.execution.static_relations import (
    StaticChainRelationIndex,
    build_static_chain_relation_index,
)
from Virus_Scan.detection.registries.chain_registry import (
    CHAIN_REGISTRY_DIGEST,
    CHAIN_REGISTRY_VERSION,
)

_MAX_FILTER_ITEMS = 256


def _text_filter(value: object) -> frozenset[str] | None:
    if value is None:
        return None
    if type(value) not in (tuple, list, set, frozenset):
        return frozenset()
    raw = tuple(value) if type(value) in (tuple, list) else tuple(sorted(value))
    return frozenset(
        text
        for item in raw[:_MAX_FILTER_ITEMS]
        if type(item) is str and (text := str.__str__(item).strip().lower())
    )


def _selected_compiled_rules(
    *,
    match_modes: object = None,
    families: object = None,
    rule_ids: object = None,
) -> tuple[CompiledChainRule, ...]:
    return COMPILED_CHAIN_REGISTRY.selected_rules(
        match_modes=_text_filter(match_modes),
        families=_text_filter(families),
        rule_ids=_text_filter(rule_ids),
    )


def _ordered_rules(rules: tuple[CompiledChainRule, ...]) -> tuple[CompiledChainRule, ...]:
    return tuple(rule for rule in rules if rule.source.match_mode == "ordered")


def _correlation_rules(rules: tuple[CompiledChainRule, ...]) -> tuple[CompiledChainRule, ...]:
    return tuple(rule for rule in rules if rule.source.match_mode in {"anchor", "unordered"})


def _decision_rank(decision: ChainDecision) -> tuple[object, ...]:
    status_rank = {
        "confirmed": 0,
        "candidate": 1,
        "partial": 2,
        "blocked": 3,
        "rejected": 4,
    }
    order_rank = {
        "observed_order": 0,
        "causal_link": 1,
        "static_control_flow": 2,
        "synthetic_order": 3,
        "unordered_correlation": 4,
        "partial": 5,
    }
    return (
        status_rank[decision.status],
        order_rank[decision.candidate.order_class],
        -decision.candidate.confidence,
        -decision.candidate.support,
        -decision.operational_severity,
        tuple(sorted(decision.candidate.distinct_root_ids)),
        decision.candidate.chain_id,
    )


def _unique_decisions(decisions: tuple[ChainDecision, ...]) -> tuple[ChainDecision, ...]:
    by_id: dict[str, ChainDecision] = {}
    for decision in decisions:
        chain_id = decision.candidate.chain_id
        current = by_id.get(chain_id)
        if current is None or _decision_rank(decision) < _decision_rank(current):
            by_id[chain_id] = decision
    return tuple(sorted(by_id.values(), key=_decision_rank))[:256]


def _event_signatures(index: ChainEventIndex) -> tuple[str, ...]:
    return tuple(item.signature for item in index.indexed_events)


def _multiset_contains(current: tuple[str, ...], previous: tuple[str, ...]) -> bool:
    current_counts = Counter(current)
    return all(current_counts[value] >= count for value, count in Counter(previous).items())


def _previous_reuse_state(
    previous: object,
    *,
    selected_rule_ids: tuple[str, ...],
    runtime_ordered_signatures: tuple[str, ...],
    static_ordered_signatures: tuple[str, ...],
    correlation_signatures: tuple[str, ...],
) -> tuple[dict[str, ChainRuleOutcome], str]:
    if previous is None:
        return {}, "initial_generation"
    if type(previous) is not ChainEvidenceGeneration:
        return {}, "previous_generation_invalid"
    if (
        previous.registry_version != CHAIN_REGISTRY_VERSION
        or previous.registry_digest != CHAIN_REGISTRY_DIGEST
        or previous.compiled_registry_version != COMPILED_CHAIN_REGISTRY_VERSION
        or previous.compiled_registry_digest != COMPILED_CHAIN_REGISTRY_DIGEST
    ):
        return {}, "registry_identity_changed"
    if previous.selected_rule_ids != selected_rule_ids:
        return {}, "selected_rule_set_changed"
    if not (
        _multiset_contains(
            runtime_ordered_signatures, previous.runtime_ordered_event_signatures,
        )
        and _multiset_contains(
            static_ordered_signatures, previous.static_ordered_event_signatures,
        )
        and _multiset_contains(
            correlation_signatures, previous.correlation_event_signatures,
        )
    ):
        return {}, "non_monotonic_evidence"
    return {item.chain_id: item for item in previous.outcomes}, ""


def _generation_digest(record: object) -> str:
    payload = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _evaluate_rule_outcome(
    rule: CompiledChainRule,
    event_index: ChainEventIndex,
    static_relation_index: StaticChainRelationIndex,
) -> ChainRuleOutcome:
    decision = None
    if rule.chain_id in event_index.candidate_rule_ids:
        decision = evaluate_compiled_chain_rule(rule, event_index, static_relation_index)
    return ChainRuleOutcome(
        chain_id=rule.chain_id,
        rule_digest=rule.digest,
        input_digest=_generation_digest({
            "event_dependency_digest": event_index.dependency_digest(rule),
            "static_relation_digest": static_relation_index.dependency_digest(
                bool(rule.source.static_relations),
            ),
        }),
        decision=decision,
    )


def _is_static_control_flow_event(event: ChainEvent) -> bool:
    return (
        event.modality == "static_control_flow"
        and event.timing_provenance == "static_control_flow"
    )


def _ordered_rule_domains(rule: CompiledChainRule) -> tuple[bool, bool]:
    """Return ``(runtime_allowed, static_allowed)`` for one ordered rule.

    Static order is usable only when the rule explicitly declares the
    ``static_control_flow`` modality.  Rules without a modality declaration
    retain the historical runtime/API/tag-order domain and are never silently
    upgraded to static-control-flow authority.
    """
    modalities = rule.source.required_modalities
    static_allowed = "static_control_flow" in modalities
    runtime_allowed = (
        not modalities
        or any(modality != "static_control_flow" for modality in modalities)
    )
    return runtime_allowed, static_allowed


def _ordered_rule_input_digest(
    rule: CompiledChainRule,
    runtime_index: ChainEventIndex,
    static_index: ChainEventIndex,
    static_relation_index: StaticChainRelationIndex,
) -> str:
    runtime_allowed, static_allowed = _ordered_rule_domains(rule)
    domains: dict[str, str] = {}
    if runtime_allowed:
        domains["runtime"] = runtime_index.dependency_digest(rule)
    if static_allowed:
        domains["static_control_flow"] = static_index.dependency_digest(rule)
    return _generation_digest({
        "chain_id": rule.chain_id,
        "ordered_domain_inputs": domains,
        "static_relation_digest": static_relation_index.dependency_digest(
            bool(rule.source.static_relations),
        ),
    })


def _evaluate_ordered_rule_outcome(
    rule: CompiledChainRule,
    runtime_index: ChainEventIndex,
    static_index: ChainEventIndex,
    static_relation_index: StaticChainRelationIndex,
) -> ChainRuleOutcome:
    runtime_allowed, static_allowed = _ordered_rule_domains(rule)
    decisions: list[ChainDecision] = []
    if runtime_allowed and rule.chain_id in runtime_index.candidate_rule_ids:
        runtime_decision = evaluate_compiled_chain_rule(rule, runtime_index, static_relation_index)
        if type(runtime_decision) is ChainDecision:
            decisions.append(runtime_decision)
    if static_allowed and rule.chain_id in static_index.candidate_rule_ids:
        static_decision = evaluate_compiled_chain_rule(rule, static_index, static_relation_index)
        if type(static_decision) is ChainDecision:
            decisions.append(static_decision)
    decision = min(decisions, key=_decision_rank) if decisions else None
    return ChainRuleOutcome(
        chain_id=rule.chain_id,
        rule_digest=rule.digest,
        input_digest=_ordered_rule_input_digest(rule, runtime_index, static_index, static_relation_index),
        decision=decision,
    )


def evaluate_chain_evidence_generation(
    *,
    tags: object = None,
    ordered_events: object = None,
    api_calls: object = None,
    match_modes: object = None,
    families: object = None,
    rule_ids: object = None,
    static_program_analyses: object = None,
    previous_generation: object = None,
) -> ChainEvidenceGeneration:
    """Evaluate one immutable evidence generation with exact per-rule reuse.

    Reuse is allowed only for a monotonic evidence extension under identical
    source and compiled registries and an identical selected-rule set.  A
    changed rule dependency digest is reevaluated; unaffected rule outcomes,
    including explicit no-decision outcomes, are reused.
    """
    rules = _selected_compiled_rules(
        match_modes=match_modes,
        families=families,
        rule_ids=rule_ids,
    )
    selected_rule_ids = tuple(rule.chain_id for rule in rules)
    failures: list[dict[str, object]] = []
    static_relation_index = build_static_chain_relation_index(static_program_analyses)

    ordered_rules = _ordered_rules(rules)
    correlation_rules = _correlation_rules(rules)
    tag_events: tuple[ChainEvent, ...] = ()
    if tags is not None and (ordered_rules or correlation_rules):
        materialized_tags, tag_failures = tag_chain_events(tags)
        tag_events = materialized_tags
        failures.extend(tag_failures)

    timeline_events: tuple[ChainEvent, ...] = ()
    api_events: tuple[ChainEvent, ...] = ()
    if ordered_rules:
        timeline_events, timeline_failures = sequence_chain_events(
            ordered_events, source="timeline",
        )
        failures.extend(timeline_failures)
    if ordered_rules or correlation_rules:
        api_events, api_failures = sequence_chain_events(
            api_calls, source="api_calls",
        )
        failures.extend(api_failures)

    static_tag_events = tuple(
        event for event in tag_events if _is_static_control_flow_event(event)
    )
    runtime_tag_events = tuple(
        event for event in tag_events if not _is_static_control_flow_event(event)
    )
    runtime_ordered_input = timeline_events or api_events or runtime_tag_events
    static_ordered_input = static_tag_events
    correlation_input = merge_chain_events(tag_events, api_events) if correlation_rules else ()
    runtime_ordered_index = build_chain_event_index(runtime_ordered_input, ordered_rules)
    static_ordered_index = build_chain_event_index(static_ordered_input, ordered_rules)
    correlation_index = build_chain_event_index(correlation_input, correlation_rules)
    runtime_ordered_signatures = _event_signatures(runtime_ordered_index)
    static_ordered_signatures = _event_signatures(static_ordered_index)
    correlation_signatures = _event_signatures(correlation_index)
    previous_outcomes, recompute_reason = _previous_reuse_state(
        previous_generation,
        selected_rule_ids=selected_rule_ids,
        runtime_ordered_signatures=runtime_ordered_signatures,
        static_ordered_signatures=static_ordered_signatures,
        correlation_signatures=correlation_signatures,
    )

    outcomes: list[ChainRuleOutcome] = []
    evaluated: list[str] = []
    reused: list[str] = []
    for rule in rules:
        if rule.source.match_mode == "ordered":
            input_digest = _ordered_rule_input_digest(
                rule, runtime_ordered_index, static_ordered_index, static_relation_index,
            )
        else:
            input_digest = _generation_digest({
                "event_dependency_digest": correlation_index.dependency_digest(rule),
                "static_relation_digest": static_relation_index.dependency_digest(
                    bool(rule.source.static_relations),
                ),
            })
        prior = previous_outcomes.get(rule.chain_id)
        if (
            prior is not None
            and prior.rule_digest == rule.digest
            and prior.input_digest == input_digest
        ):
            outcomes.append(prior)
            reused.append(rule.chain_id)
            continue
        if rule.source.match_mode == "ordered":
            outcomes.append(_evaluate_ordered_rule_outcome(
                rule, runtime_ordered_index, static_ordered_index, static_relation_index,
            ))
        else:
            outcomes.append(_evaluate_rule_outcome(rule, correlation_index, static_relation_index))
        evaluated.append(rule.chain_id)

    outcomes_tuple = tuple(outcomes)
    decisions = _unique_decisions(tuple(
        outcome.decision
        for outcome in outcomes_tuple
        if outcome.decision is not None
    ))
    evidence = ChainEvidence(
        registry_version=CHAIN_REGISTRY_VERSION,
        registry_digest=CHAIN_REGISTRY_DIGEST,
        decisions=decisions,
        failures=tuple(failures[:64]),
    )
    generation_record = {
        "compiled_registry_digest": COMPILED_CHAIN_REGISTRY_DIGEST,
        "compiled_registry_version": COMPILED_CHAIN_REGISTRY_VERSION,
        "correlation_event_digest": correlation_index.event_digest,
        "evaluated_rule_ids": tuple(sorted(evaluated)),
        "evidence": evidence.to_record(),
        "full_recompute_reason": recompute_reason,
        "runtime_ordered_event_digest": runtime_ordered_index.event_digest,
        "static_ordered_event_digest": static_ordered_index.event_digest,
        "static_relation_digest": static_relation_index.digest,
        "outcomes": tuple(item.to_record() for item in outcomes_tuple),
        "registry_digest": CHAIN_REGISTRY_DIGEST,
        "registry_version": CHAIN_REGISTRY_VERSION,
        "reused_rule_ids": tuple(sorted(reused)),
        "selected_rule_ids": selected_rule_ids,
    }
    return ChainEvidenceGeneration(
        generation_id=_generation_digest(generation_record),
        registry_version=CHAIN_REGISTRY_VERSION,
        registry_digest=CHAIN_REGISTRY_DIGEST,
        compiled_registry_version=COMPILED_CHAIN_REGISTRY_VERSION,
        compiled_registry_digest=COMPILED_CHAIN_REGISTRY_DIGEST,
        selected_rule_ids=selected_rule_ids,
        runtime_ordered_event_digest=runtime_ordered_index.event_digest,
        static_ordered_event_digest=static_ordered_index.event_digest,
        static_relation_digest=static_relation_index.digest,
        correlation_event_digest=correlation_index.event_digest,
        runtime_ordered_event_signatures=runtime_ordered_signatures,
        static_ordered_event_signatures=static_ordered_signatures,
        correlation_event_signatures=correlation_signatures,
        outcomes=outcomes_tuple,
        evaluated_rule_ids=tuple(sorted(evaluated)),
        reused_rule_ids=tuple(sorted(reused)),
        full_recompute_reason=recompute_reason,
        evidence=evidence,
    )


def evaluate_chain_evidence(
    *,
    tags: object = None,
    ordered_events: object = None,
    api_calls: object = None,
    match_modes: object = None,
    families: object = None,
    rule_ids: object = None,
    static_program_analyses: object = None,
) -> ChainEvidence:
    """Evaluate canonical rules through the one generation-owned matcher."""
    return evaluate_chain_evidence_generation(
        tags=tags,
        ordered_events=ordered_events,
        api_calls=api_calls,
        match_modes=match_modes,
        families=families,
        rule_ids=rule_ids,
        static_program_analyses=static_program_analyses,
    ).evidence


def published_chain_names(
    evidence: ChainEvidence,
    *,
    statuses: object = ("confirmed", "candidate"),
) -> tuple[str, ...]:
    """Return a deterministic concise projection from canonical decisions."""
    if type(evidence) is not ChainEvidence:
        return ()
    allowed = _text_filter(statuses)
    if allowed is None:
        allowed = frozenset({"confirmed", "candidate"})
    return tuple(
        decision.candidate.chain_id
        for decision in evidence.decisions
        if decision.status in allowed
    )


def published_chain_records(evidence: ChainEvidence) -> tuple[dict[str, object], ...]:
    """Return bounded JSON-safe records from the canonical evidence bundle."""
    if type(evidence) is not ChainEvidence:
        return ()
    return tuple(decision.to_record() for decision in evidence.decisions)


__all__ = (
    "evaluate_chain_evidence",
    "evaluate_chain_evidence_generation",
    "published_chain_names",
    "published_chain_records",
)
