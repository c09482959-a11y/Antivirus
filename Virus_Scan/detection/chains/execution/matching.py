"""Deterministic distinct-root matching for compiled canonical Chain rules."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from Virus_Scan.contracts.chain_evidence import (
    ChainCandidate,
    ChainDecision,
    ChainEvent,
    ChainExplanation,
    ChainRule,
    ChainStep,
    MatchedChainStep,
)
from Virus_Scan.detection.chains.execution.compiled_registry import (
    ChainEventIndex,
    CompiledChainRule,
    CompiledChainStep,
    build_chain_event_index,
    compiled_chain_rules_for,
)
from Virus_Scan.detection.chains.execution.static_relations import (
    StaticChainRelationIndex,
    build_static_chain_relation_index,
    static_rule_relation_failures,
)


_STATUS_RANK = MappingProxyType({"confirmed": 4, "candidate": 3, "partial": 2, "blocked": 1, "rejected": 0})
_MAX_ORDERED_STATES = 512

_IDENTITY_REQUIREMENTS = (
    ("same_actor", "actor_identity"),
    ("same_target", "target_identity"),
    ("same_artifact", "artifact_identity"),
    ("same_host", "host_identity"),
    ("same_process", "process_identity"),
    ("same_connection", "connection_identity"),
)


def _field_available(event: ChainEvent, field_name: str) -> bool:
    if field_name == "source_location":
        return event.source_location.identifies_physical_source
    if field_name == "timestamp":
        return event.timestamp is not None
    value = getattr(event, field_name)
    return type(value) is str and value not in {"", "unavailable"}


def _has_explicit_constraints(rule: ChainRule) -> bool:
    return any((
        rule.same_actor, rule.same_target, rule.same_artifact, rule.same_host,
        rule.same_process, rule.same_connection, rule.platform_match,
        bool(rule.required_platforms), bool(rule.required_modalities),
        bool(rule.required_fields), rule.minimum_direct_observations > 0,
        bool(rule.static_relations),
    ))


def _implicit_anchor_group_failure(
    rule: ChainRule, events: tuple[ChainEvent, ...],
) -> int:
    required_count = sum(not step.optional for step in rule.steps)
    if (
        rule.match_mode != "anchor"
        or _has_explicit_constraints(rule)
        or len(events) < required_count
    ):
        return 0
    groups = tuple(event.correlation_group for event in events[:required_count])
    return int(not all(groups) or len(set(groups)) != 1)


def _constraint_failures(rule: ChainRule, events: tuple[ChainEvent, ...]) -> tuple[str, ...]:
    failures: set[str] = set()
    if not events:
        return ()
    for flag_name, field_name in _IDENTITY_REQUIREMENTS:
        if not getattr(rule, flag_name):
            continue
        values = tuple(getattr(event, field_name) for event in events)
        if any(not value for value in values):
            failures.add(flag_name + "_unavailable")
        elif len(set(values)) != 1:
            failures.add(flag_name + "_mismatch")
    platforms = tuple(event.platform for event in events)
    if rule.platform_match:
        if any(not value for value in platforms):
            failures.add("platform_match_unavailable")
        elif len(set(platforms)) != 1:
            failures.add("platform_match_mismatch")
    if rule.required_platforms:
        if any(not value for value in platforms):
            failures.add("required_platform_unavailable")
        elif any(value not in rule.required_platforms for value in platforms):
            failures.add("required_platform_unsupported")
    if rule.required_modalities:
        modalities = tuple(event.modality for event in events)
        if any(value in {"", "unavailable"} for value in modalities):
            failures.add("required_modality_unavailable")
        elif any(value not in rule.required_modalities for value in modalities):
            failures.add("required_modality_unsupported")
    direct_count = sum(event.directness == "direct" for event in events)
    if direct_count < rule.minimum_direct_observations:
        failures.add("minimum_direct_observations_unsatisfied")
    for field_name in rule.required_fields:
        if any(not _field_available(event, field_name) for event in events):
            failures.add("required_field_unavailable:" + field_name)
    return tuple(sorted(failures))


@dataclass(frozen=True)
class _OrderedState:
    matched: tuple[MatchedChainStep, ...] = ()
    missing: tuple[int, ...] = ()
    next_position: int = 0
    used_roots: frozenset[str] = frozenset()
    first_timestamp: float | None = None
    previous_timestamp: float | None = None
    previous_ordinal: int | None = None


def _event_compatible(state: _OrderedState, step: ChainStep, event: ChainEvent, rule: ChainRule) -> bool:
    if event.root_evidence_id in state.used_roots:
        return False
    if state.previous_ordinal is not None and step.max_gap is not None:
        if event.ordinal - state.previous_ordinal > step.max_gap:
            return False
    if state.previous_timestamp is not None and event.timestamp is not None:
        if event.timestamp < state.previous_timestamp:
            return False
    if state.first_timestamp is not None and event.timestamp is not None and rule.maximum_time_gap is not None:
        if event.timestamp - state.first_timestamp > rule.maximum_time_gap:
            return False
    return True


def _advance_state(
    state: _OrderedState,
    *,
    step_index: int,
    alternative: str,
    event: ChainEvent,
    event_position: int,
) -> _OrderedState:
    timestamp = event.timestamp
    first_timestamp = state.first_timestamp
    if first_timestamp is None and timestamp is not None:
        first_timestamp = timestamp
    previous_timestamp = timestamp if timestamp is not None else state.previous_timestamp
    return _OrderedState(
        matched=(*state.matched, MatchedChainStep(step_index=step_index, alternative=alternative, event=event)),
        missing=state.missing,
        next_position=event_position + 1,
        used_roots=frozenset((*state.used_roots, event.root_evidence_id)),
        first_timestamp=first_timestamp,
        previous_timestamp=previous_timestamp,
        previous_ordinal=event.ordinal,
    )


def _state_rank(
    state: _OrderedState,
    rule: ChainRule,
    static_relation_index: StaticChainRelationIndex | None = None,
) -> tuple[object, ...]:
    """Return an ascending best-match key with earliest deterministic tie-breaks."""
    required_matched = sum(not rule.steps[item.step_index].optional for item in state.matched)
    span = 0
    if len(state.matched) > 1:
        span = state.matched[-1].event.ordinal - state.matched[0].event.ordinal
    identity = tuple(
        (item.step_index, item.event.ordinal, item.event.evidence_id)
        for item in state.matched
    )
    required_matches = tuple(
        item for item in state.matched
        if not rule.steps[item.step_index].optional
    )
    required_events = tuple(item.event for item in required_matches)
    relation_failures = static_rule_relation_failures(
        rule.static_relations, required_matches, static_relation_index,
    )
    return (
        -required_matched,
        len(_constraint_failures(rule, required_events)) + len(relation_failures),
        _implicit_anchor_group_failure(rule, required_events),
        -sum(item.event.directness == "direct" for item in state.matched),
        -len(state.matched),
        -len(state.used_roots),
        len(state.missing),
        span,
        identity,
    )


def _prune_states(
    states: list[_OrderedState],
    rule: ChainRule,
    static_relation_index: StaticChainRelationIndex | None = None,
) -> tuple[_OrderedState, ...]:
    unique: dict[tuple[object, ...], _OrderedState] = {}
    for state in states:
        key = (
            state.next_position,
            state.used_roots,
            state.missing,
            tuple((item.step_index, item.event.evidence_id) for item in state.matched),
        )
        unique[key] = state
    ranked = sorted(unique.values(), key=lambda item: _state_rank(item, rule))
    return tuple(ranked[:_MAX_ORDERED_STATES])


def _ordered_matches(
    compiled_rule: CompiledChainRule,
    event_index: ChainEventIndex,
    static_relation_index: StaticChainRelationIndex | None = None,
) -> tuple[tuple[MatchedChainStep, ...], tuple[int, ...]]:
    rule = compiled_rule.source
    states: tuple[_OrderedState, ...] = (_OrderedState(),)
    for step_index, compiled_step in enumerate(compiled_rule.steps):
        step = compiled_step.source
        matching_events = event_index.matching_events(compiled_step)
        next_states: list[_OrderedState] = []
        for state in states:
            if step.optional:
                next_states.append(state)
            else:
                next_states.append(_OrderedState(
                    matched=state.matched,
                    missing=(*state.missing, step_index),
                    next_position=state.next_position,
                    used_roots=state.used_roots,
                    first_timestamp=state.first_timestamp,
                    previous_timestamp=state.previous_timestamp,
                    previous_ordinal=state.previous_ordinal,
                ))
            for event_position, alternative in matching_events:
                if event_position < state.next_position:
                    continue
                event = event_index.events[event_position]
                if _event_compatible(state, step, event, rule):
                    next_states.append(_advance_state(
                        state,
                        step_index=step_index,
                        alternative=alternative,
                        event=event,
                        event_position=event_position,
                    ))
        states = _prune_states(next_states, rule, static_relation_index)
    best = min(states, key=lambda item: _state_rank(item, rule, static_relation_index), default=_OrderedState())
    return best.matched, best.missing


def _unordered_matches(
    compiled_rule: CompiledChainRule,
    event_index: ChainEventIndex,
    static_relation_index: StaticChainRelationIndex | None = None,
) -> tuple[tuple[MatchedChainStep, ...], tuple[int, ...]]:
    rule = compiled_rule.source
    states: tuple[_OrderedState, ...] = (_OrderedState(),)
    for step_index, compiled_step in enumerate(compiled_rule.steps):
        step = compiled_step.source
        matching_events = tuple(sorted(
            event_index.matching_events(compiled_step),
            key=lambda item: (
                event_index.events[item[0]].ordinal,
                event_index.events[item[0]].evidence_id,
            ),
        ))
        next_states: list[_OrderedState] = []
        for state in states:
            if step.optional:
                next_states.append(state)
            else:
                next_states.append(_OrderedState(
                    matched=state.matched,
                    missing=(*state.missing, step_index),
                    next_position=0,
                    used_roots=state.used_roots,
                    first_timestamp=state.first_timestamp,
                    previous_timestamp=state.previous_timestamp,
                    previous_ordinal=state.previous_ordinal,
                ))
            for event_position, alternative in matching_events:
                event = event_index.events[event_position]
                if event.root_evidence_id in state.used_roots:
                    continue
                next_states.append(_OrderedState(
                    matched=(*state.matched, MatchedChainStep(
                        step_index=step_index, alternative=alternative, event=event,
                    )),
                    missing=state.missing,
                    next_position=0,
                    used_roots=frozenset((*state.used_roots, event.root_evidence_id)),
                    first_timestamp=state.first_timestamp,
                    previous_timestamp=state.previous_timestamp,
                    previous_ordinal=state.previous_ordinal,
                ))
        states = _prune_states(next_states, rule, static_relation_index)
    best = min(states, key=lambda item: _state_rank(item, rule, static_relation_index), default=_OrderedState())
    return best.matched, best.missing


def _anchor_has_causal_link(rule: ChainRule, events: tuple[ChainEvent, ...]) -> bool:
    required_count = sum(not step.optional for step in rule.steps)
    if required_count == 1:
        return bool(events) and not _constraint_failures(rule, events[:1])
    required_events = events[:required_count]
    if len(required_events) < required_count or _constraint_failures(rule, required_events):
        return False
    if _has_explicit_constraints(rule):
        return True
    groups = tuple(event.correlation_group for event in required_events)
    return all(groups) and len(set(groups)) == 1


def _order_class(rule: ChainRule, events: tuple[ChainEvent, ...], missing: tuple[int, ...]) -> str:
    if missing:
        return "partial"
    if rule.match_mode == "anchor":
        return "causal_link" if _anchor_has_causal_link(rule, events) else "unordered_correlation"
    if rule.match_mode == "unordered":
        return "unordered_correlation"
    sources = {event.source for event in events}
    if sources and sources <= {"timeline", "timeline_observation"}:
        return "observed_order"
    if events and all(
        event.modality == "static_control_flow"
        and event.timing_provenance == "static_control_flow"
        for event in events
    ):
        return "static_control_flow"
    return "synthetic_order"


def evaluate_compiled_chain_rule(
    compiled_rule: CompiledChainRule,
    event_index: ChainEventIndex,
    static_relation_index: StaticChainRelationIndex | None = None,
) -> ChainDecision | None:
    """Evaluate one compiled rule over one generation-owned event index."""
    rule = compiled_rule.source
    blocked_reason = event_index.forbidden_reason(compiled_rule)
    matched, missing = (
        _ordered_matches(compiled_rule, event_index, static_relation_index)
        if rule.match_mode == "ordered"
        else _unordered_matches(compiled_rule, event_index, static_relation_index)
    )
    required_count = compiled_rule.required_step_count
    matched_required = required_count - len(missing)
    distinct_roots = {step.event.root_evidence_id for step in matched}
    required_events = tuple(
        step.event for step in matched if not rule.steps[step.step_index].optional
    )
    relation_requirements = static_rule_relation_failures(
        rule.static_relations,
        tuple(step for step in matched if not rule.steps[step.step_index].optional),
        static_relation_index,
    )
    physical_root_requirements = (
        ()
        if all(step.event.has_physical_root_authority for step in matched)
        else ("physical_root_unavailable",)
    )
    unmet_requirements = tuple(sorted({
        *_constraint_failures(rule, required_events),
        *relation_requirements,
        *physical_root_requirements,
    }))
    support = matched_required / max(1, required_count)
    structural_full_match = (
        not missing and len(distinct_roots) >= rule.minimum_distinct_roots
    )
    full_match = structural_full_match and not unmet_requirements
    partial_match = (
        required_count > 1
        and matched_required >= 2
        and len(distinct_roots) >= min(2, rule.minimum_distinct_roots)
        and matched_required >= (required_count + 1) // 2
    )
    if not full_match and not partial_match:
        return None
    order_class = _order_class(rule, tuple(step.event for step in matched), missing)
    if blocked_reason:
        status = "blocked"
    elif (
        full_match
        and rule.match_mode == "ordered"
        and (
            order_class == "static_control_flow"
            or (
                order_class == "observed_order"
                and (
                    rule.maximum_time_gap is None
                    or all(step.event.timestamp is not None for step in matched)
                )
            )
        )
    ):
        status = "confirmed"
    elif full_match and rule.match_mode == "anchor" and order_class == "causal_link":
        status = "confirmed"
    elif structural_full_match:
        status = "candidate"
    else:
        status = "partial"
    confidence = min(rule.confidence * support, 0.68 if status == "candidate" else 1.0)
    if status == "partial":
        confidence = min(confidence, 0.45)
    candidate = ChainCandidate(
        chain_id=rule.chain_id,
        rule_version=rule.version,
        family=rule.family,
        order_class=order_class,
        matched_steps=matched,
        missing_step_indexes=missing,
        confidence=confidence,
        support=support,
        correlation_group=rule.correlation_group,
        blocked_reason=blocked_reason,
        unmet_requirements=unmet_requirements,
    )
    root_ids = tuple(sorted(candidate.distinct_root_ids))
    requirement_suffix = "" if not unmet_requirements else ":unmet=" + ",".join(unmet_requirements)
    summary = (
        f"{status}:{order_class}:{len(matched)}/{required_count}:"
        f"distinct_roots={len(root_ids)}{requirement_suffix}"
    )
    explanation = ChainExplanation(
        chain_id=rule.chain_id,
        summary=summary,
        evidence_ids=tuple(step.event.evidence_id for step in matched),
        root_evidence_ids=root_ids,
        rejected_reason=blocked_reason,
    )
    scoreable = (
        rule.scoreable
        and status in {"confirmed", "candidate"}
        and not blocked_reason
        and candidate.physically_rooted
    )
    score_points = rule.score_points if status == "confirmed" else rule.score_points * 0.6 if status == "candidate" else 0.0
    anchor_floor = rule.anchor_floor if status == "confirmed" else 0.0
    return ChainDecision(
        rule=rule,
        candidate=candidate,
        status=status,
        scoreable=scoreable,
        score_points=score_points,
        operational_severity=rule.operational_severity,
        anchor_floor=anchor_floor,
        explanation=explanation,
    )


def evaluate_chain_rule(
    rule: ChainRule,
    events: tuple[ChainEvent, ...],
    *,
    static_program_analyses: object = None,
) -> ChainDecision | None:
    """Evaluate one rule through the same compiled matcher used by the registry."""
    compiled_rule = compiled_chain_rules_for((rule,))[0]
    event_index = build_chain_event_index(events, (compiled_rule,))
    if rule.chain_id not in event_index.candidate_rule_ids:
        return None
    static_relation_index = build_static_chain_relation_index(static_program_analyses)
    return evaluate_compiled_chain_rule(compiled_rule, event_index, static_relation_index)


def _decision_sort_key(item: ChainDecision) -> tuple[object, ...]:
    return (
        -_STATUS_RANK[item.status],
        -item.candidate.confidence,
        -item.operational_severity,
        item.candidate.chain_id,
    )


def evaluate_compiled_chain_rules(
    compiled_rules: tuple[CompiledChainRule, ...],
    event_index: ChainEventIndex,
    static_relation_index: StaticChainRelationIndex | None = None,
) -> tuple[ChainDecision, ...]:
    """Evaluate only rules reachable from the generation's matched terms."""
    decisions = tuple(
        decision
        for rule in compiled_rules
        if rule.chain_id in event_index.candidate_rule_ids
        if (decision := evaluate_compiled_chain_rule(rule, event_index, static_relation_index)) is not None
    )
    return tuple(sorted(decisions, key=_decision_sort_key))[:256]


def evaluate_chain_rules(
    rules: tuple[ChainRule, ...],
    events: tuple[ChainEvent, ...],
    *,
    static_program_analyses: object = None,
) -> tuple[ChainDecision, ...]:
    compiled_rules = compiled_chain_rules_for(rules)
    event_index = build_chain_event_index(events, compiled_rules)
    static_relation_index = build_static_chain_relation_index(static_program_analyses)
    return evaluate_compiled_chain_rules(compiled_rules, event_index, static_relation_index)


__all__ = (
    "evaluate_chain_rule",
    "evaluate_chain_rules",
    "evaluate_compiled_chain_rule",
    "evaluate_compiled_chain_rules",
)
