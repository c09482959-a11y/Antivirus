"""Immutable compiled indexes for the canonical Chain registry.

The source :class:`ChainRule` registry remains the only policy owner.  This
module derives deterministic, session-bound lookup structures from that source
and never changes rule semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.chain_evidence import (
    CHAIN_CORRELATION_FIELDS,
    ChainEvent,
    ChainRule,
    ChainStep,
)
from Virus_Scan.detection.registries.chain_registry import (
    CANONICAL_CHAIN_RULES,
    CHAIN_REGISTRY_DIGEST,
    CHAIN_REGISTRY_VERSION,
)

COMPILED_CHAIN_REGISTRY_VERSION = "stage2636_11020_compiled_chain_registry_v4"
_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")
_FIELD_BITS = MappingProxyType({
    field_name: 1 << index
    for index, field_name in enumerate(sorted(CHAIN_CORRELATION_FIELDS))
})


def tokenize_chain_term(value: str) -> tuple[str, ...]:
    """Tokenize one already-normalized Chain term at exact word boundaries."""
    return tuple(_TOKEN_PATTERN.findall(value))


def _contains_tokens(haystack: tuple[str, ...], needle: tuple[str, ...]) -> bool:
    if not needle or len(needle) > len(haystack):
        return False
    width = len(needle)
    return any(
        haystack[index:index + width] == needle
        for index in range(len(haystack) - width + 1)
    )


def _digest_record(record: object) -> str:
    payload = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class CompiledAlternative:
    text: str
    tokens: tuple[str, ...]
    first_token: str

    def to_record(self) -> dict[str, object]:
        return {
            "first_token": self.first_token,
            "text": self.text,
            "tokens": self.tokens,
        }


@dataclass(frozen=True, slots=True)
class CompiledChainStep:
    source: ChainStep
    alternatives: tuple[CompiledAlternative, ...]
    digest: str

    def to_record(self) -> dict[str, object]:
        return {
            "alternatives": tuple(item.to_record() for item in self.alternatives),
            "digest": self.digest,
            "max_gap": self.source.max_gap,
            "optional": self.source.optional,
        }


@dataclass(frozen=True, slots=True)
class CompiledChainRule:
    source: ChainRule
    steps: tuple[CompiledChainStep, ...]
    forbidden: tuple[CompiledAlternative, ...]
    required_field_mask: int
    required_step_count: int
    digest: str

    @property
    def chain_id(self) -> str:
        return self.source.chain_id

    def to_record(self) -> dict[str, object]:
        return {
            "chain_id": self.source.chain_id,
            "digest": self.digest,
            "forbidden": tuple(item.to_record() for item in self.forbidden),
            "required_field_mask": self.required_field_mask,
            "required_step_count": self.required_step_count,
            "source_rule": self.source.to_record(),
            "steps": tuple(step.to_record() for step in self.steps),
        }


@dataclass(frozen=True, slots=True)
class IndexedChainEvent:
    event: ChainEvent
    tokens: tuple[str, ...]
    matched_alternatives: frozenset[str]
    positive_signal: bool
    signature: str


@dataclass(frozen=True, slots=True)
class ChainEventIndex:
    """One immutable, pretokenized index for one evidence generation."""

    events: tuple[ChainEvent, ...]
    indexed_events: tuple[IndexedChainEvent, ...]
    event_digest: str
    matched_alternatives: frozenset[str]
    positive_positions_by_alternative: Mapping[str, tuple[int, ...]]
    all_positions_by_alternative: Mapping[str, tuple[int, ...]]
    step_matches: Mapping[str, tuple[tuple[int, str], ...]]
    forbidden_reason_by_rule: Mapping[str, str]
    dependency_digest_by_rule: Mapping[str, str]
    candidate_rule_ids: frozenset[str]

    def matching_events(self, step: CompiledChainStep) -> tuple[tuple[int, str], ...]:
        return self.step_matches.get(step.digest, ())

    def forbidden_reason(self, rule: CompiledChainRule) -> str:
        return self.forbidden_reason_by_rule.get(rule.chain_id, "")

    def dependency_digest(self, rule: CompiledChainRule) -> str:
        return self.dependency_digest_by_rule.get(rule.chain_id, "")


@dataclass(frozen=True, slots=True)
class CompiledChainRegistry:
    source_version: str
    source_digest: str
    version: str
    digest: str
    rules: tuple[CompiledChainRule, ...]
    rule_by_id: Mapping[str, CompiledChainRule]
    rule_ids_by_family: Mapping[str, tuple[str, ...]]
    rule_ids_by_mode: Mapping[str, tuple[str, ...]]
    rule_ids_by_alternative: Mapping[str, tuple[str, ...]]
    rule_ids_by_platform: Mapping[str, tuple[str, ...]]
    rule_ids_by_modality: Mapping[str, tuple[str, ...]]
    alternatives_by_first_token: Mapping[str, tuple[CompiledAlternative, ...]]

    def selected_rules(
        self,
        *,
        match_modes: frozenset[str] | None = None,
        families: frozenset[str] | None = None,
        rule_ids: frozenset[str] | None = None,
    ) -> tuple[CompiledChainRule, ...]:
        selected = tuple(
            rule for rule in self.rules
            if (match_modes is None or rule.source.match_mode in match_modes)
            and (families is None or rule.source.family in families)
            and (rule_ids is None or rule.chain_id in rule_ids)
        )
        return selected


def _compiled_alternative(value: str) -> CompiledAlternative:
    tokens = tokenize_chain_term(value)
    return CompiledAlternative(
        text=value,
        tokens=tokens,
        first_token=tokens[0] if tokens else "",
    )


def compile_chain_step(step: ChainStep) -> CompiledChainStep:
    if type(step) is not ChainStep:
        raise TypeError("chain_step_required")
    alternatives = tuple(_compiled_alternative(value) for value in step.alternatives)
    record = {
        "alternatives": tuple(item.to_record() for item in alternatives),
        "max_gap": step.max_gap,
        "optional": step.optional,
    }
    return CompiledChainStep(
        source=step,
        alternatives=alternatives,
        digest=_digest_record(record),
    )


def compile_chain_rule(rule: ChainRule) -> CompiledChainRule:
    if type(rule) is not ChainRule:
        raise TypeError("chain_rule_required")
    steps = tuple(compile_chain_step(step) for step in rule.steps)
    forbidden = tuple(_compiled_alternative(value) for value in rule.forbidden_evidence)
    required_field_mask = 0
    for field_name in rule.required_fields:
        required_field_mask |= _FIELD_BITS[field_name]
    record = {
        "forbidden": tuple(item.to_record() for item in forbidden),
        "required_field_mask": required_field_mask,
        "required_step_count": sum(not step.source.optional for step in steps),
        "source_rule": rule.to_record(),
        "steps": tuple(step.to_record() for step in steps),
    }
    return CompiledChainRule(
        source=rule,
        steps=steps,
        forbidden=forbidden,
        required_field_mask=required_field_mask,
        required_step_count=record["required_step_count"],
        digest=_digest_record(record),
    )


def _mapping_of_tuples(values: dict[str, set[str]]) -> Mapping[str, tuple[str, ...]]:
    return MappingProxyType({
        key: tuple(sorted(items))
        for key, items in sorted(values.items())
    })


def compile_chain_registry(rules: tuple[ChainRule, ...]) -> CompiledChainRegistry:
    if type(rules) is not tuple or any(type(rule) is not ChainRule for rule in rules):
        raise TypeError("chain_rule_tuple_required")
    compiled_rules = tuple(compile_chain_rule(rule) for rule in rules)
    if tuple(rule.chain_id for rule in compiled_rules) != tuple(sorted(rule.chain_id for rule in compiled_rules)):
        raise ValueError("compiled_chain_registry_order_invalid")

    by_family: dict[str, set[str]] = {}
    by_mode: dict[str, set[str]] = {}
    by_alternative: dict[str, set[str]] = {}
    by_platform: dict[str, set[str]] = {}
    by_modality: dict[str, set[str]] = {}
    alternatives: dict[str, CompiledAlternative] = {}
    for compiled in compiled_rules:
        chain_id = compiled.chain_id
        by_family.setdefault(compiled.source.family, set()).add(chain_id)
        by_mode.setdefault(compiled.source.match_mode, set()).add(chain_id)
        for platform in compiled.source.required_platforms:
            by_platform.setdefault(platform, set()).add(chain_id)
        for modality in compiled.source.required_modalities:
            by_modality.setdefault(modality, set()).add(chain_id)
        for step in compiled.steps:
            for alternative in step.alternatives:
                alternatives[alternative.text] = alternative
                by_alternative.setdefault(alternative.text, set()).add(chain_id)
        for forbidden in compiled.forbidden:
            alternatives[forbidden.text] = forbidden

    by_first: dict[str, list[CompiledAlternative]] = {}
    for alternative in alternatives.values():
        by_first.setdefault(alternative.first_token, []).append(alternative)
    first_token_index = MappingProxyType({
        token: tuple(sorted(items, key=lambda item: item.text))
        for token, items in sorted(by_first.items())
    })
    record = {
        "compiled_rules": tuple(rule.to_record() for rule in compiled_rules),
        "source_digest": CHAIN_REGISTRY_DIGEST,
        "source_version": CHAIN_REGISTRY_VERSION,
        "version": COMPILED_CHAIN_REGISTRY_VERSION,
    }
    return CompiledChainRegistry(
        source_version=CHAIN_REGISTRY_VERSION,
        source_digest=CHAIN_REGISTRY_DIGEST,
        version=COMPILED_CHAIN_REGISTRY_VERSION,
        digest=_digest_record(record),
        rules=compiled_rules,
        rule_by_id=MappingProxyType({rule.chain_id: rule for rule in compiled_rules}),
        rule_ids_by_family=_mapping_of_tuples(by_family),
        rule_ids_by_mode=_mapping_of_tuples(by_mode),
        rule_ids_by_alternative=_mapping_of_tuples(by_alternative),
        rule_ids_by_platform=_mapping_of_tuples(by_platform),
        rule_ids_by_modality=_mapping_of_tuples(by_modality),
        alternatives_by_first_token=first_token_index,
    )


def _event_signature(event: ChainEvent) -> str:
    return _digest_record(event.to_record())


def _event_is_positive(event: ChainEvent) -> bool:
    return (
        event.polarity == "positive"
        and not event.unavailable_reason
        and event.evidence_kind not in {"suppression", "failure"}
    )


def _matches_alternative(
    *,
    term: str,
    tokens: tuple[str, ...],
    alternative: CompiledAlternative,
) -> bool:
    return term == alternative.text or _contains_tokens(tokens, alternative.tokens)


def _alternative_catalog(
    compiled_rules: tuple[CompiledChainRule, ...],
) -> tuple[CompiledAlternative, ...]:
    by_text: dict[str, CompiledAlternative] = {}
    for rule in compiled_rules:
        for step in rule.steps:
            for alternative in step.alternatives:
                by_text[alternative.text] = alternative
        for forbidden in rule.forbidden:
            by_text[forbidden.text] = forbidden
    return tuple(by_text[key] for key in sorted(by_text))


def build_chain_event_index(
    events: tuple[ChainEvent, ...],
    compiled_rules: tuple[CompiledChainRule, ...],
) -> ChainEventIndex:
    """Build one exact immutable event index for the supplied rule set."""
    if type(events) is not tuple or any(type(event) is not ChainEvent for event in events):
        raise TypeError("chain_event_tuple_required")
    if type(compiled_rules) is not tuple or any(
        type(rule) is not CompiledChainRule for rule in compiled_rules
    ):
        raise TypeError("compiled_chain_rule_tuple_required")

    catalog = _alternative_catalog(compiled_rules)
    by_first: dict[str, tuple[CompiledAlternative, ...]] = {}
    mutable_first: dict[str, list[CompiledAlternative]] = {}
    for alternative in catalog:
        mutable_first.setdefault(alternative.first_token, []).append(alternative)
    by_first = {
        token: tuple(sorted(items, key=lambda item: item.text))
        for token, items in mutable_first.items()
    }

    indexed: list[IndexedChainEvent] = []
    all_positions: dict[str, list[int]] = {}
    positive_positions: dict[str, list[int]] = {}
    matched_union: set[str] = set()
    for position, event in enumerate(events):
        tokens = tokenize_chain_term(event.term)
        candidate_alternatives: dict[str, CompiledAlternative] = {}
        for token in frozenset(tokens):
            for alternative in by_first.get(token, ()):
                candidate_alternatives[alternative.text] = alternative
        matched = frozenset(
            text for text, alternative in sorted(candidate_alternatives.items())
            if _matches_alternative(term=event.term, tokens=tokens, alternative=alternative)
        )
        positive = _event_is_positive(event)
        indexed.append(IndexedChainEvent(
            event=event,
            tokens=tokens,
            matched_alternatives=matched,
            positive_signal=positive,
            signature=_event_signature(event),
        ))
        matched_union.update(matched)
        for text in matched:
            all_positions.setdefault(text, []).append(position)
            if positive:
                positive_positions.setdefault(text, []).append(position)

    step_match_map: dict[str, tuple[tuple[int, str], ...]] = {}
    unique_steps: dict[str, CompiledChainStep] = {}
    for rule in compiled_rules:
        for step in rule.steps:
            unique_steps[step.digest] = step
    for digest, step in unique_steps.items():
        position_alternative: dict[int, str] = {}
        for alternative in step.alternatives:
            for position in positive_positions.get(alternative.text, ()):
                position_alternative.setdefault(position, alternative.text)
        step_match_map[digest] = tuple(sorted(position_alternative.items()))

    forbidden_reasons: dict[str, str] = {}
    dependency_digests: dict[str, str] = {}
    candidate_rule_ids: set[str] = set()
    for rule in compiled_rules:
        relevant_positions: set[int] = set()
        has_positive_step_match = False
        for step in rule.steps:
            matches = step_match_map[step.digest]
            if matches:
                has_positive_step_match = True
                relevant_positions.update(position for position, _alternative in matches)
        if has_positive_step_match:
            candidate_rule_ids.add(rule.chain_id)

        reason = ""
        forbidden_texts = tuple(item.text for item in rule.forbidden)
        for position, item in enumerate(indexed):
            matched_forbidden = next((
                forbidden for forbidden in forbidden_texts
                if item.event.evidence_kind == forbidden
                or forbidden in item.matched_alternatives
            ), "")
            if matched_forbidden:
                relevant_positions.add(position)
                if not reason:
                    reason = "forbidden_evidence:" + matched_forbidden
        forbidden_reasons[rule.chain_id] = reason
        relevant_records = tuple(
            indexed[position].event.to_record()
            for position in sorted(relevant_positions)
        )
        dependency_digests[rule.chain_id] = _digest_record({
            "events": relevant_records,
            "rule_digest": rule.digest,
        })

    event_digest = _digest_record(tuple(item.event.to_record() for item in indexed))
    return ChainEventIndex(
        events=events,
        indexed_events=tuple(indexed),
        event_digest=event_digest,
        matched_alternatives=frozenset(matched_union),
        positive_positions_by_alternative=MappingProxyType({
            key: tuple(value) for key, value in sorted(positive_positions.items())
        }),
        all_positions_by_alternative=MappingProxyType({
            key: tuple(value) for key, value in sorted(all_positions.items())
        }),
        step_matches=MappingProxyType(dict(sorted(step_match_map.items()))),
        forbidden_reason_by_rule=MappingProxyType(dict(sorted(forbidden_reasons.items()))),
        dependency_digest_by_rule=MappingProxyType(dict(sorted(dependency_digests.items()))),
        candidate_rule_ids=frozenset(candidate_rule_ids),
    )


COMPILED_CHAIN_REGISTRY = compile_chain_registry(CANONICAL_CHAIN_RULES)
COMPILED_CHAIN_REGISTRY_DIGEST = COMPILED_CHAIN_REGISTRY.digest


def compiled_chain_rules_for(
    rules: tuple[ChainRule, ...],
) -> tuple[CompiledChainRule, ...]:
    """Return canonical compiled rules when possible, otherwise compile exactly."""
    compiled: list[CompiledChainRule] = []
    for rule in rules:
        canonical = COMPILED_CHAIN_REGISTRY.rule_by_id.get(rule.chain_id)
        if canonical is not None and canonical.source == rule:
            compiled.append(canonical)
        else:
            compiled.append(compile_chain_rule(rule))
    return tuple(compiled)


__all__ = (
    "COMPILED_CHAIN_REGISTRY",
    "COMPILED_CHAIN_REGISTRY_DIGEST",
    "COMPILED_CHAIN_REGISTRY_VERSION",
    "ChainEventIndex",
    "CompiledAlternative",
    "CompiledChainRegistry",
    "CompiledChainRule",
    "CompiledChainStep",
    "IndexedChainEvent",
    "build_chain_event_index",
    "compile_chain_registry",
    "compile_chain_rule",
    "compile_chain_step",
    "compiled_chain_rules_for",
    "tokenize_chain_term",
)
