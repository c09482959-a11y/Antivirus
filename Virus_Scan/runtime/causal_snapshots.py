"""Deterministic causal snapshots for event-native runtime replay.

Stage 35 moves replay evidence from best-effort topology inspection toward
reproducible snapshots.  The snapshot is immutable, sorted, digestible, and
includes event, budget, dependency, invariant, and domain-generation state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Iterable, Mapping, Tuple
import hashlib
import json
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_exact_owner_field,
    materialize_json_no_hook,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_type_name,
)
from Virus_Scan.contracts.worker_record import make_json_safe
from Virus_Scan.runtime.causal_text import causal_text, causal_sort_key
from Virus_Scan.runtime.governance_inputs import (
    runtime_int,
    runtime_sequence,
    runtime_text,
)


def _causal_snapshot_owned_text(*parts: str) -> str:
    return "".join(parts)


def _causal_snapshot_unavailable_text(value: object) -> str:
    return _causal_snapshot_owned_text("causal_text_unavailable:", no_hook_type_name(value))


def _causal_snapshot_event_field(field_name: str) -> str:
    return _causal_snapshot_owned_text("causal_snapshot_event_", field_name)


def _causal_snapshot_field(field_name: str) -> str:
    return _causal_snapshot_owned_text("causal_snapshot_", field_name)


def _causal_int(value: object, default: int = 0) -> int:
    metric, _issues = runtime_int(
        value,
        field_name="causal_snapshot_integer",
        default=default,
    )
    return metric


def _causal_failure_event(value: object, *, reason: str) -> dict[str, object]:
    unavailable = _causal_snapshot_unavailable_text(value)
    return {
        "seq": 0,
        "domain": unavailable,
        "kind": unavailable,
        "event_key": unavailable,
        "schema_version": 1,
        "owner": "runtime",
        "parent_seq": None,
        "event_unavailable": True,
        "event_unavailable_reason": reason,
        "event_value_type": no_hook_type_name(value),
    }


def _ordered_sequence(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if type(value) is tuple:
        return value
    if type(value) is list:
        return tuple(list.__iter__(value))
    if type(value) in (set, frozenset):
        return tuple(sorted(value, key=lambda item: json.dumps(materialize_json_no_hook(item, context="causal_sequence_item"), sort_keys=True, default=causal_text, allow_nan=False)))
    items = no_hook_sequence_items(value)
    if items:
        return items
    return (_causal_failure_event(value, reason="non_materializable_causal_event_sequence"),)


def _freeze(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        return MappingProxyType({causal_text(k, empty="causal_text_empty"): _freeze(v) for k, v in sorted(items, key=lambda kv: causal_sort_key(kv[0]))})
    if type(value) in (list, tuple, set, frozenset):
        seq = tuple(value) if type(value) in (tuple, list) else tuple(sorted(value, key=lambda x: json.dumps(_jsonable(x), default=causal_text, sort_keys=True, allow_nan=False)))
        return tuple(_freeze(v) for v in seq)
    return value


def _event_mapping(ev: object) -> Mapping[str, object]:
    materialized = materialize_json_no_hook(ev, context="causal_event", max_depth=10)
    if type(materialized) is dict:
        if "unavailable_reason" in materialized and "domain" not in materialized:
            return _causal_failure_event(ev, reason="non_materializable_causal_event")
        normalized = dict.copy(materialized)
        evidence: list[Mapping[str, object]] = []
        for field_name in ("seq", "schema_version", "causal_depth"):
            if field_name not in normalized:
                continue
            parsed, issues = runtime_int(
                dict.get(normalized, field_name),
                field_name=_causal_snapshot_event_field(field_name),
                default=0 if field_name != "schema_version" else 1,
            )
            normalized[field_name] = parsed
            evidence.extend(issues)
        parent = dict.get(normalized, "parent_seq")
        if parent is not None:
            parsed_parent, issues = runtime_int(
                parent,
                field_name="causal_snapshot_event_parent_seq",
                default=0,
            )
            normalized["parent_seq"] = None if issues else parsed_parent
            evidence.extend(issues)
        if evidence:
            normalized["input_evidence"] = tuple(evidence)
        return normalized
    return _causal_failure_event(ev, reason="non_mapping_causal_event")


def _jsonable(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is not None:
        return {causal_text(k, empty="causal_text_empty"): _jsonable(v) for k, v in sorted(items, key=lambda kv: causal_sort_key(kv[0]))}
    if type(value) in (tuple, list):
        return [_jsonable(v) for v in value]
    if type(value) in (set, frozenset):
        return [_jsonable(v) for v in sorted(value, key=lambda item: json.dumps(_jsonable(item), default=causal_text, sort_keys=True, allow_nan=False))]
    if type(value) is float:
        return make_json_safe(value)
    if type(value) in (str, int, bool) or value is None:
        return value
    return causal_text(value, empty="causal_text_empty")


@dataclass(frozen=True)
class CausalReplaySnapshot:
    generation: int
    event_count: int
    last_seq: int
    digest: str
    events: Tuple[Mapping[str, object], ...] = field(default_factory=tuple)
    budgets: Mapping[str, object] = field(default_factory=dict)
    dependencies: Mapping[str, object] = field(default_factory=dict)
    invariants: Mapping[str, object] = field(default_factory=dict)
    domain_generations: Mapping[str, int] = field(default_factory=dict)
    input_evidence: tuple[Mapping[str, object], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if type(self) is not CausalReplaySnapshot:
            exception_message = "causal replay snapshot owner rejected"
            raise TypeError(exception_message)
        evidence_rows, evidence = runtime_sequence(
            self.input_evidence,
            field_name="causal_snapshot_input_evidence",
        )
        evidence = tuple(evidence_rows) + evidence
        for field_name in ("generation", "event_count", "last_seq"):
            value, issues = runtime_int(
                no_hook_exact_owner_field(self, CausalReplaySnapshot, field_name),
                field_name=_causal_snapshot_field(field_name),
                default=0,
            )
            evidence += issues
            object.__setattr__(self, field_name, value)
        digest, issues = runtime_text(
            self.digest,
            field_name="causal_snapshot_digest",
            default="causal_snapshot_digest_unavailable",
        )
        evidence += issues
        object.__setattr__(self, "digest", digest)
        object.__setattr__(self, "events", tuple(_freeze(e) for e in _ordered_sequence(self.events)))
        object.__setattr__(self, "budgets", _freeze({} if self.budgets is None else self.budgets))
        object.__setattr__(self, "dependencies", _freeze({} if self.dependencies is None else self.dependencies))
        object.__setattr__(self, "invariants", _freeze({} if self.invariants is None else self.invariants))
        object.__setattr__(self, "domain_generations", _freeze({} if self.domain_generations is None else self.domain_generations))
        object.__setattr__(self, "input_evidence", tuple(_freeze(e) for e in evidence))

    def as_dict(self) -> dict[str, object]:
        return {
            "generation": self.generation,
            "event_count": self.event_count,
            "last_seq": self.last_seq,
            "digest": self.digest,
            "events": [_jsonable(e) for e in self.events],
            "budgets": _jsonable(self.budgets),
            "dependencies": _jsonable(self.dependencies),
            "invariants": _jsonable(self.invariants),
            "domain_generations": _jsonable(self.domain_generations),
            "input_evidence": _jsonable(self.input_evidence),
        }


def build_causal_snapshot(*, events: Iterable[object], budgets: Mapping[str, object] | None = None,
                          dependencies: Mapping[str, object] | None = None,
                          invariants: Mapping[str, object] | None = None,
                          domain_generations: Mapping[str, int] | None = None,
                          generation: int = 0) -> CausalReplaySnapshot:
    mapped = [_event_mapping(ev) for ev in _ordered_sequence(events)]
    ordered = sorted(
        mapped,
        key=lambda row: (
            _causal_int(row.get("seq"), 0),
            causal_text(row.get("domain"), empty=""),
            causal_text(row.get("kind"), empty=""),
            causal_text(row.get("event_key"), empty=""),
        ),
    )
    rows = [MappingProxyType(_jsonable(row)) for row in ordered]
    generation_value, generation_issues = runtime_int(
        generation,
        field_name="causal_snapshot_generation",
        default=0,
    )
    budgets_value = {} if budgets is None else budgets
    dependencies_value = {} if dependencies is None else dependencies
    invariants_value = {} if invariants is None else invariants
    domain_generations_value = {} if domain_generations is None else domain_generations
    payload = {
        "generation": generation_value,
        "events": [_jsonable(r) for r in rows],
        "budgets": _jsonable(budgets_value),
        "dependencies": _jsonable(dependencies_value),
        "invariants": _jsonable(invariants_value),
        "domain_generations": _jsonable(domain_generations_value),
    }
    digest = hashlib.sha256(json.dumps(make_json_safe(payload), sort_keys=True, separators=(",", ":"), default=causal_text, allow_nan=False).encode('utf-8', 'replace')).hexdigest()
    last_seq = _causal_int(ordered[-1].get("seq"), 0) if ordered else 0
    return CausalReplaySnapshot(
        generation=generation_value, event_count=len(rows), last_seq=last_seq, digest=digest,
        events=tuple(rows), budgets=_freeze(budgets_value), dependencies=_freeze(dependencies_value),
        invariants=_freeze(invariants_value), domain_generations=_freeze(domain_generations_value),
        input_evidence=generation_issues,
    )


__all__ = ("CausalReplaySnapshot", "build_causal_snapshot")
