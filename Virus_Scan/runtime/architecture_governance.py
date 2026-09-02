"""Stage 40 architecture governance and maintainability controls.

This module turns the Window 9 maintainability recommendations into runtime
artifacts instead of advisory notes.  It operates on immutable event snapshots
and contract snapshots, so it does not introduce mutable service-discovery
surfaces or indirection surfaces.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence
import hashlib
import json
import math
from types import MappingProxyType

from Virus_Scan.contracts.no_hook_materialization import (
    exact_int_or_none,
    materialize_json_no_hook,
    no_hook_exact_nonnegative_int,
    no_hook_mapping_items,
    no_hook_text,
    no_hook_type_name,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value, materialize_runtime_value

ArchitectureValue = object


def _join_architecture_text(*parts: str) -> str:
    out = ""
    for part in parts:
        out = str.__add__(out, part)
    return out


def _architecture_pair(domain: str, kind: str) -> str:
    return _join_architecture_text(domain, ":", kind)


def _architecture_triple(domain: str, kind: str, owner: str) -> str:
    return _join_architecture_text(domain, ":", kind, ":", owner)


def _unsupported_sequence_label(value: ArchitectureValue) -> str:
    return _join_architecture_text("unsupported_sequence:", no_hook_type_name(value))


def _unsupported_text_label(value: ArchitectureValue) -> str:
    return _join_architecture_text("unsupported_text:", no_hook_type_name(value))


def _contracts_unavailable_label(value: ArchitectureValue) -> str:
    return _join_architecture_text("contracts_unavailable:", no_hook_type_name(value))


def _contract_key_unavailable_label(index: int, reason: str, key: ArchitectureValue) -> str:
    reason_text = reason or "blank_architecture_contract_key"
    return _join_architecture_text("contract_key_unavailable:", int.__str__(index), ":", reason_text, ":", no_hook_type_name(key))


def _unsupported_event_label(reason: str, value_type: str) -> str:
    return _join_architecture_text("unsupported_event:", reason, ":", value_type)


def _event_unavailable_label(prefix: str, reason: str) -> str:
    return _join_architecture_text(prefix, ":event_unavailable:", reason)


def _owner_mismatch_label(domain: str, kind: str, owner: str, expected_owner: str) -> str:
    return _join_architecture_text(_architecture_pair(domain, kind), ":owner=", owner, ":expected=", expected_owner)


def _no_semantic_owner_label(domain: str, kind: str) -> str:
    return _join_architecture_text(_architecture_pair(domain, kind), ":no_semantic_owner")


def _migration_required_label(key: str, version: int, expected: int) -> str:
    return _join_architecture_text(key, ":event_v", int.__str__(version), ":contract_v", int.__str__(expected))


def _parent_child_edge_label(parent_domain: str, parent_kind: str, src: str) -> str:
    return _join_architecture_text(_architecture_pair(parent_domain, parent_kind), "->", src)


def _architecture_text(value: ArchitectureValue, default: str = "") -> str:
    text, reason = no_hook_text(
        value,
        missing_reason="missing_architecture_text",
        unsupported_reason="unsafe_architecture_text_rejected",
    )
    if reason:
        return default
    return text


def _architecture_text_tuple(values: ArchitectureValue) -> tuple[str, ...]:
    if values is None:
        return ()
    if type(values) is tuple:
        source = values
    elif type(values) is list:
        source = tuple(list.__iter__(values))
    else:
        return (_unsupported_sequence_label(values),)
    out: list[str] = []
    for item in source:
        text = _architecture_text(item, "")
        if text:
            out.append(text)
        else:
            out.append(_unsupported_text_label(item))
    return tuple(out)


def _architecture_int(value: ArchitectureValue, default: int = 0) -> int:
    exact = exact_int_or_none(value)
    if exact is not None:
        return exact
    if type(value) is float and math.isfinite(value) and value.is_integer():
        numerator, denominator = float.as_integer_ratio(value)
        return numerator // denominator
    metric, _reason = no_hook_exact_nonnegative_int(
        value,
        default=default,
        reason="unsafe_architecture_integer_rejected",
        allow_exact_text=True,
    )
    return metric


def _architecture_int_tuple(values: ArchitectureValue) -> tuple[int, ...]:
    if values is None:
        return ()
    if type(values) is tuple:
        source = values
    elif type(values) is list:
        source = tuple(list.__iter__(values))
    else:
        return ()
    return tuple(_architecture_int(item, 0) for item in source)


def _safe_event_sequence(events: ArchitectureValue, *, max_events: int | None = None) -> tuple[ArchitectureValue, ...]:
    if events is None:
        return ()
    if type(events) is tuple:
        source = events
    elif type(events) is list:
        source = tuple(list.__iter__(events))
    else:
        return (_unsupported_event_record(events, reason="non_materializable_architecture_event_sequence"),)
    if max_events is None:
        return source
    limit, reason = no_hook_exact_nonnegative_int(
        max_events,
        default=2048,
        reason="unsafe_architecture_max_events_rejected",
        allow_exact_text=True,
    )
    if reason:
        return (
            _unsupported_event_record(
                max_events,
                reason=reason,
            ),
        )
    if limit == 0:
        return ()
    return source[-limit:]


def _event_failure_record(value: ArchitectureValue, *, reason: str) -> dict[str, ArchitectureValue]:
    return {
        "seq": 0,
        "domain": "governance",
        "kind": "unsupported_event",
        "owner": "runtime",
        "schema_version": 1,
        "parent_seq": None,
        "causal_depth": 0,
        "lineage_id": "",
        "event_key": "unsupported_event",
        "event_unavailable": True,
        "event_unavailable_reason": reason,
        "event_value_type": no_hook_type_name(value),
        "payload": materialize_json_no_hook(value, context="architecture_event_failure", max_depth=2),
    }


def _unsupported_event_record(value: ArchitectureValue, *, reason: str) -> dict[str, ArchitectureValue]:
    return _event_failure_record(value, reason=reason)


def _event_dict(ev: ArchitectureValue) -> dict[str, ArchitectureValue]:
    materialized = materialize_json_no_hook(ev, context="architecture_event")
    if type(materialized) is dict:
        if "unavailable_reason" in materialized and "domain" not in materialized:
            return _event_failure_record(ev, reason=str.__str__(materialized.get("unavailable_reason") or "non_materializable_architecture_event"))
        return materialized
    return _event_failure_record(ev, reason="non_materializable_architecture_event")


def _event_dicts(events: ArchitectureValue, *, max_events: int | None = None) -> tuple[dict[str, ArchitectureValue], ...]:
    return tuple(_event_dict(ev) for ev in _safe_event_sequence(events, max_events=max_events))


def _safe_contract_map(contracts: ArchitectureValue) -> tuple[dict[str, ArchitectureValue], tuple[str, ...]]:
    if contracts is None:
        return {}, ("contracts_unavailable:missing_architecture_contracts",)
    items = no_hook_mapping_items(contracts)
    if items is None:
        return {}, (_contracts_unavailable_label(contracts),)
    out: dict[str, ArchitectureValue] = {}
    unavailable: list[str] = []
    for index, (key, value) in enumerate(items):
        key_text, key_reason = no_hook_text(
            key,
            missing_reason="missing_architecture_contract_key",
            unsupported_reason="unsafe_architecture_contract_key_rejected",
        )
        if key_reason or key_text == "":
            unavailable.append(_contract_key_unavailable_label(index, key_reason, key))
            continue
        materialized = materialize_json_no_hook(value, context="architecture_contract")
        out[key_text] = materialized
    return out, tuple(unavailable)


def _data_text(data: dict[str, ArchitectureValue], key: str, default: str = "") -> str:
    return _architecture_text(dict.get(data, key, default), default)


def _data_int(data: dict[str, ArchitectureValue], key: str, default: int = 0) -> int:
    return _architecture_int(dict.get(data, key, default), default)


def _contract_version(contract: ArchitectureValue, default: int = 1) -> int | None:
    if type(contract) is not dict:
        return None
    return _architecture_int(dict.get(contract, "version", default), default)


@dataclass(frozen=True)
class SemanticOwnershipReport:
    ok: bool
    duplicated_concepts: tuple[str, ...] = field(default_factory=tuple)
    orphaned_concepts: tuple[str, ...] = field(default_factory=tuple)
    ownership: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not SemanticOwnershipReport:
            exception_message = "semantic ownership report owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(self, "ok", self.ok if type(self.ok) is bool else False)
        object.__setattr__(self, "duplicated_concepts", _architecture_text_tuple(self.duplicated_concepts))
        object.__setattr__(self, "orphaned_concepts", _architecture_text_tuple(self.orphaned_concepts))
        object.__setattr__(self, "ownership", freeze_runtime_value(self.ownership if self.ownership is not None else {}))

    def as_dict(self) -> dict[str, ArchitectureValue]:
        return {
            "ok": self.ok,
            "duplicated_concepts": list(self.duplicated_concepts),
            "orphaned_concepts": list(self.orphaned_concepts),
            "ownership": materialize_runtime_value(self.ownership),
        }


@dataclass(frozen=True)
class SchemaEvolutionReport:
    ok: bool
    unknown_contracts: tuple[str, ...] = field(default_factory=tuple)
    missing_schema_versions: tuple[int, ...] = field(default_factory=tuple)
    migration_required: tuple[str, ...] = field(default_factory=tuple)
    contract_count: int = 0

    def __post_init__(self) -> None:
        if type(self) is not SchemaEvolutionReport:
            exception_message = "schema evolution report owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(self, "ok", self.ok if type(self.ok) is bool else False)
        object.__setattr__(self, "unknown_contracts", _architecture_text_tuple(self.unknown_contracts))
        object.__setattr__(self, "missing_schema_versions", _architecture_int_tuple(self.missing_schema_versions))
        object.__setattr__(self, "migration_required", _architecture_text_tuple(self.migration_required))
        object.__setattr__(self, "contract_count", _architecture_int(self.contract_count, 0))

    def as_dict(self) -> dict[str, ArchitectureValue]:
        return {
            "ok": self.ok,
            "unknown_contracts": list(self.unknown_contracts),
            "missing_schema_versions": list(self.missing_schema_versions),
            "migration_required": list(self.migration_required),
            "contract_count": self.contract_count,
        }


@dataclass(frozen=True)
class GovernanceTopologyAudit:
    ok: bool
    hidden_dependencies: tuple[str, ...] = field(default_factory=tuple)
    orphaned_events: tuple[int, ...] = field(default_factory=tuple)
    duplicated_semantics: tuple[str, ...] = field(default_factory=tuple)
    unstable_paths: tuple[str, ...] = field(default_factory=tuple)
    graph_digest: str = ""

    def __post_init__(self) -> None:
        if type(self) is not GovernanceTopologyAudit:
            exception_message = "governance topology audit owner rejected"
            raise TypeError(exception_message)
        object.__setattr__(self, "ok", self.ok if type(self.ok) is bool else False)
        object.__setattr__(self, "hidden_dependencies", _architecture_text_tuple(self.hidden_dependencies))
        object.__setattr__(self, "orphaned_events", _architecture_int_tuple(self.orphaned_events))
        object.__setattr__(self, "duplicated_semantics", _architecture_text_tuple(self.duplicated_semantics))
        object.__setattr__(self, "unstable_paths", _architecture_text_tuple(self.unstable_paths))
        object.__setattr__(self, "graph_digest", _architecture_text(self.graph_digest, ""))

    def as_dict(self) -> dict[str, ArchitectureValue]:
        return {
            "ok": self.ok,
            "hidden_dependencies": list(self.hidden_dependencies),
            "orphaned_events": list(self.orphaned_events),
            "duplicated_semantics": list(self.duplicated_semantics),
            "unstable_paths": list(self.unstable_paths),
            "graph_digest": self.graph_digest,
        }


# One authoritative owner per semantic concept.  These names intentionally match
# runtime domains/event contract owners so drift can be detected mechanically.
SEMANTIC_OWNERSHIP: Mapping[str, str] = MappingProxyType({
    "engine_semantics": "scanner",
    "loader_continuity": "scanner",
    "replay_influence": "replay",
    "lineage_continuity": "replay",
    "orchestration_staging": "governance",
    "scheduler_pressure": "scheduler",
    "telemetry_integrity": "telemetry",
    "cache_generation": "cache",
    "semantic_budget": "semantic",
    "schema_migration": "runtime",
    "topology_governance": "governance",
    "fault_isolation": "saturation",
})

_EVENT_CONCEPT_HINTS: Mapping[str, str] = MappingProxyType({
    "replay": "replay_influence",
    "lineage": "lineage_continuity",
    "scheduler": "scheduler_pressure",
    "queue": "scheduler_pressure",
    "telemetry": "telemetry_integrity",
    "cache": "cache_generation",
    "semantic": "semantic_budget",
    "governance": "topology_governance",
    "saturation": "fault_isolation",
    "extraction": "orchestration_staging",
    "scanner": "engine_semantics",
})


def _stable_digest(items: ArchitectureValue) -> str:
    payload = materialize_json_no_hook(items, context="architecture_digest")
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def semantic_ownership_report(events: Sequence[ArchitectureValue] = ()) -> SemanticOwnershipReport:
    concept_to_event_types: dict[str, set[str]] = {k: set() for k in SEMANTIC_OWNERSHIP}
    orphaned: set[str] = set()
    for data in _event_dicts(events):
        domain = _data_text(data, "domain", "")
        kind = _data_text(data, "kind", "")
        owner = _data_text(data, "owner", "")
        event_unavailable_reason = _data_text(data, "event_unavailable_reason", "")
        if event_unavailable_reason:
            orphaned.add(_unsupported_event_label(event_unavailable_reason, _data_text(data, "event_value_type", "unknown")))
            continue
        concept = _EVENT_CONCEPT_HINTS.get(domain)
        if concept:
            event_types = dict.get(concept_to_event_types, concept)
            if event_types is None:
                event_types = set()
                concept_to_event_types[concept] = event_types
            event_types.add(_architecture_triple(domain, kind, owner))
            expected_owner = SEMANTIC_OWNERSHIP.get(concept)
            if expected_owner and owner not in {expected_owner, "runtime"}:
                orphaned.add(_owner_mismatch_label(domain, kind, owner, expected_owner))
        elif domain:
            orphaned.add(_no_semantic_owner_label(domain, kind))
    duplicated = []
    for concept, event_types in sorted(dict.items(concept_to_event_types)):
        owners = {item.rsplit(":", 1)[-1] for item in event_types}
        expected = SEMANTIC_OWNERSHIP.get(concept)
        effective = {o for o in owners if o and o not in (expected, "runtime")}
        if effective:
            duplicated.append(concept)
    return SemanticOwnershipReport(ok=not duplicated and not orphaned, duplicated_concepts=tuple(duplicated), orphaned_concepts=tuple(sorted(orphaned)), ownership=SEMANTIC_OWNERSHIP)


def schema_evolution_report(events: Sequence[ArchitectureValue], contracts: Mapping[str, ArchitectureValue]) -> SchemaEvolutionReport:
    contract_map, contract_unavailable = _safe_contract_map(contracts)
    unknown: set[str] = set(contract_unavailable)
    missing_versions: list[int] = []
    migration_required: set[str] = set()
    for data in _event_dicts(events):
        domain = _data_text(data, "domain", "runtime")
        kind = _data_text(data, "kind", "event")
        key = _architecture_pair(domain, kind)
        version = _data_int(data, "schema_version", 0)
        if _data_text(data, "event_unavailable_reason", ""):
            unknown.add(_event_unavailable_label(key, _data_text(data, "event_unavailable_reason", "unknown")))
        if version <= 0:
            missing_versions.append(_data_int(data, "seq", 0))
        contract = contract_map.get(key)
        expected = _contract_version(contract)
        if expected is None:
            unknown.add(key)
            continue
        if version != expected:
            migration_required.add(_migration_required_label(key, version, expected))
    return SchemaEvolutionReport(ok=not unknown and not missing_versions and not migration_required, unknown_contracts=tuple(sorted(unknown)), missing_schema_versions=tuple(missing_versions[:64]), migration_required=tuple(sorted(migration_required)), contract_count=len(contract_map))


def governance_topology_audit(events: Sequence[ArchitectureValue], contracts: Mapping[str, ArchitectureValue]) -> GovernanceTopologyAudit:
    event_list = _event_dicts(events)
    by_seq = {_data_int(ev, "seq", 0): ev for ev in event_list}
    hidden: set[str] = set()
    orphaned: list[int] = []
    unstable: set[str] = set()
    edges: list[tuple[str, str]] = []
    contract_map, contract_unavailable = _safe_contract_map(contracts)
    hidden.update(contract_unavailable)
    for ev in event_list:
        seq = _data_int(ev, "seq", 0)
        parent_seq = dict.get(ev, "parent_seq")
        domain = _data_text(ev, "domain", "runtime")
        kind = _data_text(ev, "kind", "event")
        src = _architecture_pair(domain, kind)
        if _data_text(ev, "event_unavailable_reason", ""):
            hidden.add(_event_unavailable_label(src, _data_text(ev, "event_unavailable_reason", "unknown")))
        if src not in contract_map:
            hidden.add(src)
        if parent_seq is not None:
            parent = by_seq.get(_architecture_int(parent_seq, -1))
            if not parent:
                orphaned.append(seq)
            else:
                parent_domain = _data_text(parent, "domain", "runtime")
                parent_kind = _data_text(parent, "kind", "event")
                dst = _parent_child_edge_label(parent_domain, parent_kind, src)
                edges.append((_architecture_pair(parent_domain, parent_kind), src))
                if parent_domain in {"telemetry", "scheduler", "governance"} and domain in {"replay", "telemetry", "scheduler", "governance"}:
                    if parent_domain != domain:
                        unstable.add(dst)
    sem = semantic_ownership_report(events=event_list)
    digest = _stable_digest(tuple(sorted(edges)))
    ok = not hidden and not orphaned and sem.ok and not unstable
    return GovernanceTopologyAudit(ok=ok, hidden_dependencies=tuple(sorted(hidden)), orphaned_events=tuple(orphaned[:64]), duplicated_semantics=tuple(sem.duplicated_concepts), unstable_paths=tuple(sorted(unstable)), graph_digest=digest)


def causal_architecture_visualization(events: Sequence[ArchitectureValue], contracts: Mapping[str, ArchitectureValue], *, max_events: int = 2048) -> dict[str, ArchitectureValue]:
    event_list = _event_dicts(events, max_events=max_events)
    nodes = []
    edges = []
    domain_counts: dict[str, int] = {}
    stabilization_edges: list[dict[str, ArchitectureValue]] = []
    by_seq = {_data_int(ev, "seq", 0): ev for ev in event_list}
    for ev in event_list:
        seq = _data_int(ev, "seq", 0)
        domain = _data_text(ev, "domain", "runtime")
        kind = _data_text(ev, "kind", "event")
        owner = _data_text(ev, "owner", "runtime")
        domain_counts[domain] = domain_counts.get(domain, 0) + 1
        nodes.append({
            "id": seq,
            "label": _architecture_pair(domain, kind),
            "domain": domain,
            "kind": kind,
            "owner": owner,
            "depth": _data_int(ev, "causal_depth", 0),
            "lineage_id": _data_text(ev, "lineage_id", ""),
            "event_unavailable_reason": _data_text(
                ev,
                "event_unavailable_reason",
                "",
            ),
        })
        parent_seq = dict.get(ev, "parent_seq")
        if parent_seq is not None and _architecture_int(parent_seq, -1) in by_seq:
            parent_seq_int = _architecture_int(parent_seq, -1)
            parent = by_seq[parent_seq_int]
            parent_domain = _data_text(parent, "domain", "runtime")
            edge = {"source": parent_seq_int, "target": seq, "source_domain": parent_domain, "target_domain": domain}
            edges.append(edge)
            if domain in {"governance", "scheduler", "telemetry", "replay", "saturation"} or parent_domain in {"governance", "scheduler", "telemetry", "replay", "saturation"}:
                stabilization_edges.append(edge)
    audit = governance_topology_audit(event_list, contracts)
    schema = schema_evolution_report(event_list, contracts)
    semantic = semantic_ownership_report(event_list)
    return {
        "nodes": nodes,
        "edges": edges,
        "domain_counts": dict(sorted(dict.items(domain_counts))),
        "stabilization_dependency_edges": stabilization_edges[:512],
        "governance_convergence_diagram": {
            "planes": ["replay", "telemetry", "scheduler", "governance", "semantic", "saturation"],
            "edge_count": len(stabilization_edges),
            "risk_edges": audit.unstable_paths[:64],
        },
        "topology_audit": audit.as_dict(),
        "schema_evolution": schema.as_dict(),
        "semantic_ownership": semantic.as_dict(),
        "graph_digest": audit.graph_digest,
    }


__all__ = (
    "SEMANTIC_OWNERSHIP",
    "GovernanceTopologyAudit",
    "SchemaEvolutionReport",
    "SemanticOwnershipReport",
    "causal_architecture_visualization",
    "governance_topology_audit",
    "schema_evolution_report",
    "semantic_ownership_report",
)
