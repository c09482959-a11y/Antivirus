"""Mutation coordinator implementation for runtime domains.

RuntimeRoot is the only authoritative mutation coordinator for runtime domains.
Domains may mutate local state, but every mutation is budgeted, lineage-tracked,
and mirrored onto the immutable causal event bus.  Cross-domain coordination uses
append-only events rather than shared metadata synchronization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from threading import RLock
from typing import Dict, Mapping, Tuple
import time

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_text,
)
from .causal_event_stream import EventBus, get_global_event_bus
from .governance_inputs import (
    runtime_float,
    runtime_int,
    runtime_mapping,
    runtime_text,
)
from .immutable_core import freeze_runtime_value, materialize_runtime_value
from .governance_planes import GovernancePlane, make_governance_planes, observe_governance_plane
from .governance_read_model import (
    _register_runtime_root_type,
    build_governance_read_model,
)


PLR2004N10_0 = 10.0
PLR2004N25_0 = 25.0
PLR2004N50_0 = 50.0


def _record_semantic_influence(
    budget: dict[tuple[str, str, str], float],
    source: str,
    target: str,
    kind: str,
    weight: float = 1.0,
    *,
    budget_limit: float = 12.0,
) -> Mapping[str, object]:
    evidence: tuple[Mapping[str, object], ...] = ()
    source_text, issues = runtime_text(
        source, field_name="semantic_influence_source", default="input_rejected"
    )
    evidence += issues
    target_text, issues = runtime_text(
        target, field_name="semantic_influence_target", default="input_rejected"
    )
    evidence += issues
    kind_text, issues = runtime_text(
        kind, field_name="semantic_influence_kind", default="input_rejected"
    )
    evidence += issues
    requested, issues = runtime_float(
        weight,
        field_name="semantic_influence_weight",
        default=0.0,
        minimum=0.0,
    )
    evidence += issues
    limit, issues = runtime_float(
        budget_limit,
        field_name="semantic_influence_budget_limit",
        default=12.0,
        minimum=0.0,
    )
    evidence += issues
    key = (source_text, target_text, kind_text)
    prev = budget.get(key, 0.0)
    if evidence:
        return MappingProxyType(
            {
                "source": source_text,
                "target": target_text,
                "kind": kind_text,
                "weight": prev,
                "requested": requested,
                "applied": 0.0,
                "budget_limit": limit,
                "throttled": True,
                "runtime_input_rejected": True,
                "input_evidence": evidence,
            }
        )
    remaining = max(0.0, limit - prev)
    damp = 1.0 if prev < 1.0 else (0.5 if prev < limit * 0.75 else 0.25)
    applied = min(remaining, requested * damp)
    total = min(limit, prev + applied)
    budget[key] = total
    return MappingProxyType({
        'source': key[0],
        'target': key[1],
        'kind': key[2],
        'weight': total,
        'requested': requested,
        'applied': applied,
        'budget_limit': limit,
        'throttled': applied < requested or total >= limit,
    })


@dataclass(frozen=True)
class RuntimeEvent:
    domain: str
    kind: str
    payload: Mapping[str, object] = field(default_factory=dict)
    generation: int = 0
    timestamp: float = field(default_factory=time.time)
    seq: int = 0
    lineage_id: str = ""

    def __post_init__(self) -> None:
        if type(self) is not RuntimeEvent:
            exception_message = "coordinator runtime event owner rejected"
            raise TypeError(exception_message)
        evidence: tuple[Mapping[str, object], ...] = ()
        domain, issues = runtime_text(
            self.domain, field_name="coordinator_event_domain", default="runtime"
        )
        evidence += issues
        kind, issues = runtime_text(
            self.kind, field_name="coordinator_event_kind", default="input_rejected"
        )
        evidence += issues
        lineage, lineage_reason = no_hook_text(
            self.lineage_id,
            missing_reason="coordinator_event_lineage_id_missing",
            unsupported_reason="coordinator_event_lineage_id_rejected",
        )
        issues = (
            ()
            if not lineage_reason
            else (
                {
                    "runtime_input_rejected": True,
                    "field_name": "coordinator_event_lineage_id",
                    "reason": lineage_reason,
                    "final_json_must_record": True,
                    "checkpoint_must_record": True,
                    "replay_must_record": True,
                },
            )
        )
        evidence += issues
        generation, issues = runtime_int(
            self.generation,
            field_name="coordinator_event_generation",
            default=0,
        )
        evidence += issues
        seq, issues = runtime_int(
            self.seq, field_name="coordinator_event_seq", default=0
        )
        evidence += issues
        timestamp, issues = runtime_float(
            self.timestamp,
            field_name="coordinator_event_timestamp",
            minimum=0.0,
        )
        evidence += issues
        payload = freeze_runtime_value(
            {} if self.payload is None else self.payload
        )
        if evidence:
            items = no_hook_mapping_items(payload)
            payload_state = (
                dict(items) if items is not None else {"payload": payload}
            )
            payload_state["input_evidence"] = evidence
            payload = freeze_runtime_value(payload_state)
        object.__setattr__(self, "domain", domain)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "payload", payload)
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "seq", seq)
        object.__setattr__(self, "lineage_id", lineage)
        object.__setattr__(self, "timestamp", timestamp)

    def as_dict(self) -> dict[str, object]:
        return {
            "domain": self.domain,
            "kind": self.kind,
            "payload": materialize_runtime_value(self.payload),
            "generation": self.generation,
            "timestamp": round(self.timestamp, 6),
            "seq": self.seq,
            "lineage_id": self.lineage_id,
        }


@dataclass(frozen=True)
class MutationRecord:
    domain: str
    key: str
    generation: int
    mutation_count: int
    seq: int
    lineage_id: str
    timestamp: float = field(default_factory=time.time)



_DOMAIN_KEY_PREFIXES: Mapping[str, tuple[str, ...]] = MappingProxyType({
    "runtime": ("root.", "domain."),
    "scheduler": ("queue.", "worker.", "stage."),
    "queue": ("claim.", "job.", "feed."),
    "replay": ("lineage.", "snapshot."),
    "telemetry": ("counter.", "gauge.", "sample."),
    "semantic": ("owner.", "contract.", "influence."),
    "governance": ("decision.", "observation."),
    "topology": ("risk.", "projection."),
    "recovery": ("decision.", "failure."),
})




def _runtime_mutation_text_fragment(value: object, *, replacement: str = "runtime_input_rejected") -> str:
    if type(value) is str:
        return str.__str__(value)
    if type(value) is int and type(value) is not bool:
        return int.__str__(value)
    text, reason = no_hook_text(
        value,
        missing_reason="runtime_mutation_text_missing",
        unsupported_reason="runtime_mutation_text_rejected",
    )
    if reason or not text:
        return replacement
    return text


def _runtime_mutation_message(prefix: str, value: object, suffix: str = "") -> str:
    return (
        str.__str__(prefix)
        + _runtime_mutation_text_fragment(value)
        + str.__str__(suffix)
    )


def _runtime_mutation_pair(left: object, separator: str, right: object) -> str:
    return (
        _runtime_mutation_text_fragment(left)
        + str.__str__(separator)
        + _runtime_mutation_text_fragment(right)
    )


def _runtime_mapping_items(value: object) -> tuple[tuple[object, object], ...]:
    if type(value) is dict:
        return tuple(dict.items(value))
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    return tuple(items)

def _runtime_domain_mutation_allowed(domain: str, key: str, *, declared_domains: tuple[str, ...]) -> bool:
    domain_name, domain_issues = runtime_text(
        domain, field_name="runtime_mutation_domain", default="input_rejected"
    )
    key_text, key_issues = runtime_text(
        key, field_name="runtime_mutation_key", default="input_rejected"
    )
    prefixes = _DOMAIN_KEY_PREFIXES.get(domain_name, ())
    return not (
        domain_issues
        or key_issues
        or domain_name not in declared_domains
        or bool(prefixes and not any(key_text.startswith(prefix) for prefix in prefixes))
    )

class RuntimeDomain:
    """Owned mutable domain with immutable external snapshots."""
    def __init__(self, root: "RuntimeRoot", name: str, *, max_events: int = 4096, max_mutations: int = 250000, volatility_window: int = 1024) -> None:
        self.root = root
        self.name, name_issues = runtime_text(
            name, field_name="runtime_domain_name", default="input_rejected"
        )
        if name_issues:
            exception_message = "runtime domain name rejected"
            raise ValueError(exception_message)
        self._lock = RLock()
        self._generation = 0
        self._state: Dict[str, object] = {}
        self._events: list[RuntimeEvent] = []
        self._max_events, _issues = runtime_int(
            max_events, field_name="runtime_domain_max_events", default=4096
        )
        self._max_events = max(1, self._max_events)
        self._max_mutations, _issues = runtime_int(
            max_mutations,
            field_name="runtime_domain_max_mutations",
            default=250000,
        )
        self._max_mutations = max(1, self._max_mutations)
        self._mutation_count = 0
        self._mutation_records: list[MutationRecord] = []
        self._volatility_window, _issues = runtime_int(
            volatility_window,
            field_name="runtime_domain_volatility_window",
            default=1024,
        )
        self._volatility_window = max(1, self._volatility_window)
        self._frozen = False

    @property
    def generation(self) -> int:
        return self._generation

    @property
    def mutation_count(self) -> int:
        return self._mutation_count

    def set(self, key: str, value: object, *, kind: str = "set", lineage_id: str | None = None) -> object:
        return self.root.mutate(
            self.name, key, value, kind=kind, lineage_id=lineage_id
        )

    def apply_mutation(self, key: str, value: object, *, kind: str, lineage_id: str | None = None) -> object:
        return self._apply_mutation(key, value, kind=kind, lineage_id=lineage_id)

    def _apply_mutation(self, key: str, value: object, *, kind: str, lineage_id: str | None = None) -> object:
        key_text, key_issues = runtime_text(
            key, field_name="runtime_mutation_key", default="input_rejected"
        )
        kind_text, kind_issues = runtime_text(
            kind, field_name="runtime_mutation_kind", default="input_rejected"
        )
        if key_issues or kind_issues:
            raise ValueError("runtime mutation key or kind rejected")
        with self._lock:
            if self._frozen:
                raise RuntimeError(_runtime_mutation_message("runtime domain ", self.name, " is frozen"))
            if self._mutation_count >= self._max_mutations:
                raise RuntimeError(_runtime_mutation_message("mutation budget exceeded for runtime domain ", self.name))
            if not _runtime_domain_mutation_allowed(self.name, key_text, declared_domains=self.root.DOMAIN_NAMES):
                raise RuntimeError(_runtime_mutation_message("runtime domain ", self.name, " does not own key"))
            stored_value = freeze_runtime_value(value)
            next_generation = self._generation + 1
            next_mutation_count = self._mutation_count + 1
            event_payload = {"key": key_text}

            # Publish/validate the causal event before committing local state so an
            # unregistered or invalid event contract cannot leave a partial
            # runtime mutation behind.  Event publication is the authoritative
            # cross-domain contract gate; state and lineage are committed only
            # after it accepts the mutation event.
            causal = self.root.bus.emit(
                self.name,
                kind_text,
                event_payload,
                generation=next_generation,
                lineage_id=lineage_id,
                workload_id=_runtime_mutation_pair(self.name, ":", key_text),
                cost=1.0,
            )

            self._state[key_text] = stored_value
            self._generation = next_generation
            self._mutation_count = next_mutation_count
            ev = RuntimeEvent(self.name, kind_text, event_payload, self._generation, seq=causal.seq, lineage_id=causal.lineage_id)
            rec = MutationRecord(self.name, key_text, self._generation, self._mutation_count, causal.seq, causal.lineage_id)
            self._events.append(ev)
            self._mutation_records.append(rec)
            if len(self._events) > self._max_events:
                del self._events[: len(self._events) - self._max_events]
            if len(self._mutation_records) > self._volatility_window:
                del self._mutation_records[: len(self._mutation_records) - self._volatility_window]
            return materialize_runtime_value(stored_value)

    def emit(self, kind: str, payload: Mapping[str, object] | None = None, *, lineage_id: str | None = None) -> RuntimeEvent:
        kind_text, kind_issues = runtime_text(
            kind, field_name="runtime_emit_kind", default="input_rejected"
        )
        payload_state, payload_issues = runtime_mapping(
            payload, field_name="runtime_emit_payload"
        )
        input_evidence = kind_issues + payload_issues
        if input_evidence:
            payload_state["input_evidence"] = input_evidence
            payload_state["runtime_input_rejected"] = True
        workload_id, workload_issues = runtime_text(
            dict.get(payload_state, "workload_id", self.name),
            field_name="runtime_emit_workload_id",
            default=self.name,
        )
        cost, cost_issues = runtime_float(
            dict.get(payload_state, "cost", 1.0),
            field_name="runtime_emit_cost",
            default=0.0,
            minimum=0.0,
        )
        if workload_issues or cost_issues:
            payload_state["input_evidence"] = (
                tuple(dict.get(payload_state, "input_evidence", ()))
                + workload_issues
                + cost_issues
            )
            payload_state["runtime_input_rejected"] = True
        with self._lock:
            causal = self.root.bus.emit(
                self.name,
                kind_text,
                payload_state,
                generation=self._generation,
                lineage_id=lineage_id,
                workload_id=workload_id,
                cost=cost,
            )
            ev = RuntimeEvent(
                self.name,
                kind_text,
                payload_state,
                self._generation,
                seq=causal.seq,
                lineage_id=causal.lineage_id,
            )
            self._events.append(ev)
            if len(self._events) > self._max_events:
                del self._events[: len(self._events) - self._max_events]
            return ev

    def get(self, key: str, default: object = None) -> object:
        key_text, issues = runtime_text(
            key, field_name="runtime_state_key", default="input_rejected"
        )
        if issues:
            return materialize_runtime_value(freeze_runtime_value(issues[0]))
        with self._lock:
            value = self._state.get(key_text, default)
            return materialize_runtime_value(value)

    def snapshot(self) -> Mapping[str, object]:
        with self._lock:
            return freeze_runtime_value(self._state)

    def event_snapshot(self) -> Tuple[RuntimeEvent, ...]:
        with self._lock:
            return tuple(sorted(self._events, key=lambda ev: (ev.seq, ev.domain, ev.kind)))

    def mutation_lineage(self) -> Tuple[MutationRecord, ...]:
        with self._lock:
            return tuple(self._mutation_records)

    def volatility(self) -> Mapping[str, object]:
        with self._lock:
            keys: Dict[str, int] = {}
            for rec in self._mutation_records:
                keys[rec.key] = keys.get(rec.key, 0) + 1
            return freeze_runtime_value({"domain": self.name, "mutations": self._mutation_count, "generation": self._generation, "hot_keys": dict(sorted(dict.items(keys), key=lambda kv: (-kv[1], kv[0]))[:16])})

    def freeze(self) -> None:
        with self._lock:
            self._frozen = True
            self.emit("freeze", {})


class RuntimeRoot:
    DOMAIN_NAMES = ("runtime", "scheduler", "queue", "replay", "telemetry", "calibration", "extraction", "cache", "semantic", "config", "scanner", "reporting", "governance", "topology", "saturation", "recovery")
    # Stage 36 hardening: runtime domains are not service-discovery namespaces.
    # New mutable domains must be declared here so every mutation has known ownership.
    STRICT_DOMAIN_OWNERSHIP = True

    def __init__(self) -> None:
        self._lock = RLock()
        self.bus = get_global_event_bus()
        self._domains: Dict[str, RuntimeDomain] = {}
        for name in self.DOMAIN_NAMES:
            self._domains[name] = RuntimeDomain(self, name)
        self._semantic_budget: Dict[tuple[str, str, str], float] = {}
        self._budget_limit = 12.0
        self._circuit_breakers: Dict[str, int] = {}
        self._pressure: Dict[str, float] = {}
        self._planes: Dict[str, GovernancePlane] = make_governance_planes()
        self._last_governance_checkpoint: Mapping[str, object] | None = None

    def domain(self, name: str) -> RuntimeDomain:
        key, issues = runtime_text(
            name, field_name="runtime_root_domain", default="input_rejected"
        )
        if issues:
            raise ValueError("runtime domain rejected")
        with self._lock:
            if key not in self._domains:
                if self.STRICT_DOMAIN_OWNERSHIP:
                    raise RuntimeError(_runtime_mutation_message("undeclared runtime mutation domain: ", key))
                self._domains[key] = RuntimeDomain(self, key)
            return self._domains[key]

    def mutate(self, domain: str, key: str, value: object, *, kind: str = "set", lineage_id: str | None = None) -> object:
        return self.domain(domain).apply_mutation(
            key, value, kind=kind, lineage_id=lineage_id
        )

    def emit(self, domain: str, kind: str, payload: Mapping[str, object] | None = None, *, lineage_id: str | None = None) -> RuntimeEvent:
        return self.domain(domain).emit(kind, payload, lineage_id=lineage_id)

    def record_influence(self, source: str, target: str, kind: str, weight: float = 1.0, *, lineage_id: str | None = None) -> Mapping[str, object]:
        with self._lock:
            payload = dict(_record_semantic_influence(self._semantic_budget, source, target, kind, weight, budget_limit=self._budget_limit))
            self.emit("semantic", "influence_budget", payload, lineage_id=lineage_id)
            if payload.get("throttled"):
                self.emit("semantic", "influence_throttled", payload, lineage_id=lineage_id)
                key = (payload.get("source", ""), payload.get("target", ""), payload.get("kind", ""))
                breaker = "semantic:" + "|".join(map(str, key))
                self._circuit_breakers[breaker] = self._circuit_breakers.get(breaker, 0) + 1
            return freeze_runtime_value(payload)


    def record_pressure(self, domain: str, amount: float = 1.0, *, workload_id: str = "global", lineage_id: str | None = None) -> Mapping[str, object]:
        key, domain_issues = runtime_text(
            domain, field_name="runtime_pressure_domain", default="input_rejected"
        )
        raw, amount_issues = runtime_float(
            amount,
            field_name="runtime_pressure_amount",
            default=0.0,
            minimum=0.0,
        )
        workload, workload_issues = runtime_text(
            workload_id,
            field_name="runtime_pressure_workload_id",
            default="input_rejected",
        )
        input_evidence = domain_issues + amount_issues + workload_issues
        if input_evidence:
            return freeze_runtime_value(
                {
                    "domain": key,
                    "pressure": 0.0,
                    "raw": raw,
                    "delta": 0.0,
                    "tripped": True,
                    "workload_id": workload,
                    "governance_decision": "reject_input_and_isolate",
                    "runtime_input_rejected": True,
                    "input_evidence": input_evidence,
                }
            )
        with self._lock:
            prev = self._pressure.get(key, 0.0)
            # Enforced damping: pressure growth decelerates, and high pressure trips isolation.
            delta = raw * (0.50 if prev > PLR2004N10_0 else 1.0) * (0.25 if prev > PLR2004N50_0 else 1.0)
            value = min(100.0, prev + delta)
            self._pressure[key] = value
            plane_name = key if key in {"replay", "telemetry", "scheduler", "saturation", "semantic"} else "saturation"
            plane = observe_governance_plane(self._planes, plane_name, delta)
            tripped = value >= PLR2004N25_0 or plane.get("state") == "tripped"
            governance_decision = "recommend_isolation" if tripped else "observe"
            payload = {"domain": key, "pressure": value, "raw": raw, "delta": delta, "tripped": tripped, "workload_id": workload, "plane": plane, "governance_decision": governance_decision}
            self.emit("governance", "pressure", payload, lineage_id=lineage_id)
            if plane.get("transitioned"):
                self.emit("governance", "plane_transition", {"plane": plane_name, "state": plane.get("state"), "pressure": plane.get("pressure")}, lineage_id=lineage_id)
            if tripped:
                self._circuit_breakers[key] = self._circuit_breakers.get(key, 0) + 1
                self.emit("governance", "circuit_breaker", payload, lineage_id=lineage_id)
            return freeze_runtime_value(payload)

    def snapshot(self) -> Mapping[str, Mapping[str, object]]:
        with self._lock:
            return freeze_runtime_value({name: dom.snapshot() for name, dom in sorted(dict.items(self._domains))})

    def governance_read_domains(self) -> dict[str, RuntimeDomain]:
        with self._lock:
            return dict(self._domains)

    def governance_read_semantic_budget(self) -> dict[tuple[str, str, str], float]:
        with self._lock:
            return dict(self._semantic_budget)

    def governance_read_planes(self) -> dict[str, GovernancePlane]:
        with self._lock:
            return dict(self._planes)

    def governance_read_circuit_breakers(self) -> dict[str, int]:
        with self._lock:
            return dict(self._circuit_breakers)

    def governance_read_pressure(self) -> dict[str, float]:
        with self._lock:
            return dict(self._pressure)


    def convergence_latency_snapshot(self, *, max_allowed_seq_lag: int = 128) -> Mapping[str, object]:
        """Enforce convergence-latency budgets across governance planes.

        This is sequence-based rather than wall-clock based so replay is
        deterministic.  If a domain is under pressure but has not emitted a
        recent corrective event, the snapshot marks a hard convergence violation
        for rollback/degradation policy.
        """
        lag_limit, lag_issues = runtime_int(
            max_allowed_seq_lag,
            field_name="runtime_convergence_max_allowed_seq_lag",
            default=128,
        )
        lag_limit = max(1, lag_limit)
        with self._lock:
            seq = self.bus.sequence
            events = self.bus.snapshot()
            corrective_domains = {"governance", "replay", "telemetry", "scheduler", "saturation", "semantic"}
            last_by_domain: Dict[str, int] = dict.fromkeys(corrective_domains, 0)
            for ev in events:
                if ev.domain in corrective_domains:
                    last_by_domain[ev.domain] = max(last_by_domain.get(ev.domain, 0), ev.seq)
            pressured = []
            for name, pressure in dict.items(self._pressure):
                plane = name if name in corrective_domains else "saturation"
                if pressure >= 25.0:
                    pressured.append(plane)
            drift = []
            lag: Dict[str, int] = {}
            for plane in sorted(set(pressured)):
                sequence_lag = seq - last_by_domain.get(plane, 0)
                lag[plane] = sequence_lag
                if sequence_lag > lag_limit:
                    drift.append(plane)
            return freeze_runtime_value({"violated": bool(drift), "drift_domains": drift, "sequence": seq, "max_allowed_seq_lag": lag_limit, "lag": lag, "input_evidence": lag_issues})

    def immutable_state_audit(self) -> Mapping[str, object]:
        """Audit that mutable runtime state is reachable only through declared domains."""
        with self._lock:
            undeclared = []
            mutable_values = []
            for name, dom in sorted(dict.items(self._domains)):
                if name not in self.DOMAIN_NAMES:
                    undeclared.append(name)
                items = no_hook_mapping_items(dom.snapshot()) or ()
                for key, value in items:
                    if isinstance(value, (dict, list, set, bytearray)):
                        mutable_values.append(_runtime_mutation_pair(name, ".", key))
            return freeze_runtime_value({"ok": not undeclared and not mutable_values, "undeclared_domains": undeclared, "mutable_values": mutable_values[:64], "declared_domain_count": len(self.DOMAIN_NAMES)})

    def governance_snapshot(self) -> Mapping[str, object]:
        """Build governance snapshot through read-model services.

        RuntimeRoot remains the mutation coordinator; replay/topology/governance
        reconstruction is delegated to explicit read models to reduce convergence
        pressure and make observation separate from control.
        """
        with self._lock:
            snap = build_governance_read_model(self)
            self._last_governance_checkpoint = snap.get("deterministic_checkpoint")
            return snap

    def restore_last_governance_checkpoint(self) -> bool:
        with self._lock:
            if not self._last_governance_checkpoint:
                return False
            self.bus.restore_checkpoint(self._last_governance_checkpoint)
            self.emit("governance", "rollback_restore", {"sequence": self.bus.sequence}, lineage_id="governance-rollback")
            return True

    def replay_snapshot(self) -> Mapping[str, object]:
        bus = self.bus
        if type(bus) is not EventBus:
            raise TypeError("runtime root event bus owner rejected")
        snap = self.governance_snapshot()
        return freeze_runtime_value({
            "event_sequence": snap["event_sequence"],
            "semantic_budget": snap["semantic_budget"],
            "domain_generations": {k: v["generation"] for k, v in _runtime_mapping_items(snap["domains"])},
            "events": snap["events"],
            "event_invariants": snap.get("event_invariants"),
            "replay_integrity": snap.get("replay_integrity"),
            "replay_lineage_pressure": snap.get("replay_lineage_pressure"),
            "compressed_replay": snap.get("compressed_replay"),
            "compressed_causal_tracing": snap.get("compressed_causal_tracing"),
            "replay_tombstones": tuple(bus.replay_tombstones()),
        })

_register_runtime_root_type(RuntimeRoot)
_RUNTIME_ROOT = RuntimeRoot()


def get_runtime_root() -> RuntimeRoot:
    return _RUNTIME_ROOT


__all__ = ("MutationRecord", "RuntimeDomain", "RuntimeEvent", "RuntimeRoot", "get_runtime_root")
