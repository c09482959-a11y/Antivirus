"""Canonical causal event stream implementation.

FactEventStore is the append-only causal truth. EventBus is retained here as
the owned deterministic event stream implementation used by governance, replay,
mutation coordination, and runtime calibration.
"""
from __future__ import annotations

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field
from dataclasses import dataclass, field
from threading import RLock
from time import time
from typing import Mapping, Tuple
import hashlib
import uuid

from .event_contracts import event_contract_snapshot, validate_event_contract
from .immutable_core import materialize_runtime_value
from .runtime_debt import get_runtime_debt_ledger
from .fact_event_store import FactEventStore
from .runtime_economics_ledger import observe_runtime_economics
from .causal_snapshots import build_causal_snapshot
from .causal_text import causal_text_default
from .causal_event_stream_support import (
    _causal_digest_material,
    _causal_event_key,
    _causal_event_row_without_timestamp,
    _causal_field_text,
    _causal_finite_float,
    _causal_indexed_text,
    _causal_int,
    _causal_lineage_seed,
    _causal_owned_text,
    _causal_payload_for_contract,
    _causal_payload_items,
    _causal_runtime_text,
    _freeze_causal_value,
    _payload_with_input_evidence,
    _stable_payload_key,
)
from .causal_event_stream_checkpoint_support import restore_checkpoint_for_bus
from .causal_event_stream_query_support import (
    budget_snapshot_for_bus,
    causal_topology_forecast_for_bus,
    causal_trace_visualization_for_bus,
    compressed_causal_trace_for_bus,
    compressed_replay_for_bus,
    dependency_snapshot_for_bus,
    deterministic_checkpoint_for_bus,
    invariant_snapshot_for_bus,
    replay_digest_for_bus,
    replay_lineage_pressure_for_bus,
    telemetry_resource_budget_for_bus,
    topology_pressure_forecast_for_bus,
)
from .governance_inputs import (
    runtime_bool,
    runtime_float,
    runtime_int,
    runtime_sequence,
)
















































































@dataclass(frozen=True)
class CausalEvent:
    seq: int
    lineage_id: str
    domain: str
    kind: str
    payload: Mapping[str, object] = field(default_factory=dict)
    generation: int = 0
    parent_seq: int | None = None
    timestamp: float = field(default_factory=time)
    workload_id: str = "global"
    event_key: str = ""
    suppressed_count: int = 0
    cost: float = 1.0
    severity: str = "operational"
    schema_version: int = 1
    owner: str = "runtime"
    propagation: str = "append_only"
    causal_depth: int = 0
    causal_path: tuple[int, ...] = ()
    causal_digest: str = ""

    def __post_init__(self) -> None:
        if type(self) is not CausalEvent:
            raise TypeError("causal event owner rejected")
        evidence: tuple[Mapping[str, object], ...] = ()
        for field_name, text_default in (
            ("lineage_id", ""),
            ("domain", "runtime"),
            ("kind", "event"),
            ("workload_id", "global"),
            ("event_key", ""),
            ("severity", "operational"),
            ("owner", "runtime"),
            ("propagation", "append_only"),
            ("causal_digest", ""),
        ):
            text, issues = _causal_runtime_text(
                no_hook_exact_owner_field(self, type(self), field_name),
                field_name=_causal_field_text("causal_event_", field_name),
                default=text_default,
            )
            evidence += issues
            object.__setattr__(self, field_name, text)
        for field_name, int_default in (
            ("seq", 0),
            ("generation", 0),
            ("suppressed_count", 0),
            ("schema_version", 1),
            ("causal_depth", 0),
        ):
            metric, issues = runtime_int(
                no_hook_exact_owner_field(self, type(self), field_name),
                field_name=_causal_field_text("causal_event_", field_name),
                default=int_default,
            )
            evidence += issues
            object.__setattr__(self, field_name, metric)
        timestamp, issues = runtime_float(
            self.timestamp,
            field_name="causal_event_timestamp",
            default=0.0,
            minimum=0.0,
        )
        evidence += issues
        cost, issues = runtime_float(
            self.cost,
            field_name="causal_event_cost",
            default=0.0,
            minimum=0.0,
        )
        evidence += issues
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "cost", cost)
        if self.parent_seq is not None:
            parent_seq, issues = runtime_int(
                self.parent_seq,
                field_name="causal_event_parent_seq",
                default=0,
            )
            evidence += issues
            object.__setattr__(self, "parent_seq", None if issues else parent_seq)
        path, issues = runtime_sequence(
            self.causal_path, field_name="causal_event_causal_path"
        )
        evidence += issues
        causal_path: list[int] = []
        for index, item in enumerate(path):
            seq, issues = runtime_int(
                item,
                field_name=_causal_indexed_text("causal_event_causal_path_", index),
                default=0,
            )
            evidence += issues
            if not issues:
                causal_path.append(seq)
        object.__setattr__(self, "causal_path", tuple(causal_path))
        object.__setattr__(
            self,
            "payload",
            _payload_with_input_evidence(self.payload, evidence),
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "seq": self.seq,
            "lineage_id": self.lineage_id,
            "domain": self.domain,
            "kind": self.kind,
            "generation": self.generation,
            "parent_seq": self.parent_seq,
            "timestamp": round(self.timestamp, 6),
            "causal_digest": self.causal_digest,
            "workload_id": self.workload_id,
            "event_key": self.event_key,
            "suppressed_count": self.suppressed_count,
            "cost": round(self.cost, 4),
            "severity": self.severity,
            "schema_version": self.schema_version,
            "owner": self.owner,
            "propagation": self.propagation,
            "causal_depth": self.causal_depth,
            "causal_path": list(self.causal_path),
            "payload": materialize_runtime_value(self.payload),
        }


@dataclass(frozen=True)
class ReplayTombstone:
    seq: int
    lineage_id: str
    domain: str
    kind: str
    reason: str
    parent_seq: int | None = None
    workload_id: str = "global"

    def __post_init__(self) -> None:
        if type(self) is not ReplayTombstone:
            raise TypeError("replay tombstone owner rejected")
        seq, _issues = runtime_int(
            self.seq, field_name="replay_tombstone_seq", default=0
        )
        object.__setattr__(self, "seq", seq)
        for field_name, default in (
            ("lineage_id", ""),
            ("domain", "runtime"),
            ("kind", "event"),
            ("reason", "causal_text_unavailable:reason"),
            ("workload_id", "global"),
        ):
            text, _issues = _causal_runtime_text(
                no_hook_exact_owner_field(self, type(self), field_name),
                field_name=_causal_field_text("replay_tombstone_", field_name),
                default=default,
            )
            object.__setattr__(self, field_name, text)
        if self.parent_seq is not None:
            parent_seq, issues = runtime_int(
                self.parent_seq,
                field_name="replay_tombstone_parent_seq",
                default=0,
            )
            object.__setattr__(self, "parent_seq", None if issues else parent_seq)

    def as_dict(self) -> dict[str, object]:
        return {
            "seq": self.seq,
            "lineage_id": self.lineage_id,
            "domain": self.domain,
            "kind": self.kind,
            "reason": self.reason,
            "parent_seq": self.parent_seq,
            "workload_id": self.workload_id,
        }


@dataclass
class WorkloadEventBudget:
    max_events: int = 4096
    max_cost: float = 8192.0
    max_per_key: int = 64
    max_depth: int = 64
    max_fanout_per_parent: int = 256
    emitted: int = 0
    cost: float = 0.0
    suppressed: int = 0
    per_key: dict[str, int] = field(default_factory=dict)
    reasons: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not WorkloadEventBudget:
            raise TypeError("workload event budget owner rejected")
        evidence: tuple[Mapping[str, object], ...] = ()
        for field_name in (
            "max_events",
            "max_per_key",
            "max_depth",
            "max_fanout_per_parent",
            "emitted",
            "suppressed",
        ):
            value, issues = runtime_int(
                no_hook_exact_owner_field(self, type(self), field_name),
                field_name=_causal_field_text("workload_event_budget_", field_name),
                default=0,
            )
            evidence += issues
            object.__setattr__(self, field_name, value)
        cost, issues = runtime_float(
            self.cost,
            field_name="workload_event_budget_cost",
            default=0.0,
            minimum=0.0,
        )
        evidence += issues
        self.cost = cost
        max_cost, issues = runtime_float(
            self.max_cost,
            field_name="workload_event_budget_max_cost",
            default=0.0,
            minimum=0.0,
        )
        evidence += issues
        self.max_cost = max_cost
        if type(self.per_key) is not dict or type(self.reasons) is not dict:
            raise TypeError("workload event budget counters must be exact dictionaries")
        for counter_name, counter in (
            ("per_key", self.per_key),
            ("reasons", self.reasons),
        ):
            for key, raw_count in tuple(dict.items(counter)):
                if type(key) is not str:
                    raise TypeError(
                        _causal_owned_text("workload event budget ", counter_name, " key rejected")
                    )
                _count, issues = runtime_int(
                    raw_count,
                    field_name=_causal_owned_text("workload_event_budget_", counter_name, "_count"),
                    default=0,
                )
                evidence += issues
        if evidence:
            raise ValueError("workload event budget configuration rejected")

    def _reject(self, reason: str) -> tuple[bool, str]:
        self.suppressed += 1
        self.reasons[reason] = self.reasons.get(reason, 0) + 1
        return False, reason

    def allow(self, event_key: str, cost: float, *, critical: bool = False, depth: int = 0, parent_fanout: int = 0) -> tuple[bool, str]:
        k, key_issues = _causal_runtime_text(
            event_key,
            field_name="workload_event_budget_event_key",
            default="unknown",
        )
        event_cost, cost_issues = runtime_float(
            cost,
            field_name="workload_event_budget_event_cost",
            default=0.0,
            minimum=0.0,
        )
        event_depth, depth_issues = runtime_int(
            depth,
            field_name="workload_event_budget_depth",
            default=0,
        )
        fanout, fanout_issues = runtime_int(
            parent_fanout,
            field_name="workload_event_budget_parent_fanout",
            default=0,
        )
        is_critical, critical_issues = runtime_bool(
            critical,
            field_name="workload_event_budget_critical",
            default=False,
        )
        if key_issues + cost_issues + depth_issues + fanout_issues + critical_issues:
            return self._reject("event_budget_input_rejected")
        self.emitted += 1
        self.cost += event_cost
        self.per_key[k] = self.per_key.get(k, 0) + 1
        if is_critical:
            return True, "critical"
        if event_depth > self.max_depth:
            return self._reject("event_depth_exceeded")
        if fanout >= self.max_fanout_per_parent:
            return self._reject("event_fanout_exceeded")
        if self.emitted > self.max_events:
            return self._reject("event_budget_exceeded")
        if self.cost > self.max_cost:
            return self._reject("event_cost_exceeded")
        if self.per_key[k] > self.max_per_key:
            return self._reject("event_key_burst_suppressed")
        return True, "allowed"

    def snapshot(self) -> dict[str, object]:
        return {
            "emitted": self.emitted,
            "cost": round(self.cost, 4),
            "suppressed": self.suppressed,
            "unique_keys": len(self.per_key),
            "reasons": dict(sorted(dict.items(self.reasons))),
            "hot_keys": dict(sorted(dict.items(self.per_key), key=lambda kv: (-kv[1], kv[0]))[:16]),
        }


@dataclass(frozen=True)
class _NormalizedEmission:
    domain: str
    kind: str
    generation: int
    lineage_id: str
    lineage_missing: bool
    parent_seq: int | None
    workload_id: str
    cost: float
    evidence: tuple[Mapping[str, object], ...]


@dataclass(frozen=True)
class _EmissionContext:
    domain: str
    kind: str
    payload: object
    generation: int
    lineage_id: str
    lineage_missing: bool
    parent_seq: int | None
    workload_id: str
    severity: str
    critical: bool
    cost: float
    depth: int
    payload_key: str
    event_key: str
    dedup_key: tuple[str, str, str, str]
    budget: WorkloadEventBudget
    parent_fanout: int
    contract: object
    contract_ok: bool
    contract_reason: str




class EventBus:
    """Append-only causal event stream with deterministic ordering and hard replay economics.

    Stage 38 closes the remaining Stage 37 governance gaps directly in the bus:
    replay lineage has absolute ceilings, topology forecasting carries confidence
    and anomaly classification, deterministic checkpoints can be restored, and
    causal trace data is available without consulting mutable runtime globals.
    """
    def __init__(self, max_events: int = 65536, *, max_events_per_workload: int = 4096, max_cost_per_workload: float = 8192.0, max_per_key: int = 64, max_fanout_per_parent: int = 256, max_lineage_events: int = 2048, max_lineages: int = 16384, max_descendants_per_lineage: int = 4096, max_stabilization_recursion_depth: int = 3) -> None:
        self._lock = RLock()
        self._seq = 0
        config_evidence: tuple[Mapping[str, object], ...] = ()
        self._max_events, issues = runtime_int(
            max_events, field_name="event_bus_max_events", default=65536
        )
        config_evidence += issues
        self._max_events = max(1, self._max_events)
        self._events: list[CausalEvent] = []
        self._by_seq: dict[int, CausalEvent] = {}
        self._budgets: dict[str, WorkloadEventBudget] = {}
        self._dedup: dict[tuple[str, str, str, str], tuple[int, int]] = {}
        self._suppressed_summaries: dict[tuple[str, str, str, str], int] = {}
        self._parent: dict[int, int | None] = {}
        self._depth: dict[int, int] = {}
        self._children: dict[int, int] = {}
        self._suppressed_reasons: dict[str, int] = {}
        self._lineage_counts: dict[str, int] = {}
        self._checkpoint_generation = 0
        self._max_events_per_workload, issues = runtime_int(
            max_events_per_workload,
            field_name="event_bus_max_events_per_workload",
            default=4096,
        )
        config_evidence += issues
        self._max_events_per_workload = max(1, self._max_events_per_workload)
        self._max_cost_per_workload, issues = runtime_float(
            max_cost_per_workload,
            field_name="event_bus_max_cost_per_workload",
            default=8192.0,
            minimum=0.0,
        )
        config_evidence += issues
        self._max_per_key, issues = runtime_int(
            max_per_key, field_name="event_bus_max_per_key", default=64
        )
        config_evidence += issues
        self._max_per_key = max(1, self._max_per_key)
        self._max_fanout_per_parent, issues = runtime_int(
            max_fanout_per_parent,
            field_name="event_bus_max_fanout_per_parent",
            default=256,
        )
        config_evidence += issues
        self._max_fanout_per_parent = max(1, self._max_fanout_per_parent)
        self._contract_violations = 0
        self._max_lineage_events, issues = runtime_int(
            max_lineage_events,
            field_name="event_bus_max_lineage_events",
            default=2048,
        )
        config_evidence += issues
        self._max_lineage_events = max(1, self._max_lineage_events)
        self._max_lineages, issues = runtime_int(
            max_lineages, field_name="event_bus_max_lineages", default=16384
        )
        config_evidence += issues
        self._max_lineages = max(1, self._max_lineages)
        self._lineage_pruned: dict[str, int] = {}
        self._last_checkpoint: dict[str, object] | None = None
        self._max_descendants_per_lineage, issues = runtime_int(
            max_descendants_per_lineage,
            field_name="event_bus_max_descendants_per_lineage",
            default=4096,
        )
        config_evidence += issues
        self._max_descendants_per_lineage = max(
            1, self._max_descendants_per_lineage
        )
        self._max_stabilization_recursion_depth, issues = runtime_int(
            max_stabilization_recursion_depth,
            field_name="event_bus_max_stabilization_recursion_depth",
            default=3,
        )
        config_evidence += issues
        self._max_stabilization_recursion_depth = max(
            1, self._max_stabilization_recursion_depth
        )
        self._lineage_descendants: dict[str, int] = {}
        self._fact_store = FactEventStore(max_events=self._max_events)
        self._replay_tombstones: list[ReplayTombstone] = []
        self._config_input_evidence = config_evidence
        self._checkpoint_restore_evidence: tuple[Mapping[str, object], ...] = ()

    def _budget(self, workload_id: str) -> WorkloadEventBudget:
        wid = causal_text_default(workload_id, "global")[:256]
        if wid not in self._budgets:
            self._budgets[wid] = WorkloadEventBudget(
                max_events=self._max_events_per_workload,
                max_cost=self._max_cost_per_workload,
                max_per_key=self._max_per_key,
                max_fanout_per_parent=self._max_fanout_per_parent,
            )
        return self._budgets[wid]

    def _note_suppressed(self, reason: str) -> None:
        self._suppressed_reasons[reason] = self._suppressed_reasons.get(reason, 0) + 1

    def _causal_depth(self, parent_seq: int | None) -> int:
        if parent_seq is None:
            return 0
        return int(self._depth.get(int(parent_seq), 0)) + 1

    def _causal_path(self, parent_seq: int | None) -> tuple[int, ...]:
        if parent_seq is None:
            return ()
        parent = int(parent_seq)
        prev = self._by_seq.get(parent)
        if not prev:
            return (parent,)
        return (*prev.causal_path, parent)[-64:]

    def _causal_digest(self, domain: str, kind: str, event_key: str, parent_seq: int | None, seq: int) -> str:
        parent_digest = "root"
        if parent_seq is not None and int(parent_seq) in self._by_seq:
            parent_event = self._by_seq[int(parent_seq)]
            if type(parent_event) is not CausalEvent:
                raise TypeError("causal event stream parent owner rejected")
            parent_digest = parent_event.causal_digest or "root"
        return hashlib.sha256(_causal_digest_material(parent_digest, seq, domain, kind, event_key).encode("utf-8", "replace")).hexdigest()[:32]


    def _stabilization_recursion_depth(self, parent_seq: int | None, domain: str, kind: str) -> int:
        """Count consecutive governance/stabilization hops in the causal chain.

        Stage 39 makes stabilization firebreaks enforceable inside the event
        stream.  A corrective event is allowed, but recursive corrective chains
        are hard-stopped before they can trigger replay/telemetry/scheduler
        escalation loops.
        """
        corrective = {"governance", "telemetry", "scheduler", "replay", "saturation"}
        names = {"pressure", "circuit_breaker", "plane_transition", "rollback_restore", "influence_throttled", "stabilization", "suppress", "throttle"}
        cur_is_corrective = causal_text_default(domain, "runtime") in corrective or any(x in causal_text_default(kind, "event") for x in names)
        if not cur_is_corrective:
            return 0
        depth = 1
        cur = int(parent_seq) if parent_seq is not None else None
        while cur is not None:
            ev = self._by_seq.get(cur)
            if not ev:
                break
            ev_is_corrective = ev.domain in corrective or any(x in ev.kind for x in names)
            if not ev_is_corrective:
                break
            depth += 1
            cur = ev.parent_seq
        return depth

    def _would_loop(self, parent_seq: int | None, max_depth: int = 64) -> bool:
        if parent_seq is None:
            return False
        seen = set()
        cur: int | None = int(parent_seq)
        depth = 0
        while cur is not None and cur not in seen and depth <= max_depth:
            seen.add(cur)
            cur = self._parent.get(cur)
            depth += 1
        return cur in seen or depth > max_depth

    def _suppressed_event(self, domain: str, kind: str, reason: str, *, seq: int | None, lineage_id: str | None, generation: int, parent_seq: int | None, wid: str, event_key: str, suppressed_count: int, severity: str, owner: str, propagation: str, depth: int) -> CausalEvent:
        self._note_suppressed(reason)
        try:
            tombstone = ReplayTombstone(
                seq=int(seq if seq is not None else self._seq),
                lineage_id=causal_text_default(lineage_id, reason),
                domain=domain,
                kind=kind,
                reason=reason,
                parent_seq=parent_seq,
                workload_id=wid,
            )
            self._replay_tombstones.append(tombstone)
            if len(self._replay_tombstones) > 8192:
                del self._replay_tombstones[: len(self._replay_tombstones) - 8192]
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_suppressed_failure('event_tombstone_record_failed', exc, domain='runtime')
        return CausalEvent(
            int(seq if seq is not None else self._seq),
            causal_text_default(lineage_id, reason), domain, kind,
            _freeze_causal_value({"suppressed": True, "reason": reason}),
            _causal_int(generation, 0), parent_seq, workload_id=wid, event_key=event_key,
            suppressed_count=suppressed_count, cost=0.0, severity=severity,
            owner=owner, propagation=propagation, causal_depth=depth,
            causal_path=self._causal_path(parent_seq),
            causal_digest=self._causal_digest(domain, kind, event_key, parent_seq, int(seq if seq is not None else self._seq)),
        )

    def _prepare_emission(
        self,
        domain: object,
        kind: object,
        payload: object,
        *,
        generation: object,
        lineage_id: object,
        parent_seq: object,
        workload_id: object,
        severity: object,
        cost: object,
    ) -> _EmissionContext:
        normalized = self._normalize_emission_inputs(
            domain,
            kind,
            generation=generation,
            lineage_id=lineage_id,
            parent_seq=parent_seq,
            workload_id=workload_id,
            cost=cost,
        )
        contract_payload = _causal_payload_for_contract(payload)
        contract, contract_ok, contract_reason = validate_event_contract(
            normalized.domain, normalized.kind, contract_payload
        )
        severity_text, severity_issues = _causal_runtime_text(
            severity,
            field_name="causal_emit_severity",
            default=causal_text_default(contract.severity, "operational"),
        )
        severity_text = severity_text.lower()
        evidence = normalized.evidence + severity_issues
        payload_items = _causal_payload_items(payload)
        payload_for_event = (
            contract_payload
            if payload_items is None and isinstance(payload, Mapping)
            else payload
        )
        prepared_payload = _payload_with_input_evidence(
            payload_for_event, evidence
        )
        event_cost = min(
            normalized.cost,
            _causal_finite_float(contract.max_cost, 64.0, minimum=0.0),
        )
        depth = self._causal_depth(normalized.parent_seq)
        payload_key = _stable_payload_key(prepared_payload)
        event_key = _causal_event_key(
            normalized.domain, normalized.kind, contract.version, payload_key
        )
        budget = self._budget(normalized.workload_id)
        parent_fanout = (
            self._children.get(normalized.parent_seq, 0)
            if normalized.parent_seq is not None
            else 0
        )
        return _EmissionContext(
            domain=normalized.domain,
            kind=normalized.kind,
            payload=prepared_payload,
            generation=normalized.generation,
            lineage_id=normalized.lineage_id,
            lineage_missing=normalized.lineage_missing,
            parent_seq=normalized.parent_seq,
            workload_id=normalized.workload_id,
            severity=severity_text,
            critical=(
                severity_text == "critical" or contract.severity == "critical"
            ),
            cost=event_cost,
            depth=depth,
            payload_key=payload_key,
            event_key=event_key,
            dedup_key=(
                normalized.workload_id,
                normalized.domain,
                normalized.kind,
                payload_key,
            ),
            budget=budget,
            parent_fanout=parent_fanout,
            contract=contract,
            contract_ok=contract_ok,
            contract_reason=contract_reason,
        )

    def _normalize_emission_inputs(
        self,
        domain: object,
        kind: object,
        *,
        generation: object,
        lineage_id: object,
        parent_seq: object,
        workload_id: object,
        cost: object,
    ) -> _NormalizedEmission:
        evidence: tuple[Mapping[str, object], ...] = ()
        domain_text, issues = _causal_runtime_text(
            domain, field_name="causal_emit_domain", default="runtime"
        )
        evidence += issues
        kind_text, issues = _causal_runtime_text(
            kind, field_name="causal_emit_kind", default="event"
        )
        evidence += issues
        workload_text, issues = _causal_runtime_text(
            workload_id,
            field_name="causal_emit_workload_id",
            default="global",
        )
        evidence += issues
        workload_text = workload_text[:256]
        generation_value, issues = runtime_int(
            generation, field_name="causal_emit_generation", default=0
        )
        evidence += issues
        parent = None
        if parent_seq is not None:
            parent, issues = runtime_int(
                parent_seq, field_name="causal_emit_parent_seq", default=0
            )
            evidence += issues
            if issues:
                parent = None
        event_cost, issues = runtime_float(
            cost,
            field_name="causal_emit_cost",
            default=0.0,
            minimum=0.0,
        )
        evidence += issues
        lineage_missing = lineage_id is None
        if lineage_missing:
            lineage_text = uuid.uuid5(
                uuid.NAMESPACE_URL,
                _causal_lineage_seed(workload_text, domain_text, kind_text, self._seq + 1),
            ).hex
        else:
            lineage_text, issues = _causal_runtime_text(
                lineage_id,
                field_name="causal_emit_lineage_id",
                default="runtime_input_rejected",
            )
            evidence += issues
        return _NormalizedEmission(
            domain=domain_text,
            kind=kind_text,
            generation=generation_value,
            lineage_id=lineage_text,
            lineage_missing=lineage_missing,
            parent_seq=parent,
            workload_id=workload_text,
            cost=event_cost,
            evidence=evidence,
        )

    def _budget_suppressed_event(
        self,
        context: _EmissionContext,
        reason: str,
        *,
        lineage_id: str,
        severity: str,
        seq: int | None = None,
        suppressed_count: int | None = None,
    ) -> CausalEvent:
        context.budget.suppressed += 1
        context.budget.reasons[reason] = (
            context.budget.reasons.get(reason, 0) + 1
        )
        return self._suppressed_event(
            context.domain,
            context.kind,
            reason,
            seq=self._seq if seq is None else seq,
            lineage_id=lineage_id,
            generation=context.generation,
            parent_seq=context.parent_seq,
            wid=context.workload_id,
            event_key=context.event_key,
            suppressed_count=(
                context.budget.suppressed
                if suppressed_count is None
                else suppressed_count
            ),
            severity=severity,
            owner=context.contract.owner,
            propagation=context.contract.propagation,
            depth=context.depth,
        )

    def _pre_authorization_suppression(
        self, context: _EmissionContext
    ) -> CausalEvent | None:
        parent = context.parent_seq
        if parent is not None and parent not in self._by_seq and not context.critical:
            lineage = "unknown_parent" if context.lineage_missing else context.lineage_id
            return self._budget_suppressed_event(
                context, "unknown_parent", lineage_id=lineage, severity="anomaly"
            )
        if parent is not None and not context.critical:
            parent_event = self._by_seq.get(parent)
            isolated_domains = {"replay", "governance", "scheduler", "saturation"}
            if (
                parent_event is not None
                and parent_event.domain == "telemetry"
                and context.domain in isolated_domains
            ):
                get_runtime_debt_ledger().record(
                    context.workload_id, telemetry=0.25
                )
                lineage = (
                    "telemetry_isolated"
                    if context.lineage_missing
                    else context.lineage_id
                )
                return self._budget_suppressed_event(
                    context,
                    "telemetry_isolation_domain",
                    lineage_id=lineage,
                    severity="critical",
                )
        return self._lineage_suppression(context)

    def _lineage_suppression(
        self, context: _EmissionContext
    ) -> CausalEvent | None:
        lineage_count = self._lineage_counts.get(context.lineage_id, 0)
        if not context.critical and lineage_count >= self._max_lineage_events:
            self._lineage_pruned[context.lineage_id] = (
                self._lineage_pruned.get(context.lineage_id, 0) + 1
            )
            return self._budget_suppressed_event(
                context,
                "lineage_hard_ceiling",
                lineage_id=context.lineage_id,
                severity="critical",
            )
        descendants = self._lineage_descendants.get(context.lineage_id, 0)
        if (
            not context.critical
            and descendants >= self._max_descendants_per_lineage
        ):
            self._lineage_pruned[context.lineage_id] = (
                self._lineage_pruned.get(context.lineage_id, 0) + 1
            )
            return self._budget_suppressed_event(
                context,
                "lineage_descendant_hard_ceiling",
                lineage_id=context.lineage_id,
                severity="critical",
            )
        recursion_depth = self._stabilization_recursion_depth(
            context.parent_seq, context.domain, context.kind
        )
        if (
            not context.critical
            and recursion_depth > self._max_stabilization_recursion_depth
        ):
            return self._budget_suppressed_event(
                context,
                "stabilization_recursion_firebreak",
                lineage_id=context.lineage_id,
                severity="critical",
            )
        if (
            not context.critical
            and context.lineage_id not in self._lineage_counts
            and len(self._lineage_counts) >= self._max_lineages
        ):
            return self._budget_suppressed_event(
                context,
                "lineage_domain_ceiling",
                lineage_id=context.lineage_id,
                severity="critical",
            )
        return None

    def _authorize_emission(
        self, context: _EmissionContext
    ) -> tuple[object, str, float, CausalEvent | None]:
        payload = context.payload
        severity = context.severity
        event_cost = context.cost
        if not context.contract_ok:
            self._contract_violations += 1
            if not context.critical:
                payload = _causal_payload_for_contract(payload)
                payload["contract_violation"] = context.contract_reason
                severity = "anomaly"
                event_cost = max(event_cost, 2.0)
        allowed, reason = context.budget.allow(
            context.event_key,
            event_cost,
            critical=context.critical,
            depth=context.depth,
            parent_fanout=context.parent_fanout,
        )
        previous = self._dedup.get(context.dedup_key)
        if previous and not context.critical:
            last_seq, count = previous
            count += 1
            self._dedup[context.dedup_key] = (last_seq, count)
            if count % 64 != 0:
                self._suppressed_summaries[context.dedup_key] = (
                    self._suppressed_summaries.get(context.dedup_key, 0) + 1
                )
                event = self._budget_suppressed_event(
                    context,
                    "equivalent_event",
                    seq=last_seq,
                    lineage_id=(
                        "dedup"
                        if context.lineage_missing
                        else context.lineage_id
                    ),
                    suppressed_count=count,
                    severity=severity,
                )
                return payload, severity, event_cost, event
        if not allowed:
            self._suppressed_summaries[context.dedup_key] = (
                self._suppressed_summaries.get(context.dedup_key, 0) + 1
            )
            lineage = (
                "budget_suppressed"
                if context.lineage_missing
                else context.lineage_id
            )
            event = self._suppressed_event(
                context.domain,
                context.kind,
                reason,
                seq=self._seq,
                lineage_id=lineage,
                generation=context.generation,
                parent_seq=context.parent_seq,
                wid=context.workload_id,
                event_key=context.event_key,
                suppressed_count=context.budget.suppressed,
                severity=severity,
                owner=context.contract.owner,
                propagation=context.contract.propagation,
                depth=context.depth,
            )
            return payload, severity, event_cost, event
        if self._would_loop(
            context.parent_seq, max_depth=context.budget.max_depth
        ) and not context.critical:
            lineage = (
                "loop_suppressed"
                if context.lineage_missing
                else context.lineage_id
            )
            event = self._budget_suppressed_event(
                context,
                "event_loop_detected",
                lineage_id=lineage,
                severity="critical",
            )
            return payload, severity, event_cost, event
        get_runtime_debt_ledger().record(
            context.workload_id, event=event_cost
        )
        try:
            observe_runtime_economics("event_publish_cost", event_cost)
        except RECOVERABLE_RUNTIME_ERRORS as exc:
            record_suppressed_failure(
                "event_publish_authorize_failed", exc, domain="runtime"
            )
        return payload, severity, event_cost, None

    def _append_emission(
        self,
        context: _EmissionContext,
        payload: object,
        severity: str,
        event_cost: float,
    ) -> CausalEvent:
        self._seq += 1
        suppressed = self._suppressed_summaries.pop(context.dedup_key, 0)
        event = CausalEvent(
            seq=self._seq,
            lineage_id=context.lineage_id,
            domain=context.domain,
            kind=context.kind,
            payload=payload,
            generation=context.generation,
            parent_seq=context.parent_seq,
            workload_id=context.workload_id,
            event_key=context.event_key,
            suppressed_count=suppressed,
            cost=event_cost,
            severity=severity,
            schema_version=context.contract.version,
            owner=context.contract.owner,
            propagation=context.contract.propagation,
            causal_depth=context.depth,
            causal_path=self._causal_path(context.parent_seq),
            causal_digest=self._causal_digest(
                context.domain,
                context.kind,
                context.event_key,
                context.parent_seq,
                self._seq,
            ),
        )
        pruned = self._fact_store.append(
            event, context.parent_seq, context.depth
        )
        self._events = self._fact_store.events
        self._by_seq = self._fact_store.by_seq
        self._parent = self._fact_store.parent
        self._depth = self._fact_store.depth
        self._children = self._fact_store.children
        self._dedup[context.dedup_key] = (event.seq, 1)
        lineage = context.lineage_id
        self._lineage_counts[lineage] = self._lineage_counts.get(lineage, 0) + 1
        self._lineage_descendants[lineage] = (
            self._lineage_descendants.get(lineage, 0)
            + (1 if context.parent_seq is not None else 0)
        )
        for item in pruned:
            item_lineage = item.lineage_id
            self._lineage_counts[item_lineage] = max(
                0, self._lineage_counts.get(item_lineage, 0) - 1
            )
            if item.parent_seq is not None:
                self._lineage_descendants[item_lineage] = max(
                    0, self._lineage_descendants.get(item_lineage, 0) - 1
                )
            if self._lineage_counts.get(item_lineage) == 0:
                self._lineage_counts.pop(item_lineage, None)
                self._lineage_descendants.pop(item_lineage, None)
            self._lineage_pruned[item_lineage] = (
                self._lineage_pruned.get(item_lineage, 0) + 1
            )
        return event

    def emit(self, domain: str, kind: str, payload: Mapping[str, object] | None = None, *, generation: int = 0, lineage_id: str | None = None, parent_seq: int | None = None, workload_id: str = "global", severity: str = "operational", cost: float = 1.0) -> CausalEvent:
        with self._lock:
            context = self._prepare_emission(
                domain,
                kind,
                payload,
                generation=generation,
                lineage_id=lineage_id,
                parent_seq=parent_seq,
                workload_id=workload_id,
                severity=severity,
                cost=cost,
            )
            suppressed = self._pre_authorization_suppression(context)
            if suppressed is not None:
                return suppressed
            prepared_payload, prepared_severity, prepared_cost, suppressed = (
                self._authorize_emission(context)
            )
            if suppressed is not None:
                return suppressed
            return self._append_emission(
                context,
                prepared_payload,
                prepared_severity,
                prepared_cost,
            )

    @property
    def fact_store(self) -> FactEventStore:
        """Append-only factual store; preferred read-side source for replay/topology."""
        return self._fact_store

    def append_fact(self, domain: str, kind: str, payload: Mapping[str, object] | None = None, **kwargs: object) -> CausalEvent:
        """Runtime-safe factual append using existing ordering logic.

        This preserves deterministic event behavior while making the intended
        API explicit for future replacement of from policy-heavy EventBus calls.
        """
        return self.emit(domain, kind, payload, **kwargs)

    def deterministic_snapshot(self) -> object:
        """Return immutable replay snapshot with causal digest and governance metadata."""
        with self._lock:
            return build_causal_snapshot(
                events=tuple(self._events),
                budgets=self.budget_snapshot(),
                dependencies=self.dependency_snapshot(),
                invariants=self.invariant_snapshot(),
                generation=0,
            )

    def snapshot(self) -> Tuple[CausalEvent, ...]:
        with self._lock:
            return self._fact_store.snapshot()

    def replay_tombstones(self) -> tuple[dict[str, object], ...]:
        """Compact causal tombstones for suppressed publication events."""
        with self._lock:
            return tuple(tombstone.as_dict() for tombstone in self._replay_tombstones)

    def canonical_replay(self) -> tuple[dict[str, object], ...]:
        with self._lock:
            return tuple(_causal_event_row_without_timestamp(ev) for ev in self.snapshot())

    def since(self, seq: int) -> Tuple[CausalEvent, ...]:
        sequence, issues = runtime_int(
            seq,
            field_name="causal_since_sequence",
            default=0,
        )
        if issues:
            raise ValueError("causal since sequence rejected")
        with self._lock:
            return tuple(ev for ev in self.snapshot() if ev.seq > sequence)

    def trace(self, seq: int) -> tuple[dict[str, object], ...]:
        sequence, issues = runtime_int(
            seq,
            field_name="causal_trace_sequence",
            default=0,
        )
        if issues:
            raise ValueError("causal trace sequence rejected")
        with self._lock:
            ev = self._by_seq.get(sequence)
            if not ev:
                return ()
            lineage = [*list(ev.causal_path), ev.seq]
            return tuple(self._by_seq[s].as_dict() for s in lineage if s in self._by_seq)


    def compressed_replay(self, *, max_payload_keys: int = 8) -> tuple[dict[str, object], ...]:
        """Return deterministic compressed replay lineage records."""
        return compressed_replay_for_bus(self, max_payload_keys=max_payload_keys)

    def compressed_causal_trace(self, *, max_events: int = 512, checkpoint_stride: int = 64) -> dict[str, object]:
        """Return a saturation-safe causal trace summary."""
        return compressed_causal_trace_for_bus(
            self, max_events=max_events, checkpoint_stride=checkpoint_stride
        )

    def telemetry_resource_budget(self) -> dict[str, object]:
        """Budget observability so tracing cannot destabilize runtime orchestration."""
        return telemetry_resource_budget_for_bus(self)

    def replay_lineage_pressure(self) -> dict[str, object]:
        """Forecast replay-lineage pressure before saturation collapses topology."""
        return replay_lineage_pressure_for_bus(self)

    def deterministic_checkpoint(self) -> dict[str, object]:
        """Persistable deterministic checkpoint for all event-stream mutations."""
        return deterministic_checkpoint_for_bus(self)

    def causal_topology_forecast(self) -> dict[str, object]:
        """Causal forecast based on ancestry growth rather than only pressure totals."""
        return causal_topology_forecast_for_bus(self)

    def topology_pressure_forecast(self) -> dict[str, object]:
        """Predict topology instability from density, fanout, suppression, and depth."""
        return topology_pressure_forecast_for_bus(self)

    def budget_snapshot(self) -> dict[str, object]:
        return budget_snapshot_for_bus(self)

    def dependency_snapshot(self) -> dict[str, object]:
        return dependency_snapshot_for_bus(self)

    def invariant_snapshot(self) -> dict[str, object]:
        return invariant_snapshot_for_bus(self)

    def replay_digest(self) -> str:
        """Stable digest over canonical replay records; timestamp-independent."""
        return replay_digest_for_bus(self)

    def causal_trace_visualization(self, *, max_events: int = 2048) -> dict[str, object]:
        """Return a compact graph-friendly causal trace across runtime domains."""
        return causal_trace_visualization_for_bus(self, max_events=max_events)

    def restore_checkpoint(self, checkpoint: Mapping[str, object]) -> None:
        """Restore deterministic stream state from a causal checkpoint."""
        restore_checkpoint_for_bus(self, checkpoint, event_factory=CausalEvent)

    def contract_snapshot(self) -> Mapping[str, object]:
        return event_contract_snapshot()

    @property
    def sequence(self) -> int:
        with self._lock:
            return int(self._seq)

    def reset(self) -> None:
        with self._lock:
            self._seq = 0
            self._events.clear()
            self._by_seq.clear()
            self._budgets.clear()
            self._dedup.clear()
            self._suppressed_summaries.clear()
            self._parent.clear()
            self._depth.clear()
            self._children.clear()
            self._suppressed_reasons.clear()
            self._lineage_counts.clear()
            self._checkpoint_generation = 0
            self._contract_violations = 0
            self._lineage_pruned.clear()
            self._lineage_descendants.clear()
            self._last_checkpoint = None
            self._checkpoint_restore_evidence = ()


_GLOBAL_EVENT_BUS = EventBus()


def get_global_event_bus() -> EventBus:
    return _GLOBAL_EVENT_BUS


def reset_global_event_bus() -> EventBus:
    _GLOBAL_EVENT_BUS.reset()
    return _GLOBAL_EVENT_BUS


__all__ = ("CausalEvent", "EventBus", "WorkloadEventBudget", "get_global_event_bus", "reset_global_event_bus")
