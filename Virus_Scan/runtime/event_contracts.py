"""Authoritative event contracts for UMIGE runtime governance.

Each cross-domain event is validated against a contract that defines ownership,
propagation policy, severity, and schema version. Unknown events fail closed
instead of being routed to a unowned bucket.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_owner_field, no_hook_mapping_items
from Virus_Scan.runtime.governance_inputs import (
    runtime_float,
    runtime_int,
    runtime_sequence,
    runtime_text,
)


def _contract_text(value: object, default: str) -> str:
    if type(value) is str:
        return str.__str__(value)
    return default


def _contract_field(field_name: object) -> str:
    return "event_contract_" + _contract_text(field_name, "field")


def _contract_indexed_field(prefix: str, index: int) -> str:
    index_text = int.__str__(index) if type(index) is int else "0"
    return str.__str__(prefix) + "_" + index_text


def _contract_rejected_message(field_name: object) -> str:
    return "event contract " + _contract_text(field_name, "field") + " rejected"


def _contract_key(domain: object, kind: object) -> str:
    return _contract_text(domain, "input_rejected") + ":" + _contract_text(kind, "input_rejected")


def _contract_unregistered_message(key: object) -> str:
    return "unregistered event contract: " + _contract_text(key, "input_rejected")


def _event_contract_items() -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(_EVENT_CONTRACTS)
    if items is None:
        return ()
    return tuple(sorted(items, key=lambda row: row[0]))


@dataclass(frozen=True)
class EventContract:
    domain: str
    kind: str
    owner: str
    version: int = 1
    severity: str = "operational"
    propagation: str = "append_only"
    max_cost: float = 64.0
    required_fields: tuple[str, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if type(self) is not EventContract:
            exception_message = "event contract owner rejected"
            raise TypeError(exception_message)
        for field_name, default in (
            ("domain", "runtime"),
            ("kind", "event"),
            ("owner", "runtime"),
            ("severity", "operational"),
            ("propagation", "append_only"),
            ("description", ""),
        ):
            value, issues = runtime_text(
                no_hook_exact_owner_field(self, EventContract, field_name),
                field_name=_contract_field(field_name),
                default=default,
            )
            if issues and field_name != "description":
                raise ValueError(_contract_rejected_message(field_name))
            object.__setattr__(self, field_name, value)
        version, issues = runtime_int(
            self.version, field_name="event_contract_version", default=1
        )
        if issues:
            exception_message = "event contract version rejected"
            raise ValueError(exception_message)
        max_cost, issues = runtime_float(
            self.max_cost,
            field_name="event_contract_max_cost",
            default=64.0,
            minimum=0.0,
        )
        if issues:
            exception_message = "event contract max cost rejected"
            raise ValueError(exception_message)
        fields, issues = runtime_sequence(
            self.required_fields, field_name="event_contract_required_fields"
        )
        if issues:
            exception_message = "event contract required fields rejected"
            raise ValueError(exception_message)
        required: list[str] = []
        for index, field_name in enumerate(fields):
            text, issues = runtime_text(
                field_name,
                field_name=_contract_indexed_field("event_contract_required_field", index),
                default="input_rejected",
            )
            if issues:
                exception_message = "event contract required field rejected"
                raise ValueError(exception_message)
            required.append(text)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "max_cost", max_cost)
        object.__setattr__(self, "required_fields", tuple(required))

    @property
    def key(self) -> str:
        return _contract_key(
            no_hook_exact_owner_field(self, EventContract, "domain"),
            no_hook_exact_owner_field(self, EventContract, "kind"),
        )

    def validate(self, payload: Mapping[str, object] | None) -> tuple[bool, str]:
        data_items = no_hook_mapping_items({} if payload is None else payload)
        if data_items is None:
            return False, "event_payload_mapping_rejected"
        data = dict(data_items)
        missing = [field for field in self.required_fields if field not in data]
        if missing:
            return False, "missing_fields:" + ",".join(sorted(missing))
        return True, "ok"


_DEFAULT_CONTRACTS = (
    EventContract("runtime", "event", "runtime", description="Generic runtime event"),
    EventContract("runtime", "unit", "runtime", description="Deterministic unit-test runtime event"),
    EventContract("runtime", "unit2", "runtime", description="Deterministic unit-test runtime event"),
    EventContract("runtime", "after", "runtime", description="Deterministic replay continuation event"),
    EventContract("runtime", "exports_registered", "runtime", required_fields=("count",)),
    EventContract("runtime", "freeze", "runtime"),
    EventContract("runtime", "contract_violation", "runtime", severity="anomaly"),
    EventContract("runtime", "event_budget_suppressed", "runtime", severity="anomaly"),
    EventContract("runtime", "event_loop_suppressed", "runtime", severity="critical"),
    EventContract("runtime", "equivalent_event_suppressed", "runtime", severity="operational"),
    EventContract("runtime", "simulation_summary", "runtime", required_fields=("workloads",)),
    EventContract("calibration", "analytical_snapshot", "calibration", required_fields=("path_hash", "tag_count")),
    EventContract("semantic", "influence_budget", "semantic", required_fields=("source", "target", "kind")),
    EventContract("semantic", "influence_throttled", "semantic", severity="anomaly", required_fields=("source", "target", "kind")),
    EventContract("governance", "pressure", "governance", required_fields=("domain", "pressure")),
    EventContract("governance", "circuit_breaker", "governance", severity="critical", required_fields=("domain", "pressure")),
    EventContract("governance", "plane_transition", "governance", required_fields=("plane", "state")),
    EventContract("telemetry", "burst_suppressed", "telemetry", severity="operational"),
    EventContract("replay", "lineage_record", "replay", required_fields=("lineage_id",)),
    EventContract("replay", "integrity_violation", "replay", severity="critical"),
    EventContract("scheduler", "debt", "scheduler", required_fields=("workload_id", "debt")),
    EventContract("queue", "aging_boost", "queue", required_fields=("workload_id",)),
    EventContract("extraction", "budget", "extraction", required_fields=("workload_id",)),
    EventContract("failure", "structured", "failure", severity="anomaly"),
    EventContract("cache", "new_generation", "cache", required_fields=("cache", "generation")),
    EventContract("cache", "lineage_invalidation", "cache", required_fields=("cache", "lineage_id", "count")),
    EventContract("cache", "ttl_eviction", "cache", required_fields=("cache", "count", "size")),
    EventContract("cache", "capacity_eviction", "cache", required_fields=("cache", "count", "size")),
    EventContract("cache", "stale_generation_rejected", "cache", required_fields=("cache", "entry_generation", "expected_generation")),
    EventContract("config", "bootstrap_registration_validated", "runtime", required_fields=("module_count",)),
    EventContract("config", "dependency_providers_registered", "runtime"),
    EventContract("config", "top_level_begin", "runtime"),
    EventContract("config", "top_level_phase_completed", "runtime", required_fields=("phase",)),
    EventContract("config", "top_level_finished", "runtime"),
    EventContract("config", "top_level_failed", "runtime"),
    EventContract("config", "runtime_initialized", "runtime"),
    EventContract("governance", "rollback_restore", "governance", required_fields=("sequence",)),
)


_EVENT_CONTRACTS: Mapping[str, EventContract] = MappingProxyType({c.key: c for c in _DEFAULT_CONTRACTS})


def get_event_contract(domain: str, kind: str) -> EventContract:
    domain_text, domain_issues = runtime_text(
        domain, field_name="event_contract_domain", default="input_rejected"
    )
    kind_text, kind_issues = runtime_text(
        kind, field_name="event_contract_kind", default="input_rejected"
    )
    if domain_issues or kind_issues:
        exception_message = "unregistered event contract: input_rejected"
        raise KeyError(exception_message)
    key = _contract_key(domain_text, kind_text)
    contract = _EVENT_CONTRACTS.get(key)
    if contract is not None:
        return contract
    raise KeyError(_contract_unregistered_message(key))


def validate_event_contract(domain: str, kind: str, payload: Mapping[str, object] | None) -> tuple[EventContract, bool, str]:
    contract = get_event_contract(domain, kind)
    ok, reason = contract.validate(payload)
    return contract, ok, reason


def event_contract_snapshot() -> Mapping[str, object]:
    return MappingProxyType({k: {
        "domain": v.domain,
        "kind": v.kind,
        "owner": v.owner,
        "version": v.version,
        "severity": v.severity,
        "propagation": v.propagation,
        "max_cost": v.max_cost,
        "required_fields": list(v.required_fields),
    } for k, v in _event_contract_items()})


__all__ = ("EventContract", "event_contract_snapshot", "get_event_contract", "validate_event_contract")
