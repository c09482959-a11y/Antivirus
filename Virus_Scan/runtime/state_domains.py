"""Owned runtime domains with immutable external views.

Queues, counters, caches, and budgets change only through named owner domains.
Every external read receives a read-only snapshot and every mutation emits an
immutable RuntimeEvent record.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping, MutableMapping, NoReturn
from threading import RLock

from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.runtime.governance_inputs import runtime_int, runtime_text
from Virus_Scan.runtime.immutable_core import freeze_runtime_value

RUNTIME_DOMAIN_MUTATION_BUDGET_REJECTED = "runtime domain mutation budget rejected"


def _raise_runtime_domain_mutation_budget_rejected() -> NoReturn:
    raise ValueError(RUNTIME_DOMAIN_MUTATION_BUDGET_REJECTED)


DEFAULT_DOMAINS = (
    "runtime",
    "runtime_configuration",
    "scheduler",
    "telemetry",
    "replay",
    "calibration",
    "extraction",
    "scanner",
    "reporting",
    "config",
    "detection",
    "logging",
    "model",
    "persistence",
    "routing",
    "scoring",
    "yara",
)


@dataclass
class RuntimeDomain:
    name: str
    max_mutations: int = 100000
    _state: MutableMapping[str, object] = field(default_factory=dict)
    _mutation_count: int = 0
    _generation: int = 0
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def __post_init__(self) -> None:
        if type(self) is not RuntimeDomain:
            exception_message = "runtime domain owner rejected"
            raise TypeError(exception_message)
        self.name, issues = runtime_text(
            self.name, field_name="runtime_domain_name", default="input_rejected"
        )
        if issues:
            exception_message = "runtime domain name rejected"
            raise ValueError(exception_message)
        self.max_mutations, issues = runtime_int(
            self.max_mutations,
            field_name="runtime_domain_max_mutations",
            default=100000,
        )
        if issues:
            _raise_runtime_domain_mutation_budget_rejected()
        self.max_mutations = max(1, self.max_mutations)
        if type(self._state) is not dict:
            exception_message = "runtime domain state must be an owned dictionary"
            raise TypeError(exception_message)

    def set(self, key: str, value: object) -> object:
        key_text, issues = runtime_text(
            key, field_name="runtime_domain_key", default="input_rejected"
        )
        if issues:
            exception_message = "runtime domain key rejected"
            raise ValueError(exception_message)
        with self._lock:
            if self._mutation_count >= self.max_mutations:
                raise RuntimeError("mutation budget exceeded for domain " + self.name)
            self._mutation_count += 1
            self._generation += 1
            frozen = freeze_runtime_value(value)
            self._state[key_text] = frozen
            return frozen


    def snapshot(self) -> MappingProxyType:
        with self._lock:
            return freeze_runtime_value(self._state)


    @property
    def mutation_count(self) -> int:
        with self._lock:
            return int(self._mutation_count)

    @property
    def generation(self) -> int:
        with self._lock:
            return int(self._generation)


@dataclass
class RuntimeDomainRegistry:
    domains: dict[str, RuntimeDomain] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self) is not RuntimeDomainRegistry:
            exception_message = "runtime domain registry owner rejected"
            raise TypeError(exception_message)
        if type(self.domains) is not dict:
            exception_message = "runtime domain registry must own an exact dictionary"
            raise TypeError(exception_message)
        for name in DEFAULT_DOMAINS:
            self.domains.setdefault(name, RuntimeDomain(name))

    def domain(self, name: str) -> RuntimeDomain:
        name, issues = runtime_text(
            name, field_name="runtime_registry_domain", default="input_rejected"
        )
        if issues:
            exception_message = "unregistered runtime ownership domain: input_rejected"
            raise KeyError(exception_message)
        try:
            return self.domains[name]
        except KeyError as exc:
            raise KeyError("unregistered runtime ownership domain: " + name) from exc

    def set(self, domain: str, key: str, value: object) -> object:
        return self.domain(domain).set(key, value)

    def snapshot(self) -> Mapping[str, Mapping[str, object]]:
        domain_items = no_hook_mapping_items(self.domains)
        snapshot: dict[str, Mapping[str, object]] = {}
        for name, domain in sorted(domain_items if domain_items is not None else ()):
            if type(name) is str and type(domain) is RuntimeDomain:
                snapshot[name] = domain.snapshot()
        return MappingProxyType(snapshot)

    def mutation_counts(self) -> dict[str, int]:
        domain_items = no_hook_mapping_items(self.domains)
        return {name: domain.mutation_count for name, domain in sorted(domain_items if domain_items is not None else ())}



__all__ = ("DEFAULT_DOMAINS", "RuntimeDomain", "RuntimeDomainRegistry")
