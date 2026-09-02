"""Runtime-owned mutable state boundary for UMIGE.

Orchestration writes go through RuntimeStateOwner, are assigned to an explicit
ownership domain, and receive a mutation generation. There is no retired registry
mirroring or secondary publication path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, MutableMapping, NoReturn, TYPE_CHECKING
from threading import RLock

from Virus_Scan.runtime.readonly import ReadonlyRuntimeView
from Virus_Scan.runtime.state_domains import RuntimeDomainRegistry
from Virus_Scan.runtime.immutable_core import freeze_runtime_value
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.runtime.governance_inputs import runtime_mapping, runtime_text

if TYPE_CHECKING:
    from types import MappingProxyType


_RUNTIME_STATE_OWNER_TYPE_REJECTED = "runtime state owner type rejected"


def _raise_runtime_state_owner_type_rejected() -> NoReturn:
    raise TypeError(_RUNTIME_STATE_OWNER_TYPE_REJECTED)


def _runtime_owner_exact_text(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)
    return "input_rejected"


def _runtime_owner_issue(field_name: object) -> str:
    return _runtime_owner_exact_text(field_name) + " rejected"


def _runtime_owner_path(namespace: str, key: str) -> str:
    return str.__str__(namespace) + "." + str.__str__(key)


def _runtime_owner_items(value: dict[object, object]) -> tuple[tuple[object, object], ...]:
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    return items


def _runtime_owner_text(value: object, *, field_name: str) -> str:
    text, issues = runtime_text(
        value,
        field_name=field_name,
        default="input_rejected",
    )
    if issues:
        raise ValueError(_runtime_owner_issue(field_name))
    return text


@dataclass
class RuntimeStateOwner:
    """Single write authority for orchestration/runtime-owned shared values."""

    state: MutableMapping[str, object] = field(default_factory=dict)
    domains: RuntimeDomainRegistry = field(default_factory=RuntimeDomainRegistry)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)
    _generation: int = 0

    def __post_init__(self) -> None:
        if type(self) is not RuntimeStateOwner:
            _raise_runtime_state_owner_type_rejected()
        if type(self.state) is not dict:
            exception_message = "runtime state owner must own an exact dictionary"
            raise TypeError(exception_message)
        if type(self.domains) is not RuntimeDomainRegistry:
            exception_message = "runtime state owner domains must be RuntimeDomainRegistry"
            raise TypeError(exception_message)
        normalized: dict[str, object] = {}
        for key, value in _runtime_owner_items(self.state):
            normalized[
                _runtime_owner_text(key, field_name="runtime_owner_initial_key")
            ] = freeze_runtime_value(value)
        self.state.clear()
        self.state.update(normalized)

    def refresh(self, new_state: Mapping[str, Any] | None = None) -> MutableMapping[str, object]:
        """Refresh runtime values without replacing the mutable owner map.

        Bootstrap/lifecycle initialization returns immutable snapshots for audit
        determinism.  The runtime owner remains the single mutable lifecycle
        authority, so refresh canonicalizes snapshot values into this owner
        instead of adopting a read-only mapping as the active write store.
        """
        if new_state is not None:
            materialized, issues = runtime_mapping(
                new_state,
                field_name="runtime_owner_refresh_state",
            )
            if issues:
                exception_message = "runtime owner refresh state rejected"
                raise TypeError(exception_message)
            prepared = [
                (
                    _runtime_owner_text(
                        key,
                        field_name="runtime_owner_refresh_key",
                    ),
                    freeze_runtime_value(value),
                )
                for key, value in _runtime_owner_items(materialized)
            ]
        else:
            prepared = []
        with self._lock:
            if new_state is not None:
                self.state.clear()
                for key, frozen in prepared:
                    self.state[key] = frozen
                    self.domains.set("runtime", key, frozen)
                self.domains.set("runtime", "root.state_refreshed", True)
                self._generation += 1
            return self.state

    def get(self, name: str, default: object = None) -> object:
        key = _runtime_owner_text(name, field_name="runtime_owner_get_key")
        with self._lock:
            return self.state.get(key, default)

    def set(self, name: str, value: object, *, domain: str = "runtime") -> object:
        key = _runtime_owner_text(name, field_name="runtime_owner_set_key")
        domain_name = _runtime_owner_text(
            domain,
            field_name="runtime_owner_set_domain",
        )
        frozen = freeze_runtime_value(value)
        with self._lock:
            self.domains.set(domain_name, key, frozen)
            self.state[key] = frozen
            self._generation += 1
            return value

    def update(self, values: dict[str, object], *, namespace: str | None = None, domain: str = "runtime") -> None:
        materialized, issues = runtime_mapping(
            values,
            field_name="runtime_owner_update_values",
        )
        if issues:
            exception_message = "RuntimeStateOwner.update expects an owned mapping"
            raise TypeError(exception_message)
        namespace_text = (
            ""
            if namespace is None
            else _runtime_owner_text(
                namespace,
                field_name="runtime_owner_update_namespace",
            )
        )
        domain_name = _runtime_owner_text(
            domain,
            field_name="runtime_owner_update_domain",
        )
        prepared = []
        for key, value in _runtime_owner_items(materialized):
            key_text = _runtime_owner_text(
                key,
                field_name="runtime_owner_update_key",
            )
            out_key = (
                _runtime_owner_path(namespace_text, key_text)
                if namespace_text
                else key_text
            )
            prepared.append((out_key, freeze_runtime_value(value)))
        with self._lock:
            for out_key, frozen in prepared:
                self.domains.set(domain_name, out_key, frozen)
                self.state[out_key] = frozen
                self._generation += 1

    def has(self, name: str) -> bool:
        key = _runtime_owner_text(name, field_name="runtime_owner_has_key")
        with self._lock:
            return key in self.state


    def snapshot(self) -> MappingProxyType:
        with self._lock:
            return freeze_runtime_value(self.state)

    def readonly_view(self) -> ReadonlyRuntimeView:
        with self._lock:
            return ReadonlyRuntimeView.from_mapping(self.state, config=self.state.get("RUNTIME_CONFIG"), generation=self._generation)


    def mutation_counts(self) -> dict[str, int]:
        return self.domains.mutation_counts()

    def install_config(self, config: object) -> None:
        """Publish an immutable scan/session config snapshot.

        The config object is frozen by RuntimeConfig.  Runtime adaptation may
        produce future configs, but this active snapshot is never mutated in
        place.
        """
        self.set("RUNTIME_CONFIG", config, domain="config")
        stage_limits = config.stage_limits.as_dict()
        self.set("UMIGE_SHARED_STAGE_LIMITS", stage_limits, domain="scheduler")
        self.set("UMIGE_ARCHIVE_LIMITS", config.archive_limits, domain="extraction")
        self.set("UMIGE_RESOURCE_ECONOMICS", config.economics, domain="scheduler")

    def install_telemetry(self, telemetry: object) -> None:
        self.set("UMIGE_RUNTIME_TELEMETRY", telemetry, domain="telemetry")


__all__ = ("RuntimeStateOwner",)
