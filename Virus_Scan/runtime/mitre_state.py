"""Sole mutable runtime owner for the active immutable ATT&CK repository."""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.detection.api.attack_repository_contracts import AttackRepositorySnapshot
from Virus_Scan.detection.api.attack_repository_status_contracts import canonical_runtime_repository_status
from Virus_Scan.runtime.resource_lock import ResourceLockSet


@dataclass(frozen=True, slots=True)
class MitreRuntimeSnapshot:
    enabled: bool
    available: bool
    repository: AttackRepositorySnapshot | None
    status: Mapping[str, object]

    def __post_init__(self) -> None:
        if type(self) is not MitreRuntimeSnapshot:
            raise TypeError("mitre_runtime_snapshot_owner_invalid")
        if type(self.enabled) is not bool or type(self.available) is not bool:
            raise TypeError("mitre_runtime_flags_invalid")
        if self.repository is not None and type(self.repository) is not AttackRepositorySnapshot:
            raise TypeError("mitre_runtime_repository_invalid")
        if self.available != (self.repository is not None):
            raise ValueError("mitre_runtime_availability_mismatch")
        if type(self.status) is not MappingProxyType:
            raise TypeError("mitre_runtime_status_not_frozen")




def _freeze_status_value(value: object) -> object:
    if type(value) in (str, bool, int, float, type(None)):
        return value
    if type(value) is tuple:
        return tuple(_freeze_status_value(item) for item in value[:256])
    if type(value) is list:
        return tuple(_freeze_status_value(item) for item in value[:256])
    if type(value) is dict:
        out: dict[str, object] = {}
        for key, item in tuple(dict.items(value))[:256]:
            if type(key) is not str:
                raise TypeError("mitre_runtime_status_key_invalid")
            out[str.__str__(key)] = _freeze_status_value(item)
        return MappingProxyType(out)
    raise TypeError("mitre_runtime_status_value_invalid")


def _freeze_status(status: dict[str, object]) -> Mapping[str, object]:
    frozen = _freeze_status_value(status)
    if type(frozen) is not MappingProxyType:
        raise TypeError("mitre_runtime_status_not_mapping")
    return frozen

_LOCK = RLock()
_REPOSITORY: AttackRepositorySnapshot | None = None
_ENABLED = True
_STATUS: Mapping[str, object] = MappingProxyType({"unavailable_reason": "mitre_not_initialized", "enabled": True, "available": False})
_LOCK_SET: ResourceLockSet | None = None


def configure_mitre_runtime(
    repository: AttackRepositorySnapshot | None,
    *,
    enabled: bool,
    status: dict[str, object],
    lock_set: ResourceLockSet | None,
) -> MitreRuntimeSnapshot:
    if repository is not None and type(repository) is not AttackRepositorySnapshot:
        raise TypeError("mitre_runtime_repository_invalid")
    if type(enabled) is not bool or type(status) is not dict:
        raise TypeError("mitre_runtime_configuration_invalid")
    if lock_set is not None and type(lock_set) is not ResourceLockSet:
        raise TypeError("mitre_runtime_lock_set_invalid")
    lock_paths = () if lock_set is None else lock_set.paths
    if repository is not None and not lock_paths:
        raise ValueError("mitre_runtime_repository_lock_required")
    derived_lock_state = (
        "active_files_locked" if repository is not None
        else "sentinel_held" if lock_paths
        else "unavailable"
    )
    derived_lock_count = len(lock_paths)
    supplied_lock_state = dict.get(status, "lock_state")
    supplied_lock_count = dict.get(status, "locked_resource_count")
    if supplied_lock_state is not None and supplied_lock_state != derived_lock_state:
        raise ValueError("mitre_runtime_lock_state_mismatch")
    if supplied_lock_count is not None and supplied_lock_count != derived_lock_count:
        raise ValueError("mitre_runtime_lock_count_mismatch")
    canonical_input = dict(status)
    canonical_input["lock_state"] = derived_lock_state
    canonical_input["locked_resource_count"] = derived_lock_count
    canonical = canonical_runtime_repository_status(repository, enabled=enabled, status=canonical_input)
    frozen = _freeze_status(canonical)
    global _REPOSITORY, _ENABLED, _STATUS, _LOCK_SET
    with _LOCK:
        prior = _LOCK_SET
        _REPOSITORY = repository
        _ENABLED = enabled
        _STATUS = frozen
        _LOCK_SET = lock_set
    if prior is not None and prior is not lock_set:
        prior.release_all()
    return mitre_runtime_snapshot()


def mitre_runtime_snapshot() -> MitreRuntimeSnapshot:
    with _LOCK:
        repository = _REPOSITORY
        return MitreRuntimeSnapshot(
            enabled=_ENABLED,
            available=repository is not None,
            repository=repository,
            status=_STATUS,
        )


def release_mitre_runtime() -> None:
    global _REPOSITORY, _ENABLED, _STATUS, _LOCK_SET
    with _LOCK:
        lock_set = _LOCK_SET
        _LOCK_SET = None
        _REPOSITORY = None
        _ENABLED = True
        _STATUS = MappingProxyType({
            "unavailable_reason": "mitre_runtime_released",
            "enabled": True,
            "available": False,
        })
    if lock_set is not None:
        lock_set.release_all()


__all__ = (
    "MitreRuntimeSnapshot", "configure_mitre_runtime", "mitre_runtime_snapshot",
    "release_mitre_runtime",
)
