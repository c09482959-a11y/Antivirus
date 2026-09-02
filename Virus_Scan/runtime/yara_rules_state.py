"""Lifecycle-owned YARA rule loading state.

YARA rule objects, source paths, and load counters are owned here behind an
explicit lock.  Consumers read snapshots from this owner instead of module-level
publication values.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PosixPath, WindowsPath
import math
from threading import RLock
from types import MappingProxyType
from typing import Mapping, NoReturn

from Virus_Scan.runtime.resource_lock import ResourceLockSet
from Virus_Scan.contracts.no_hook_materialization import (
    exact_bool_or_none,
    materialize_json_no_hook,
    no_hook_exact_nonnegative_int,
    no_hook_failure,
    no_hook_json_sort_key,
    no_hook_mapping_items,
)


YARA_PUBLICATION_VERSION = "yara_publication_v1"
YARA_LIGHT_SNAPSHOT_OWNER_REJECTED = "yara light snapshot owner rejected"
_PATH_TYPES = (Path, PosixPath, WindowsPath)


def _raise_yara_light_snapshot_owner_rejected() -> NoReturn:
    raise TypeError(YARA_LIGHT_SNAPSHOT_OWNER_REJECTED)


YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE = "yara_snapshot_key_text_unavailable"
YARA_SOURCE_PATH_TEXT_UNAVAILABLE = "yara_source_path_text_unavailable"


def _yara_rules_exact_text(value: object, *, default_text: str = "") -> str:
    """Detach runtime-owned YARA snapshot text without arbitrary ``__str__``.

    YARA rule snapshots are runtime-owned and can flow into scheduler/publication
    metadata.  Snapshot text must therefore be detached from caller-owned
    objects; unsupported objects are represented by explicit unavailable text
    rather than being coerced through arbitrary ``str(value)``.
    """
    if value is None:
        return default_text
    if type(value) is str:
        return str.__str__(value)
    if type(value) is bytes:
        return bytes(value).decode("utf-8", errors="replace")
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return int.__str__(value)
    if type(value) is float:
        return float.__str__(value) if math.isfinite(value) else default_text
    return default_text


def _yara_snapshot_key_text(value: object) -> str:
    text = _yara_rules_exact_text(value, default_text=YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE).strip()
    return text or "empty_yara_snapshot_key"


def _unique_yara_snapshot_key(base: str, used: set[str]) -> str:
    if base not in used:
        used.add(base)
        return base
    index = 2
    while base + "_" + int.__str__(index) in used:
        index += 1
    unique = base + "_" + int.__str__(index)
    used.add(unique)
    return unique


def _immutable_yara_evidence(reason: str, value: object) -> MappingProxyType:
    materialized = materialize_json_no_hook(
        no_hook_failure(reason, value),
        context="yara_snapshot_evidence",
        max_depth=4,
        max_items=16,
    )
    if type(materialized) is dict:
        return MappingProxyType(
            dict(dict.items(materialized))
        )
    return MappingProxyType({
        "value": None,
        "unavailable_reason": "yara_snapshot_evidence_materialization_failed",
        "value_type": "unknown",
    })


def _freeze_yara_snapshot_mapping(value: object, *, depth: int = 0) -> MappingProxyType:
    items = no_hook_mapping_items(value)
    if items is None:
        return _immutable_yara_evidence("yara_snapshot_mapping_unreadable", value)
    ordered = sorted(
        ((_yara_snapshot_key_text(key), position, item_value) for position, (key, item_value) in enumerate(items)),
        key=lambda item: (item[0].lower(), item[0], item[1]),
    )
    used: set[str] = set()
    frozen: dict[str, object] = {}
    for key_text, _position, item_value in ordered:
        frozen[_unique_yara_snapshot_key(key_text, used)] = _freeze_yara_snapshot_value(item_value, depth=depth + 1)
    return MappingProxyType(frozen)


def _freeze_yara_snapshot_sequence(value: object, *, depth: int) -> tuple[object, ...]:
    return tuple(_freeze_yara_snapshot_value(item, depth=depth + 1) for item in value)


def _freeze_yara_snapshot_set(value: object, *, depth: int) -> tuple[object, ...]:
    frozen_items = tuple(_freeze_yara_snapshot_value(item, depth=depth + 1) for item in value)
    return tuple(
        item
        for _sort_key, _position, item in sorted(
            ((no_hook_json_sort_key(materialize_json_no_hook(item, context="yara_snapshot_set_sort", max_depth=4, max_items=16)), position, item) for position, item in enumerate(frozen_items)),
            key=lambda entry: (entry[0], entry[1]),
        )
    )


def _freeze_yara_snapshot_value(value: object, *, depth: int = 0) -> object:
    """Detach JSON-style mutable rule metadata while preserving top-level compiled rule carriers."""
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        if math.isfinite(value):
            return value
        return _immutable_yara_evidence(
            "yara_snapshot_nonfinite_number_rejected",
            value,
        )
    if type(value) is str:
        return str.__str__(value)
    if isinstance(value, str):
        return _immutable_yara_evidence("yara_snapshot_text_subclass_rejected", value)
    if isinstance(value, MappingProxyType) or type(value) is dict:
        return _freeze_yara_snapshot_mapping(value, depth=depth)
    if isinstance(value, dict):
        return _immutable_yara_evidence("yara_snapshot_mapping_subclass_rejected", value)
    if type(value) in (list, tuple):
        return _freeze_yara_snapshot_sequence(value, depth=depth)
    if type(value) in (set, frozenset):
        return _freeze_yara_snapshot_set(value, depth=depth)
    if depth == 0:
        # Compiled yara-python rule objects are live runtime-owned carriers used
        # by the matcher.  Preserve non-string carriers only at the top-level
        # rules slot; string subclasses remain rejected at this boundary above.
        return value
    return _immutable_yara_evidence("yara_snapshot_value_unsupported", value)

def _yara_source_path_text(value: object) -> str | None:
    if value is None:
        return None
    text = _yara_rules_exact_text(value, default_text=YARA_SOURCE_PATH_TEXT_UNAVAILABLE).strip()
    return text or "empty_yara_source_path"


def _yara_loaded_count(value: object) -> int:
    count, _reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason="yara_loaded_count_rejected",
        allow_exact_text=False,
    )
    return count


def _default_yara_status(reason: str) -> MappingProxyType:
    return MappingProxyType({"unavailable_reason": reason})


def _freeze_yara_status(value: object, *, reason: str) -> MappingProxyType:
    if type(value) is dict or type(value) is MappingProxyType:
        return _freeze_yara_snapshot_mapping(value)
    return _default_yara_status(reason)


@dataclass(frozen=True)
class YaraLightSnapshot:
    rules: object = None
    ok: bool = False
    loaded_count: int = 0
    source: object = None
    identity: object = None
    load_result: object = None
    import_error_logged: bool = False
    status: object = field(default_factory=lambda: _default_yara_status("yaralight_not_initialized"))

    def __post_init__(self) -> None:
        if type(self) is not YaraLightSnapshot:
            _raise_yara_light_snapshot_owner_rejected()
        object.__setattr__(self, "rules", _freeze_yara_snapshot_value(self.rules))
        object.__setattr__(self, "ok", exact_bool_or_none(self.ok) is True)
        object.__setattr__(self, "loaded_count", _yara_loaded_count(self.loaded_count))
        object.__setattr__(self, "import_error_logged", exact_bool_or_none(self.import_error_logged) is True)
        object.__setattr__(self, "status", _freeze_yara_status(self.status, reason="yaralight_status_invalid"))


@dataclass(frozen=True)
class YaraRulesSnapshot:
    rules: object = None
    loaded_count: int = 0
    source_path: str | None = None
    source: object = None
    identity: object = None
    load_result: object = None
    status: object = field(default_factory=lambda: _default_yara_status("yara_primary_not_initialized"))

    def __post_init__(self) -> None:
        if type(self) is not YaraRulesSnapshot:
            raise TypeError("yara rules snapshot owner rejected")
        object.__setattr__(self, "rules", _freeze_yara_snapshot_value(self.rules))
        object.__setattr__(self, "loaded_count", _yara_loaded_count(self.loaded_count))
        object.__setattr__(self, "source_path", _yara_source_path_text(self.source_path))
        object.__setattr__(self, "status", _freeze_yara_status(self.status, reason="yara_primary_status_invalid"))


@dataclass(frozen=True)
class YaraRuntimeSnapshot:
    enabled: bool = True
    available: bool = False
    primary: YaraRulesSnapshot = field(default_factory=YaraRulesSnapshot)
    light: YaraLightSnapshot = field(default_factory=YaraLightSnapshot)
    status: object = field(default_factory=lambda: _default_yara_status("yara_not_initialized"))

    def __post_init__(self) -> None:
        if type(self) is not YaraRuntimeSnapshot:
            raise TypeError("yara_runtime_snapshot_owner_invalid")
        enabled = exact_bool_or_none(self.enabled) is True
        available = exact_bool_or_none(self.available) is True
        if type(self.primary) is not YaraRulesSnapshot or type(self.light) is not YaraLightSnapshot:
            raise TypeError("yara_runtime_package_snapshot_invalid")
        derived_available = self.primary.rules is not None or self.light.ok
        if available != derived_available:
            raise ValueError("yara_runtime_availability_mismatch")
        object.__setattr__(self, "enabled", enabled)
        object.__setattr__(self, "available", available)
        object.__setattr__(self, "status", _freeze_yara_status(self.status, reason="yara_runtime_status_invalid"))


class YaraRulesState:
    """Single lifecycle owner for compiled primary/light rules and publication evidence."""

    def __init__(self) -> None:
        if type(self) is not YaraRulesState:
            raise TypeError("yara_rules_state_owner_invalid")
        self._lock = RLock()
        self._light = YaraLightSnapshot()
        self._primary = YaraRulesSnapshot()
        self._enabled = True
        self._status = _default_yara_status("yara_not_initialized")
        self._resource_locks: ResourceLockSet | None = None
        self._readonly = False

    def light_snapshot(self) -> YaraLightSnapshot:
        with self._lock:
            return YaraLightSnapshot(
                rules=self._light.rules,
                ok=exact_bool_or_none(self._light.ok) is True,
                loaded_count=_yara_loaded_count(self._light.loaded_count),
                source=self._light.source,
                identity=self._light.identity,
                load_result=self._light.load_result,
                import_error_logged=exact_bool_or_none(self._light.import_error_logged) is True,
                status=self._light.status,
            )

    def primary_snapshot(self) -> YaraRulesSnapshot:
        with self._lock:
            return YaraRulesSnapshot(
                rules=self._primary.rules,
                loaded_count=_yara_loaded_count(self._primary.loaded_count),
                source_path=self._primary.source_path,
                source=self._primary.source,
                identity=self._primary.identity,
                load_result=self._primary.load_result,
                status=self._primary.status,
            )

    def runtime_snapshot(self) -> YaraRuntimeSnapshot:
        with self._lock:
            primary = YaraRulesSnapshot(
                rules=self._primary.rules,
                loaded_count=self._primary.loaded_count,
                source_path=self._primary.source_path,
                source=self._primary.source,
                identity=self._primary.identity,
                load_result=self._primary.load_result,
                status=self._primary.status,
            )
            light = YaraLightSnapshot(
                rules=self._light.rules,
                ok=self._light.ok,
                loaded_count=self._light.loaded_count,
                source=self._light.source,
                identity=self._light.identity,
                load_result=self._light.load_result,
                import_error_logged=self._light.import_error_logged,
                status=self._light.status,
            )
            return YaraRuntimeSnapshot(
                enabled=self._enabled,
                available=primary.rules is not None or light.ok,
                primary=primary,
                light=light,
                status=self._status,
            )

    def mark_light_import_error(self) -> None:
        with self._lock:
            self._light = YaraLightSnapshot(
                rules=self._light.rules,
                ok=exact_bool_or_none(self._light.ok) is True,
                loaded_count=_yara_loaded_count(self._light.loaded_count),
                source=self._light.source,
                identity=self._light.identity,
                load_result=self._light.load_result,
                import_error_logged=True,
                status=self._light.status,
            )

    def set_light_rules(
        self, rules: object, ok: bool, loaded_count: int | None = None, *,
        source: object = None,
        identity: object = None,
        load_result: object = None,
    ) -> None:
        with self._lock:
            self._light = YaraLightSnapshot(
                rules=rules,
                ok=exact_bool_or_none(ok) is True,
                loaded_count=_yara_loaded_count(self._light.loaded_count if loaded_count is None else loaded_count),
                source=source,
                identity=identity,
                load_result=load_result,
                import_error_logged=exact_bool_or_none(self._light.import_error_logged) is True,
                status=self._light.status,
            )

    def set_primary_rules(
        self, rules: object, *, source_path: str | None = None,
        loaded_count: int | None = None, source: object = None,
        identity: object = None,
        load_result: object = None,
    ) -> None:
        with self._lock:
            self._primary = YaraRulesSnapshot(
                rules=rules,
                loaded_count=_yara_loaded_count(self._primary.loaded_count if loaded_count is None else loaded_count),
                source_path=self._primary.source_path if source_path is None else _yara_source_path_text(source_path),
                source=source,
                identity=identity,
                load_result=load_result,
                status=self._primary.status,
            )

    def clear_primary_rules(self) -> None:
        with self._lock:
            self._primary = YaraRulesSnapshot(
                rules=None,
                loaded_count=_yara_loaded_count(self._primary.loaded_count),
                source_path=self._primary.source_path,
                source=None,
                identity=None,
                load_result=None,
                status=self._primary.status,
            )

    def configure_runtime(
        self,
        *,
        enabled: bool,
        config_status: dict[str, object],
        primary_status: dict[str, object],
        light_status: dict[str, object],
        lock_set: ResourceLockSet | None,
        readonly: bool,
    ) -> YaraRuntimeSnapshot:
        if type(enabled) is not bool or type(readonly) is not bool:
            raise TypeError("yara_runtime_flags_invalid")
        if type(config_status) is not dict or type(primary_status) is not dict or type(light_status) is not dict:
            raise TypeError("yara_runtime_status_contract_invalid")
        if lock_set is not None and type(lock_set) is not ResourceLockSet:
            raise TypeError("yara_runtime_lock_set_invalid")
        lock_paths = () if lock_set is None else lock_set.paths
        with self._lock:
            primary_available = self._primary.rules is not None
            light_available = self._light.ok
            available = primary_available or light_available
            if available and not lock_paths:
                raise ValueError("yara_runtime_active_rules_lock_required")
            lock_state = (
                "active_files_locked" if available
                else "readonly_resources_locked" if readonly and lock_paths
                else "initialization_resources_locked" if lock_paths
                else "unavailable"
            )
            locked_count = len(lock_paths)
            supplied_state = dict.get(config_status, "lock_state")
            supplied_count = dict.get(config_status, "locked_resource_count")
            if supplied_state is not None and supplied_state != lock_state:
                raise ValueError("yara_runtime_lock_state_mismatch")
            if supplied_count is not None and supplied_count != locked_count:
                raise ValueError("yara_runtime_lock_count_mismatch")

            primary_data = dict(primary_status)
            primary_data["enabled"] = enabled and dict.get(config_status, "full_enabled") is True
            primary_data["available"] = primary_available
            light_data = dict(light_status)
            light_data["enabled"] = enabled and dict.get(config_status, "light_enabled") is True
            light_data["available"] = light_available

            reason = dict.get(config_status, "unavailable_reason")
            if type(reason) is not str:
                reason = ""
            if available:
                reason = ""
            elif not reason:
                primary_reason = dict.get(primary_data, "unavailable_reason")
                light_reason = dict.get(light_data, "unavailable_reason")
                reason = (
                    primary_reason if type(primary_reason) is str and primary_reason
                    else light_reason if type(light_reason) is str and light_reason
                    else "yara_rules_unavailable"
                )

            runtime_data = dict(config_status)
            runtime_data.update({
                "available": available,
                "enabled": enabled,
                "light": light_data,
                "lock_state": lock_state,
                "locked_resource_count": locked_count,
                "primary": primary_data,
                "publication_version": YARA_PUBLICATION_VERSION,
                "readonly": readonly,
                "unavailable_reason": reason,
            })
            prior = self._resource_locks
            self._enabled = enabled
            self._readonly = readonly
            self._resource_locks = lock_set
            self._primary = YaraRulesSnapshot(
                rules=self._primary.rules,
                loaded_count=self._primary.loaded_count,
                source_path=self._primary.source_path,
                source=self._primary.source,
                identity=self._primary.identity,
                load_result=self._primary.load_result,
                status=primary_data,
            )
            self._light = YaraLightSnapshot(
                rules=self._light.rules,
                ok=self._light.ok,
                loaded_count=self._light.loaded_count,
                source=self._light.source,
                identity=self._light.identity,
                load_result=self._light.load_result,
                import_error_logged=self._light.import_error_logged,
                status=light_data,
            )
            self._status = _freeze_yara_status(runtime_data, reason="yara_runtime_status_invalid")
        if prior is not None and prior is not lock_set:
            prior.release_all()
        return self.runtime_snapshot()

    def acquire_read_lock(self, path: Path) -> None:
        if type(path) not in _PATH_TYPES:
            raise TypeError("yara_runtime_read_lock_path_invalid")
        if not path.is_file():
            raise ValueError("yara_runtime_read_lock_file_invalid")
        with self._lock:
            lock_set = self._resource_locks
            if lock_set is None:
                raise RuntimeError("yara_runtime_lock_set_unavailable")
            resolved = path.resolve()
            if any(existing.resolve() == resolved for existing in lock_set.paths):
                return
            lock_set.acquire(path, writable=False)
            status = dict(self._status)
            status["locked_resource_count"] = len(lock_set.paths)
            status["lock_state"] = "active_files_locked" if (self._primary.rules is not None or self._light.ok) else "readonly_resources_locked"
            self._status = _freeze_yara_status(status, reason="yara_runtime_status_invalid")

    def lock_paths(self) -> tuple[Path, ...]:
        with self._lock:
            lock_set = self._resource_locks
            return () if lock_set is None else lock_set.paths

    def readonly(self) -> bool:
        with self._lock:
            return self._readonly

    def release_runtime(self) -> None:
        with self._lock:
            lock_set = self._resource_locks
            self._resource_locks = None
            self._readonly = False
            self._light = YaraLightSnapshot(status={"unavailable_reason": "yara_runtime_released"})
            self._primary = YaraRulesSnapshot(status={"unavailable_reason": "yara_runtime_released"})
            self._status = _freeze_yara_status({
                "available": False,
                "enabled": self._enabled,
                "lock_state": "unavailable",
                "locked_resource_count": 0,
                "publication_version": YARA_PUBLICATION_VERSION,
                "readonly": False,
                "unavailable_reason": "yara_runtime_released",
            }, reason="yara_runtime_released")
        if lock_set is not None:
            lock_set.release_all()


_YARA_RULES_STATE = YaraRulesState()


def yara_rules_state() -> YaraRulesState:
    return _YARA_RULES_STATE


def yara_runtime_snapshot() -> YaraRuntimeSnapshot:
    return _YARA_RULES_STATE.runtime_snapshot()


def release_yara_runtime() -> None:
    _YARA_RULES_STATE.release_runtime()


__all__ = (
    "YARA_PUBLICATION_VERSION",
    "YARA_SNAPSHOT_KEY_TEXT_UNAVAILABLE",
    "YARA_SOURCE_PATH_TEXT_UNAVAILABLE",
    "YaraLightSnapshot",
    "YaraRulesSnapshot",
    "YaraRulesState",
    "YaraRuntimeSnapshot",
    "release_yara_runtime",
    "yara_rules_state",
    "yara_runtime_snapshot",
)
