"""Lifecycle-owned profile persistence state.

Profile learning historically rebounded module globals for staged-benign cache,
dirty flags, and periodic flush counters.  This owner centralizes those mutable
transitions behind explicit methods so profile persistence no longer depends on
function-level ``global`` statements or hidden singleton rebinding.
"""
from __future__ import annotations
from typing import TYPE_CHECKING

from dataclasses import dataclass, field
from threading import RLock

from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.runtime.immutable_core import freeze_runtime_value

if TYPE_CHECKING:
    from collections.abc import Mapping

def _profile_field(value: object) -> str:
    if type(value) is str:
        return str.__str__(value)
    return "profile_field"


def _profile_reason(field_name: object, suffix: str) -> str:
    return _profile_field(field_name) + "_" + str.__str__(suffix)


def _profile_rejection(field_name: object) -> str:
    return _profile_field(field_name) + " rejected"


def _profile_key(value: object, *, field_name: str) -> str:
    text, reason = no_hook_text(
        value,
        missing_reason=_profile_reason(field_name, "missing"),
        unsupported_reason=_profile_reason(field_name, "rejected"),
    )
    if reason or text == "":
        raise ValueError(_profile_rejection(field_name))
    return text


@dataclass
class ProfilePersistenceState:
    """Thread-safe owner for profile persistence mutation state."""

    staged_benign_cache: dict[str, object] | None = None
    staged_benign_dirty: bool = False
    staged_benign_update_count: int = 0
    profile_update_count: int = 0
    engine_cache: dict[str, dict[str, object]] = field(default_factory=dict)
    profile_write_buffer: dict[str, dict[str, object]] = field(default_factory=dict)
    profile_dirty: set[str] = field(default_factory=set)
    profile_corruption_events: list[dict[str, object]] = field(default_factory=list)
    active_profiles_dir: str | None = None
    lock: RLock = field(default_factory=RLock)

    def bind_profiles_dir(self, profiles_dir: str) -> None:
        """Bind cached profile state to one persistent directory.

        Tests and runtime scans may explicitly reconfigure the profile directory.
        Cached engine profiles from a previous directory must not be reused after
        that ownership boundary changes.
        """
        normalized = _profile_key(
            profiles_dir, field_name="profiles_directory"
        )
        with self.lock:
            if self.active_profiles_dir == normalized:
                return
            self.active_profiles_dir = normalized
            self.engine_cache.clear()
            self.profile_write_buffer.clear()
            self.profile_dirty.clear()
            self.profile_corruption_events.clear()
            self.profile_update_count = 0
            self.staged_benign_cache = None
            self.staged_benign_dirty = False
            self.staged_benign_update_count = 0


    def get_engine_profile(self, engine: str) -> dict[str, object] | None:
        key = _profile_key(engine, field_name="profile_engine")
        with self.lock:
            profile = self.engine_cache.get(key)
            return profile if type(profile) is dict else None

    def cache_engine_profile(self, engine: str, profile: dict[str, object]) -> dict[str, object]:
        key = _profile_key(engine, field_name="profile_engine")
        if type(profile) is not dict:
            exception_message = "engine profile must be an owned dictionary"
            raise TypeError(exception_message)
        with self.lock:
            self.engine_cache[key] = profile
            return profile

    def restore_engine_profile(
        self, engine: str, profile: dict[str, object] | None,
    ) -> None:
        key = _profile_key(engine, field_name="profile_engine")
        if profile is not None and type(profile) is not dict:
            raise TypeError("engine profile must be an owned dictionary")
        with self.lock:
            if profile is None:
                self.engine_cache.pop(key, None)
            else:
                self.engine_cache[key] = profile
            self.profile_write_buffer.pop(key, None)
            self.profile_dirty.discard(key)

    def mark_profile_dirty(self, engine: str, profile: dict[str, object]) -> int:
        key = _profile_key(engine, field_name="profile_engine")
        if type(profile) is not dict:
            exception_message = "engine profile must be an owned dictionary"
            raise TypeError(exception_message)
        with self.lock:
            self.engine_cache[key] = profile
            self.profile_write_buffer[key] = profile
            self.profile_dirty.add(key)
            self.profile_update_count += 1
            return self.profile_update_count

    def dirty_profile_items(self) -> list[tuple[str, dict[str, object]]]:
        with self.lock:
            return [
                (engine, self.profile_write_buffer[engine])
                for engine in sorted(self.profile_dirty)
                if isinstance(self.profile_write_buffer.get(engine), dict)
            ]

    def clear_profile_dirty(self, engines: list[str] | tuple[str, ...] | set[str] | None = None) -> None:
        if engines is not None and type(engines) not in (
            list,
            tuple,
            set,
            frozenset,
        ):
            exception_message = "profile engine sequence rejected"
            raise TypeError(exception_message)
        with self.lock:
            if engines is None:
                self.profile_dirty.clear()
                self.profile_write_buffer.clear()
                return
            for engine in no_hook_sequence_items(engines):
                key = _profile_key(engine, field_name="profile_engine")
                self.profile_dirty.discard(key)
                self.profile_write_buffer.pop(key, None)

    def clear_all_profiles(self) -> None:
        with self.lock:
            self.engine_cache.clear()
            self.profile_write_buffer.clear()
            self.profile_dirty.clear()
            self.profile_update_count = 0

    def record_profile_corruption_event(self, event: dict[str, object]) -> None:
        with self.lock:
            self.profile_corruption_events.append(
                freeze_runtime_value({} if event is None else event)
            )

    def _freeze_profile_corruption_value(self, value: object) -> object:
        return freeze_runtime_value(value)

    def profile_corruption_events_snapshot(self) -> tuple[Mapping[str, object], ...]:
        with self.lock:
            return tuple(
                self._freeze_profile_corruption_value(item)
                for item in self.profile_corruption_events
            )

    def get_staged_cache(self) -> dict[str, object] | None:
        with self.lock:
            return self.staged_benign_cache

    def set_staged_cache(self, store: dict[str, object] | None, *, dirty: bool | None = None) -> dict[str, object] | None:
        if store is not None and type(store) is not dict:
            exception_message = "staged profile cache must be an owned dictionary"
            raise TypeError(exception_message)
        if dirty is not None and type(dirty) is not bool:
            exception_message = "staged profile dirty flag rejected"
            raise TypeError(exception_message)
        with self.lock:
            self.staged_benign_cache = store
            if dirty is not None:
                self.staged_benign_dirty = dirty
            return self.staged_benign_cache

    def staged_dirty(self) -> bool:
        with self.lock:
            return self.staged_benign_dirty

    def mark_staged_dirty(self, store: dict[str, object] | None = None) -> int:
        if store is not None and type(store) is not dict:
            exception_message = "staged profile cache must be an owned dictionary"
            raise TypeError(exception_message)
        with self.lock:
            if store is not None:
                self.staged_benign_cache = store
            self.staged_benign_dirty = True
            self.staged_benign_update_count += 1
            return self.staged_benign_update_count

    def clear_staged_dirty(self) -> None:
        with self.lock:
            self.staged_benign_dirty = False

    def reset_staged_update_count(self) -> None:
        with self.lock:
            self.staged_benign_update_count = 0

    def increment_profile_update_count(self) -> int:
        with self.lock:
            self.profile_update_count += 1
            return self.profile_update_count

    def reset_profile_update_count(self) -> None:
        with self.lock:
            self.profile_update_count = 0


_PROFILE_PERSISTENCE_STATE = ProfilePersistenceState()


def profile_persistence_state() -> ProfilePersistenceState:
    return _PROFILE_PERSISTENCE_STATE


__all__ = ("ProfilePersistenceState", "profile_persistence_state")
